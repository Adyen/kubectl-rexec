package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"
	rcmd "k8s.io/client-go/tools/remotecommand"
	"k8s.io/streaming/pkg/httpstream"
)

func impersonatedRESTConfig(user string, groups []string) (*restclient.Config, error) {
	if err := ensureValidToken(); err != nil {
		return nil, err
	}
	cfg, err := restclient.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	cfg.Host = "https://" + apiServerDial
	cfg.BearerToken = token
	cfg.TLSClientConfig = restclient.TLSClientConfig{CAFile: caPath}
	cfg.Impersonate = restclient.ImpersonationConfig{
		UserName: user, Groups: groups,
		// Matches the Extra key checked by the validating webhook in canPass
		Extra: map[string][]string{"secret-sauce": {SecretSauce}},
	}
	// Required to build a REST client from a hand-rolled impersonation config
	cfg.GroupVersion = &corev1.SchemeGroupVersion
	cfg.APIPath = "/api"
	cfg.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	return cfg, nil
}

func podExecURL(cfg *restclient.Config, namespace, pod string, opts *corev1.PodExecOptions) (string, error) {
	client, err := restclient.RESTClientFor(cfg)
	if err != nil {
		return "", err
	}
	return client.Post().Namespace(namespace).Resource("pods").Name(pod).SubResource("exec").
		VersionedParams(opts, scheme.ParameterCodec).URL().String(), nil
}

// newPodExecExecutor tries WebSocket egress first (GET), falling back to SPDY (POST)
// when the apiserver does not support a WebSocket upgrade
func newPodExecExecutor(cfg *restclient.Config, execURL string) (rcmd.Executor, error) {
	u, err := url.Parse(execURL)
	if err != nil {
		return nil, err
	}
	spdy, err := rcmd.NewSPDYExecutor(cfg, http.MethodPost, u)
	if err != nil {
		return nil, err
	}
	ws, err := rcmd.NewWebSocketExecutor(cfg, http.MethodGet, execURL)
	if err != nil {
		return nil, err
	}
	return rcmd.NewFallbackExecutor(
		withEgressLog(ws, "websocket"),
		withEgressLog(spdy, "spdy"),
		shouldFallbackEgress,
	)
}

func shouldFallbackEgress(err error) bool {
	if httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err) {
		SysLogger.Debug().Err(err).Msg("websocket egress unavailable, falling back to spdy")
		return true
	}
	return false
}

func withEgressLog(exec rcmd.Executor, protocol string) rcmd.Executor {
	return &egressLoggingExecutor{inner: exec, protocol: protocol}
}

type egressLoggingExecutor struct {
	inner    rcmd.Executor
	protocol string
}

func (e *egressLoggingExecutor) Stream(opts rcmd.StreamOptions) error {
	return e.StreamWithContext(context.Background(), opts)
}

func (e *egressLoggingExecutor) StreamWithContext(ctx context.Context, opts rcmd.StreamOptions) error {
	err := e.inner.StreamWithContext(ctx, opts)
	if err == nil {
		logEgress(e.protocol)
	}
	return err
}
