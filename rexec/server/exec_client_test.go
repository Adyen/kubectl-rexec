package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"
	rcmd "k8s.io/client-go/tools/remotecommand"
	"k8s.io/streaming/pkg/httpstream"
)

func TestNewPodExecExecutor(t *testing.T) {
	cfg := &restclient.Config{Host: "https://kubernetes.default.svc"}
	execURL := "https://kubernetes.default.svc/api/v1/namespaces/default/pods/foo/exec?stdin=true&stdout=true"
	exec, err := newPodExecExecutor(cfg, execURL)
	if err != nil {
		t.Fatal(err)
	}
	if exec == nil {
		t.Fatal("expected non-nil executor")
	}
}

func TestPodExecURL(t *testing.T) {
	cfg := &restclient.Config{
		Host:     "https://kubernetes.default.svc",
		APIPath:  "/api",
		ContentConfig: restclient.ContentConfig{
			GroupVersion:         &corev1.SchemeGroupVersion,
			NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
		},
	}
	url, err := podExecURL(cfg, "ns1", "pod1", &corev1.PodExecOptions{
		Container: "c1",
		Command:   []string{"sh"},
		Stdin:     true,
		Stdout:    true,
		TTY:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"/api/v1/namespaces/ns1/pods/pod1/exec",
		"container=c1",
		"command=sh",
		"stdin=true",
		"stdout=true",
		"tty=true",
	} {
		if !strings.Contains(url, want) {
			t.Fatalf("podExecURL() = %q, want substring %q", url, want)
		}
	}
}

func TestShouldFallbackEgress(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "generic", err: errors.New("connection refused"), want: false},
		{name: "upgrade failure", err: &httpstream.UpgradeFailureError{}, want: true},
		{name: "wrapped upgrade failure", err: errors.Join(errors.New("dial"), &httpstream.UpgradeFailureError{}), want: true},
		{name: "https proxy", err: errors.New("proxy: unknown scheme: https"), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldFallbackEgress(tt.err); got != tt.want {
				t.Fatalf("shouldFallbackEgress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEgressLoggingExecutor(t *testing.T) {
	t.Run("propagates error", func(t *testing.T) {
		want := errors.New("stream failed")
		exec := withEgressLog(&stubExecutor{err: want}, "websocket")
		err := exec.StreamWithContext(context.Background(), rcmd.StreamOptions{})
		if !errors.Is(err, want) {
			t.Fatalf("StreamWithContext() = %v, want %v", err, want)
		}
	})

	t.Run("success", func(t *testing.T) {
		inner := &stubExecutor{}
		exec := withEgressLog(inner, "spdy")
		if err := exec.StreamWithContext(context.Background(), rcmd.StreamOptions{}); err != nil {
			t.Fatal(err)
		}
		if !inner.called {
			t.Fatal("expected inner executor to be invoked")
		}
	})
}

type stubExecutor struct {
	err    error
	called bool
}

func (s *stubExecutor) Stream(opts rcmd.StreamOptions) error {
	return s.StreamWithContext(context.Background(), opts)
}

func (s *stubExecutor) StreamWithContext(context.Context, rcmd.StreamOptions) error {
	s.called = true
	return s.err
}
