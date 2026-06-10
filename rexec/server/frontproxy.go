package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	authConfigMapNamespace       = "kube-system"
	authConfigMapName            = "extension-apiserver-authentication"
	requestHeaderCAKey           = "requestheader-client-ca-file"
	requestHeaderAllowedNamesKey = "requestheader-allowed-names"
)

// RequestHeaderCAPool holds the front-proxy CA the kube-apiserver uses to sign
// the client certificate it presents when proxying aggregated API traffic.
// Inbound exec requests must present a certificate chaining to this pool before
// their X-Remote-* identity headers may be trusted.
var RequestHeaderCAPool *x509.CertPool

// RequestHeaderAllowedNames is the list of client-certificate common names the
// kube-apiserver is allowed to present. An empty list means any name validated
// by RequestHeaderCAPool is accepted, matching kube-apiserver behaviour.
var RequestHeaderAllowedNames []string

// loadFrontProxyConfig reads the requestheader CA and allowed client-certificate
// common names from the kube-system extension-apiserver-authentication ConfigMap.
// The kube-apiserver publishes there the CA it uses to sign the proxy client
// certificate. An aggregated API server must verify inbound client certificates
// against this CA before trusting the X-Remote-User / X-Remote-Group headers,
// otherwise any caller able to reach the backend directly can forge them and
// have the server impersonate an arbitrary user (e.g. system:masters).
func loadFrontProxyConfig() error {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to build in-cluster config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client: %w", err)
	}
	cm, err := clientset.CoreV1().ConfigMaps(authConfigMapNamespace).Get(context.Background(), authConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to read %s/%s: %w", authConfigMapNamespace, authConfigMapName, err)
	}

	caPEM, ok := cm.Data[requestHeaderCAKey]
	if !ok || caPEM == "" {
		return fmt.Errorf("%s missing from %s/%s", requestHeaderCAKey, authConfigMapNamespace, authConfigMapName)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return errors.New("failed to parse requestheader client CA certificate")
	}
	RequestHeaderCAPool = pool

	if raw, ok := cm.Data[requestHeaderAllowedNamesKey]; ok && raw != "" {
		var names []string
		if err := json.Unmarshal([]byte(raw), &names); err != nil {
			return fmt.Errorf("failed to parse %s: %w", requestHeaderAllowedNamesKey, err)
		}
		RequestHeaderAllowedNames = names
	}
	return nil
}

// verifiedFrontProxy reports whether the request arrived over a TLS connection
// presenting a client certificate that chains to the requestheader CA and whose
// common name is in the allowed-names list (an empty list allows any verified
// name). Only requests that satisfy this may be trusted to carry X-Remote-*
// identity headers used for impersonation.
func verifiedFrontProxy(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return false
	}
	if len(RequestHeaderAllowedNames) == 0 {
		return true
	}
	cn := r.TLS.VerifiedChains[0][0].Subject.CommonName
	for _, allowed := range RequestHeaderAllowedNames {
		if allowed == cn {
			return true
		}
	}
	return false
}
