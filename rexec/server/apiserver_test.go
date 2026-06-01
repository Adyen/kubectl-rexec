package server

import (
	"os"
	"testing"
)

func TestInitAPIServer(t *testing.T) {
	oldDomain, oldHost, oldDial := ClusterDomain, apiServerHost, apiServerDial
	t.Cleanup(func() {
		ClusterDomain, apiServerHost, apiServerDial = oldDomain, oldHost, oldDial
	})

	ClusterDomain = "corp.internal"
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	initAPIServer()

	if apiServerHost != "kubernetes.default.svc.corp.internal" {
		t.Fatalf("apiServerHost = %q, want kubernetes.default.svc.corp.internal", apiServerHost)
	}
	if apiServerDial != "10.96.0.1:443" {
		t.Fatalf("apiServerDial = %q, want 10.96.0.1:443", apiServerDial)
	}
}

func TestInitAPIServerIPv6(t *testing.T) {
	oldDomain, oldHost, oldDial := ClusterDomain, apiServerHost, apiServerDial
	t.Cleanup(func() {
		ClusterDomain, apiServerHost, apiServerDial = oldDomain, oldHost, oldDial
	})

	ClusterDomain = "cluster.local"
	t.Setenv("KUBERNETES_SERVICE_HOST", "fd00:10:96::1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	initAPIServer()

	if apiServerHost != "kubernetes.default.svc.cluster.local" {
		t.Fatalf("apiServerHost = %q, want kubernetes.default.svc.cluster.local", apiServerHost)
	}
	if apiServerDial != "[fd00:10:96::1]:443" {
		t.Fatalf("apiServerDial = %q, want [fd00:10:96::1]:443", apiServerDial)
	}
}

func TestInitAPIServerDefaultDomain(t *testing.T) {
	oldDomain, oldHost, oldDial := ClusterDomain, apiServerHost, apiServerDial
	t.Cleanup(func() {
		ClusterDomain, apiServerHost, apiServerDial = oldDomain, oldHost, oldDial
	})

	ClusterDomain = ""
	os.Unsetenv("CLUSTER_DOMAIN")
	os.Unsetenv("KUBERNETES_SERVICE_HOST")
	os.Unsetenv("KUBERNETES_SERVICE_PORT")
	initAPIServer()

	if apiServerHost != "kubernetes.default.svc.cluster.local" {
		t.Fatalf("apiServerHost = %q, want kubernetes.default.svc.cluster.local", apiServerHost)
	}
	if apiServerDial != "kubernetes.default.svc.cluster.local:443" {
		t.Fatalf("apiServerDial = %q, want kubernetes.default.svc.cluster.local:443", apiServerDial)
	}
}
