package server

import (
	"net"
	"os"
	"strings"
)

const defaultClusterDomain = "cluster.local"

var (
	ClusterDomain string
	apiServerHost string // tls ServerName and reverse-proxy Host header
	apiServerDial string // tcp dial target
)

func initAPIServer() {
	apiServerHost = "kubernetes.default.svc." + clusterDomain()

	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	if host == "" {
		host = apiServerHost
	}
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if port == "" {
		port = "443"
	}
	apiServerDial = net.JoinHostPort(host, port)
}

func clusterDomain() string {
	if ClusterDomain != "" {
		return ClusterDomain
	}
	if d := os.Getenv("CLUSTER_DOMAIN"); d != "" {
		return d
	}
	if d := detectClusterDomain(); d != "" {
		return d
	}
	return defaultClusterDomain
}

func detectClusterDomain() string {
	const svc = "kubernetes.default.svc"
	cname, err := net.LookupCNAME(svc)
	if err != nil {
		return ""
	}
	cname = strings.TrimSuffix(cname, ".")
	prefix := svc + "."
	if strings.HasPrefix(cname, prefix) {
		return strings.TrimPrefix(cname, prefix)
	}
	return ""
}
