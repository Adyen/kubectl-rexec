package server

import (
	"net"
	"os"
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
	return defaultClusterDomain
}
