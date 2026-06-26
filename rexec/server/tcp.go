package server

import (
	"crypto/tls"
	"net/http"
)

func apiServerTLSConfig() *tls.Config {
	return &tls.Config{
		RootCAs:    CAPool,
		ServerName: apiServerHost,
	}
}

func baseAPIServerTransport() *http.Transport {
	return &http.Transport{
		DisableKeepAlives:  true,
		DisableCompression: true,
	}
}

// non-tty exec and WebSocket probes go straight to apiserver TLS without auditing.
func apiServerTransport() *http.Transport {
	tr := baseAPIServerTransport()
	tr.TLSClientConfig = apiServerTLSConfig()
	return tr
}

func registerSession(ctxid, user, namespace, pod, container, clientIP string) sessionInfo {
	info := sessionInfo{
		User: user, NameSpace: namespace, Pod: pod, Container: container, ClientIP: clientIP,
	}
	mapSync.Lock()
	sessionMap[ctxid] = info
	mapSync.Unlock()
	logSessionEvent("session_start", user, ctxid, namespace, pod, container, clientIP)
	return info
}

func endSession(ctxid string) {
	mapSync.Lock()
	info, ok := sessionMap[ctxid]
	delete(sessionMap, ctxid)
	mapSync.Unlock()

	if ok {
		commandSync.Lock()
		flushCommandBufferLocked(ctxid, info)
		delete(commandMap, ctxid)
		commandSync.Unlock()
		logSessionEvent("session_end", info.User, ctxid, info.NameSpace, info.Pod, info.Container, info.ClientIP)
		return
	}

	commandSync.Lock()
	delete(commandMap, ctxid)
	commandSync.Unlock()
}
