package server

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
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

// non-tty exec goes straight to apiserver tls without keystroke logging
func apiServerTransport() *http.Transport {
	tr := baseAPIServerTransport()
	tr.TLSClientConfig = apiServerTLSConfig()
	return tr
}

// tty exec uses tls conn wrapped in tcplogger so we can audit keystrokes
func auditedAPIServerTransport(sessionID string, info sessionInfo) *http.Transport {
	tr := baseAPIServerTransport()
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialAuditedConn(ctx, sessionID, info)
	}
	return tr
}

func dialAuditedConn(ctx context.Context, sessionID string, info sessionInfo) (net.Conn, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", apiServerDial)
	if err != nil {
		recordError("upstream_connect")
		return nil, err
	}
	tlsConn := tls.Client(raw, apiServerTLSConfig())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		recordError("upstream_connect")
		raw.Close()
		return nil, err
	}
	return &TCPLogger{Conn: tlsConn, ctxid: sessionID, info: info}, nil
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

	commandSync.Lock()
	delete(commandMap, ctxid)
	commandSync.Unlock()

	if ok {
		logSessionEvent("session_end", info.User, ctxid, info.NameSpace, info.Pod, info.Container, info.ClientIP)
	}
}

// tcplogger is on client to apiserver websocket direction
// write path is audited read path is pass through only
type TCPLogger struct {
	net.Conn
	ctxid string
	info  sessionInfo
}

func (t *TCPLogger) Write(b []byte) (n int, err error) {
	n, err = t.Conn.Write(b)
	if n > 0 {
		t.auditClientFrame(b[:n])
	}
	return n, err
}

func (t *TCPLogger) auditClientFrame(frameBytes []byte) {
	// a single write operation may contain multiple combined frames. Continue
	// parsing until the entire buffer has been processed to ensure no keystrokes
	// are omitted from the audit log.
	for len(frameBytes) > 0 {
		parsed, consumed, err := parseWebSocketFrame(frameBytes)
		if err != nil {
			recordError("ws_parse")
			SysLogger.Error().Err(err).Msg("failed to parse ws frame")
			return
		}
		frameBytes = frameBytes[consumed:]

		// websocket opcodes we might see: 0x0 continuation 0x1 text 0x2 binary
		// 0x8 close 0x9 ping 0xA pong
		// kubectl exec sends terminal input as 0x2 binary only that goes to async audit
		if parsed.Opcode != 0x2 {
			continue
		}

		if auditLogger.GetLevel() == zerolog.TraceLevel {
			t.logTraceStroke(parsed.Payload)
		}
		asyncAuditChan <- asyncAudit{ctxid: t.ctxid, info: t.info, ascii: parsed.Payload}
	}
}

func (t *TCPLogger) logTraceStroke(payload []byte) {
	stroke, err := hex.DecodeString(fmt.Sprintf("%x", payload))
	if err != nil {
		SysLogger.Error().Err(err).Msg("failed to parse payload")
		return
	}
	auditLogger.Trace().
		Str("user", t.info.User).
		Str("session", t.ctxid).
		Str("namespace", t.info.NameSpace).
		Str("pod", t.info.Pod).
		Str("container", t.info.Container).
		Str("client_ip", t.info.ClientIP).
		// tty payload has nul bytes strip for trace log
		Str("stroke", strings.ReplaceAll(string(stroke), "\u0000", "")).
		Msg("")
}
