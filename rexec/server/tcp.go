package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

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
		if closeErr := raw.Close(); closeErr != nil {
			SysLogger.Error().Err(closeErr).Msg("failed to close raw connection")
		}
		return nil, err
	}
	return &TCPLogger{Conn: tlsConn, ctxid: sessionID, info: info}, nil
}

func registerSession(ctxid, user, namespace, pod, container, clientIP string, tty bool) sessionInfo {
	info := sessionInfo{
		User: user, NameSpace: namespace, Pod: pod, Container: container, ClientIP: clientIP, TTY: tty,
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

	// Flush a trailing command that never saw a line terminator: shells
	// execute it when the session's stdin hits EOF, so discarding it here
	// would leave the last command of a session unaudited.
	commandSync.Lock()
	remaining := commandMap[ctxid]
	delete(commandMap, ctxid)
	commandSync.Unlock()
	if ok && len(remaining) > 0 {
		logCommand(string(remaining), info.User, ctxid, info.NameSpace, info.Pod, info.Container, info.ClientIP)
	}

	if ok {
		logSessionEvent("session_end", info.User, ctxid, info.NameSpace, info.Pod, info.Container, info.ClientIP)
	}
}

// wsCodec describes how stdin is encoded on the wire for the negotiated
// Kubernetes WebSocket subprotocol.
type wsCodec int32

const (
	// codecUnknown means the 101 response has not been observed yet; payloads
	// are then interpreted under both raw and base64 rules (they cannot be
	// confused: raw channel 0 is 0x00, base64 channel 0 is ASCII '0').
	codecUnknown wsCodec = iota
	// codecRaw is used by "v4.channel.k8s.io", "v5.channel.k8s.io",
	// "channel.k8s.io" and the empty protocol: every message is prefixed with
	// a raw channel byte.
	codecRaw
	// codecBase64 is used by "base64.channel.k8s.io" and
	// "v4.base64.channel.k8s.io": every message is prefixed with an ASCII
	// channel digit and the data is base64-encoded.
	codecBase64
)

// Kubectl's WebSocket stdin chunks are 32 KiB. Bound per-session memory well
// below the pod's limit, including the frame header and masking key.
const maxFrameBuf = 64 << 10 // 64 KiB

// maxUpgradeResponseHead bounds the buffered bytes while looking for the end
// of the upstream 101 response headers.
const maxUpgradeResponseHead = 16 << 10 // 16 KiB

// tcplogger is on client to apiserver websocket direction.
// The write path (client -> apiserver) is audited; the read path is tapped only
// until the negotiated subprotocol is learned from the 101 response, then it is
// a pure pass-through.
type TCPLogger struct {
	net.Conn
	ctxid string
	info  sessionInfo

	auditSync     sync.Mutex // guards websocketOpen, headerTail, frameBuf and write order
	websocketOpen bool
	headerTail    []byte
	frameBuf      []byte

	respMu   sync.Mutex // guards respTail
	respTail []byte
	respDone atomic.Bool
	codec    atomic.Int32
}

func (t *TCPLogger) Write(b []byte) (n int, err error) {
	t.auditSync.Lock()
	defer t.auditSync.Unlock()

	if err := t.auditClientBytes(b); err != nil {
		// Upstream must never receive bytes that the audit cannot account for.
		_ = t.Conn.Close()
		return 0, err
	}
	return t.Conn.Write(b)
}

// Read taps the upstream -> client direction until the end of the 101 upgrade
// response, so the negotiated subprotocol is known when auditing client frames.
// The bytes themselves are passed through untouched.
func (t *TCPLogger) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 && !t.respDone.Load() {
		t.observeUpgradeResponse(p[:n])
	}
	return n, err
}

// observeUpgradeResponse buffers response bytes until the header terminator and
// records the negotiated subprotocol from it.
func (t *TCPLogger) observeUpgradeResponse(b []byte) {
	t.respMu.Lock()
	defer t.respMu.Unlock()

	combined := append(t.respTail, b...)
	if idx := bytes.Index(combined, []byte("\r\n\r\n")); idx >= 0 {
		t.codec.Store(int32(codecForProtocol(headerValue(combined[:idx], "Sec-WebSocket-Protocol"))))
		t.respTail = nil
		t.respDone.Store(true)
		return
	}
	if len(combined) > maxUpgradeResponseHead {
		// give up sniffing; codecUnknown falls back to dual interpretation
		t.respTail = nil
		t.respDone.Store(true)
		return
	}
	t.respTail = combined
}

// headerValue extracts a header value from a raw HTTP response head.
func headerValue(head []byte, name string) string {
	for _, line := range bytes.Split(head, []byte("\r\n")) {
		k, v, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(string(k)), name) {
			return strings.TrimSpace(string(v))
		}
	}
	return ""
}

// codecForProtocol maps a negotiated WebSocket subprotocol to its codec.
// Unknown or absent protocols default to the raw channel-prefixed binary
// encoding, matching the kubelet's treatment of the empty subprotocol.
func codecForProtocol(protocol string) wsCodec {
	switch protocol {
	case "base64.channel.k8s.io", "v4.base64.channel.k8s.io":
		return codecBase64
	default:
		return codecRaw
	}
}

func (t *TCPLogger) auditClientBytes(data []byte) error {
	if !t.websocketOpen {
		data = t.consumeHTTPUpgrade(data)
	}
	if len(data) > 0 {
		return t.bufferAndAuditFrames(data)
	}
	return nil
}

// consumeHTTPUpgrade ignores the initial HTTP upgrade request. Retaining only
// the last three bytes is sufficient to detect a \r\n\r\n boundary split
// across writes without buffering the complete request headers.
func (t *TCPLogger) consumeHTTPUpgrade(data []byte) []byte {
	const headerEnd = "\r\n\r\n"

	combined := make([]byte, 0, len(t.headerTail)+len(data))
	combined = append(combined, t.headerTail...)
	combined = append(combined, data...)

	if index := bytes.Index(combined, []byte(headerEnd)); index >= 0 {
		t.websocketOpen = true
		t.headerTail = nil
		return combined[index+len(headerEnd):]
	}

	const boundaryTailLength = len(headerEnd) - 1
	if len(combined) > boundaryTailLength {
		combined = combined[len(combined)-boundaryTailLength:]
	}
	t.headerTail = append(t.headerTail[:0], combined...)
	return nil
}

// bufferAndAuditFrames appends freshly written bytes to the frame buffer and
// audits every complete frame. An incomplete trailing frame is kept for the
// next Write: the reverse proxy copies the stream in chunks (io.Copy with a
// 32 KiB buffer, or however the peer paces its segments), so a frame spanning
// multiple writes is normal and must not be dropped from the audit.
func (t *TCPLogger) bufferAndAuditFrames(data []byte) error {
	for len(data) > 0 {
		n := min(len(data), maxFrameBuf-len(t.frameBuf))
		t.frameBuf = append(t.frameBuf, data[:n]...)
		data = data[n:]

		for len(t.frameBuf) > 0 {
			if declared, ok := declaredPayloadLength(t.frameBuf); ok {
				headerLen := 2
				switch t.frameBuf[1] & 0x7f {
				case 126:
					headerLen = 4
				case 127:
					headerLen = 10
				}
				if t.frameBuf[1]&0x80 != 0 {
					headerLen += 4
				}
				if declared < 0 || declared > int64(maxFrameBuf-headerLen) {
					return t.frameError("declared frame exceeds audit limit")
				}
			}
			parsed, consumed, err := parseWebSocketFrame(t.frameBuf)
			if err != nil {
				break // incomplete header or payload
			}
			t.auditFrame(parsed)
			t.frameBuf = t.frameBuf[consumed:]
		}
		if len(t.frameBuf) == maxFrameBuf {
			return t.frameError("incomplete frame filled audit buffer")
		}
	}
	if len(t.frameBuf) == 0 {
		t.frameBuf = nil
	}
	return nil
}

func (t *TCPLogger) frameError(message string) error {
	recordError("ws_frame_overflow")
	t.frameBuf = nil
	return fmt.Errorf("WebSocket audit: %s", message)
}

// declaredPayloadLength returns the payload length declared in the frame
// header, and whether enough header bytes are buffered to know it.
func declaredPayloadLength(buf []byte) (int64, bool) {
	if len(buf) < 2 {
		return 0, false
	}
	switch n := int64(buf[1] & 0x7F); n {
	case 126:
		if len(buf) < 4 {
			return 0, false
		}
		return int64(binary.BigEndian.Uint16(buf[2:4])), true
	case 127:
		if len(buf) < 10 {
			return 0, false
		}
		return int64(binary.BigEndian.Uint64(buf[2:10])), true
	default:
		return n, true
	}
}

// auditFrame audits the stdin content of one complete frame.
//
// The kubelet's wsstream layer (x/net/websocket) delivers every non-control
// frame, including reserved opcodes, as independent channel-prefixed data.
// Continuation frames are relabeled but not reassembled. Audit every such
// frame using the same rule so no stdin escapes the audit.
func (t *TCPLogger) auditFrame(parsed *webSocketFrame) {
	switch parsed.Opcode {
	case 0x8, 0x9, 0xA: // close, ping, pong: no stdin content
		return
	}
	t.auditChannelPayload(parsed.Payload)
}

func (t *TCPLogger) auditChannelPayload(payload []byte) {
	if len(payload) < 2 {
		return
	}
	switch wsCodec(t.codec.Load()) {
	case codecRaw:
		t.auditRawPayload(payload)
	case codecBase64:
		t.auditBase64Payload(payload)
	default:
		// The negotiated subprotocol is unknown (the 101 response was not
		// observed). Both encodings are still unambiguous: raw stdin starts
		// with a 0x00 channel byte, base64 stdin starts with ASCII '0' (0x30,
		// which as a raw channel number exceeds the valid channel count and
		// is discarded upstream).
		if payload[0] == 0x00 {
			t.auditRawPayload(payload)
			return
		}
		t.auditBase64Payload(payload)
	}
}

// auditRawPayload audits channel-0 data from a binary-codec payload.
// Kubernetes prefixes each message with its remotecommand stream channel;
// only channel 0 is terminal stdin (channel 4 carries resize data).
func (t *TCPLogger) auditRawPayload(payload []byte) {
	if payload[0] != 0x00 {
		return
	}
	t.emitStdinAudit(payload[1:])
}

// auditBase64Payload audits channel-0 data from a base64-codec payload, where
// the channel is the ASCII digit prefix and the data is base64-encoded.
func (t *TCPLogger) auditBase64Payload(payload []byte) {
	if payload[0] != '0' {
		return
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(payload)-1))
	n, err := base64.StdEncoding.Decode(decoded, payload[1:])
	if err != nil {
		recordError("ws_base64")
		SysLogger.Error().Err(err).Msg("failed to base64-decode ws stdin payload")
		return
	}
	t.emitStdinAudit(decoded[:n])
}

func (t *TCPLogger) emitStdinAudit(stdin []byte) {
	if len(stdin) == 0 {
		return
	}
	if auditLogger.GetLevel() == zerolog.TraceLevel {
		t.logTraceStroke(stdin)
	}
	asyncAuditChan <- asyncAudit{ctxid: t.ctxid, info: t.info, ascii: stdin}
}

func (t *TCPLogger) logTraceStroke(payload []byte) {
	// NUL bytes are preserved: zerolog JSON-escapes them safely, and
	// record-oriented consumers (xargs -0, scripts) treat them as meaningful,
	// so the audit trail must reflect the bytes that were actually delivered.
	auditLogger.Trace().
		Str("user", t.info.User).
		Str("session", t.ctxid).
		Str("namespace", t.info.NameSpace).
		Str("pod", t.info.Pod).
		Str("container", t.info.Container).
		Str("client_ip", t.info.ClientIP).
		Str("stroke", string(payload)).
		Msg("")
}
