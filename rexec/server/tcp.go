package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
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

// maxFrameBuf bounds the buffered bytes of a single incomplete WebSocket
// frame. Legitimate stdin frames are a handful of bytes; this only guards
// against a hostile or broken peer declaring a giant payload.
const maxFrameBuf = 32 << 20 // 32 MiB

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

	auditSync     sync.Mutex // guards websocketOpen, headerTail, frameBuf
	websocketOpen bool
	headerTail    []byte
	frameBuf      []byte

	respMu   sync.Mutex // guards respTail
	respTail []byte
	respDone atomic.Bool
	codec    atomic.Int32
}

func (t *TCPLogger) Write(b []byte) (n int, err error) {
	n, err = t.Conn.Write(b)
	if n > 0 {
		t.auditClientBytes(b[:n])
	}
	return n, err
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

func (t *TCPLogger) auditClientBytes(data []byte) {
	t.auditSync.Lock()
	defer t.auditSync.Unlock()

	if !t.websocketOpen {
		data = t.consumeHTTPUpgrade(data)
	}
	if len(data) > 0 {
		t.bufferAndAuditFrames(data)
	}
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
func (t *TCPLogger) bufferAndAuditFrames(data []byte) {
	t.frameBuf = append(t.frameBuf, data...)
	for len(t.frameBuf) > 0 {
		// Reject absurd declared lengths before parsing: an 8-byte length can
		// overflow int64 downstream, and a peer promising an oversized frame
		// would otherwise pin the buffer while the rest never arrives.
		if declared, ok := declaredPayloadLength(t.frameBuf); ok && (declared < 0 || declared > maxFrameBuf) {
			recordError("ws_frame_overflow")
			SysLogger.Error().Int64("declared", declared).Msg("dropping oversized ws frame from audit buffer")
			t.frameBuf = nil
			return
		}
		parsed, consumed, err := parseWebSocketFrame(t.frameBuf)
		if err != nil {
			// All parse errors mean the frame is incomplete; wait for the
			// rest of it instead of discarding the bytes.
			if len(t.frameBuf) > maxFrameBuf {
				recordError("ws_frame_overflow")
				SysLogger.Error().Int("buffered", len(t.frameBuf)).Msg("dropping oversized incomplete ws frame from audit buffer")
				t.frameBuf = nil
			}
			return
		}
		t.auditFrame(parsed)
		t.frameBuf = t.frameBuf[consumed:]
	}
	t.frameBuf = nil
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
// The kubelet's wsstream layer (x/net/websocket) delivers EVERY data-carrying
// frame as an independent message: continuation frames are relabeled to the
// preceding data opcode but are never reassembled, and the payload type is not
// enforced (a text frame on a binary protocol is accepted). The first payload
// byte of every such frame is therefore interpreted as the channel, exactly
// like upstream does, regardless of the FIN bit. Auditing per frame with the
// same rule means nothing that can reach container stdin escapes the audit.
func (t *TCPLogger) auditFrame(parsed *webSocketFrame) {
	switch parsed.Opcode {
	case 0x0, 0x1, 0x2: // continuation, text, binary
		t.auditChannelPayload(parsed.Payload)
	default:
		// 0x8 close, 0x9 ping, 0xA pong: no stdin content
	}
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
