package server

// Regression tests for exec-session audit hardening.
// Each test covers an input shape the kubelet's wsstream layer accepts and
// delivers to container stdin; the audit tap must observe every one of them,
// and non-WebSocket interactive sessions must be rejected.

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

// maskedFrame builds a client WebSocket frame with explicit FIN/opcode control.
func maskedFrame(fin bool, opcode byte, payload []byte, key [4]byte) []byte {
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	out := []byte{b0}
	switch {
	case len(payload) < 126:
		out = append(out, 0x80|byte(len(payload)))
	default:
		out = append(out, 0x80|126, byte(len(payload)>>8), byte(len(payload)))
	}
	out = append(out, key[:]...)
	for i, p := range payload {
		out = append(out, p^key[i%4])
	}
	return out
}

// scriptedConn is a stubConn that can also serve scripted read data.
type scriptedConn struct {
	stubConn
	readBuf [][]byte
}

func (s *scriptedConn) Read(p []byte) (int, error) {
	for len(s.readBuf) > 0 && len(s.readBuf[0]) == 0 {
		s.readBuf = s.readBuf[1:]
	}
	if len(s.readBuf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.readBuf[0])
	s.readBuf[0] = s.readBuf[0][n:]
	return n, nil
}

func setupAuditCapture(t *testing.T, capacity int) {
	t.Helper()
	oldChan := asyncAuditChan
	t.Cleanup(func() { asyncAuditChan = oldChan })
	asyncAuditChan = make(chan asyncAudit, capacity)
}

func expectAudit(t *testing.T, want string) {
	t.Helper()
	select {
	case got := <-asyncAuditChan:
		if string(got.ascii) != want {
			t.Fatalf("audit payload = %q, want %q", got.ascii, want)
		}
	default:
		t.Fatalf("expected audit payload %q, got none", want)
	}
}

func expectNoAudit(t *testing.T) {
	t.Helper()
	select {
	case got := <-asyncAuditChan:
		t.Fatalf("unexpected audit payload %q", got.ascii)
	default:
	}
}

func forwardedBytes(conn *stubConn) []byte {
	var out bytes.Buffer
	for _, w := range conn.written {
		out.Write(w)
	}
	return out.Bytes()
}

// wsstream delivers each frame as a standalone message, including
// continuation frames (relabeled to the preceding data opcode), so a
// continuation carrying its own channel byte is stdin and must be audited.
func TestRegressionContinuationFrameAudited(t *testing.T) {
	setupAuditCapture(t, 8)
	conn := &stubConn{}
	logger := &TCPLogger{Conn: conn, ctxid: "s1", websocketOpen: true}

	key := [4]byte{0x01, 0x02, 0x03, 0x04}
	f1 := maskedFrame(false, 0x2, []byte{0x00}, key)                           // FIN=0 binary, channel byte only
	f2 := maskedFrame(true, 0x0, append([]byte{0x00}, []byte("id\n")...), key) // FIN=1 continuation, own channel byte
	all := append(append([]byte{}, f1...), f2...)

	if _, err := logger.Write(all); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(forwardedBytes(conn), all) {
		t.Fatal("forwarded bytes differ from client bytes")
	}
	expectAudit(t, "id\n")
	expectNoAudit(t)
}

// A continuation frame without any preceding data frame is also delivered
// upstream as a standalone message, so it must be audited too.
func TestRegressionOrphanContinuationAudited(t *testing.T) {
	setupAuditCapture(t, 8)
	logger := &TCPLogger{Conn: &stubConn{}, ctxid: "s1", websocketOpen: true}

	key := [4]byte{0x01, 0x02, 0x03, 0x04}
	frame := maskedFrame(true, 0x0, append([]byte{0x00}, []byte("whoami\n")...), key)
	if _, err := logger.Write(frame); err != nil {
		t.Fatal(err)
	}
	expectAudit(t, "whoami\n")
}

// A frame split across transport writes is normal on a proxied stream; the
// audit tap must buffer the incomplete frame and audit it once complete.
func TestRegressionSplitFrameAudited(t *testing.T) {
	setupAuditCapture(t, 8)
	conn := &stubConn{}
	logger := &TCPLogger{Conn: conn, ctxid: "s1", websocketOpen: true}

	key := [4]byte{0xaa, 0xbb, 0xcc, 0xdd}
	frame := maskedFrame(true, 0x2, append([]byte{0x00}, []byte("whoami\n")...), key)
	half := len(frame) / 2

	if _, err := logger.Write(frame[:half]); err != nil {
		t.Fatal(err)
	}
	expectNoAudit(t) // incomplete frame stays buffered

	if _, err := logger.Write(frame[half:]); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(forwardedBytes(conn), frame) {
		t.Fatal("forwarded bytes differ from original frame")
	}
	expectAudit(t, "whoami\n")
}

// wsstream does not enforce the payload type: a text frame carrying a
// channel-0 payload on a binary protocol is accepted as stdin upstream.
func TestRegressionTextFrameStdinAudited(t *testing.T) {
	setupAuditCapture(t, 8)
	logger := &TCPLogger{Conn: &stubConn{}, ctxid: "s1", websocketOpen: true}

	key := [4]byte{0x77, 0x66, 0x55, 0x44}
	frame := maskedFrame(true, 0x1, append([]byte{0x00}, []byte("id\n")...), key)
	if _, err := logger.Write(frame); err != nil {
		t.Fatal(err)
	}
	expectAudit(t, "id\n")
}

// On a base64 subprotocol the channel is an ASCII digit and stdin is
// base64-encoded; the audit must decode it.
func TestRegressionBase64StdinAudited(t *testing.T) {
	setupAuditCapture(t, 8)

	respHead := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: upgrade\r\n" +
		"Sec-WebSocket-Protocol: v4.base64.channel.k8s.io\r\n\r\n"
	// deliver the 101 head in two reads to exercise the buffering
	split := len(respHead) / 2
	conn := &scriptedConn{readBuf: [][]byte{[]byte(respHead[:split]), []byte(respHead[split:])}}
	logger := &TCPLogger{Conn: conn, ctxid: "s1", websocketOpen: true}

	buf := make([]byte, 4096)
	if _, err := logger.Read(buf); err != nil {
		t.Fatal(err)
	}
	if got := wsCodec(logger.codec.Load()); got != codecUnknown {
		t.Fatalf("codec after partial 101 = %v, want codecUnknown (still sniffing)", got)
	}
	if _, err := logger.Read(buf); err != nil {
		t.Fatal(err)
	}
	if got := wsCodec(logger.codec.Load()); got != codecBase64 {
		t.Fatalf("codec after full 101 = %v, want codecBase64", got)
	}

	key := [4]byte{0x11, 0x22, 0x33, 0x44}
	payload := "0" + base64.StdEncoding.EncodeToString([]byte("id\n"))
	frame := maskedFrame(true, 0x1, []byte(payload), key)
	if _, err := logger.Write(frame); err != nil {
		t.Fatal(err)
	}
	expectAudit(t, "id\n")
}

// When the 101 response was never observed, the dual-interpretation fallback
// must still audit base64 stdin (payload starts with ASCII '0').
func TestRegressionBase64StdinAuditedUnknownCodec(t *testing.T) {
	setupAuditCapture(t, 8)
	logger := &TCPLogger{Conn: &stubConn{}, ctxid: "s1", websocketOpen: true}

	key := [4]byte{0x11, 0x22, 0x33, 0x44}
	payload := "0" + base64.StdEncoding.EncodeToString([]byte("whoami\n"))
	frame := maskedFrame(true, 0x1, []byte(payload), key)
	if _, err := logger.Write(frame); err != nil {
		t.Fatal(err)
	}
	expectAudit(t, "whoami\n")
}

// Control: normal binary stdin frames keep being audited exactly once,
// and non-stdin channels stay unaudited.
func TestRegressionBinaryStdinAuditedOnce(t *testing.T) {
	setupAuditCapture(t, 8)
	logger := &TCPLogger{Conn: &stubConn{}, ctxid: "s1", websocketOpen: true}
	logger.codec.Store(int32(codecRaw))

	key := [4]byte{0x01, 0x02, 0x03, 0x04}
	frame := maskedFrame(true, 0x2, append([]byte{0x00}, []byte("ls\n")...), key)
	resize := maskedFrame(true, 0x2, append([]byte{0x04}, []byte(`{"Width":80}`)...), key)
	if _, err := logger.Write(append(frame, resize...)); err != nil {
		t.Fatal(err)
	}
	expectAudit(t, "ls\n")
	expectNoAudit(t)
}

// Control frames carry no stdin and must not be audited.
func TestRegressionControlFramesNotAudited(t *testing.T) {
	setupAuditCapture(t, 8)
	logger := &TCPLogger{Conn: &stubConn{}, ctxid: "s1", websocketOpen: true}

	key := [4]byte{0x01, 0x02, 0x03, 0x04}
	ping := maskedFrame(true, 0x9, []byte{0x00, 0x00}, key)
	pong := maskedFrame(true, 0xA, []byte{0x00, 0x00}, key)
	closef := maskedFrame(true, 0x8, []byte{0x03, 0xe8}, key)
	if _, err := logger.Write(append(append(ping, pong...), closef...)); err != nil {
		t.Fatal(err)
	}
	expectNoAudit(t)
}

// A frame whose declared length exceeds the cap (including int64-overflow
// territory) is dropped loudly instead of pinning the buffer or misparsing.
func TestRegressionFrameBufferOverflowDropped(t *testing.T) {
	setupAuditCapture(t, 8)
	logger := &TCPLogger{Conn: &stubConn{}, ctxid: "s1", websocketOpen: true}

	var ext [8]byte
	binary.BigEndian.PutUint64(ext[:], maxFrameBuf+1)
	huge := append([]byte{0x82, 0xFF}, ext[:]...) // FIN binary, 8-byte length, masked
	if _, err := logger.Write(huge); err != nil {
		t.Fatal(err)
	}
	if len(logger.frameBuf) != 0 {
		t.Fatal("oversized declared frame must be dropped from the audit buffer")
	}

	// an unreasonably large length must also be dropped
	binary.BigEndian.PutUint64(ext[:], math.MaxUint64)
	huge = append([]byte{0x82, 0x7F}, ext[:]...) // unmasked variant
	if _, err := logger.Write(huge); err != nil {
		t.Fatal(err)
	}
	if len(logger.frameBuf) != 0 {
		t.Fatal("overflowing declared length must be dropped from the audit buffer")
	}
}

// stdin/tty must be decoded with the same truthiness rules as the
// kube-apiserver (anything but absent/0/false is true), so every interactive
// session selects the recording transport.
func TestRegressionParseParamsKubernetesTruthiness(t *testing.T) {
	recording := []string{"1", "TRUE", "True", "yes", "", "true"}
	oneoff := []string{"0", "false", "FALSE", "fAlSe"}

	for _, v := range recording {
		if _, rec, _ := parseParams(url.Values{"stdin": []string{v}}); !rec {
			t.Fatalf("stdin=%q must select the recording transport", v)
		}
		if _, rec, _ := parseParams(url.Values{"tty": []string{v}}); !rec {
			t.Fatalf("tty=%q must select the recording transport", v)
		}
	}
	for _, v := range oneoff {
		if _, rec, _ := parseParams(url.Values{"stdin": []string{v}}); rec {
			t.Fatalf("stdin=%q must select the one-off transport", v)
		}
	}
	if _, rec, _ := parseParams(url.Values{"command": []string{"sh"}}); rec {
		t.Fatal("absent stdin/tty must select the one-off transport")
	}
}

// SPDY interactive sessions must be rejected: the audit tap parses WebSocket
// frames, so proxying SPDY would serve an unaudited session.
func TestRegressionRejectsSPDYRecordingSession(t *testing.T) {
	oldNames := RequestHeaderAllowedNames
	t.Cleanup(func() { RequestHeaderAllowedNames = oldNames })
	RequestHeaderAllowedNames = nil

	req := httptest.NewRequest(http.MethodGet,
		"/apis/audit.adyen.internal/v1beta1/namespaces/ns/pods/pod/exec?command=sh&tty=true", nil)
	req.Header.Set("X-Remote-User", "alice")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "SPDY/3.1")
	req.Header.Set("X-Stream-Protocol-Version", "v4.channel.k8s.io")
	req = withFrontProxyCert(req, "front-proxy-client")
	req = mux.SetURLVars(req, map[string]string{"namespace": "ns", "pod": "pod"})

	rr := httptest.NewRecorder()
	rexecHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rr.Body.String(), "WebSocket") {
		t.Fatalf("body = %q, want a WebSocket requirement message", rr.Body.String())
	}
}

// The one-off (non-interactive) path must keep working for SPDY clients:
// `kubectl rexec cp` uses a SPDY executor without stdin/tty.
func TestRegressionOneoffSPDYPassesTransportGate(t *testing.T) {
	oldNames := RequestHeaderAllowedNames
	t.Cleanup(func() { RequestHeaderAllowedNames = oldNames })
	RequestHeaderAllowedNames = nil

	req := httptest.NewRequest(http.MethodGet,
		"/apis/audit.adyen.internal/v1beta1/namespaces/ns/pods/pod/exec?command=tar&stdout=true", nil)
	req.Header.Set("X-Remote-User", "alice")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "SPDY/3.1")
	req = withFrontProxyCert(req, "front-proxy-client")
	req = mux.SetURLVars(req, map[string]string{"namespace": "ns", "pod": "pod"})

	rr := httptest.NewRecorder()
	rexecHandler(rr, req)

	// No service-account token exists in tests, so the handler fails later
	// with a 500; what matters is that the transport gate did not reject it.
	if rr.Code == http.StatusBadRequest {
		t.Fatalf("one-off SPDY session must not be rejected by the transport gate: %s", rr.Body.String())
	}
}

// A WebSocket interactive session passes the transport gate.
func TestRegressionWebSocketRecordingPassesTransportGate(t *testing.T) {
	oldNames := RequestHeaderAllowedNames
	t.Cleanup(func() { RequestHeaderAllowedNames = oldNames })
	RequestHeaderAllowedNames = nil

	req := httptest.NewRequest(http.MethodGet,
		"/apis/audit.adyen.internal/v1beta1/namespaces/ns/pods/pod/exec?command=sh&stdin=true", nil)
	req.Header.Set("X-Remote-User", "alice")
	req.Header.Set("Connection", "keep-alive, Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req = withFrontProxyCert(req, "front-proxy-client")
	req = mux.SetURLVars(req, map[string]string{"namespace": "ns", "pod": "pod"})

	rr := httptest.NewRecorder()
	rexecHandler(rr, req)

	if rr.Code == http.StatusBadRequest {
		t.Fatalf("WebSocket recording session must pass the transport gate: %s", rr.Body.String())
	}
}

// The webhook body must be bounded; oversized AdmissionReviews get a 413.
func TestRegressionExecHandlerRejectsOversizedBody(t *testing.T) {
	big := bytes.Repeat([]byte("a"), maxAdmissionReviewBytes)
	body := append([]byte(`{"kind":"AdmissionReview","request":{"uid":"`), big...)
	body = append(body, []byte(`"}}`)...)

	req := httptest.NewRequest(http.MethodPost, "/validate-exec", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	execHandler(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusRequestEntityTooLarge)
	}
}

// auditCommands decodes the command records an auditLogger wrote to buf.
func auditCommands(t *testing.T, buf *bytes.Buffer) []string {
	t.Helper()
	var cmds []string
	decoder := json.NewDecoder(buf)
	for {
		var rec map[string]any
		if err := decoder.Decode(&rec); errors.Is(err, io.EOF) {
			return cmds
		} else if err != nil {
			t.Fatal(err)
		}
		if cmd, ok := rec["command"].(string); ok {
			cmds = append(cmds, cmd)
		}
	}
}

// A trailing command without a line terminator is still executed by shells
// when stdin hits EOF, so it must be flushed into the audit at session end
// instead of being discarded with the session's line buffer.
func TestRegressionUnterminatedCommandFlushedAtSessionEnd(t *testing.T) {
	oldSessionMap := sessionMap
	oldCommandMap := commandMap
	oldAuditLogger := auditLogger
	oldMax := MaxStokesPerLine
	t.Cleanup(func() {
		sessionMap = oldSessionMap
		commandMap = oldCommandMap
		auditLogger = oldAuditLogger
		MaxStokesPerLine = oldMax
	})

	sessionMap = map[string]sessionInfo{}
	commandMap = map[string][]byte{}
	MaxStokesPerLine = 2000 // production default
	var output bytes.Buffer
	auditLogger = zerolog.New(&output)

	const id = "eof-session"
	registerSession(id, "mallory", "default", "shell", "app", "192.0.2.1")
	storeOrFlush(asyncAudit{ctxid: id, ascii: []byte("touch /tmp/stealth")}) // no trailing CR/LF
	endSession(id)

	found := false
	for _, cmd := range auditCommands(t, &output) {
		if strings.Contains(cmd, "touch /tmp/stealth") {
			found = true
		}
	}
	if !found {
		t.Fatal("unterminated final command must be flushed to the command audit at session end")
	}
}

// NUL bytes are meaningful to record-oriented consumers (xargs -0, scripts):
// the audited command must contain exactly the bytes that were delivered,
// not a silently merged version with NULs stripped.
func TestRegressionNULBytesPreservedInAudit(t *testing.T) {
	oldSessionMap := sessionMap
	oldCommandMap := commandMap
	oldAuditLogger := auditLogger
	oldMax := MaxStokesPerLine
	t.Cleanup(func() {
		sessionMap = oldSessionMap
		commandMap = oldCommandMap
		auditLogger = oldAuditLogger
		MaxStokesPerLine = oldMax
	})

	sessionMap = map[string]sessionInfo{}
	commandMap = map[string][]byte{}
	MaxStokesPerLine = 2000
	var output bytes.Buffer
	auditLogger = zerolog.New(&output)

	const id = "nul-session"
	registerSession(id, "mallory", "default", "shell", "app", "192.0.2.1")
	storeOrFlush(asyncAudit{ctxid: id, ascii: []byte("id\x00whoami\r")})

	cmds := auditCommands(t, &output)
	if len(cmds) != 1 {
		t.Fatalf("expected exactly one command record, got %v", cmds)
	}
	if !strings.Contains(cmds[0], "id\x00whoami") {
		t.Fatalf("NUL byte must be preserved in the audit record, got %q", cmds[0])
	}
}
