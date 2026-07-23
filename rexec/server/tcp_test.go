package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// fake network connection
type stubConn struct {
	written [][]byte
}

func (s *stubConn) Read([]byte) (int, error) { return 0, io.EOF }
func (s *stubConn) Write(p []byte) (int, error) {
	s.written = append(s.written, append([]byte(nil), p...))
	return len(p), nil
}
func (s *stubConn) Close() error                     { return nil }
func (s *stubConn) LocalAddr() net.Addr              { return nil }
func (s *stubConn) RemoteAddr() net.Addr             { return nil }
func (s *stubConn) SetDeadline(time.Time) error      { return nil }
func (s *stubConn) SetReadDeadline(time.Time) error  { return nil }
func (s *stubConn) SetWriteDeadline(time.Time) error { return nil }

func TestAPIServerTransportsDiffer(t *testing.T) {
	plain := apiServerTransport()
	if plain.TLSClientConfig == nil {
		t.Fatal("non-TTY transport must use TLSClientConfig")
	}
	if plain.DialTLSContext != nil {
		t.Fatal("non-TTY transport must not set DialTLSContext")
	}

	audited := auditedAPIServerTransport("sess", sessionInfo{})
	if audited.DialTLSContext == nil {
		t.Fatal("TTY transport must set DialTLSContext")
	}
	if audited.TLSClientConfig != nil {
		t.Fatal("TTY transport must not use TLSClientConfig (TLS is done in DialTLSContext)")
	}
}

func TestEndSessionIdempotent(t *testing.T) {
	oldSessionMap := sessionMap
	oldCommandMap := commandMap
	t.Cleanup(func() {
		sessionMap = oldSessionMap
		commandMap = oldCommandMap
	})

	sessionMap = map[string]sessionInfo{}
	commandMap = map[string][]byte{}

	endSession("never-existed")
	endSession("never-existed")

	id := "gone"
	sessionMap[id] = sessionInfo{User: "bob"}
	commandMap[id] = []byte{'x'}

	endSession(id)
	endSession(id)

	if len(sessionMap) != 0 || len(commandMap) != 0 {
		t.Fatalf("maps should be empty, sessionMap=%d commandMap=%d", len(sessionMap), len(commandMap))
	}
}

func TestQueuedAuditRetainsSessionInfoAfterEnd(t *testing.T) {
	oldSessionMap := sessionMap
	oldCommandMap := commandMap
	oldAuditLogger := auditLogger
	oldMaxStrokesPerLine := MaxStokesPerLine
	t.Cleanup(func() {
		sessionMap = oldSessionMap
		commandMap = oldCommandMap
		auditLogger = oldAuditLogger
		MaxStokesPerLine = oldMaxStrokesPerLine
	})

	sessionMap = map[string]sessionInfo{}
	commandMap = map[string][]byte{}
	MaxStokesPerLine = 2000

	var output bytes.Buffer
	auditLogger = zerolog.New(&output)

	const sessionID = "queued-session"
	wantInfo := registerSession(sessionID, "alice", "test-ns", "shell", "app", "192.0.2.1")
	queued := asyncAudit{ctxid: sessionID, info: wantInfo, ascii: []byte("whoami\r")}

	// Reproduce the asynchronous ordering that caused the original bug: the
	// request ends and removes sessionMap before the queued keystrokes flush.
	endSession(sessionID)
	storeOrFlush(queued)

	type auditRecord struct {
		User      string `json:"user"`
		Session   string `json:"session"`
		Namespace string `json:"namespace"`
		Pod       string `json:"pod"`
		Container string `json:"container"`
		ClientIP  string `json:"client_ip"`
		Command   string `json:"command"`
	}

	decoder := json.NewDecoder(&output)
	for {
		var got auditRecord
		if err := decoder.Decode(&got); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if got.Command != "whoami" {
			continue
		}

		if got.User != wantInfo.User || got.Session != sessionID ||
			got.Namespace != wantInfo.NameSpace || got.Pod != wantInfo.Pod ||
			got.Container != wantInfo.Container || got.ClientIP != wantInfo.ClientIP {
			t.Fatalf("queued audit metadata = %+v, want session info %+v", got, wantInfo)
		}
		return
	}

	t.Fatalf("queued command was not audited; output=%s", output.String())
}

func TestSessionLifecycleConcurrentWithAudit(t *testing.T) {
	oldSessionMap := sessionMap
	oldCommandMap := commandMap
	oldAuditLogger := auditLogger
	oldMaxStrokesPerLine := MaxStokesPerLine
	t.Cleanup(func() {
		sessionMap = oldSessionMap
		commandMap = oldCommandMap
		auditLogger = oldAuditLogger
		MaxStokesPerLine = oldMaxStrokesPerLine
	})

	sessionMap = map[string]sessionInfo{}
	commandMap = map[string][]byte{}
	auditLogger = zerolog.Nop()
	MaxStokesPerLine = 2000

	const (
		sessionID  = "concurrent-session"
		iterations = 2000
	)

	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(2)

	go func() {
		defer workers.Done()
		<-start
		for range iterations {
			registerSession(sessionID, "alice", "test-ns", "shell", "app", "192.0.2.1")
			runtime.Gosched()
			endSession(sessionID)
		}
	}()

	go func() {
		defer workers.Done()
		<-start
		logger := &TCPLogger{ctxid: sessionID}
		for range iterations {
			logger.logTraceStroke([]byte("x"))
			storeOrFlush(asyncAudit{ctxid: sessionID, ascii: []byte("x\r")})
			runtime.Gosched()
		}
	}()

	close(start)
	workers.Wait()
}

func TestTCPLoggerWriteSkipsNonBinaryOpcode(t *testing.T) {
	oldChan := asyncAuditChan
	t.Cleanup(func() { asyncAuditChan = oldChan })

	asyncAuditChan = make(chan asyncAudit, 1)
	logger := &TCPLogger{Conn: &stubConn{}, ctxid: "s1", websocketOpen: true}

	// FIN + text opcode 0x1, unmasked, empty payload
	_, err := logger.Write([]byte{0x81, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-asyncAuditChan:
		t.Fatal("text frame must not enqueue async audit")
	default:
	}
}

func TestTCPLoggerWriteAuditsCoalescedFrames(t *testing.T) {
	oldChan := asyncAuditChan
	t.Cleanup(func() { asyncAuditChan = oldChan })

	asyncAuditChan = make(chan asyncAudit, 4)
	wantInfo := sessionInfo{
		User:      "alice",
		NameSpace: "default",
		Pod:       "shell",
		Container: "app",
		ClientIP:  "192.0.2.1",
	}
	logger := &TCPLogger{Conn: &stubConn{}, ctxid: "s1", info: wantInfo, websocketOpen: true}

	key := [4]byte{0x01, 0x02, 0x03, 0x04}
	first := buildFrame(0x2, append([]byte{0}, []byte("echo")...), true, key)
	second := buildFrame(0x2, append([]byte{0}, []byte("date")...), true, key)

	if _, err := logger.Write(append(append([]byte(nil), first...), second...)); err != nil {
		t.Fatal(err)
	}

	want := []string{"echo", "date"}
	for _, w := range want {
		select {
		case got := <-asyncAuditChan:
			if got.info != wantInfo {
				t.Fatalf("audit session info = %+v, want %+v", got.info, wantInfo)
			}
			if string(got.ascii) != w {
				t.Fatalf("audit payload = %q, want %q", got.ascii, w)
			}
		default:
			t.Fatalf("expected coalesced frame %q to be enqueued", w)
		}
	}
}

func TestTCPLoggerWriteSkipsHTTPUpgradeHeaders(t *testing.T) {
	oldChan := asyncAuditChan
	t.Cleanup(func() { asyncAuditChan = oldChan })

	asyncAuditChan = make(chan asyncAudit, 8)
	logger := &TCPLogger{Conn: &stubConn{}, ctxid: "s1"}

	header := []byte("GET /exec HTTP/1.1\r\nUpgrade: websocket\r\n\r\n")
	split := len(header) - 2
	if _, err := logger.Write(header[:split]); err != nil {
		t.Fatal(err)
	}

	frame := buildFrame(0x2, append([]byte{0}, []byte("echo proof\r")...), true, [4]byte{1, 2, 3, 4})
	if _, err := logger.Write(append(header[split:], frame...)); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-asyncAuditChan:
		if string(got.ascii) != "echo proof\r" {
			t.Fatalf("audit payload = %q, want %q", got.ascii, "echo proof\\r")
		}
	default:
		t.Fatal("expected stdin frame after HTTP upgrade to be audited")
	}

	select {
	case got := <-asyncAuditChan:
		t.Fatalf("HTTP upgrade generated an extra audit payload %q", got.ascii)
	default:
	}
}

func TestTCPLoggerWriteSkipsNonStdinChannels(t *testing.T) {
	oldChan := asyncAuditChan
	t.Cleanup(func() { asyncAuditChan = oldChan })

	asyncAuditChan = make(chan asyncAudit, 1)
	logger := &TCPLogger{Conn: &stubConn{}, ctxid: "s1", websocketOpen: true}
	resize := buildFrame(0x2, append([]byte{4}, []byte(`{"Width":80,"Height":24}`)...), true, [4]byte{1, 2, 3, 4})

	if _, err := logger.Write(resize); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-asyncAuditChan:
		t.Fatalf("resize channel must not be audited, got %q", got.ascii)
	default:
	}
}

func TestTCPLoggerWriteStillForwardsOnParseError(t *testing.T) {
	oldChan := asyncAuditChan
	t.Cleanup(func() { asyncAuditChan = oldChan })

	asyncAuditChan = make(chan asyncAudit, 1)
	conn := &stubConn{}
	logger := &TCPLogger{Conn: conn, ctxid: "s1", websocketOpen: true}

	n, err := logger.Write([]byte{0x00})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(conn.written) != 1 {
		t.Fatalf("expected 1 byte forwarded, n=%d writes=%d", n, len(conn.written))
	}

	select {
	case <-asyncAuditChan:
		t.Fatal("invalid frame must not enqueue audit")
	default:
	}
}

func TestAuditedDialTLSContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tr := auditedAPIServerTransport("sess", sessionInfo{})
	_, err := tr.DialTLSContext(ctx, "tcp", "unused")
	if err == nil {
		t.Fatal("expected error when context is already cancelled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
