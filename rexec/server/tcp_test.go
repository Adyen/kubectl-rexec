package server

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
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

	audited := auditedAPIServerTransport("sess")
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

func TestTCPLoggerWriteSkipsNonBinaryOpcode(t *testing.T) {
	oldChan := asyncAuditChan
	t.Cleanup(func() { asyncAuditChan = oldChan })

	asyncAuditChan = make(chan asyncAudit, 1)
	logger := &TCPLogger{Conn: &stubConn{}, ctxid: "s1"}

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

func TestTCPLoggerWriteStillForwardsOnParseError(t *testing.T) {
	oldChan := asyncAuditChan
	t.Cleanup(func() { asyncAuditChan = oldChan })

	asyncAuditChan = make(chan asyncAudit, 1)
	conn := &stubConn{}
	logger := &TCPLogger{Conn: conn, ctxid: "s1"}

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

	tr := auditedAPIServerTransport("sess")
	_, err := tr.DialTLSContext(ctx, "tcp", "unused")
	if err == nil {
		t.Fatal("expected error when context is already cancelled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
