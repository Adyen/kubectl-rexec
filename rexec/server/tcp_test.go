package server

import (
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestAPIServerTransport(t *testing.T) {
	tr := apiServerTransport()
	if tr.TLSClientConfig == nil {
		t.Fatal("apiserver transport must use TLSClientConfig")
	}
	if tr.DialTLSContext != nil {
		t.Fatal("apiserver transport must not set DialTLSContext")
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

func TestEndSessionFlushesPendingCommand(t *testing.T) {
	oldSessionMap := sessionMap
	oldCommandMap := commandMap
	oldAuditLogger := auditLogger
	t.Cleanup(func() {
		sessionMap = oldSessionMap
		commandMap = oldCommandMap
		auditLogger = oldAuditLogger
	})

	sessionMap = map[string]sessionInfo{}
	commandMap = map[string][]byte{}

	var buf strings.Builder
	auditLogger = zerolog.New(&buf)

	id := "flush-me"
	info := sessionInfo{User: "bob", NameSpace: "ns", Pod: "p", Container: "c", ClientIP: "1.2.3.4"}
	sessionMap[id] = info
	commandMap[id] = []byte("ls")

	endSession(id)

	if !strings.Contains(buf.String(), `"command":"ls"`) {
		t.Fatalf("expected flushed command in audit log, got %s", buf.String())
	}
}

func TestAuditedStdinEnqueuesReads(t *testing.T) {
	oldChan := asyncAuditChan
	t.Cleanup(func() { asyncAuditChan = oldChan })
	asyncAuditChan = make(chan asyncAudit, 1)

	info := sessionInfo{User: "alice", NameSpace: "ns", Pod: "p"}
	r := newAuditedStdin(strings.NewReader("ls"), "sess", info)
	buf := make([]byte, 8)
	if _, err := r.Read(buf); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-asyncAuditChan:
		if string(got.ascii) != "ls" {
			t.Fatalf("audit payload = %q, want ls", got.ascii)
		}
	default:
		t.Fatal("expected stdin read to be audited")
	}
}

func TestStoreOrFlushIgnoresControlChars(t *testing.T) {
	oldCommandMap := commandMap
	t.Cleanup(func() { commandMap = oldCommandMap })

	commandMap = map[string][]byte{}
	info := sessionInfo{User: "alice", NameSpace: "ns", Pod: "p"}

	storeOrFlush(asyncAudit{ctxid: "s", info: info, ascii: []byte("ls")})
	storeOrFlush(asyncAudit{ctxid: "s", info: info, ascii: []byte{3, 4}})

	if len(commandMap["s"]) != 0 {
		t.Fatalf("expected buffer cleared after Ctrl+C/D, got %q", commandMap["s"])
	}
}

func TestStoreOrFlushTraceKeystrokes(t *testing.T) {
	oldCommandMap := commandMap
	oldAuditLogger := auditLogger
	oldTrace := AuditFullTraceLog
	t.Cleanup(func() {
		commandMap = oldCommandMap
		auditLogger = oldAuditLogger
		AuditFullTraceLog = oldTrace
	})

	commandMap = map[string][]byte{}
	AuditFullTraceLog = true
	var buf strings.Builder
	auditLogger = zerolog.New(&buf).With().Timestamp().Str("facility", "audit").Logger().Level(zerolog.TraceLevel)

	info := sessionInfo{User: "alice", NameSpace: "ns", Pod: "p"}
	storeOrFlush(asyncAudit{ctxid: "s", info: info, ascii: []byte("a")})

	if !strings.Contains(buf.String(), `"event":"keystroke"`) || !strings.Contains(buf.String(), `"byte":97`) {
		t.Fatalf("expected trace keystroke log, got %s", buf.String())
	}
}
