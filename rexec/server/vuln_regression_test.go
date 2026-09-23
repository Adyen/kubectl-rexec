package server

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

func extendedFrame(opcode byte, length uint64, payload []byte) []byte {
	frame := []byte{0x80 | opcode, 0xff}
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], length)
	frame = append(frame, encoded[:]...)
	frame = append(frame, 1, 2, 3, 4)
	for i, b := range payload {
		frame = append(frame, b^frame[10+i%4])
	}
	return frame
}

func TestRegressionReservedWebSocketOpcodesAudited(t *testing.T) {
	for _, tc := range []struct {
		name   string
		opcode byte
	}{{"reserved data opcode", 0x3}, {"reserved control opcode", 0xb}} {
		t.Run(tc.name, func(t *testing.T) {
			setupAuditCapture(t, 1)
			conn := &stubConn{}
			logger := &TCPLogger{Conn: conn, websocketOpen: true}
			frame := maskedFrame(true, tc.opcode, []byte("\x00id\n"), [4]byte{1, 2, 3, 4})

			if _, err := logger.Write(frame); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(forwardedBytes(conn), frame) {
				t.Fatal("accepted frame was not forwarded intact")
			}
			expectAudit(t, "id\n")
			expectNoAudit(t)
		})
	}
}

func TestRegressionUnauditableFramesNotForwarded(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{"MSB-set length", extendedFrame(0x2, 1<<63|4, []byte("\x00id\n"))},
		{"over audit capacity", extendedFrame(0x2, 1<<20, nil)},
		{"32 MiB boundary", extendedFrame(0x2, 32<<20, nil)},
		{"truncated huge frame", extendedFrame(0x2, 1<<20, bytes.Repeat([]byte{0xff}, 128<<10))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &stubConn{}
			logger := &TCPLogger{Conn: conn, websocketOpen: true}
			if _, err := logger.Write(tc.frame); err == nil {
				t.Fatal("unauditable frame must fail closed")
			}
			if len(forwardedBytes(conn)) != 0 {
				t.Fatal("unauditable frame reached upstream")
			}
			if len(logger.frameBuf) != 0 {
				t.Fatal("failed frame must not pin an audit buffer")
			}
		})
	}
}

func TestRegressionNonTTYBackspacesCannotEraseCommand(t *testing.T) {
	output := setupCommandAudit(t)
	auditLogger = zerolog.New(output).Level(zerolog.InfoLevel)
	const command = "touch harmless '"
	strokes := command + strings.Repeat("\b", len(command)) + "'\n"
	storeOrFlush(asyncAudit{
		ctxid: "non-tty",
		info:  sessionInfo{User: "alice"},
		ascii: []byte(strokes),
	})

	commands := auditCommands(t, output)
	if len(commands) != 1 || commands[0] != strings.TrimSuffix(strokes, "\n") {
		t.Fatalf("non-TTY command audit = %q, want literal stdin %q", commands, strokes)
	}
}

func TestRegressionTTYBackspaceStillEditsCommand(t *testing.T) {
	output := setupCommandAudit(t)
	storeOrFlush(asyncAudit{
		ctxid: "tty",
		info:  sessionInfo{User: "alice", TTY: true},
		ascii: []byte("abc\b\bde\r"),
	})
	if commands := auditCommands(t, output); len(commands) != 1 || commands[0] != "ade" {
		t.Fatalf("TTY command audit = %q, want [ade]", commands)
	}
}

func TestRegressionNilAdmissionRequestRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/validate-exec", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	execHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("nil AdmissionReview.Request: status = %d, want 400", rr.Code)
	}
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (w *deadlineRecorder) SetReadDeadline(t time.Time) error {
	w.deadline = t
	return nil
}

func TestRegressionWebhookSetsBodyDeadline(t *testing.T) {
	body := `{"request":{"uid":"123","kind":{"kind":"PodExecOptions"}}}`
	req := httptest.NewRequest(http.MethodPost, "/validate-exec", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	before := time.Now()

	instrumentHandler("webhook", webhookHandler)(w, req)

	if w.deadline.Before(before.Add(time.Second)) || w.deadline.After(time.Now().Add(30*time.Second)) {
		t.Fatalf("webhook body read deadline = %v, want a short nonzero deadline", w.deadline)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("valid AdmissionReview: status = %d, body = %q", w.Code, w.Body.String())
	}
}

func TestRegressionRecordedSessionLimitRejectsBeforeProxy(t *testing.T) {
	oldNames := RequestHeaderAllowedNames
	t.Cleanup(func() { RequestHeaderAllowedNames = oldNames })
	RequestHeaderAllowedNames = nil

	for range cap(recordingSessions) {
		recordingSessions <- struct{}{}
	}
	t.Cleanup(func() {
		for range cap(recordingSessions) {
			<-recordingSessions
		}
	})

	req := httptest.NewRequest(http.MethodGet,
		"/apis/audit.adyen.internal/v1beta1/namespaces/ns/pods/pod/exec?command=sh&stdin=true", nil)
	req.Header.Set("X-Remote-User", "alice")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req = withFrontProxyCert(req, "front-proxy-client")
	req = mux.SetURLVars(req, map[string]string{"namespace": "ns", "pod": "pod"})

	rr := httptest.NewRecorder()
	rexecHandler(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("when recorded-session limit is reached: status = %d, want 503", rr.Code)
	}
}
