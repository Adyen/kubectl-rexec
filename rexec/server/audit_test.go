package server

import (
	"bytes"
	"net/url"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
)

// TestParseParamsNeedsRecording covers which exec requests are flagged for
// keystroke recording. The security-critical case is `kubectl exec -i` WITHOUT
// `-t`: it streams interactive stdin (a shell, a REPL) that must be audited even
// though no tty is allocated. Before the fix the decision keyed only on the tty
// parameter, so a stdin-only session slipped through with the audited transport
// disabled and only its initial command ("sh") logged, leaving an unaudited
// interactive shell.
func TestParseParamsNeedsRecording(t *testing.T) {
	tests := []struct {
		name          string
		query         string
		wantRecording bool
		wantContainer string
	}{
		{
			name:          "tty session (-i -t) is recorded",
			query:         "command=sh&container=app&stdin=true&stdout=true&stderr=true&tty=true",
			wantRecording: true,
			wantContainer: "app",
		},
		{
			name:          "stdin-only session (-i, no -t) is recorded",
			query:         "command=sh&container=app&stdin=true&stdout=true&stderr=true",
			wantRecording: true,
			wantContainer: "app",
		},
		{
			name:          "true one-off (no stdin, no tty) is not recorded",
			query:         "command=ls&container=app&stdout=true&stderr=true",
			wantRecording: false,
			wantContainer: "app",
		},
		{
			name:          "explicit stdin=false is not recorded",
			query:         "command=ls&stdin=false&stdout=true",
			wantRecording: false,
		},
		{
			name:          "explicit tty=false is not recorded",
			query:         "command=ls&tty=false&stdout=true",
			wantRecording: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := url.ParseQuery(tt.query)
			if err != nil {
				t.Fatalf("parse query: %v", err)
			}
			_, needsRecording, container := parseParams(params)
			if needsRecording != tt.wantRecording {
				t.Fatalf("needsRecording = %v, want %v", needsRecording, tt.wantRecording)
			}
			if container != tt.wantContainer {
				t.Fatalf("container = %q, want %q", container, tt.wantContainer)
			}
		})
	}
}

// TestParseParamsMatchesKubectlWire encodes PodExecOptions exactly as the kubectl
// client does and confirms a stdin-only exec (-i without -t) is flagged for
// recording. This guards against drift in the wire format: the tty parameter is
// omitted entirely when false (which is what originally enabled the bypass), so
// recording must not depend on its presence.
func TestParseParamsMatchesKubectlWire(t *testing.T) {
	cases := []struct {
		name          string
		opts          corev1.PodExecOptions
		wantRecording bool
	}{
		{
			name:          "kubectl exec -i (stdin, no tty)",
			opts:          corev1.PodExecOptions{Command: []string{"sh"}, Stdin: true, Stdout: true, Stderr: true},
			wantRecording: true,
		},
		{
			name:          "kubectl exec -i -t (stdin and tty)",
			opts:          corev1.PodExecOptions{Command: []string{"sh"}, Stdin: true, Stdout: true, Stderr: true, TTY: true},
			wantRecording: true,
		},
		{
			name:          "kubectl exec (no stdin, no tty)",
			opts:          corev1.PodExecOptions{Command: []string{"ls"}, Stdout: true, Stderr: true},
			wantRecording: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			v, err := scheme.ParameterCodec.EncodeParameters(&opts, corev1.SchemeGroupVersion)
			if err != nil {
				t.Fatalf("encode params: %v", err)
			}
			_, needsRecording, _ := parseParams(v)
			if needsRecording != tc.wantRecording {
				t.Fatalf("needsRecording = %v, want %v (query=%q)", needsRecording, tc.wantRecording, v.Encode())
			}
		})
	}
}

// captureAudit redirects the package audit logger to a buffer for assertions and
// restores it when the test finishes.
func captureAudit(t *testing.T) *bytes.Buffer {
	t.Helper()
	old := auditLogger
	buf := &bytes.Buffer{}
	auditLogger = zerolog.New(buf).Level(zerolog.InfoLevel)
	t.Cleanup(func() { auditLogger = old })
	return buf
}

// TestStoreOrFlushSplitsOnLineFeedAndCarriageReturn confirms that line input is
// flushed as a command on both LF and CR. A raw-mode tty sends CR on Enter, but a
// non-tty stdin session (now recorded after the bypass fix) sends LF. Without
// handling LF, the keystrokes of an audited stdin-only shell would accumulate
// instead of being segmented into auditable commands.
func TestStoreOrFlushSplitsOnLineFeedAndCarriageReturn(t *testing.T) {
	oldMap := commandMap
	oldMax := MaxStokesPerLine
	t.Cleanup(func() {
		commandMap = oldMap
		MaxStokesPerLine = oldMax
	})
	commandMap = map[string][]byte{}
	MaxStokesPerLine = 2000

	buf := captureAudit(t)

	// "ls -la\n" and "whoami\r" exercise LF and CR respectively; the trailing LF
	// after "exit" flushes the final command so the buffer ends empty.
	storeOrFlush(asyncAudit{
		ctxid: "sess-lf",
		info:  sessionInfo{User: "alice", NameSpace: "default", Pod: "shell", Container: "app"},
		ascii: []byte("ls -la\nwhoami\rexit\n"),
	})

	out := buf.String()
	for _, want := range []string{"ls -la", "whoami", "exit"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected command %q in audit log, got: %s", want, out)
		}
	}
	if got := commandMap["sess-lf"]; len(got) != 0 {
		t.Fatalf("command buffer should be empty after trailing newline, got %q", got)
	}
}
