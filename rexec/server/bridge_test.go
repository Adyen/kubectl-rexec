package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	execconst "k8s.io/apimachinery/pkg/util/remotecommand"
	rcmd "k8s.io/client-go/tools/remotecommand"
	executil "k8s.io/client-go/util/exec"
	"k8s.io/streaming/pkg/httpstream/wsstream"
)

func TestIngressReady(t *testing.T) {
	stdin := strings.NewReader("")
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	errw := &bytes.Buffer{}

	tests := []struct {
		name string
		in   *execIngress
		tty  bool
		want bool
	}{
		{
			name: "non-tty needs stderr",
			in:   &execIngress{stdin: stdin, stdout: stdout, errorw: errw},
			tty:  false,
			want: false,
		},
		{
			name: "non-tty all mandatory",
			in:   &execIngress{stdin: stdin, stdout: stdout, stderr: stderr, errorw: errw},
			tty:  false,
			want: true,
		},
		{
			name: "tty without stderr",
			in:   &execIngress{stdin: stdin, stdout: stdout, errorw: errw},
			tty:  true,
			want: true,
		},
		{
			name: "missing stdin",
			in:   &execIngress{stdout: stdout, stderr: stderr, errorw: errw},
			tty:  false,
			want: false,
		},
		{
			name: "missing error stream",
			in:   &execIngress{stdin: stdin, stdout: stdout, stderr: stderr},
			tty:  false,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ingressReady(tt.in, tt.tty); got != tt.want {
				t.Fatalf("ingressReady() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMapSPDYStream(t *testing.T) {
	stream := func(streamType string) *fakeHTTPStream {
		h := http.Header{}
		h.Set(corev1.StreamType, streamType)
		return &fakeHTTPStream{headers: h}
	}

	tests := []struct {
		streamType string
		check      func(t *testing.T, in *execIngress, s *fakeHTTPStream)
	}{
		{
			streamType: corev1.StreamTypeStdin,
			check: func(t *testing.T, in *execIngress, s *fakeHTTPStream) {
				if in.stdin != s {
					t.Fatal("stdin not assigned")
				}
			},
		},
		{
			streamType: corev1.StreamTypeStdout,
			check: func(t *testing.T, in *execIngress, s *fakeHTTPStream) {
				if in.stdout != s {
					t.Fatal("stdout not assigned")
				}
			},
		},
		{
			streamType: corev1.StreamTypeStderr,
			check: func(t *testing.T, in *execIngress, s *fakeHTTPStream) {
				if in.stderr != s {
					t.Fatal("stderr not assigned")
				}
			},
		},
		{
			streamType: corev1.StreamTypeError,
			check: func(t *testing.T, in *execIngress, s *fakeHTTPStream) {
				if in.errorw != s {
					t.Fatal("error stream not assigned")
				}
			},
		},
		{
			streamType: corev1.StreamTypeResize,
			check: func(t *testing.T, in *execIngress, s *fakeHTTPStream) {
				if in.resize != s {
					t.Fatal("resize stream not assigned")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.streamType, func(t *testing.T) {
			in := &execIngress{}
			s := stream(tt.streamType)
			if err := mapSPDYStream(in, s); err != nil {
				t.Fatal(err)
			}
			tt.check(t, in, s)
		})
	}

	t.Run("unexpected", func(t *testing.T) {
		in := &execIngress{}
		if err := mapSPDYStream(in, stream("bogus")); err == nil {
			t.Fatal("expected error for unknown stream type")
		}
	})
}

func TestWsIngressProtocols(t *testing.T) {
	t.Run("non-tty", func(t *testing.T) {
		protocols := wsIngressProtocols(false)
		cfg := protocols[wsstream.ChannelWebSocketProtocol]
		if len(cfg.Channels) != execconst.StreamErr+1 {
			t.Fatalf("channel count = %d, want %d", len(cfg.Channels), execconst.StreamErr+1)
		}
		assertWsIngressProtocols(t, protocols)
	})

	t.Run("tty", func(t *testing.T) {
		protocols := wsIngressProtocols(true)
		cfg := protocols[wsstream.ChannelWebSocketProtocol]
		if len(cfg.Channels) != execconst.StreamResize+1 {
			t.Fatalf("channel count = %d, want %d", len(cfg.Channels), execconst.StreamResize+1)
		}
		assertWsIngressProtocols(t, protocols)
	})
}

func assertWsIngressProtocols(t *testing.T, protocols map[string]wsstream.ChannelProtocolConfig) {
	t.Helper()
	for _, name := range []string{
		wsstream.ChannelWebSocketProtocol,
		wsstream.Base64ChannelWebSocketProtocol,
		execconst.StreamProtocolV5Name,
		"",
	} {
		if _, ok := protocols[name]; !ok {
			t.Fatalf("missing protocol %q", name)
		}
	}
}

func TestExecErrorStatus(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status string
		reason metav1.StatusReason
		msg    string
		cause  string
	}{
		{name: "success", err: nil, status: metav1.StatusSuccess},
		{name: "failure", err: errors.New("boom"), status: metav1.StatusFailure, msg: "boom"},
		{
			name:   "exit code",
			err:    executil.CodeExitError{Code: 42},
			status: metav1.StatusFailure,
			reason: execconst.NonZeroExitCodeReason,
			cause:  "42",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := execErrorStatus(tt.err)
			if st.Status != tt.status {
				t.Fatalf("status = %q, want %q", st.Status, tt.status)
			}
			if tt.msg != "" && st.Message != tt.msg {
				t.Fatalf("message = %q, want %q", st.Message, tt.msg)
			}
			if tt.reason != "" && st.Reason != tt.reason {
				t.Fatalf("reason = %q, want %q", st.Reason, tt.reason)
			}
			if tt.cause != "" {
				if st.Details == nil || len(st.Details.Causes) != 1 || st.Details.Causes[0].Message != tt.cause {
					t.Fatalf("unexpected exit details: %+v", st.Details)
				}
			}
		})
	}
}

func TestWriteExecStatus(t *testing.T) {
	var buf bytes.Buffer
	if err := writeExecStatus(&buf, executil.CodeExitError{Code: 7}); err != nil {
		t.Fatal(err)
	}
	var st metav1.Status
	if err := json.Unmarshal(buf.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Reason != execconst.NonZeroExitCodeReason {
		t.Fatalf("reason = %q", st.Reason)
	}
}

func TestResizeQueueNext(t *testing.T) {
	q := &resizeQueue{dec: json.NewDecoder(strings.NewReader(`{"Width":80,"Height":24}`))}
	size := q.Next()
	if size == nil || size.Width != 80 || size.Height != 24 {
		t.Fatalf("unexpected size: %+v", size)
	}
	if q.Next() != nil {
		t.Fatal("expected nil after decoder exhausted")
	}
}

func TestIsExecStreamRequest(t *testing.T) {
	wsGet, _ := http.NewRequest(http.MethodGet, "/exec", nil)
	wsGet.Header.Set("Connection", "Upgrade")
	wsGet.Header.Set("Upgrade", "websocket")

	spdyGet, _ := http.NewRequest(http.MethodGet, "/exec", nil)
	spdyGet.Header.Set("Connection", "Upgrade")
	spdyGet.Header.Set("Upgrade", "SPDY/3.1")

	plainGet, _ := http.NewRequest(http.MethodGet, "/exec", nil)
	post, _ := http.NewRequest(http.MethodPost, "/exec", nil)

	tests := []struct {
		name string
		req  *http.Request
		want bool
	}{
		{name: "post", req: post, want: true},
		{name: "plain get", req: plainGet, want: false},
		{name: "websocket upgrade get", req: wsGet, want: true},
		{name: "spdy upgrade get", req: spdyGet, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isExecStreamRequest(tt.req); got != tt.want {
				t.Fatalf("isExecStreamRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

type fakeHTTPStream struct {
	headers http.Header
}

func (f *fakeHTTPStream) Read(p []byte) (int, error)  { return 0, nil }
func (f *fakeHTTPStream) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeHTTPStream) Close() error                { return nil }
func (f *fakeHTTPStream) Reset() error                { return nil }
func (f *fakeHTTPStream) Headers() http.Header        { return f.headers }
func (f *fakeHTTPStream) Identifier() uint32          { return 1 }

var _ rcmd.TerminalSizeQueue = (*resizeQueue)(nil)
