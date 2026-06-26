package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	execconst "k8s.io/apimachinery/pkg/util/remotecommand"
	rcmd "k8s.io/client-go/tools/remotecommand"
	executil "k8s.io/client-go/util/exec"
	"k8s.io/streaming/pkg/httpstream"
	httpstreamspdy "k8s.io/streaming/pkg/httpstream/spdy"
	"k8s.io/streaming/pkg/httpstream/wsstream"
)

var streamProtocols = []string{
	execconst.StreamProtocolV5Name,
	execconst.StreamProtocolV4Name,
	execconst.StreamProtocolV3Name,
	execconst.StreamProtocolV2Name,
	execconst.StreamProtocolV1Name,
}

type bridgeParams struct {
	namespace, pod, container, user, sessionID string
	groups, command                            []string
	tty                                        bool
	info                                       sessionInfo
}

type execIngress struct {
	stdin, resize          io.Reader
	stdout, stderr, errorw io.Writer
	close                  func()
}

// bridgeTTYExec upgrades the aggregation-layer exec stream, bridges it to a real
// pod exec via remotecommand, and audits stdin keystrokes
func bridgeTTYExec(w http.ResponseWriter, r *http.Request, p bridgeParams) error {
	in, err := acceptIngress(w, r, p.tty)
	if err != nil {
		return err
	}
	defer in.close()

	cfg, err := impersonatedRESTConfig(p.user, p.groups)
	if err != nil {
		return err
	}
	execURL, err := podExecURL(cfg, p.namespace, p.pod, &corev1.PodExecOptions{
		Container: p.container, Command: p.command, Stdin: true, Stdout: true, Stderr: true, TTY: p.tty,
	})
	if err != nil {
		return err
	}
	exec, err := newPodExecExecutor(cfg, execURL)
	if err != nil {
		return err
	}

	opts := rcmd.StreamOptions{
		Stdin: newAuditedStdin(in.stdin, p.sessionID, p.info), Stdout: in.stdout, Stderr: in.stderr, Tty: p.tty,
	}
	if in.resize != nil {
		opts.TerminalSizeQueue = &resizeQueue{json.NewDecoder(in.resize)}
	}

	streamErr := exec.StreamWithContext(r.Context(), opts)
	// Report exit status back on the ingress error stream (remotecommand protocol)
	if in.errorw != nil {
		if err := writeExecStatus(in.errorw, streamErr); err != nil {
			SysLogger.Error().Err(err).Msg("failed to write exec status to ingress error stream")
		}
	}
	return streamErr
}

// isExecStreamRequest reports whether the aggregation layer is opening an exec
// stream. On Kubernetes 1.30+ this is typically GET with an upgrade header, not POST
func isExecStreamRequest(r *http.Request) bool {
	return r.Method == http.MethodPost || httpstream.IsUpgradeRequest(r) || wsstream.IsWebSocketRequest(r)
}

func acceptIngress(w http.ResponseWriter, r *http.Request, tty bool) (*execIngress, error) {
	if wsstream.IsWebSocketRequest(r) {
		logIngress("websocket")
		return acceptWebSocketIngress(w, r, tty)
	}
	logIngress("spdy")
	return acceptSPDYIngress(w, r, tty)
}

func acceptSPDYIngress(w http.ResponseWriter, r *http.Request, tty bool) (*execIngress, error) {
	if _, err := httpstream.Handshake(r, w, streamProtocols); err != nil {
		return nil, err
	}

	in := &execIngress{}
	ch := make(chan spdyStream, 8)
	conn := httpstreamspdy.NewResponseUpgrader().UpgradeResponse(w, r, func(s httpstream.Stream, replySent <-chan struct{}) error {
		ch <- spdyStream{s, replySent}
		return nil
	})
	if conn == nil {
		return nil, errors.New("spdy upgrade failed")
	}
	in.close = func() { conn.Close() }

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Wait for mandatory streams (stdin, stdout, error, stderr unless TTY)
	for !ingressReady(in, tty) {
		select {
		case sr := <-ch:
			<-sr.reply // upgrade reply must complete before reading stream headers
			if err := mapSPDYStream(in, sr.stream); err != nil {
				return nil, err
			}
		case <-ctx.Done():
			return nil, fmt.Errorf("spdy ingress timed out: %w", ctx.Err())
		}
	}
	// Resize may open after the mandatory streams, drain it without blocking forever
	for {
		select {
		case sr := <-ch:
			<-sr.reply
			if in.resize == nil {
				_ = mapSPDYStream(in, sr.stream)
			}
		default:
			return in, nil
		}
	}
}

func acceptWebSocketIngress(w http.ResponseWriter, r *http.Request, tty bool) (*execIngress, error) {
	conn := wsstream.NewConn(wsIngressProtocols(tty))
	r = r.WithContext(ingressLogContext(r.Context()))
	_, rwcs, err := conn.Open(w, r)
	if err != nil {
		return nil, err
	}
	if len(rwcs) < 4 {
		return nil, fmt.Errorf("websocket ingress: got %d channels, want at least 4", len(rwcs))
	}
	in := &execIngress{
		stdin: rwcs[execconst.StreamStdIn], stdout: rwcs[execconst.StreamStdOut],
		stderr: rwcs[execconst.StreamStdErr], errorw: rwcs[execconst.StreamErr],
		close: func() { conn.Close() },
	}
	if tty && len(rwcs) > execconst.StreamResize {
		in.resize = rwcs[execconst.StreamResize]
	}
	return in, nil
}

// wsIngressProtocols builds WebSocket subprotocol configs for remotecommand ingress
func wsIngressProtocols(tty bool) map[string]wsstream.ChannelProtocolConfig {
	n := execconst.StreamErr + 1
	if tty {
		n = execconst.StreamResize + 1
	}
	channels := make([]wsstream.ChannelType, n)
	for i := range channels {
		channels[i] = wsstream.ReadWriteChannel
	}
	cfg := wsstream.ChannelProtocolConfig{Binary: true, Channels: channels}
	protocols := map[string]wsstream.ChannelProtocolConfig{
		wsstream.ChannelWebSocketProtocol:       cfg,
		wsstream.Base64ChannelWebSocketProtocol: {Binary: false, Channels: channels},
	}
	// Advertise V1–V5 names (and empty default) so kubectl can pick a compatible subprotocol
	for _, name := range append(streamProtocols, "") {
		protocols[name] = cfg
	}
	return protocols
}

type spdyStream struct {
	stream httpstream.Stream
	reply  <-chan struct{}
}

func ingressReady(in *execIngress, tty bool) bool {
	if in.stdin == nil || in.stdout == nil || in.errorw == nil {
		return false
	}
	return tty || in.stderr != nil // TTY merges stderr into stdout
}

func mapSPDYStream(in *execIngress, s httpstream.Stream) error {
	switch s.Headers().Get(corev1.StreamType) {
	case corev1.StreamTypeStdin:
		in.stdin = s
	case corev1.StreamTypeStdout:
		in.stdout = s
	case corev1.StreamTypeStderr:
		in.stderr = s
	case corev1.StreamTypeError:
		in.errorw = s
	case corev1.StreamTypeResize:
		in.resize = s
	default:
		return fmt.Errorf("unexpected spdy stream type %q", s.Headers().Get(corev1.StreamType))
	}
	return nil
}

func writeExecStatus(w io.Writer, err error) error {
	bs, err := json.Marshal(execErrorStatus(err))
	if err != nil {
		return err
	}
	_, err = w.Write(bs)
	return err
}

func execErrorStatus(err error) metav1.Status {
	if err == nil {
		return metav1.Status{Status: metav1.StatusSuccess}
	}
	if exitErr, ok := errors.AsType[executil.ExitError](err); ok {
		return metav1.Status{
			Status: metav1.StatusFailure, Reason: execconst.NonZeroExitCodeReason,
			Details: &metav1.StatusDetails{Causes: []metav1.StatusCause{{
				Type: execconst.ExitCodeCauseType, Message: strconv.Itoa(exitErr.ExitStatus()),
			}}},
		}
	}
	return metav1.Status{Status: metav1.StatusFailure, Message: err.Error()}
}

type resizeQueue struct{ dec *json.Decoder }

func (q *resizeQueue) Next() *rcmd.TerminalSize {
	var size rcmd.TerminalSize
	if q.dec == nil || q.dec.Decode(&size) != nil {
		return nil
	}
	return &size
}
