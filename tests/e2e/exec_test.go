//go:build e2e

package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

const (
	primaryContainer   = "primary"
	secondaryContainer = "secondary"
	commandTimeout     = 30 * time.Second
	auditTimeout       = 15 * time.Second
)

type environment struct {
	context      string
	kubectl      string
	namespace    string
	otherNS      string
	plugin       string
	pod          string
	unannotated  string
	expectedUser string
	auditSince   string
}

type commandResult struct {
	stdout   string
	stderr   string
	exitCode int
}

type auditRecord struct {
	Level     string `json:"level"`
	Facility  string `json:"facility"`
	User      string `json:"user"`
	Session   string `json:"session"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
	ClientIP  string `json:"client_ip"`
	Command   string `json:"command"`
	Event     string `json:"event"`
	Stroke    string `json:"stroke"`
}

func TestExecCLISurfaceIsCovered(t *testing.T) {
	env := loadEnvironment(t)
	result := env.runRexec(t, "", nil, "exec", "--help")
	requireExitCode(t, result, 0)

	// Every command-local flag must name the contract test that exercises it.
	// A new upstream exec flag therefore fails this test until its behavior is
	// deliberately added to the suite.
	coverage := map[string]string{
		"container":           "TestExecTargets/container selection",
		"filename":            "TestExecTargets/filename",
		"help":                "TestExecCLISurfaceIsCovered",
		"pod-running-timeout": "TestExecTargets/pod running timeout",
		"quiet":               "TestExecTargets/quiet",
		"stdin":               "TestExecStdinAndAudit",
		"tty":                 "TestExecTTYAndResize",
	}

	got := localFlagNames(t, result.stdout)
	want := make([]string, 0, len(coverage))
	for flag := range coverage {
		want = append(want, flag)
	}
	sort.Strings(want)

	if !slices.Equal(got, want) {
		t.Fatalf("exec flags = %v, covered flags = %v; update the contract suite for any new flag", got, want)
	}
}

func TestExecOneOffStreamsArgumentsAndExitStatus(t *testing.T) {
	env := loadEnvironment(t)

	t.Run("stdout and stderr", func(t *testing.T) {
		stdoutToken := uniqueToken("stdout")
		stderrToken := uniqueToken("stderr")
		result := env.runRexec(t, "", nil,
			"exec", env.pod, "-n", env.namespace, "-c", primaryContainer, "--",
			"sh", "-c", `printf '%s' "$1"; printf '%s' "$2" >&2`, "sh", stdoutToken, stderrToken,
		)
		requireExitCode(t, result, 0)
		if result.stdout != stdoutToken {
			t.Errorf("stdout = %q, want %q", result.stdout, stdoutToken)
		}
		if result.stderr != stderrToken {
			t.Errorf("stderr = %q, want %q", result.stderr, stderrToken)
		}

		record := env.awaitAudit(t, "one-off command", func(record auditRecord) bool {
			return strings.Contains(record.Command, stdoutToken)
		})
		assertAuditMetadata(t, record, env.expectedUser, "oneoff", env.namespace, env.pod, primaryContainer)
	})

	t.Run("arguments are preserved", func(t *testing.T) {
		result := env.runRexec(t, "", nil,
			"exec", env.pod, "-n", env.namespace, "-c", primaryContainer, "--",
			"sh", "-c", `for value in "$@"; do printf '<%s>\n' "$value"; done`, "sh", "a b", "-n", "",
		)
		requireExitCode(t, result, 0)
		const want = "<a b>\n<-n>\n<>\n"
		if result.stdout != want {
			t.Errorf("stdout = %q, want %q", result.stdout, want)
		}
	})

	t.Run("remote exit status", func(t *testing.T) {
		result := env.runRexec(t, "", nil,
			"exec", env.pod, "-n", env.namespace, "-c", primaryContainer, "--",
			"sh", "-c", "exit 42",
		)
		requireExitCode(t, result, 42)
	})

	t.Run("missing executable", func(t *testing.T) {
		result := env.runRexec(t, "", nil,
			"exec", env.pod, "-n", env.namespace, "-c", primaryContainer, "--",
			"rexec-command-that-does-not-exist",
		)
		if result.exitCode == 0 {
			t.Fatalf("missing executable unexpectedly succeeded: stdout=%q stderr=%q", result.stdout, result.stderr)
		}
		if !strings.Contains(strings.ToLower(result.stderr), "not found") {
			t.Errorf("stderr = %q, want a not-found error", result.stderr)
		}
	})
}

func TestExecTargets(t *testing.T) {
	env := loadEnvironment(t)

	t.Run("default container annotation", func(t *testing.T) {
		result := env.runRexec(t, "", nil,
			"exec", env.pod, "-n", env.namespace, "--", "printenv", "REXEC_CONTAINER",
		)
		requireExitCode(t, result, 0)
		if result.stdout != primaryContainer+"\n" {
			t.Errorf("stdout = %q, want primary container", result.stdout)
		}
	})

	t.Run("container selection", func(t *testing.T) {
		result := env.runRexec(t, "", nil,
			"exec", env.pod, "-n", env.namespace, "-c", secondaryContainer, "--",
			"printenv", "REXEC_CONTAINER",
		)
		requireExitCode(t, result, 0)
		if result.stdout != secondaryContainer+"\n" {
			t.Errorf("stdout = %q, want secondary container", result.stdout)
		}
	})

	t.Run("quiet", func(t *testing.T) {
		normal := env.runRexec(t, "", nil,
			"exec", env.unannotated, "-n", env.namespace, "--", "printenv", "REXEC_CONTAINER",
		)
		requireExitCode(t, normal, 0)
		if !strings.Contains(normal.stderr, "Defaulted container") {
			t.Fatalf("stderr = %q, want the default-container notice", normal.stderr)
		}

		quiet := env.runRexec(t, "", nil,
			"exec", env.unannotated, "-n", env.namespace, "--quiet", "--",
			"printenv", "REXEC_CONTAINER",
		)
		requireExitCode(t, quiet, 0)
		if quiet.stderr != "" {
			t.Errorf("quiet stderr = %q, want no client notice", quiet.stderr)
		}
		if quiet.stdout != primaryContainer+"\n" {
			t.Errorf("quiet stdout = %q, want remote output", quiet.stdout)
		}
	})

	t.Run("resource name", func(t *testing.T) {
		result := env.runRexec(t, "", nil,
			"exec", "deployment/resource-target", "-n", env.namespace, "--",
			"printenv", "REXEC_CONTAINER",
		)
		requireExitCode(t, result, 0)
		if result.stdout != "resource\n" {
			t.Errorf("stdout = %q, want deployment pod output", result.stdout)
		}
	})

	t.Run("service resource", func(t *testing.T) {
		result := env.runRexec(t, "", nil,
			"exec", "service/resource-target", "-n", env.namespace, "--",
			"printenv", "REXEC_CONTAINER",
		)
		requireExitCode(t, result, 0)
		if result.stdout != "resource\n" {
			t.Errorf("stdout = %q, want service-selected pod output", result.stdout)
		}
	})

	t.Run("filename", func(t *testing.T) {
		manifest := filepath.Join(t.TempDir(), "pod.yaml")
		content := fmt.Sprintf("apiVersion: v1\nkind: Pod\nmetadata:\n  name: %s\n  namespace: %s\n", env.pod, env.namespace)
		if err := os.WriteFile(manifest, []byte(content), 0o600); err != nil {
			t.Fatalf("write pod manifest: %v", err)
		}

		result := env.runRexec(t, "", nil,
			"exec", "-f", manifest, "-c", primaryContainer, "--",
			"printenv", "REXEC_CONTAINER",
		)
		requireExitCode(t, result, 0)
		if result.stdout != primaryContainer+"\n" {
			t.Errorf("stdout = %q, want manifest-selected pod output", result.stdout)
		}
	})

	t.Run("namespace", func(t *testing.T) {
		result := env.runRexec(t, "", nil,
			"exec", "namespace-target", "-n", env.otherNS, "--",
			"printenv", "REXEC_CONTAINER",
		)
		requireExitCode(t, result, 0)
		if result.stdout != "other-namespace\n" {
			t.Errorf("stdout = %q, want namespace-selected pod output", result.stdout)
		}
	})

	t.Run("pod running timeout", func(t *testing.T) {
		result := env.runRexec(t, "", nil,
			"exec", "deployment/pending-target", "-n", env.namespace,
			"--pod-running-timeout=1s", "--", "true",
		)
		if result.exitCode == 0 {
			t.Fatalf("zero-replica deployment unexpectedly succeeded: stdout=%q stderr=%q", result.stdout, result.stderr)
		}
		if !strings.Contains(strings.ToLower(result.stderr), "timed out") {
			t.Errorf("stderr = %q, want timeout error", result.stderr)
		}
	})

	t.Run("completed pod", func(t *testing.T) {
		result := env.runRexec(t, "", nil,
			"exec", "completed-target", "-n", env.namespace, "--", "true",
		)
		if result.exitCode == 0 {
			t.Fatalf("completed pod unexpectedly accepted exec: stdout=%q stderr=%q", result.stdout, result.stderr)
		}
		if !strings.Contains(result.stderr, "cannot exec into a container in a completed pod") {
			t.Errorf("stderr = %q, want completed-pod error", result.stderr)
		}
	})

	t.Run("missing pod", func(t *testing.T) {
		result := env.runRexec(t, "", nil,
			"exec", "missing-pod", "-n", env.namespace, "--", "true",
		)
		if result.exitCode == 0 {
			t.Fatalf("missing pod unexpectedly succeeded: stdout=%q stderr=%q", result.stdout, result.stderr)
		}
		if !strings.Contains(strings.ToLower(result.stderr), "not found") {
			t.Errorf("stderr = %q, want not-found error", result.stderr)
		}
	})

	t.Run("missing container", func(t *testing.T) {
		result := env.runRexec(t, "", nil,
			"exec", env.pod, "-n", env.namespace, "-c", "missing-container", "--", "true",
		)
		if result.exitCode == 0 {
			t.Fatalf("missing container unexpectedly succeeded: stdout=%q stderr=%q", result.stdout, result.stderr)
		}
		if !strings.Contains(strings.ToLower(result.stderr), "container") {
			t.Errorf("stderr = %q, want container error", result.stderr)
		}
	})
}

func TestExecStdinAndAudit(t *testing.T) {
	env := loadEnvironment(t)

	t.Run("stdin without tty", func(t *testing.T) {
		token := uniqueToken("stdin")
		result := env.runRexec(t, token+"\n", nil,
			"exec", env.pod, "-n", env.namespace, "-c", primaryContainer, "-i", "--", "cat",
		)
		requireExitCode(t, result, 0)
		if result.stdout != token+"\n" {
			t.Errorf("stdout = %q, want %q", result.stdout, token+"\n")
		}

		record := env.awaitAudit(t, "stdin command", func(record auditRecord) bool {
			return record.Command == token
		})
		if record.Session == "oneoff" || record.Session == "" {
			t.Fatalf("stdin audit session = %q, want a recording session", record.Session)
		}
		assertAuditMetadata(t, record, env.expectedUser, record.Session, env.namespace, env.pod, primaryContainer)
		env.awaitAudit(t, "stdin trace", func(candidate auditRecord) bool {
			return candidate.Session == record.Session && strings.Contains(candidate.Stroke, token)
		})
		env.awaitAudit(t, "session start", func(candidate auditRecord) bool {
			return candidate.Session == record.Session && candidate.Event == "session_start"
		})
		env.awaitAudit(t, "session end", func(candidate auditRecord) bool {
			return candidate.Session == record.Session && candidate.Event == "session_end"
		})
	})

	t.Run("unterminated stdin is flushed", func(t *testing.T) {
		token := uniqueToken("unterminated")
		result := env.runRexec(t, token, nil,
			"exec", env.pod, "-n", env.namespace, "-c", primaryContainer, "-i", "--", "cat",
		)
		requireExitCode(t, result, 0)
		if result.stdout != token {
			t.Errorf("stdout = %q, want %q", result.stdout, token)
		}
		env.awaitAudit(t, "unterminated stdin command", func(record auditRecord) bool {
			return record.Command == token
		})
	})
}

func TestExecTTYAndResize(t *testing.T) {
	env := loadEnvironment(t)
	inputToken := uniqueToken("tty-input")
	stderrToken := uniqueToken("tty-stderr")
	script := fmt.Sprintf(`
trap 'printf "SIZE:%%s\n" "$(stty size)"' WINCH
printf 'READY:%%s\n' "$(stty size)"
printf 'TTYERR:%s\n' >&2
while :; do
	if IFS= read -r line; then
		printf 'GOT:%%s\n' "$line"
		[ "$line" = exit ] && break
	fi
done
`, stderrToken)

	ctx, cancel := context.WithTimeout(t.Context(), commandTimeout)
	defer cancel()
	args := env.rexecArgs(
		"exec", env.pod, "-n", env.namespace, "-c", primaryContainer, "-i", "-t", "--",
		"sh", "-c", script,
	)
	cmd := exec.CommandContext(ctx, env.plugin, args...)
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		t.Fatalf("start rexec in pty: %v", err)
	}
	t.Cleanup(func() {
		_ = ptmx.Close()
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	var output bytes.Buffer
	readPTYUntil(t, ptmx, &output, "READY:24 80")
	readPTYUntil(t, ptmx, &output, "TTYERR:"+stderrToken)

	if _, err := ptmx.Write([]byte(inputToken + "\r")); err != nil {
		t.Fatalf("write tty input: %v", err)
	}
	readPTYUntil(t, ptmx, &output, "GOT:"+inputToken)

	if err := pty.Setsize(ptmx, &pty.Winsize{Rows: 41, Cols: 103}); err != nil {
		t.Fatalf("resize pty: %v", err)
	}
	readPTYUntil(t, ptmx, &output, "SIZE:41 103")

	if _, err := ptmx.Write([]byte("exit\r")); err != nil {
		t.Fatalf("write tty exit: %v", err)
	}
	readPTYUntil(t, ptmx, &output, "GOT:exit")
	if err := cmd.Wait(); err != nil {
		t.Fatalf("interactive rexec: %v\noutput:\n%s", err, output.String())
	}

	record := env.awaitAudit(t, "tty input command", func(record auditRecord) bool {
		return record.Command == inputToken
	})
	if record.Session == "oneoff" || record.Session == "" {
		t.Fatalf("tty audit session = %q, want a recording session", record.Session)
	}
	assertAuditMetadata(t, record, env.expectedUser, record.Session, env.namespace, env.pod, primaryContainer)
}

func TestExecTransportContract(t *testing.T) {
	env := loadEnvironment(t)
	spdyOnly := []string{"KUBECTL_REMOTE_COMMAND_WEBSOCKETS=false"}

	t.Run("spdy one-off remains supported", func(t *testing.T) {
		token := uniqueToken("spdy")
		result := env.runRexec(t, "", spdyOnly,
			"exec", env.pod, "-n", env.namespace, "-c", primaryContainer, "--", "printf", "%s", token,
		)
		requireExitCode(t, result, 0)
		if result.stdout != token {
			t.Errorf("stdout = %q, want %q", result.stdout, token)
		}
	})

	t.Run("spdy interactive is rejected", func(t *testing.T) {
		result := env.runRexec(t, "input\n", spdyOnly,
			"exec", env.pod, "-n", env.namespace, "-c", primaryContainer, "-i", "--", "cat",
		)
		if result.exitCode == 0 {
			t.Fatalf("interactive SPDY unexpectedly succeeded: stdout=%q stderr=%q", result.stdout, result.stderr)
		}
		combined := strings.ToLower(result.stdout + result.stderr)
		if !strings.Contains(combined, "websocket") {
			t.Errorf("output = %q, want WebSocket requirement", result.stdout+result.stderr)
		}
	})
}

func TestExecAuthorizationAndWebhook(t *testing.T) {
	env := loadEnvironment(t)

	t.Run("impersonated groups are preserved", func(t *testing.T) {
		token := uniqueToken("group-rbac")
		result := env.runRexec(t, "", nil,
			"--as=rexec-e2e-group-user",
			"--as-group=system:authenticated",
			"--as-group=rexec-e2e-exec",
			"exec", env.pod, "-n", env.namespace, "-c", primaryContainer, "--",
			"printf", "%s", token,
		)
		requireExitCode(t, result, 0)
		if result.stdout != token {
			t.Errorf("stdout = %q, want %q", result.stdout, token)
		}
		record := env.awaitAudit(t, "group-authorized command", func(record auditRecord) bool {
			return record.User == "rexec-e2e-group-user" && strings.Contains(record.Command, token)
		})
		assertAuditMetadata(t, record, "rexec-e2e-group-user", "oneoff", env.namespace, env.pod, primaryContainer)
	})

	t.Run("upstream rbac is not elevated", func(t *testing.T) {
		result := env.runRexec(t, "", nil,
			"--as=rexec-e2e-denied",
			"--as-group=system:authenticated",
			"exec", env.pod, "-n", env.namespace, "-c", primaryContainer, "--", "true",
		)
		if result.exitCode == 0 {
			t.Fatalf("RBAC-denied exec unexpectedly succeeded: stdout=%q stderr=%q", result.stdout, result.stderr)
		}
		if !strings.Contains(strings.ToLower(result.stdout+result.stderr), "forbidden") {
			t.Errorf("output = %q, want forbidden error", result.stdout+result.stderr)
		}
	})

	t.Run("direct kubectl exec is denied", func(t *testing.T) {
		result := env.runKubectl(t, "",
			"--context", env.context,
			"exec", env.pod, "-n", env.namespace, "-c", primaryContainer, "--", "true",
		)
		if result.exitCode == 0 {
			t.Fatalf("direct kubectl exec unexpectedly succeeded: stdout=%q stderr=%q", result.stdout, result.stderr)
		}
		if !strings.Contains(result.stderr, "cannot use exec directly, use rexec plugin instead") {
			t.Errorf("stderr = %q, want webhook denial", result.stderr)
		}
	})
}

func loadEnvironment(t *testing.T) environment {
	t.Helper()

	required := func(name string) string {
		t.Helper()
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("%s must be set by the E2E harness", name)
		}
		return value
	}

	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		t.Fatalf("find kubectl: %v", err)
	}

	return environment{
		context:      required("REXEC_E2E_CONTEXT"),
		kubectl:      kubectl,
		namespace:    required("REXEC_E2E_NAMESPACE"),
		otherNS:      required("REXEC_E2E_OTHER_NAMESPACE"),
		plugin:       required("REXEC_E2E_PLUGIN"),
		pod:          required("REXEC_E2E_POD"),
		unannotated:  required("REXEC_E2E_UNANNOTATED_POD"),
		expectedUser: required("REXEC_E2E_USER"),
		auditSince:   time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano),
	}
}

func (e environment) rexecArgs(args ...string) []string {
	return append([]string{"--context", e.context}, args...)
}

func (e environment) runRexec(t *testing.T, stdin string, extraEnv []string, args ...string) commandResult {
	t.Helper()
	return runCommand(t, e.plugin, e.rexecArgs(args...), stdin, extraEnv)
}

func (e environment) runKubectl(t *testing.T, stdin string, args ...string) commandResult {
	t.Helper()
	return runCommand(t, e.kubectl, args, stdin, nil)
}

func runCommand(t *testing.T, binary string, args []string, stdin string, extraEnv []string) commandResult {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = append(cmd.Environ(), extraEnv...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	result := commandResult{
		stdout:   stdout.String(),
		stderr:   stderr.String(),
		exitCode: 0,
	}
	if err == nil {
		return result
	}
	if ctx.Err() != nil {
		t.Fatalf("%s %v: %v; stdout=%q stderr=%q", binary, args, ctx.Err(), result.stdout, result.stderr)
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.exitCode = exitErr.ExitCode()
		return result
	}
	t.Fatalf("%s %v: %v", binary, args, err)
	return commandResult{}
}

func requireExitCode(t *testing.T, result commandResult, want int) {
	t.Helper()
	if result.exitCode != want {
		t.Fatalf("exit code = %d, want %d; stdout=%q stderr=%q", result.exitCode, want, result.stdout, result.stderr)
	}
}

func localFlagNames(t *testing.T, help string) []string {
	t.Helper()

	const start = "\nFlags:\n"
	const end = "\nGlobal Flags:\n"
	startIndex := strings.Index(help, start)
	endIndex := strings.Index(help, end)
	if startIndex < 0 || endIndex < 0 || endIndex <= startIndex {
		t.Fatalf("cannot find local flag section in help:\n%s", help)
	}

	flagPattern := regexp.MustCompile(`--([a-z0-9-]+)`)
	var flags []string
	scanner := bufio.NewScanner(strings.NewReader(help[startIndex+len(start) : endIndex]))
	for scanner.Scan() {
		match := flagPattern.FindStringSubmatch(scanner.Text())
		if len(match) == 2 {
			flags = append(flags, match[1])
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan exec help: %v", err)
	}
	sort.Strings(flags)
	return flags
}

func uniqueToken(prefix string) string {
	return fmt.Sprintf("rexec-e2e-%s-%d", prefix, time.Now().UnixNano())
}

func (e environment) awaitAudit(t *testing.T, description string, match func(auditRecord) bool) auditRecord {
	t.Helper()

	deadline := time.Now().Add(auditTimeout)
	var lastLogs string
	for time.Now().Before(deadline) {
		records, logs, err := e.auditRecords(t.Context())
		lastLogs = logs
		if err == nil {
			for _, record := range records {
				if match(record) {
					return record
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	if len(lastLogs) > 8_000 {
		lastLogs = lastLogs[len(lastLogs)-8_000:]
	}
	t.Fatalf("%s not found in audit records; recent logs:\n%s", description, lastLogs)
	return auditRecord{}
}

func (e environment) auditRecords(parent context.Context) ([]auditRecord, string, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, e.kubectl,
		"--context", e.context,
		"logs", "-n", "kube-system", "-l", "app=rexec",
		"--since-time", e.auditSince,
		"--tail=10000",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, string(output), err
	}

	var records []auditRecord
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Bytes()
		jsonStart := bytes.IndexByte(line, '{')
		if jsonStart < 0 {
			continue
		}
		var record auditRecord
		if err := json.Unmarshal(line[jsonStart:], &record); err == nil && record.Facility == "audit" {
			records = append(records, record)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, string(output), err
	}
	return records, string(output), nil
}

func assertAuditMetadata(t *testing.T, record auditRecord, user, session, namespace, pod, container string) {
	t.Helper()

	if record.User != user {
		t.Errorf("audit user = %q, want %q", record.User, user)
	}
	if record.Session != session {
		t.Errorf("audit session = %q, want %q", record.Session, session)
	}
	if record.Namespace != namespace {
		t.Errorf("audit namespace = %q, want %q", record.Namespace, namespace)
	}
	if record.Pod != pod {
		t.Errorf("audit pod = %q, want %q", record.Pod, pod)
	}
	if record.Container != container {
		t.Errorf("audit container = %q, want %q", record.Container, container)
	}
	if record.ClientIP == "" {
		t.Error("audit client_ip is empty")
	}
}

func readPTYUntil(t *testing.T, ptmx *os.File, output *bytes.Buffer, want string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	if err := ptmx.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set pty read deadline: %v", err)
	}

	buf := make([]byte, 4_096)
	for !strings.Contains(output.String(), want) {
		n, err := ptmx.Read(buf)
		if n > 0 {
			_, _ = output.Write(buf[:n])
		}
		if err != nil {
			t.Fatalf("read pty waiting for %q: %v\noutput:\n%s", want, err, output.String())
		}
	}
}
