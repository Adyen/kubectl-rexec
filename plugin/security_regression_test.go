package plugin

// Regression tests for rexec cp extraction hardening: a malicious workload
// controls the tar stream and its own stderr, so names, links, sizes, and
// terminal output must all be treated as hostile.

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/cli-runtime/pkg/genericiooptions"
)

// With a non-directory destination, every legitimate tar entry is exactly
// srcBase or under it; names like "foobar" or "foo2/evil" must be rejected
// instead of resolving to siblings of the destination file.
func TestRegressionCpNonDirDestRejectsSiblingNames(t *testing.T) {
	tmp := t.TempDir()
	dest := filepath.Join(tmp, "bar") // non-existent => non-dir destination
	baseAbs, _ := filepath.Abs(tmp)

	rejected := []string{"foobar", "foo2/evil", "../outside", "/abs/path", "foo/../../up"}
	for _, name := range rejected {
		if got, err := computeSafeTarget(name, dest, baseAbs, "foo", false); err == nil {
			t.Fatalf("name %q must be rejected, got target %q", name, got)
		}
	}
	accepted := map[string]string{
		"foo":       dest,
		"foo/inner": filepath.Join(dest, "inner"),
	}
	for name, want := range accepted {
		got, err := computeSafeTarget(name, dest, baseAbs, "foo", false)
		if err != nil {
			t.Fatalf("name %q: unexpected error %v", name, err)
		}
		if got != want {
			t.Fatalf("name %q: target = %q, want %q", name, got, want)
		}
	}
}

// A symlink under the destination planted by another local actor must not
// redirect extraction outside the destination. The write is either confined
// to the destination root or fails; it must never land outside.
func TestRegressionCpSymlinkCannotEscapeDestination(t *testing.T) {
	tmp := t.TempDir()
	outside := t.TempDir()

	dest := filepath.Join(tmp, "dest")
	if err := os.Mkdir(dest, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dest, "logs")); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	content := []byte("pwned-by-rexec\n")
	if err := tw.WriteHeader(&tar.Header{Name: "logs/pwned", Mode: 0644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	o := &CopyOptions{IOStreams: genericiooptions.IOStreams{In: &bytes.Buffer{}, Out: &bytes.Buffer{}, ErrOut: &bytes.Buffer{}}}
	if err := o.extractTar(&buf, dest, "foo"); err != nil {
		t.Logf("extractTar failed closed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(outside, "pwned")); err == nil {
		t.Fatal("extraction escaped the destination via a pre-existing symlink")
	}
}

// The pod controls the tar stream and its own stderr: the client must bound
// memory and disk against hostile or broken workloads.
func TestRegressionCpResourceLimits(t *testing.T) {
	t.Run("archive stream cap fails the copy", func(t *testing.T) {
		var buf bytes.Buffer
		cw := &cappedWriter{w: &buf, max: 10}
		if _, err := cw.Write([]byte("123456")); err != nil {
			t.Fatalf("write within cap: %v", err)
		}
		if _, err := cw.Write([]byte("789012")); err == nil {
			t.Fatal("write past the cap must fail")
		}
		if _, err := cw.Write([]byte("x")); err == nil {
			t.Fatal("cap error must be sticky")
		}
		if buf.Len() != 10 {
			t.Fatalf("underlying writer must hold exactly the cap, got %d", buf.Len())
		}
	})

	t.Run("stderr is truncated with a marker, never fatal", func(t *testing.T) {
		tb := &truncatingBuffer{max: 10}
		if _, err := tb.Write([]byte("abcdefghijklmnopqrst")); err != nil {
			t.Fatalf("stderr overflow must not error: %v", err)
		}
		if !tb.truncated || !strings.Contains(tb.String(), "truncated") {
			t.Fatalf("expected truncation marker, got %q", tb.String())
		}
		if !strings.HasPrefix(tb.String(), "abcdefghij") {
			t.Fatalf("kept content = %q", tb.String())
		}
	})

	t.Run("entry count cap", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, name := range []string{"d/a", "d/b", "d/c"} {
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: 1, Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		o := &CopyOptions{MaxEntries: 2, IOStreams: genericiooptions.IOStreams{ErrOut: &bytes.Buffer{}}}
		err := o.extractTar(&buf, t.TempDir(), "d")
		if err == nil || !strings.Contains(err.Error(), "too many entries") {
			t.Fatalf("expected entry-count rejection, got %v", err)
		}
	})

	t.Run("extracted bytes cap uses declared sizes", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		content := bytes.Repeat([]byte("x"), 100)
		if err := tw.WriteHeader(&tar.Header{Name: "d/big", Mode: 0644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		dest := t.TempDir()
		o := &CopyOptions{MaxArchiveBytes: 10, IOStreams: genericiooptions.IOStreams{ErrOut: &bytes.Buffer{}}}
		err := o.extractTar(&buf, dest, "d")
		if err == nil || !strings.Contains(err.Error(), "exceeds the 10 byte limit") {
			t.Fatalf("expected size-cap rejection, got %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(dest, "d", "big")); statErr == nil {
			t.Fatal("oversized entry must not be written")
		}
	})
}

// Pod-controlled strings (tar entry names, link targets, stderr) reach the
// user's terminal via warnings and errors; control characters must be
// stripped so a workload cannot inject escape sequences.
func TestRegressionCpTerminalSanitization(t *testing.T) {
	if got := sanitizeTerminal("\x1b[2J\x1b[Hrm -rf\x07\nok"); got != "[2J[Hrm -rf\nok" {
		t.Fatalf("sanitizeTerminal = %q", got)
	}

	// tar entry warnings carry pod-controlled names
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "d/\x1b[31mred", Linkname: "\x1b]8;;http://evil\x07", Mode: 0777, Typeflag: tar.TypeSymlink}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var errOut bytes.Buffer
	o := &CopyOptions{IOStreams: genericiooptions.IOStreams{ErrOut: &errOut}}
	if err := o.extractTar(&buf, t.TempDir(), "d"); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(errOut.String(), "\x1b\x07") {
		t.Fatalf("warning contains control characters: %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "skipping symlink") {
		t.Fatalf("expected symlink warning, got %q", errOut.String())
	}

	// stderr embedded in errors is sanitized
	o = &CopyOptions{}
	err := o.handleExecError(errors.New("stream failed"), "boom\x1b[2J\n", &fileSpec{PodName: "p", PodNamespace: "ns", File: "/f"})
	if err == nil || strings.ContainsAny(err.Error(), "\x1b") {
		t.Fatalf("error must not contain escape characters, got %v", err)
	}
}
