package plugin

// Regression tests for rexec cp extraction hardening: a malicious workload
// controls the tar stream and its own stderr, so names, links, sizes, and
// terminal output must all be treated as hostile.

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
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
