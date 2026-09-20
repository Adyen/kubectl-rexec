package plugin

// Regression tests for rexec cp extraction hardening: a malicious workload
// controls the tar stream and its own stderr, so names, links, sizes, and
// terminal output must all be treated as hostile.

import (
	"path/filepath"
	"testing"
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
