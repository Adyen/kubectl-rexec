package plugin

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/cli-runtime/pkg/genericiooptions"
)

func TestParseFileSpec(t *testing.T) {
	tests := []struct {
		name      string
		spec      string
		namespace string
		want      *fileSpec
	}{
		{"local file", "/tmp/foo", "default", &fileSpec{File: "/tmp/foo"}},
		{"pod file", "my-pod:/tmp/foo", "default", &fileSpec{PodName: "my-pod", PodNamespace: "default", File: "/tmp/foo"}},
		{"pod with namespace", "kube-system/my-pod:/tmp/foo", "default", &fileSpec{PodName: "my-pod", PodNamespace: "kube-system", File: "/tmp/foo"}},
		{"path with colon", "pod:path:extra", "default", &fileSpec{PodName: "pod", PodNamespace: "default", File: "path:extra"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFileSpec(tt.spec, tt.namespace)
			if err != nil {
				t.Fatalf("parseFileSpec() error = %v", err)
			}
			if got.File != tt.want.File || got.PodName != tt.want.PodName || got.PodNamespace != tt.want.PodNamespace {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestValidateLocalDestination(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	testFile := filepath.Join(tmpDir, "file.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		dest    string
		wantErr bool
	}{
		{"existing dir", tmpDir, false},
		{"existing file", testFile, false},
		{"new file in dir", filepath.Join(tmpDir, "new.txt"), false},
		{"parent missing", "/nonexistent/file.txt", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLocalDestination(tt.dest)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestExtractTarSingleFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	opts := &CopyOptions{IOStreams: genericiooptions.IOStreams{ErrOut: io.Discard}}
	tarBuf := createTestTar(t, map[string]string{"myfile.txt": "content\n"})

	if err := opts.extractTar(tarBuf, tmpDir, "myfile.txt"); err != nil {
		t.Fatalf("extractTar error: %v", err)
	}

	content, _ := os.ReadFile(filepath.Join(tmpDir, "myfile.txt"))
	if string(content) != "content\n" {
		t.Errorf("content = %q, want %q", content, "content\n")
	}
}

func TestExtractTarDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	opts := &CopyOptions{IOStreams: genericiooptions.IOStreams{ErrOut: io.Discard}}
	tarBuf := createTestTar(t, map[string]string{
		"mydir/file1.txt":        "content1\n",
		"mydir/subdir/file2.txt": "content2\n",
	})

	if err := opts.extractTar(tarBuf, tmpDir, "mydir"); err != nil {
		t.Fatalf("extractTar error: %v", err)
	}

	content1, _ := os.ReadFile(filepath.Join(tmpDir, "mydir/file1.txt"))
	content2, _ := os.ReadFile(filepath.Join(tmpDir, "mydir/subdir/file2.txt"))
	if string(content1) != "content1\n" || string(content2) != "content2\n" {
		t.Errorf("unexpected content")
	}
}

func TestExtractTarSymlinkSkipped(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	var stderr bytes.Buffer
	opts := &CopyOptions{IOStreams: genericiooptions.IOStreams{ErrOut: &stderr}}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "target.txt", Mode: 0644, Size: 7})
	_, _ = tw.Write([]byte("content"))
	_ = tw.WriteHeader(&tar.Header{Name: "link.txt", Typeflag: tar.TypeSymlink, Linkname: "target.txt"})
	_ = tw.Close()

	if err := opts.extractTar(&buf, tmpDir, "target.txt"); err != nil {
		t.Fatalf("extractTar error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(tmpDir, "target.txt")); err != nil {
		t.Error("target.txt should exist")
	}

	if _, err := os.Lstat(filepath.Join(tmpDir, "link.txt")); err == nil {
		t.Error("link.txt should NOT exist (symlinks should be skipped for security)")
	}

	if !strings.Contains(stderr.String(), "skipping symlink") {
		t.Errorf("expected warning about skipping symlink, got: %s", stderr.String())
	}
}

func TestExtractTarPathTraversal(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	opts := &CopyOptions{IOStreams: genericiooptions.IOStreams{ErrOut: io.Discard}}
	tarBuf := createTestTar(t, map[string]string{"../../../etc/malicious.txt": "bad\n"})

	err = opts.extractTar(tarBuf, tmpDir, "malicious.txt")
	if err == nil {
		t.Fatal("extractTar() should have failed with path traversal attempt")
	}
	if !strings.Contains(err.Error(), "illegal file path") {
		t.Errorf("error = %v, want containing 'illegal file path'", err)
	}

	if _, err := os.Stat(filepath.Join(tmpDir, "../../../etc/malicious.txt")); err == nil {
		t.Error("malicious file should NOT have been created")
	}
}

func TestExtractTarValidDoubleDotFilename(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	opts := &CopyOptions{IOStreams: genericiooptions.IOStreams{ErrOut: io.Discard}}
	tarBuf := createTestTar(t, map[string]string{
		"file..txt":        "content1\n",
		"dir/..hidden/file": "content2\n",
	})

	if err := opts.extractTar(tarBuf, tmpDir, "file..txt"); err != nil {
		t.Fatalf("extractTar() should allow valid filenames with '..': %v", err)
	}

	if _, err := os.Stat(filepath.Join(tmpDir, "file..txt")); err != nil {
		t.Error("file..txt should exist (valid filename with double dots)")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "dir/..hidden/file")); err != nil {
		t.Error("dir/..hidden/file should exist (valid directory with double dots)")
	}
}

func TestExtractTarRenameDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	opts := &CopyOptions{IOStreams: genericiooptions.IOStreams{ErrOut: io.Discard}}

	tarBuf := createTestTar(t, map[string]string{
		"testdir/file1.txt": "content1\n",
	})

	newDestPath := filepath.Join(tmpDir, "downloaded")

	if err := opts.extractTar(tarBuf, newDestPath, "testdir"); err != nil {
		t.Fatalf("extractTar error: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(newDestPath, "file1.txt"))
	if err != nil {
		t.Fatalf("Failed to read extracted file, it was put in the wrong place: %v", err)
	}
	if string(content) != "content1\n" {
		t.Errorf("unexpected content")
	}
}

func TestRunWithArgsValidation(t *testing.T) {
	tests := []struct {
		name, src, dest, errContains string
	}{
		{"upload blocked", "/tmp/file", "pod:/tmp/file", "copying to pods is not supported"},
		{"pod to pod blocked", "pod1:/tmp/file", "pod2:/tmp/file", "destination must be a local path"},
		{"local to local", "/tmp/src", "/tmp/dest", "source must be a pod file spec"},
		{"empty path", "pod:", "/tmp/dest", "remote path cannot be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &CopyOptions{
				IOStreams: genericiooptions.IOStreams{Out: io.Discard, ErrOut: io.Discard},
				Namespace: "default",
			}
			err := o.RunWithArgs(context.Background(), tt.src, tt.dest)
			if err == nil || !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("err = %v, want containing %q", err, tt.errContains)
			}
		})
	}
}

func TestValidateCopySpecs(t *testing.T) {
	tests := []struct {
		name    string
		src     *fileSpec
		dest    *fileSpec
		wantErr bool
	}{
		{"valid", &fileSpec{PodName: "pod", PodNamespace: "ns", File: "/tmp/f"}, &fileSpec{File: "/local"}, false},
		{"upload", &fileSpec{File: "/local"}, &fileSpec{PodName: "pod", PodNamespace: "ns", File: "/tmp/f"}, true},
		{"pod to pod", &fileSpec{PodName: "p1", PodNamespace: "ns", File: "/f"}, &fileSpec{PodName: "p2", PodNamespace: "ns", File: "/f"}, true},
		{"empty path", &fileSpec{PodName: "pod", PodNamespace: "ns", File: ""}, &fileSpec{File: "/local"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCopySpecs(tt.src, tt.dest)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// createTestTar creates a tar archive for testing
func createTestTar(t *testing.T, files map[string]string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(content))})
		_, _ = tw.Write([]byte(content))
	}
	_ = tw.Close()
	return &buf
}
