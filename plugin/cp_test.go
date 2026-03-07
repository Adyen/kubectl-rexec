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

// Test constants to avoid duplicate literals
const (
	testTmpFoo        = "/tmp/foo"
	testTmpFile       = "/tmp/file"
	testTmpDest       = "/tmp/dest"
	testTmpSrc        = "/tmp/src"
	testLocalPath     = "/local/path"
	testDefaultNS     = "default"
	testContent1      = "content1\n"
	testContent2      = "content2\n"
	testTargetTxt     = "target.txt"
	testLinkTxt       = "link.txt"
	testMyFileTxt     = "myfile.txt"
	testFileDoubleDot = "file..txt"
	extractTarErrMsg  = "extractTar() error = %v"
)

// checkTestError is a helper to verify error conditions in tests
func checkTestError(t *testing.T, err error, wantErr, funcName string) {
	t.Helper()
	if wantErr == "" {
		if err != nil {
			t.Errorf("%s unexpected error = %v", funcName, err)
		}
		return
	}
	if err == nil {
		t.Errorf("%s expected error containing %q, got nil", funcName, wantErr)
	} else if !strings.Contains(err.Error(), wantErr) {
		t.Errorf("%s error = %v, want containing %q", funcName, err, wantErr)
	}
}

// testHelper provides common test setup utilities
type testHelper struct {
	t      *testing.T
	tmpDir string
	opts   *CopyOptions
	stderr *bytes.Buffer
}

// newTestHelper creates a test helper with temp directory and CopyOptions
func newTestHelper(t *testing.T) *testHelper {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "extract-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	stderr := &bytes.Buffer{}
	h := &testHelper{
		t:      t,
		tmpDir: tmpDir,
		stderr: stderr,
		opts: &CopyOptions{
			IOStreams: genericiooptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: stderr},
		},
	}

	t.Cleanup(func() { os.RemoveAll(tmpDir) })
	return h
}

// createTar creates a tar archive with the given files
func createTar(t *testing.T, files map[string]string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}); err != nil {
			t.Fatalf("failed to write tar header: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write tar content: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("failed to close tar writer: %v", err)
	}
	return &buf
}

// createTarWithSymlink creates a tar with a regular file and a symlink
func createTarWithSymlink(t *testing.T, fileName, fileContent, linkName, linkTarget string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	if err := tw.WriteHeader(&tar.Header{Name: fileName, Mode: 0644, Size: int64(len(fileContent))}); err != nil {
		t.Fatalf("failed to write file header: %v", err)
	}
	if _, err := tw.Write([]byte(fileContent)); err != nil {
		t.Fatalf("failed to write file content: %v", err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: linkName, Mode: 0777, Typeflag: tar.TypeSymlink, Linkname: linkTarget}); err != nil {
		t.Fatalf("failed to write symlink header: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("failed to close tar writer: %v", err)
	}
	return &buf
}

// assertFileContent checks that a file exists with expected content
func (h *testHelper) assertFileContent(relPath, expected string) {
	h.t.Helper()
	content, err := os.ReadFile(filepath.Join(h.tmpDir, relPath))
	if err != nil {
		h.t.Fatalf("failed to read %s: %v", relPath, err)
	}
	if string(content) != expected {
		h.t.Errorf("%s content = %q, want %q", relPath, string(content), expected)
	}
}

// assertFileExists checks that a file exists
func (h *testHelper) assertFileExists(relPath string) {
	h.t.Helper()
	if _, err := os.Stat(filepath.Join(h.tmpDir, relPath)); err != nil {
		h.t.Errorf("%s should exist: %v", relPath, err)
	}
}

// assertFileNotExists checks that a file does not exist
func (h *testHelper) assertFileNotExists(relPath string) {
	h.t.Helper()
	if _, err := os.Lstat(filepath.Join(h.tmpDir, relPath)); err == nil {
		h.t.Errorf("%s should NOT exist", relPath)
	}
}

// TestParseFileSpec tests parsing of file specifications
func TestParseFileSpec(t *testing.T) {
	tests := []struct {
		name      string
		spec      string
		namespace string
		want      *fileSpec
	}{
		{"local file", testTmpFoo, testDefaultNS, &fileSpec{File: testTmpFoo}},
		{"pod file", "my-pod:" + testTmpFoo, testDefaultNS, &fileSpec{PodName: "my-pod", PodNamespace: testDefaultNS, File: testTmpFoo}},
		{"pod file with namespace", "kube-system/my-pod:" + testTmpFoo, testDefaultNS, &fileSpec{PodName: "my-pod", PodNamespace: "kube-system", File: testTmpFoo}},
		{"file path with colon", "pod:path:extra", testDefaultNS, &fileSpec{PodName: "pod", PodNamespace: testDefaultNS, File: "path:extra"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFileSpec(tt.spec, tt.namespace)
			if err != nil {
				t.Fatalf("parseFileSpec() error = %v", err)
			}
			if got.File != tt.want.File || got.PodName != tt.want.PodName || got.PodNamespace != tt.want.PodNamespace {
				t.Errorf("parseFileSpec() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestValidateLocalDestination tests local destination validation
func TestValidateLocalDestination(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "validate-dest-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "existing-file.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	tests := []struct {
		name    string
		dest    string
		wantErr string
	}{
		{"existing directory", tmpDir, ""},
		{"existing file", testFile, ""},
		{"new file in existing dir", filepath.Join(tmpDir, "newfile.txt"), ""},
		{"parent does not exist", "/nonexistent-dir-12345/file.txt", "local directory does not exist"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLocalDestination(tt.dest)
			checkTestError(t, err, tt.wantErr, "validateLocalDestination()")
		})
	}
}

// TestExtractTarSingleFile tests extracting a single file from tar archive
func TestExtractTarSingleFile(t *testing.T) {
	h := newTestHelper(t)
	tarBuf := createTar(t, map[string]string{testMyFileTxt: "test content\n"})

	if err := h.opts.extractTar(tarBuf, h.tmpDir, testMyFileTxt); err != nil {
		t.Fatalf(extractTarErrMsg, err)
	}

	h.assertFileContent(testMyFileTxt, "test content\n")
}

// TestExtractTarDirectory tests extracting a directory structure from tar archive
func TestExtractTarDirectory(t *testing.T) {
	h := newTestHelper(t)
	tarBuf := createTar(t, map[string]string{
		"mydir/file1.txt":        testContent1,
		"mydir/subdir/file2.txt": testContent2,
	})

	if err := h.opts.extractTar(tarBuf, h.tmpDir, "mydir"); err != nil {
		t.Fatalf(extractTarErrMsg, err)
	}

	h.assertFileContent("mydir/file1.txt", testContent1)
	h.assertFileContent("mydir/subdir/file2.txt", testContent2)
}

// TestExtractTarPathTraversal tests security against path traversal attacks
func TestExtractTarPathTraversal(t *testing.T) {
	h := newTestHelper(t)
	tarBuf := createTar(t, map[string]string{"../../../etc/malicious.txt": "bad\n"})

	err := h.opts.extractTar(tarBuf, h.tmpDir, "malicious.txt")
	if err == nil {
		t.Fatal("extractTar() should have failed with path traversal attempt")
	}
	if !strings.Contains(err.Error(), "illegal file path") {
		t.Errorf("error = %v, want 'illegal file path'", err)
	}

	h.assertFileNotExists("../../../etc/malicious.txt")
}

// TestExtractTarSymlinkSkipped tests that symlinks are skipped for security
func TestExtractTarSymlinkSkipped(t *testing.T) {
	h := newTestHelper(t)
	tarBuf := createTarWithSymlink(t, testTargetTxt, "target content\n", testLinkTxt, testTargetTxt)

	if err := h.opts.extractTar(tarBuf, h.tmpDir, testTargetTxt); err != nil {
		t.Fatalf(extractTarErrMsg, err)
	}

	h.assertFileExists(testTargetTxt)
	h.assertFileNotExists(testLinkTxt)

	if !strings.Contains(h.stderr.String(), "skipping symlink") {
		t.Errorf("expected warning about skipping symlink, got: %s", h.stderr.String())
	}
}

// TestExtractTarValidDoubleDotFilename tests that valid filenames with '..' are allowed
func TestExtractTarValidDoubleDotFilename(t *testing.T) {
	h := newTestHelper(t)
	tarBuf := createTar(t, map[string]string{
		testFileDoubleDot:   testContent1,
		"dir/..hidden/file": testContent2,
	})

	if err := h.opts.extractTar(tarBuf, h.tmpDir, testFileDoubleDot); err != nil {
		t.Fatalf("extractTar() should allow valid filenames with '..': %v", err)
	}

	h.assertFileExists(testFileDoubleDot)
	h.assertFileExists("dir/..hidden/file")
}

// TestRunWithArgsValidation tests argument validation
func TestRunWithArgsValidation(t *testing.T) {
	tests := []struct {
		name, src, dest, errMsg string
	}{
		{"local to pod - not supported", testTmpFile, "pod:" + testTmpFile, "copying to pods is not supported"},
		{"pod to pod - not supported", "pod1:" + testTmpFile, "pod2:" + testTmpFile, "destination must be a local path"},
		{"local to local - source must be pod", testTmpSrc, testTmpDest, "source must be a pod file spec"},
		{"empty pod path", "pod:", testTmpDest, "remote path cannot be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &CopyOptions{
				IOStreams: genericiooptions.IOStreams{In: os.Stdin, Out: io.Discard, ErrOut: io.Discard},
				Namespace: testDefaultNS,
			}

			err := o.RunWithArgs(context.Background(), tt.src, tt.dest)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("error = %v, want containing %q", err, tt.errMsg)
			}
		})
	}
}

// TestExtractRemotePath tests extraction of path from tar stderr
func TestExtractRemotePath(t *testing.T) {
	tests := []struct {
		name   string
		stderr string
		want   string
	}{
		{"standard tar error", "tar: testfile: No such file or directory", "testfile"},
		{"with prefix", "tar: /tmp/foo: No such file or directory", "/tmp/foo"},
		{"no match", "some other error", "unknown"},
		{"empty", "", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRemotePath(tt.stderr)
			if got != tt.want {
				t.Errorf("extractRemotePath() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestValidateCopySpecs tests copy spec validation
func TestValidateCopySpecs(t *testing.T) {
	tests := []struct {
		name    string
		src     *fileSpec
		dest    *fileSpec
		wantErr string
	}{
		{
			name:    "valid pod to local",
			src:     &fileSpec{PodName: "pod", PodNamespace: "ns", File: testTmpFile},
			dest:    &fileSpec{File: testLocalPath},
			wantErr: "",
		},
		{
			name:    "local to pod blocked",
			src:     &fileSpec{File: testLocalPath},
			dest:    &fileSpec{PodName: "pod", PodNamespace: "ns", File: testTmpFile},
			wantErr: "copying to pods is not supported",
		},
		{
			name:    "pod to pod blocked",
			src:     &fileSpec{PodName: "pod1", PodNamespace: "ns", File: testTmpFile},
			dest:    &fileSpec{PodName: "pod2", PodNamespace: "ns", File: testTmpFile},
			wantErr: "destination must be a local path",
		},
		{
			name:    "empty remote path",
			src:     &fileSpec{PodName: "pod", PodNamespace: "ns", File: ""},
			dest:    &fileSpec{File: testLocalPath},
			wantErr: "remote path cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCopySpecs(tt.src, tt.dest)
			checkTestError(t, err, tt.wantErr, "validateCopySpecs()")
		})
	}
}