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

const (
	testTempPattern = "test-*"
	targetTxtFile   = "target.txt"
	tmpFooPath      = "/tmp/foo"
	errExtractTar   = "extractTar error: %v"
	myFileTxt       = "myfile.txt"
	content1Str     = "content1\n"
	content2Str     = "content2\n"
	contentStr      = "content\n"
	localPath       = "/local"
	fileDotTxt      = "file..txt"
	testDirName     = "testdir"
	maliciousPath1  = "../etc/passwd"
	maliciousPath2  = "/etc/passwd"
	maliciousPath3  = ".."
	traversalErrorMsg = "illegal file path"
	errWriteTarHeaderFmt     = "failed to write tar header: %v"
	errWriteTarContentFmt    = "failed to write tar content: %v"
	errCloseTarWriterFmt     = "failed to close tar writer: %v"
	errWriteTarHeaderForFmt  = "failed to write tar header for %q: %v"
	errWriteTarContentForFmt = "failed to write tar content for %q: %v"
)

type computeSafeTargetCase struct {
	name        string
	nameInTar   string
	destPath    string
	srcBase     string
	destIsDir   bool
	wantErr     bool
	errContains string
}

type linkTestCase struct {
	name       string
	linkName   string
	typeflag   byte
	warnSubstr string
}

func mustTempDir(t *testing.T) string {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", testTempPattern)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	return tmpDir
}

func newCopyOptions(errOut io.Writer) *CopyOptions {
	return &CopyOptions{
		IOStreams: genericiooptions.IOStreams{
			Out:    io.Discard,
			ErrOut: errOut,
		},
	}
}

func newDefaultCopyOptions() *CopyOptions {
	return newCopyOptions(io.Discard)
}

func newRunOptions() *CopyOptions {
	return &CopyOptions{
		IOStreams: genericiooptions.IOStreams{Out: io.Discard, ErrOut: io.Discard},
		Namespace: "default",
	}
}

func TestParseFileSpec(t *testing.T) {
	tests := []struct {
		name      string
		spec      string
		namespace string
		want      *fileSpec
	}{
		{"local file", tmpFooPath, "default", &fileSpec{File: tmpFooPath}},
		{"pod file", "my-pod:" + tmpFooPath, "default", &fileSpec{PodName: "my-pod", PodNamespace: "default", File: tmpFooPath}},
		{"pod with namespace", "kube-system/my-pod:" + tmpFooPath, "default", &fileSpec{PodName: "my-pod", PodNamespace: "kube-system", File: tmpFooPath}},
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
	tmpDir := mustTempDir(t)

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
		{"parent missing", filepath.Join(tmpDir, "missing-parent", "file.txt"), true},
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

type extractTarScenario struct {
	name       string
	files      map[string]string
	srcBase    string
	renameDest string
	assertions func(t *testing.T, tmpDir string, destPath string)
}

func runExtractTarScenarioCase(t *testing.T, tt extractTarScenario) {
	t.Helper()

	tmpDir := mustTempDir(t)
	opts := newDefaultCopyOptions()
	tarBuf := createTestTar(t, tt.files)

	destPath := tmpDir
	if tt.renameDest != "" {
		destPath = filepath.Join(tmpDir, tt.renameDest)
	}

	if err := opts.extractTar(tarBuf, destPath, tt.srcBase); err != nil {
		t.Fatalf(errExtractTar, err)
	}

	tt.assertions(t, tmpDir, destPath)
}

func TestExtractTarSingleFile(t *testing.T) {
	runExtractTarScenarioCase(t, extractTarScenario{
		name:    "single file",
		files:   map[string]string{myFileTxt: contentStr},
		srcBase: myFileTxt,
		assertions: func(t *testing.T, tmpDir string, destPath string) {
			content, err := os.ReadFile(filepath.Join(destPath, myFileTxt))
			if err != nil {
				t.Fatalf("failed to read extracted file: %v", err)
			}
			if string(content) != contentStr {
				t.Errorf("content = %q, want %q", content, contentStr)
			}
		},
	})
}

func TestExtractTarDirectory(t *testing.T) {
	runExtractTarScenarioCase(t, extractTarScenario{
		name:    "directory",
		files:   map[string]string{"mydir/file1.txt": content1Str, "mydir/subdir/file2.txt": content2Str},
		srcBase: "mydir",
		assertions: func(t *testing.T, tmpDir string, destPath string) {
			content1, err := os.ReadFile(filepath.Join(destPath, "mydir/file1.txt"))
			if err != nil {
				t.Fatalf("failed to read extracted file1: %v", err)
			}
			content2, err := os.ReadFile(filepath.Join(destPath, "mydir/subdir/file2.txt"))
			if err != nil {
				t.Fatalf("failed to read extracted file2: %v", err)
			}
			if string(content1) != content1Str || string(content2) != content2Str {
				t.Errorf("unexpected content")
			}
		},
	})
}

func TestExtractTarRenameDirectory(t *testing.T) {
	runExtractTarScenarioCase(t, extractTarScenario{
		name:       "rename directory",
		files:      map[string]string{"testdir/file1.txt": content1Str},
		srcBase:    "testdir",
		renameDest: "downloaded",
		assertions: func(t *testing.T, tmpDir string, destPath string) {
			content, err := os.ReadFile(filepath.Join(destPath, "file1.txt"))
			if err != nil {
				t.Fatalf("failed to read extracted file: %v", err)
			}
			if string(content) != content1Str {
				t.Errorf("unexpected content")
			}
		},
	})
}

func createLinkTar(t *testing.T, linkName string, typeflag byte, target string) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	if err := tw.WriteHeader(&tar.Header{Name: targetTxtFile, Mode: 0644, Size: 7}); err != nil {
		t.Fatalf(errWriteTarHeaderFmt, err)
	}
	if _, err := tw.Write([]byte("content")); err != nil {
		t.Fatalf(errWriteTarContentFmt, err)
	}
	if err := tw.WriteHeader(&tar.Header{
		Name:     linkName,
		Typeflag: typeflag,
		Linkname: target,
	}); err != nil {
		t.Fatalf("failed to write link header: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf(errCloseTarWriterFmt, err)
	}

	return &buf
}

func assertFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("%s should exist", path)
	}
}

func assertFileDoesNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err == nil {
		t.Errorf("%s should NOT exist", path)
	}
}

func assertContains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Errorf("expected warning containing %q, got: %s", want, got)
	}
}

func runExtractTarLinkTypesSkippedCase(t *testing.T, tt linkTestCase) {
	t.Helper()

	tmpDir := mustTempDir(t)
	var stderr bytes.Buffer
	opts := newCopyOptions(&stderr)
	tarBuf := createLinkTar(t, tt.linkName, tt.typeflag, targetTxtFile)

	if err := opts.extractTar(tarBuf, tmpDir, targetTxtFile); err != nil {
		t.Fatalf(errExtractTar, err)
	}

	assertFileExists(t, filepath.Join(tmpDir, targetTxtFile))
	assertFileDoesNotExist(t, filepath.Join(tmpDir, tt.linkName))
	assertContains(t, stderr.String(), tt.warnSubstr)
}

func TestExtractTarLinkTypesSkipped(t *testing.T) {
	tests := []linkTestCase{
		{"symlink", "link.txt", tar.TypeSymlink, "skipping symlink"},
		{"hardlink", "hardlink.txt", tar.TypeLink, "skipping hard link"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runExtractTarLinkTypesSkippedCase(t, tt)
		})
	}
}

func TestExtractTarPathTraversal(t *testing.T) {
	tmpDir := mustTempDir(t)
	opts := newDefaultCopyOptions()
	tarBuf := createTestTar(t, map[string]string{"../../../etc/malicious.txt": "bad\n"})

	err := opts.extractTar(tarBuf, tmpDir, "malicious.txt")
	if err == nil {
		t.Fatal("extractTar() should have failed with path traversal attempt")
	}
	if !strings.Contains(err.Error(), "illegal file path") {
		t.Errorf("error = %v, want containing 'illegal file path'", err)
	}

	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("failed to read destination dir: %v", err)
	}
	if len(files) > 0 {
		t.Errorf("Expected no files in destination, got: %v", files)
	}
}

func TestExtractTarValidDoubleDotFileName(t *testing.T) {
	tmpDir := mustTempDir(t)
	opts := newDefaultCopyOptions()

	tarBuf := createTestTar(t, map[string]string{
		fileDotTxt: content1Str,
	})
	if err := opts.extractTar(tarBuf, tmpDir, fileDotTxt); err != nil {
		t.Fatalf("extractTar() should allow valid filenames with '..': %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, fileDotTxt)); err != nil {
		t.Error("file..txt should exist (valid filename with double dots)")
	}
}

func TestExtractTarValidDoubleDotDirectoryName(t *testing.T) {
	tmpDir := mustTempDir(t)
	opts := newDefaultCopyOptions()

	tarBuf := createTestTar(t, map[string]string{
		"dir/..hidden/file": content2Str,
	})
	if err := opts.extractTar(tarBuf, tmpDir, ""); err != nil {
		t.Fatalf("extractTar() should allow valid directory names with '..': %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "dir/..hidden/file")); err != nil {
		t.Error("dir/..hidden/file should exist (valid directory with double dots)")
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
			o := newRunOptions()
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
		{"valid", &fileSpec{PodName: "pod", PodNamespace: "ns", File: "/tmp/f"}, &fileSpec{File: localPath}, false},
		{"upload", &fileSpec{File: localPath}, &fileSpec{PodName: "pod", PodNamespace: "ns", File: "/tmp/f"}, true},
		{"pod to pod", &fileSpec{PodName: "p1", PodNamespace: "ns", File: "/f"}, &fileSpec{PodName: "p2", PodNamespace: "ns", File: "/f"}, true},
		{"empty path", &fileSpec{PodName: "pod", PodNamespace: "ns", File: ""}, &fileSpec{File: localPath}, true},
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
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(content))}); err != nil {
			t.Fatalf(errWriteTarHeaderForFmt, name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf(errWriteTarContentForFmt, name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf(errCloseTarWriterFmt, err)
	}
	return &buf
}

func TestComputeSafeTarget(t *testing.T) {
	tmpDir := mustTempDir(t)

	tests := []computeSafeTargetCase{
		{"normal file", myFileTxt, tmpDir, "", true, false, ""},
		{"bad path", maliciousPath1, tmpDir, "", true, true, traversalErrorMsg},
		{"absolute path", maliciousPath2, tmpDir, "", true, true, traversalErrorMsg},
		{"double dot", maliciousPath3, tmpDir, "", true, true, traversalErrorMsg},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testComputeSafeTargetCase(t, tt)
		})
	}
}

func testComputeSafeTargetCase(t *testing.T, tt computeSafeTargetCase) {
	t.Helper()
	baseAbs, err := filepath.Abs(tt.destPath)
	if err != nil {
		t.Fatal(err)
	}

	result, err := computeSafeTarget(tt.nameInTar, tt.destPath, baseAbs, tt.srcBase, tt.destIsDir)

	if (err != nil) != tt.wantErr {
		t.Errorf("computeSafeTarget() error = %v, wantErr %v", err, tt.wantErr)
	}

	if err != nil && tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
		t.Errorf("error = %v, want containing %q", err, tt.errContains)
	}

	if err == nil && result == "" {
		t.Error("expected non-empty result on success")
	}
}

func TestProcessTarEntry(t *testing.T) {
	tmpDir := mustTempDir(t)

	tests := []struct {
		name    string
		header  *tar.Header
		content []byte
		wantErr bool
	}{
		{"regular file", &tar.Header{Name: myFileTxt, Typeflag: tar.TypeReg, Mode: 0644, Size: 5}, []byte("hello"), false},
		{"directory", &tar.Header{Name: testDirName, Typeflag: tar.TypeDir, Mode: 0755}, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tarReader := createTarReader(t, tt.header, tt.content)
			o := newDefaultCopyOptions()
			targetPath := filepath.Join(tmpDir, tt.header.Name)
			testProcessTarEntryScenario(t, o, tt.header, tarReader, targetPath, tt.content, tt.wantErr)
		})
	}
}

func testProcessTarEntryScenario(t *testing.T, o *CopyOptions, header *tar.Header, tarReader *tar.Reader, targetPath string, content []byte, wantErr bool) {
	t.Helper()
	err := o.processTarEntry(header, tarReader, targetPath)
	if (err != nil) != wantErr {
		t.Errorf("processTarEntry() error = %v, wantErr %v", err, wantErr)
	}

	if err == nil {
		validateTarResult(t, header, targetPath, string(content))
	}
}

func createTarReader(t *testing.T, header *tar.Header, content []byte) *tar.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(header); err != nil {
		t.Fatalf(errWriteTarHeaderFmt, err)
	}
	if content != nil {
		if _, err := tw.Write(content); err != nil {
			t.Fatalf(errWriteTarContentFmt, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf(errCloseTarWriterFmt, err)
	}

	tarReader := tar.NewReader(&buf)
	if _, err := tarReader.Next(); err != nil {
		t.Fatalf("failed to advance tar reader: %v", err)
	}
	return tarReader
}

func TestProcessTarEntryUnsupportedTypes(t *testing.T) {
	tmpDir := mustTempDir(t)

	tests := []struct {
		name   string
		header *tar.Header
	}{
		{"block device", &tar.Header{Name: "device", Typeflag: tar.TypeBlock, Mode: 0644}},
		{"char device", &tar.Header{Name: "chardev", Typeflag: tar.TypeChar, Mode: 0644}},
		{"fifo", &tar.Header{Name: "fifo", Typeflag: tar.TypeFifo, Mode: 0644}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			o := newCopyOptions(&stderr)

			tarReader := createTarReader(t, tt.header, nil)
			targetPath := filepath.Join(tmpDir, tt.header.Name)

			err := o.processTarEntry(tt.header, tarReader, targetPath)
			if err != nil {
				t.Errorf("processTarEntry() should not error for unsupported type, got: %v", err)
			}

			if !strings.Contains(stderr.String(), "skipping unsupported tar entry") {
				t.Errorf("Expected warning for unsupported tar entry, got: %s", stderr.String())
			}

			if _, err := os.Stat(targetPath); err == nil {
				t.Errorf("Unsupported tar entry should not create file: %s", tt.header.Name)
			}
		})
	}
}

func validateTarResult(t *testing.T, header *tar.Header, targetPath string, wantContent string) {
	t.Helper()
	if header.Typeflag == tar.TypeReg {
		content, err := os.ReadFile(targetPath)
		if err != nil {
			t.Errorf("file should exist, got error: %v", err)
		}
		if string(content) != wantContent {
			t.Errorf("wrong content, expected '%s', got: %s", wantContent, string(content))
		}
	}

	if header.Typeflag == tar.TypeDir {
		info, err := os.Stat(targetPath)
		if err != nil {
			t.Errorf("directory should exist, got error: %v", err)
		}
		if !info.IsDir() {
			t.Error("target should be a directory")
		}
	}
}
