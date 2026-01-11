package plugin

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/cli-runtime/pkg/genericiooptions"
)

// TestParseFileSpec tests parsing of file specifications
func TestParseFileSpec(t *testing.T) {
	tests := []struct {
		name      string
		spec      string
		namespace string
		want      *fileSpec
		wantErr   bool
	}{
		{
			name:      "local file",
			spec:      "/tmp/foo",
			namespace: "default",
			want: &fileSpec{
				File: "/tmp/foo",
			},
			wantErr: false,
		},
		{
			name:      "pod file",
			spec:      "my-pod:/tmp/foo",
			namespace: "default",
			want: &fileSpec{
				PodName:      "my-pod",
				PodNamespace: "default",
				File:         "/tmp/foo",
			},
			wantErr: false,
		},
		{
			name:      "pod file with namespace",
			spec:      "kube-system/my-pod:/tmp/foo",
			namespace: "default",
			want: &fileSpec{
				PodName:      "my-pod",
				PodNamespace: "kube-system",
				File:         "/tmp/foo",
			},
			wantErr: false,
		},
		{
			name:      "invalid spec - multiple colons",
			spec:      "pod:path:extra",
			namespace: "default",
			want:      nil,
			wantErr:   false, // Will parse as pod:path:extra
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFileSpec(tt.spec, tt.namespace)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseFileSpec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if tt.want == nil {
				return // Skip validation for invalid cases
			}
			if got.File != tt.want.File {
				t.Errorf("parseFileSpec() File = %v, want %v", got.File, tt.want.File)
			}
			if got.PodName != tt.want.PodName {
				t.Errorf("parseFileSpec() PodName = %v, want %v", got.PodName, tt.want.PodName)
			}
			if got.PodNamespace != tt.want.PodNamespace {
				t.Errorf("parseFileSpec() PodNamespace = %v, want %v", got.PodNamespace, tt.want.PodNamespace)
			}
		})
	}
}

// TestIsDestDir tests directory detection
func TestIsDestDir(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "cp-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "path with trailing slash",
			path: "/tmp/foo/",
			want: true,
		},
		{
			name: "existing directory",
			path: tmpDir,
			want: true,
		},
		{
			name: "non-existing path",
			path: "/tmp/does-not-exist-12345",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDestDir(tt.path)
			if got != tt.want {
				t.Errorf("isDestDir() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCreateTarSingleFile tests creating tar archive from a single file
func TestCreateTarSingleFile(t *testing.T) {
	// Create temporary test file
	tmpFile, err := os.CreateTemp("", "test-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	testContent := "test content\n"
	if _, err := tmpFile.WriteString(testContent); err != nil {
		t.Fatalf("failed to write test content: %v", err)
	}
	tmpFile.Close()

	// Create CopyOptions
	o := &CopyOptions{
		NoPreserve: false,
		IOStreams:  genericiooptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr},
	}

	// Create tar archive
	var buf bytes.Buffer
	destPath := "/remote/test.txt"
	err = o.createTar(tmpFile.Name(), &buf, destPath)
	if err != nil {
		t.Fatalf("createTar() error = %v", err)
	}

	// Verify tar was created (basic check - just ensure non-empty)
	if buf.Len() == 0 {
		t.Error("createTar() produced empty archive")
	}
}

// TestCreateTarDirectory tests creating tar archive from a directory
func TestCreateTarDirectory(t *testing.T) {
	// Create temporary directory structure
	tmpDir, err := os.MkdirTemp("", "test-dir-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create some test files
	testFiles := map[string]string{
		"file1.txt":        "content1\n",
		"file2.txt":        "content2\n",
		"subdir/file3.txt": "content3\n",
	}

	for path, content := range testFiles {
		fullPath := filepath.Join(tmpDir, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}
	}

	// Create CopyOptions
	o := &CopyOptions{
		NoPreserve: false,
		IOStreams:  genericiooptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr},
	}

	// Create tar archive
	var buf bytes.Buffer
	destPath := "/remote/testdir"
	err = o.createTar(tmpDir, &buf, destPath)
	if err != nil {
		t.Fatalf("createTar() error = %v", err)
	}

	// Verify tar was created
	if buf.Len() == 0 {
		t.Error("createTar() produced empty archive")
	}
}

// TestExtractTar tests extracting tar archive
func TestExtractTar(t *testing.T) {
	// Create a simple tar archive in memory
	// For simplicity, we'll use createTar then extract it

	// Create temp source file
	tmpFile, err := os.CreateTemp("", "test-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	srcPath := tmpFile.Name()
	defer os.Remove(srcPath)

	testContent := "test content for extraction\n"
	if _, err := tmpFile.WriteString(testContent); err != nil {
		t.Fatalf("failed to write test content: %v", err)
	}
	tmpFile.Close()

	// Create CopyOptions
	o := &CopyOptions{
		NoPreserve: false,
		IOStreams:  genericiooptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr},
	}

	// Create tar
	var tarBuf bytes.Buffer
	destPath := "extracted.txt"
	err = o.createTar(srcPath, &tarBuf, destPath)
	if err != nil {
		t.Fatalf("createTar() error = %v", err)
	}

	// Create temp directory for extraction
	tmpDir, err := os.MkdirTemp("", "extract-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Extract tar
	err = o.extractTar(&tarBuf, tmpDir)
	if err != nil {
		t.Fatalf("extractTar() error = %v", err)
	}

	// Verify extracted file exists and has correct content
	extractedPath := filepath.Join(tmpDir, destPath)
	content, err := os.ReadFile(extractedPath)
	if err != nil {
		t.Fatalf("failed to read extracted file: %v", err)
	}

	if string(content) != testContent {
		t.Errorf("extracted content = %q, want %q", string(content), testContent)
	}
}

// TestExtractTarPathTraversal tests security against path traversal attacks
func TestExtractTarPathTraversal(t *testing.T) {
	// Create a malicious tar with ".." in the path
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Try to write a file outside the destination directory
	header := &tar.Header{
		Name: "../../../etc/malicious.txt",
		Mode: 0644,
		Size: 4,
	}
	if err := tw.WriteHeader(header); err != nil {
		t.Fatalf("failed to write tar header: %v", err)
	}
	if _, err := tw.Write([]byte("bad\n")); err != nil {
		t.Fatalf("failed to write tar content: %v", err)
	}
	tw.Close()

	// Create temp directory for extraction
	tmpDir, err := os.MkdirTemp("", "extract-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create CopyOptions
	o := &CopyOptions{
		NoPreserve: false,
		IOStreams:  genericiooptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr},
	}

	// Try to extract - should fail with path traversal error
	err = o.extractTar(&buf, tmpDir)
	if err == nil {
		t.Fatal("extractTar() should have failed with path traversal attempt")
	}

	if !strings.Contains(err.Error(), "illegal file path") {
		t.Errorf("extractTar() error = %v, want error containing 'illegal file path'", err)
	}

	// Verify malicious file was NOT created outside tmpDir
	maliciousPath := filepath.Join(tmpDir, "../../../etc/malicious.txt")
	if _, err := os.Stat(maliciousPath); err == nil {
		t.Error("Path traversal attack succeeded - malicious file was created outside destination")
	}
}

// TestRunWithArgsValidation tests argument validation
func TestRunWithArgsValidation(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		dest    string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "pod to pod - not supported",
			src:     "pod1:/tmp/file",
			dest:    "pod2:/tmp/file",
			wantErr: true,
			errMsg:  "not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &CopyOptions{
				IOStreams: genericiooptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr},
				Namespace: "default",
			}

			err := o.RunWithArgs(tt.src, tt.dest)
			if (err != nil) != tt.wantErr {
				t.Errorf("RunWithArgs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("RunWithArgs() error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}
