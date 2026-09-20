package plugin

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/cmd/util/podcmd"
	"k8s.io/kubectl/pkg/scheme"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"
)

// CopyOptions contains the options for the audited copy command.
type CopyOptions struct {
	Container    string
	Namespace    string
	ClientConfig *restclient.Config
	Clientset    kubernetes.Interface
	IOStreams    genericiooptions.IOStreams

	// MaxArchiveBytes bounds the tar stream read from the pod and the total
	// extracted content. MaxEntries bounds the number of tar entries.
	// Zero values fall back to the defaults; the flags set explicit values.
	MaxArchiveBytes int64
	MaxEntries      int64
}

type fileSpec struct {
	PodName      string
	PodNamespace string
	File         string
}

const errPathTraversal = "illegal file path in tar: %s (path traversal attempt)"

const (
	// defaultMaxArchiveBytes bounds the tar stream pulled from a pod: the pod
	// controls the stream, so without a cap a hostile workload could exhaust
	// the client's memory.
	defaultMaxArchiveBytes = 512 << 20 // 512 MiB
	// defaultMaxEntries bounds the tar entry count against metadata bombs.
	defaultMaxEntries = 100_000
	// maxStderrBytes bounds the pod's stderr; it is only used for error
	// messages, so excess is truncated with a marker instead of failing.
	maxStderrBytes = 4 << 20 // 4 MiB
)

func (o *CopyOptions) maxArchiveBytes() int64 {
	if o.MaxArchiveBytes > 0 {
		return o.MaxArchiveBytes
	}
	return defaultMaxArchiveBytes
}

func (o *CopyOptions) maxTarEntries() int64 {
	if o.MaxEntries > 0 {
		return o.MaxEntries
	}
	return defaultMaxEntries
}

// cappedWriter fails the stream once more than max bytes pass through.
type cappedWriter struct {
	w   io.Writer
	max int64
	n   int64
	err error
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if remaining := c.max - c.n; int64(len(p)) > remaining {
		if remaining > 0 {
			_, _ = c.w.Write(p[:remaining])
		}
		c.n = c.max
		c.err = fmt.Errorf("stream exceeds the %d byte limit", c.max)
		return 0, c.err
	}
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func (c *cappedWriter) exceeded() bool { return c.err != nil }

// truncatingBuffer keeps only the first max bytes; excess is discarded and
// marked, because stderr overflow must not kill the copy.
type truncatingBuffer struct {
	buf       bytes.Buffer
	max       int64
	truncated bool
}

func (t *truncatingBuffer) Write(p []byte) (int, error) {
	if remaining := t.max - int64(t.buf.Len()); remaining >= int64(len(p)) {
		t.buf.Write(p)
	} else {
		if remaining > 0 {
			t.buf.Write(p[:remaining])
		}
		t.truncated = true
	}
	return len(p), nil
}

func (t *truncatingBuffer) String() string {
	if t.truncated {
		return t.buf.String() + "\n[... stderr truncated ...]"
	}
	return t.buf.String()
}

// sanitizeTerminal strips control characters from pod-controlled strings
// before they reach the user's terminal, so a workload cannot inject escape
// sequences (cursor movement, color bombs, OSC clipboard, ...) into cp
// warnings or error messages.
func sanitizeTerminal(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// NewCmdCp creates a new 'cp' command for the rexec plugin.
// It supports copying files and directories from containers to the local filesystem with auditing.
func NewCmdCp(f cmdutil.Factory, ioStreams genericiooptions.IOStreams) *cobra.Command {
	o := &CopyOptions{IOStreams: ioStreams}

	cmd := &cobra.Command{
		Use:   "cp <pod-src> <local-dest>",
		Short: i18n.T("Copy files and directories from containers (with audit)"),
		Long: templates.LongDesc(`
			Copy files and directories from containers to local filesystem.
			This command uses rexec for audited file transfers.

			Note: Only copying FROM pods is supported (for security reasons).
			Note: Requires 'tar' to be installed in the container.`),
		Example: templates.Examples(`
			# Copy /tmp/foo from a remote pod to /tmp/bar locally
			kubectl rexec cp my-pod:/tmp/foo /tmp/bar

			# Copy from a specific container
			kubectl rexec cp my-pod:/tmp/foo /tmp/bar -c my-container

			# Copy from a pod in a specific namespace
			kubectl rexec cp my-namespace/my-pod:/var/log/app.log ./app.log

			# Copy a directory from a remote pod
			kubectl rexec cp my-pod:/var/log /tmp/logs`),
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Complete(f, cmd, args))
			cmdutil.CheckErr(o.Validate())
			if len(args) == 2 {
				cmdutil.CheckErr(o.RunWithArgs(cmd.Context(), args[0], args[1]))
			} else {
				cmdutil.CheckErr(fmt.Errorf("source and destination are required"))
			}
		},
	}

	cmd.Flags().StringVarP(&o.Container, "container", "c", "", "Container name. If omitted, use the first container")
	cmd.Flags().Int64Var(&o.MaxArchiveBytes, "cp-max-archive-size", defaultMaxArchiveBytes, "Maximum bytes read from the pod and extracted (the pod controls the stream)")
	cmd.Flags().Int64Var(&o.MaxEntries, "cp-max-files", defaultMaxEntries, "Maximum number of tar entries accepted from the pod")
	return cmd
}

// Complete sets up the options for the copy command by initializing Kubernetes clients and configuration.
func (o *CopyOptions) Complete(f cmdutil.Factory, cmd *cobra.Command, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("source and destination are required")
	}

	var err error
	o.Namespace, _, err = f.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return err
	}

	o.ClientConfig, err = f.ToRESTConfig()
	if err != nil {
		return err
	}

	o.Clientset, err = f.KubernetesClientSet()
	return err
}

// Validate ensures that the required configuration for the copy command is present.
func (o *CopyOptions) Validate() error {
	if o.ClientConfig == nil {
		return fmt.Errorf("client config is required")
	}
	return nil
}

// RunWithArgs parses the source and destination specifications and initiates the copy operation from the pod.
func (o *CopyOptions) RunWithArgs(ctx context.Context, src, dest string) error {
	srcSpec, err := parseFileSpec(src, o.Namespace)
	if err != nil {
		return err
	}

	destSpec, err := parseFileSpec(dest, o.Namespace)
	if err != nil {
		return err
	}

	if err := validateCopySpecs(srcSpec, destSpec); err != nil {
		return err
	}

	if err := validateLocalDestination(destSpec.File); err != nil {
		return err
	}

	return o.copyFromPod(ctx, srcSpec, destSpec)
}

func validateCopySpecs(src, dest *fileSpec) error {
	if src.PodName == "" && dest.PodName == "" {
		return fmt.Errorf("source must be a pod file spec (pod:path); only pod to local copy is supported")
	}
	if src.PodName == "" && dest.PodName != "" {
		return fmt.Errorf("copying to pods is not supported for security reasons; only pod to local copy is allowed")
	}
	if src.PodName != "" && dest.PodName != "" {
		return fmt.Errorf("destination must be a local path, not a pod path; only pod to local copy is supported")
	}
	if src.PodName != "" && src.File == "" {
		return fmt.Errorf("remote path cannot be empty")
	}
	return nil
}

func validateLocalDestination(destPath string) error {
	destPath = filepath.Clean(destPath)

	_, err := os.Stat(destPath)
	if err == nil {
		return nil // existing file or directory
	}

	parentDir := filepath.Dir(destPath)
	parentInfo, err := os.Stat(parentDir)
	if err != nil {
		return fmt.Errorf("local directory does not exist: %s", parentDir)
	}
	if !parentInfo.IsDir() {
		return fmt.Errorf("local path is not a directory: %s", parentDir)
	}
	return nil
}

func (o *CopyOptions) copyFromPod(ctx context.Context, src, dest *fileSpec) error {
	pod, err := o.Clientset.CoreV1().Pods(src.PodNamespace).Get(ctx, src.PodName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("pod %s/%s not found", src.PodNamespace, src.PodName)
	}

	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return fmt.Errorf("pod %s/%s is not running (phase: %s)", src.PodNamespace, src.PodName, pod.Status.Phase)
	}

	containerName, err := o.resolveContainer(pod)
	if err != nil {
		return err
	}

	srcDir := filepath.Dir(src.File)
	srcBase := filepath.Base(src.File)
	command := []string{"tar", "cf", "-", "-C", srcDir, "--", srcBase}

	// The pod controls both streams: cap stdout hard (it becomes local files
	// and memory) and truncate stderr softly (it only feeds error messages).
	var stdout bytes.Buffer
	cappedStdout := &cappedWriter{w: &stdout, max: o.maxArchiveBytes()}
	stderr := &truncatingBuffer{max: maxStderrBytes}
	execErr := o.executeRemote(ctx, pod, containerName, command, cappedStdout, stderr)

	if execErr != nil {
		if cappedStdout.exceeded() {
			return fmt.Errorf("archive from pod exceeds the %d byte limit (raise with --cp-max-archive-size)", o.maxArchiveBytes())
		}
		return o.handleExecError(execErr, stderr.String(), src)
	}

	if stdout.Len() == 0 {
		return fmt.Errorf("no data received from pod")
	}

	if err := o.extractTar(&stdout, dest.File, srcBase); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(o.IOStreams.Out, "Copied %s:%s to %s\n", src.PodName, src.File, dest.File); err != nil {
		return fmt.Errorf("failed to write output: %v", err)
	}
	return nil
}

func (o *CopyOptions) handleExecError(execErr error, stderrStr string, src *fileSpec) error {
	podRef := fmt.Sprintf("%s/%s", src.PodNamespace, src.PodName)

	if strings.Contains(stderrStr, "tar: not found") ||
		strings.Contains(stderrStr, "executable file not found") ||
		strings.Contains(stderrStr, "sh: tar") {
		return fmt.Errorf("pod %s: tar binary not found in container", podRef)
	}

	if strings.Contains(stderrStr, "No such file or directory") {
		return fmt.Errorf("pod %s: file not found: %s", podRef, src.File)
	}

	if strings.Contains(stderrStr, "Permission denied") || strings.Contains(stderrStr, "cannot open") {
		return fmt.Errorf("pod %s: permission denied: %s", podRef, src.File)
	}

	if stderrStr != "" {
		return fmt.Errorf("pod %s: %s", podRef, strings.TrimSpace(stderrStr))
	}

	return fmt.Errorf("pod %s: command failed: %v", podRef, execErr)
}

func (o *CopyOptions) resolveContainer(pod *corev1.Pod) (string, error) {
	if o.Container != "" {
		for _, c := range pod.Spec.Containers {
			if c.Name == o.Container {
				return o.Container, nil
			}
		}
		for _, c := range pod.Spec.InitContainers {
			if c.Name == o.Container {
				return o.Container, nil
			}
		}
		return "", fmt.Errorf("container %q not found in pod %s/%s", o.Container, pod.Namespace, pod.Name)
	}

	container, err := podcmd.FindOrDefaultContainerByName(pod, "", false, o.IOStreams.ErrOut)
	if err != nil {
		return "", err
	}
	return container.Name, nil
}

func (o *CopyOptions) executeRemote(ctx context.Context, pod *corev1.Pod, container string, command []string, stdout, stderr io.Writer) error {
	restClient, err := restclient.RESTClientFor(o.ClientConfig)
	if err != nil {
		return err
	}

	req := restClient.Post().
		RequestURI(fmt.Sprintf("/apis/audit.adyen.internal/v1beta1/namespaces/%s/pods/%s/exec", pod.Namespace, pod.Name))

	req.VersionedParams(&corev1.PodExecOptions{
		Container: container,
		Command:   command,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(o.ClientConfig, "POST", req.URL())
	if err != nil {
		return err
	}

	return exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: stdout,
		Stderr: stderr,
	})
}

func (o *CopyOptions) extractTar(reader io.Reader, destPath, srcBase string) error {
	destPath = filepath.Clean(destPath)
	destInfo, statErr := os.Stat(destPath)
	destIsDir := statErr == nil && destInfo.IsDir()

	var baseDir string
	if destIsDir {
		baseDir = destPath
	} else {
		baseDir = filepath.Dir(destPath)
	}
	baseAbs, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("invalid base path: %v", err)
	}

	tarReader := tar.NewReader(reader)
	var entries, totalBytes int64
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read error: %v", err)
		}

		// The pod controls the stream: bound the entry count and the total
		// extracted content (declared sizes, so sparse entries count in full).
		entries++
		if entries > o.maxTarEntries() {
			return fmt.Errorf("tar contains too many entries (limit %d)", o.maxTarEntries())
		}
		if header.Typeflag == tar.TypeReg {
			if header.Size < 0 {
				return fmt.Errorf("tar entry %s has a negative size", sanitizeTerminal(header.Name))
			}
			totalBytes += header.Size
			if totalBytes > o.maxArchiveBytes() {
				return fmt.Errorf("extracted content exceeds the %d byte limit", o.maxArchiveBytes())
			}
		}

		// Security: validate and compute safe target path
		targetAbs, err := computeSafeTarget(header.Name, destPath, baseAbs, srcBase, destIsDir)
		if err != nil {
			return err
		}
		relTarget, err := filepath.Rel(baseAbs, targetAbs)
		if err != nil {
			return fmt.Errorf(errPathTraversal, header.Name)
		}

		// Delegated the actual file creation to reduce cognitive complexity
		if err := o.processTarEntry(header, tarReader, baseAbs, relTarget); err != nil {
			return err
		}
	}
	return nil
}

// processTarEntry handles the creation of directories, files, or skipping symlinks based on the tar header type.
// Every target is resolved with securejoin against root first, so symlinked
// path components under the destination (planted by another local actor)
// cannot redirect writes outside of root. Residual note: SecureJoin resolves
// lexically, so a local process racing a symlink swap between resolution and
// open could still win a TOCTOU window; such a process could already write
// the user's files directly, so this is accepted.
func (o *CopyOptions) processTarEntry(header *tar.Header, tarReader *tar.Reader, root, rel string) error {
	switch header.Typeflag {
	case tar.TypeDir:
		resolved, err := securejoin.SecureJoin(root, rel)
		if err != nil {
			return fmt.Errorf("mkdir failed: %v", err)
		}
		if err := os.MkdirAll(resolved, os.FileMode(header.Mode)); err != nil {
			return fmt.Errorf("mkdir failed: %v", err)
		}
	case tar.TypeReg:
		if dir := filepath.Dir(rel); dir != "." {
			resolvedDir, err := securejoin.SecureJoin(root, dir)
			if err != nil {
				return fmt.Errorf("mkdir failed: %v", err)
			}
			if err := os.MkdirAll(resolvedDir, 0755); err != nil {
				return fmt.Errorf("mkdir failed: %v", err)
			}
		}
		resolved, err := securejoin.SecureJoin(root, rel)
		if err != nil {
			return fmt.Errorf("create file failed: %v", err)
		}
		f, err := os.OpenFile(resolved, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
		if err != nil {
			return fmt.Errorf("create file failed: %v", err)
		}
		_, copyErr := io.Copy(f, tarReader)
		if closeErr := f.Close(); closeErr != nil && copyErr == nil {
			return fmt.Errorf("close file failed: %v", closeErr)
		}
		if copyErr != nil {
			return fmt.Errorf("write failed: %v", copyErr)
		}
	case tar.TypeSymlink:
		//nolint:errcheck
		_, _ = fmt.Fprintf(o.IOStreams.ErrOut, "Warning: skipping symlink %s -> %s (symlinks not supported for security)\n", sanitizeTerminal(header.Name), sanitizeTerminal(header.Linkname))
	case tar.TypeLink:
		//nolint:errcheck
		_, _ = fmt.Fprintf(o.IOStreams.ErrOut, "Warning: skipping hard link %s -> %s (hard links not supported for security)\n", sanitizeTerminal(header.Name), sanitizeTerminal(header.Linkname))
	default:
		//nolint:errcheck
		_, _ = fmt.Fprintf(o.IOStreams.ErrOut, "Warning: skipping unsupported tar entry %s (type %d)\n", sanitizeTerminal(header.Name), header.Typeflag)
	}
	return nil
}

// computeSafeTarget validates the tar entry name and computes a safe absolute target path.
func computeSafeTarget(name, destPath, baseAbs, srcBase string, destIsDir bool) (string, error) {
	cleanName := path.Clean(name)

	if cleanName == ".." || strings.HasPrefix(cleanName, "../") || path.IsAbs(cleanName) {
		return "", fmt.Errorf(errPathTraversal, name)
	}

	var target string
	if destIsDir {
		target = filepath.Join(destPath, cleanName)
	} else {
		// Copying to a non-directory destination: the tar stream is produced
		// by `tar cf - -C <dir> -- <srcBase>`, so every legitimate entry is
		// exactly srcBase or lives under it. Anything else (e.g. "foobar" or
		// "foo2/evil", which filepath.Rel would map to "../...") is a crafted
		// stream trying to write siblings of the requested file.
		if cleanName != srcBase && !strings.HasPrefix(cleanName, srcBase+"/") {
			return "", fmt.Errorf(errPathTraversal, name)
		}
		rel, err := filepath.Rel(srcBase, cleanName)
		if err != nil {
			return "", fmt.Errorf("failed to calculate relative path: %v", err)
		}
		target = filepath.Join(destPath, rel)
	}

	targetAbs, err := filepath.Abs(filepath.Clean(target))
	if err != nil {
		return "", fmt.Errorf("invalid target path: %v", err)
	}

	rel, err := filepath.Rel(baseAbs, targetAbs)
	if err != nil {
		return "", fmt.Errorf(errPathTraversal, name)
	}

	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf(errPathTraversal, name)
	}

	return targetAbs, nil
}

func parseFileSpec(spec, defaultNamespace string) (*fileSpec, error) {
	if !strings.Contains(spec, ":") {
		return &fileSpec{File: spec}, nil
	}

	parts := strings.SplitN(spec, ":", 2)
	podSpec := parts[0]
	filePath := parts[1]

	namespace := defaultNamespace
	podName := podSpec

	if strings.Contains(podSpec, "/") {
		nsParts := strings.SplitN(podSpec, "/", 2)
		namespace = nsParts[0]
		podName = nsParts[1]
	}

	return &fileSpec{
		PodName:      podName,
		PodNamespace: namespace,
		File:         filePath,
	}, nil
}
