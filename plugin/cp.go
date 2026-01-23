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

// CopyOptions holds options for the copy command
type CopyOptions struct {
	Container string
	Namespace string

	ClientConfig *restclient.Config
	Clientset    kubernetes.Interface

	IOStreams genericiooptions.IOStreams
}

// fileSpec represents a file specification
type fileSpec struct {
	PodName      string
	PodNamespace string
	File         string
}

// execStreams groups I/O streams for remote execution
type execStreams struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

// NewCmdCp creates the rexec cp command
func NewCmdCp(f cmdutil.Factory, ioStreams genericiooptions.IOStreams) *cobra.Command {
	o := &CopyOptions{
		IOStreams: ioStreams,
	}

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

	cmd.Flags().StringVarP(&o.Container, "container", "c", o.Container, "Container name. If omitted, use the first container")

	return cmd
}

// Complete fills in CopyOptions from command line args
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

	clientset, err := f.KubernetesClientSet()
	if err != nil {
		return err
	}

	o.Clientset = clientset

	return nil
}

// Validate checks that required fields are set
func (o *CopyOptions) Validate() error {
	if o.ClientConfig == nil {
		return fmt.Errorf("client config is required")
	}
	return nil
}

// validateCopySpecs ensures we only allow copying FROM pods (download only)
func validateCopySpecs(srcSpec, destSpec *fileSpec) error {
	if srcSpec.PodName == "" && destSpec.PodName == "" {
		return fmt.Errorf("source must be a pod file spec (pod:path); only pod to local copy is supported")
	}
	if srcSpec.PodName == "" && destSpec.PodName != "" {
		return fmt.Errorf("copying to pods is not supported for security reasons; only pod to local copy is allowed")
	}
	if srcSpec.PodName != "" && destSpec.PodName != "" {
		return fmt.Errorf("destination must be a local path, not a pod path; only pod to local copy is supported")
	}
	if srcSpec.PodName != "" && srcSpec.File == "" {
		return fmt.Errorf("remote path cannot be empty")
	}
	return nil
}

// validateLocalDestination checks if the local destination path is writable
func validateLocalDestination(destPath string) error {
	destPath = filepath.Clean(destPath)

	// Check if destination exists
	info, err := os.Stat(destPath)
	if err == nil {
		// Destination exists
		if info.IsDir() {
			return nil
		}
		// It's an existing file - we'll overwrite it
		return nil
	}

	// Destination doesn't exist - check if parent directory exists
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

// RunWithArgs executes the copy with source and destination arguments
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

// validateAndGetPodContainer retrieves the pod and validates it is running
func (o *CopyOptions) validateAndGetPodContainer(ctx context.Context, src *fileSpec) (*corev1.Pod, string, error) {
	pod, err := o.Clientset.CoreV1().Pods(src.PodNamespace).Get(ctx, src.PodName, metav1.GetOptions{})
	if err != nil {
		return nil, "", fmt.Errorf("pod %s/%s not found", src.PodNamespace, src.PodName)
	}

	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return nil, "", fmt.Errorf("pod %s/%s is not running (phase: %s)", src.PodNamespace, src.PodName, pod.Status.Phase)
	}

	containerName, err := o.resolveContainer(pod)
	if err != nil {
		return nil, "", err
	}

	return pod, containerName, nil
}

func (o *CopyOptions) copyFromPod(ctx context.Context, src, dest *fileSpec) error {
	pod, containerName, err := o.validateAndGetPodContainer(ctx, src)
	if err != nil {
		return err
	}

	srcDir := path.Dir(src.File)
	srcBase := path.Base(src.File)
	command := []string{"tar", "cf", "-", "-C", srcDir, "--", srcBase}

	pipeReader, pipeWriter := io.Pipe()
	var stderr bytes.Buffer
	extractErrCh := make(chan error, 1)

	go func() {
		extractErrCh <- o.extractTar(pipeReader, dest.File, srcBase)
		pipeReader.Close()
	}()

	execErr := o.executeRemote(ctx, pod, containerName, command, execStreams{
		stdout: pipeWriter,
		stderr: &stderr,
	})
	pipeWriter.Close()

	extractErr := <-extractErrCh
	if err := o.checkCopyError(execErr, extractErr, stderr.String(), src); err != nil {
		return err
	}

	fmt.Fprintf(o.IOStreams.Out, "Copied %s:%s to %s\n", src.PodName, src.File, dest.File)
	return nil
}

// checkCopyError prioritizes security errors and formats messages with pod context
func (o *CopyOptions) checkCopyError(execErr, extractErr error, stderrStr string, src *fileSpec) error {
	// Security errors take priority
	if extractErr != nil {
		msg := extractErr.Error()
		if strings.Contains(msg, "illegal file path") || strings.Contains(msg, "path traversal") {
			return extractErr
		}
	}

	if execErr != nil {
		return o.analyzeRemoteError(execErr, extractErr, stderrStr, src)
	}

	return extractErr
}

// analyzeRemoteError determines the root cause of remote execution failures
func (o *CopyOptions) analyzeRemoteError(execErr, extractErr error, stderrStr string, src *fileSpec) error {
	podRef := fmt.Sprintf("%s/%s", src.PodNamespace, src.PodName)

	// If the pipe broke, it often means the extraction side closed it early
	if extractErr != nil {
		execMsg := execErr.Error()
		if strings.Contains(execMsg, "broken pipe") ||
			strings.Contains(execMsg, "connection reset") ||
			strings.Contains(execMsg, "use of closed network connection") ||
			strings.Contains(stderrStr, "Broken pipe") {
			return extractErr
		}
	}

	// Check for missing tar binary
	if strings.Contains(stderrStr, "tar: not found") ||
		strings.Contains(stderrStr, "executable file not found") ||
		strings.Contains(stderrStr, "sh: tar") {
		return fmt.Errorf("pod %s: tar binary not found in container", podRef)
	}

	// Check for remote file/directory not found
	if strings.Contains(stderrStr, "No such file or directory") {
		remotePath := extractRemotePath(stderrStr)
		return fmt.Errorf("pod %s: remote path not found: %s", podRef, remotePath)
	}

	// Check for permission denied
	if strings.Contains(stderrStr, "Permission denied") || strings.Contains(stderrStr, "cannot open") {
		return fmt.Errorf("pod %s: permission denied reading remote path", podRef)
	}

	// Generic error with stderr
	if len(stderrStr) > 0 {
		return fmt.Errorf("pod %s: remote tar failed: %s", podRef, strings.TrimSpace(stderrStr))
	}

	return fmt.Errorf("pod %s: remote command failed: %v", podRef, execErr)
}

// extractRemotePath extracts the path from tar stderr output like "tar: foo: No such file or directory"
func extractRemotePath(stderrStr string) string {
	lines := strings.Split(stderrStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "No such file or directory") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return "unknown"
}

// resolveContainer finds the container name to use
func (o *CopyOptions) resolveContainer(pod *corev1.Pod) (string, error) {
	if len(o.Container) > 0 {
		var containerNames []string
		for _, c := range pod.Spec.Containers {
			if c.Name == o.Container {
				return o.Container, nil
			}
			containerNames = append(containerNames, c.Name)
		}
		for _, c := range pod.Spec.InitContainers {
			if c.Name == o.Container {
				return o.Container, nil
			}
			containerNames = append(containerNames, c.Name)
		}
		return "", fmt.Errorf("pod %s/%s: container %q not found (available: %s)", pod.Namespace, pod.Name, o.Container, strings.Join(containerNames, ", "))
	}
	container, err := podcmd.FindOrDefaultContainerByName(pod, "", false, o.IOStreams.ErrOut)
	if err != nil {
		return "", err
	}
	return container.Name, nil
}

// executeRemote executes a command in a pod using the rexec endpoint
func (o *CopyOptions) executeRemote(ctx context.Context, pod *corev1.Pod, container string, command []string, streams execStreams) error {
	restClient, err := restclient.RESTClientFor(o.ClientConfig)
	if err != nil {
		return err
	}

	req := restClient.Post().
		RequestURI(fmt.Sprintf("/apis/audit.adyen.internal/v1beta1/namespaces/%s/pods/%s/exec", pod.Namespace, pod.Name))

	req.VersionedParams(&corev1.PodExecOptions{
		Container: container,
		Command:   command,
		Stdin:     streams.stdin != nil,
		Stdout:    streams.stdout != nil,
		Stderr:    streams.stderr != nil,
		TTY:       false,
	}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(o.ClientConfig, "POST", req.URL())
	if err != nil {
		return err
	}

	return exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  streams.stdin,
		Stdout: streams.stdout,
		Stderr: streams.stderr,
		Tty:    false,
	})
}

// prepareExtractionRoot determines the absolute paths for the destination and base directory
func prepareExtractionRoot(destPath string) (destPathAbs, baseAbs string, destIsDir bool, err error) {
	destPath = filepath.Clean(destPath)
	destPathAbs, err = filepath.Abs(destPath)
	if err != nil {
		return "", "", false, fmt.Errorf("invalid destination path: %v", err)
	}

	destInfo, destStatErr := os.Stat(destPath)
	destIsDir = destStatErr == nil && destInfo.IsDir()

	var baseDir string
	if destIsDir {
		baseDir = destPath
	} else {
		baseDir = filepath.Dir(destPath)
	}

	baseAbs, err = filepath.Abs(baseDir)
	if err != nil {
		return "", "", false, fmt.Errorf("invalid base path: %v", err)
	}
	return destPathAbs, baseAbs, destIsDir, nil
}

// extractTar extracts a tar archive to a local path with strict security checks
func (o *CopyOptions) extractTar(reader io.Reader, destPath string, srcBase string) error {
	tarReader := tar.NewReader(reader)

	destPathAbs, baseAbs, destIsDir, err := prepareExtractionRoot(destPath)
	if err != nil {
		return err
	}

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Sanitize the header name to prevent path traversal
		sanitizedName := path.Clean(header.Name)
		if sanitizedName == ".." || strings.HasPrefix(sanitizedName, "../") || strings.Contains(sanitizedName, "/../") || path.IsAbs(sanitizedName) {
			return fmt.Errorf("illegal file path in tar: %s (path traversal attempt)", header.Name)
		}

		// Calculate target path
		var target string
		if destIsDir {
			target = filepath.Join(destPath, sanitizedName)
		} else if sanitizedName == srcBase {
			target = destPath
		} else {
			relPath := strings.TrimPrefix(sanitizedName, srcBase+"/")
			if relPath == sanitizedName {
				target = filepath.Join(filepath.Dir(destPath), sanitizedName)
			} else {
				target = filepath.Join(destPath, relPath)
			}
		}

		target = filepath.Clean(target)
		targetAbs, err := filepath.Abs(target)
		if err != nil {
			return fmt.Errorf("invalid target path: %v", err)
		}

		// Ensure the target path is contained within the base directory
		if targetAbs != baseAbs && targetAbs != destPathAbs && !strings.HasPrefix(targetAbs, baseAbs+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path in tar: %s (path traversal attempt)", header.Name)
		}

		// Write the file or create the directory
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetAbs, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory: %v", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetAbs), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory: %v", err)
			}
			f, err := os.OpenFile(targetAbs, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file: %v", err)
			}
			_, copyErr := io.Copy(f, tarReader)
			f.Close()
			if copyErr != nil {
				return fmt.Errorf("failed to write file: %v", copyErr)
			}
		case tar.TypeSymlink:
			fmt.Fprintf(o.IOStreams.ErrOut, "Warning: skipping symlink %s -> %s (symlinks not supported for security)\n", header.Name, header.Linkname)
		default:
			fmt.Fprintf(o.IOStreams.ErrOut, "Warning: skipping unsupported file type %c for %s\n", header.Typeflag, header.Name)
		}
	}

	return nil
}

// parseFileSpec parses a file spec string into a fileSpec struct
func parseFileSpec(spec, defaultNamespace string) (*fileSpec, error) {
	if !strings.Contains(spec, ":") {
		return &fileSpec{File: spec}, nil
	}

	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid file spec: %s", spec)
	}

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