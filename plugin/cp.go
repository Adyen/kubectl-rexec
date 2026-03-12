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

// CopyOptions contains the options for the audited copy command.
type CopyOptions struct {
	Container    string
	Namespace    string
	ClientConfig *restclient.Config
	Clientset    kubernetes.Interface
	IOStreams    genericiooptions.IOStreams
}

type fileSpec struct {
	PodName      string
	PodNamespace string
	File         string
}

const errPathTraversal = "illegal file path in tar: %s (path traversal attempt)"

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

	info, err := os.Stat(destPath)
	if err == nil {
		if info.IsDir() {
			return nil
		}
		return nil // existing file, will overwrite
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

	var stdout, stderr bytes.Buffer
	execErr := o.executeRemote(ctx, pod, containerName, command, &stdout, &stderr)

	if execErr != nil {
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

func (o *CopyOptions) executeRemote(ctx context.Context, pod *corev1.Pod, container string, command []string, stdout, stderr *bytes.Buffer) error {
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

	// Compute absolute paths for security validation
	destPathAbs, err := filepath.Abs(destPath)
	if err != nil {
		return fmt.Errorf("invalid destination path: %v", err)
	}

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
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read error: %v", err)
		}

		// Security: validate and compute safe target path
		targetAbs, err := computeSafeTarget(header.Name, destPath, destPathAbs, baseAbs, srcBase, destIsDir)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetAbs, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("mkdir failed: %v", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetAbs), 0755); err != nil {
				return fmt.Errorf("mkdir failed: %v", err)
			}
			f, err := os.OpenFile(targetAbs, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
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
			_, _ = fmt.Fprintf(o.IOStreams.ErrOut, "Warning: skipping symlink %s -> %s (symlinks not supported for security)\n", header.Name, header.Linkname)
		}
	}
	return nil
}

// computeSafeTarget validates the tar entry name and computes a safe absolute target path.
func computeSafeTarget(name, destPath, destPathAbs, baseAbs, srcBase string, destIsDir bool) (string, error) {

	cleanName := path.Clean(name)

	if cleanName == ".." || strings.HasPrefix(cleanName, "../") || path.IsAbs(cleanName) {
		return "", fmt.Errorf(errPathTraversal, name)
	}

	var target string
	if destIsDir {
		target = filepath.Join(destPath, cleanName)
	} else {
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

	if strings.HasPrefix(rel, "..") {
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
