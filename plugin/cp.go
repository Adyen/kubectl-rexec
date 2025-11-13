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
	Container  string
	Namespace  string
	NoPreserve bool
	MaxTries   int

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

// NewCmdCp creates the rexec cp command
func NewCmdCp(f cmdutil.Factory, ioStreams genericiooptions.IOStreams) *cobra.Command {
	o := &CopyOptions{
		IOStreams: ioStreams,
		MaxTries:  3,
	}

	cmd := &cobra.Command{
		Use:   "cp <file-spec-src> <file-spec-dest>",
		Short: i18n.T("Copy files and directories to and from containers (with audit)"),
		Long: templates.LongDesc(`
			Copy files and directories to and from containers.
			This command uses rexec for audited file transfers.
			
			Note: requires 'tar' to be installed in the container.`),
		Example: templates.Examples(`
			# Copy /tmp/foo local file to /tmp/bar in a remote pod
			kubectl rexec cp /tmp/foo my-pod:/tmp/bar
			
			# Copy /tmp/foo from a remote pod to /tmp/bar locally
			kubectl rexec cp my-pod:/tmp/foo /tmp/bar
			
			# Copy /tmp/foo local file to /tmp/bar in a specific container
			kubectl rexec cp /tmp/foo my-pod:/tmp/bar -c my-container
			
			# Copy /tmp/foo local directory to /tmp/bar in a remote pod
			kubectl rexec cp /tmp/foo my-pod:/tmp/bar`),
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Complete(f, cmd, args))
			cmdutil.CheckErr(o.Validate())
			if len(args) == 2 {
				cmdutil.CheckErr(o.RunWithArgs(args[0], args[1]))
			} else {
				cmdutil.CheckErr(fmt.Errorf("source and destination are required"))
			}
		},
	}

	cmd.Flags().StringVarP(&o.Container, "container", "c", o.Container, "Container name. If omitted, use the first container")
	cmd.Flags().BoolVar(&o.NoPreserve, "no-preserve", false, "The copied file/directory's ownership and permissions will not be preserved")
	cmd.Flags().IntVar(&o.MaxTries, "retries", 3, "Set number of retries to complete a copy operation from a container")

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

// RunWithArgs executes the copy with source and destination arguments
func (o *CopyOptions) RunWithArgs(src, dest string) error {
	srcSpec, err := parseFileSpec(src, o.Namespace)
	if err != nil {
		return err
	}

	destSpec, err := parseFileSpec(dest, o.Namespace)
	if err != nil {
		return err
	}

	// Determine direction
	if srcSpec.PodName != "" && destSpec.PodName != "" {
		return fmt.Errorf("copying between pods is not supported, use local path as intermediate")
	}

	if srcSpec.PodName != "" {
		// Copy from pod to local
		return o.copyFromPod(srcSpec, destSpec)
	}

	// Copy from local to pod
	return o.copyToPod(srcSpec, destSpec)
}

// copyFromPod copies files from a pod to local filesystem
func (o *CopyOptions) copyFromPod(src, dest *fileSpec) error {
	// Get the pod
	pod, err := o.Clientset.CoreV1().Pods(src.PodNamespace).Get(
		context.TODO(),
		src.PodName,
		metav1.GetOptions{},
	)
	if err != nil {
		return err
	}

	// Find container using same pattern as exec command
	containerName := o.Container
	if len(containerName) == 0 {
		container, err := podcmd.FindOrDefaultContainerByName(pod, containerName, false, o.IOStreams.ErrOut)
		if err != nil {
			return err
		}
		containerName = container.Name
	}

	// Prepare tar command in pod
	command := []string{"tar", "cf", "-", src.File}

	// Create a buffer to hold tar output
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	// Execute the command using rexec endpoint
	err = o.executeRemote(pod, containerName, command, nil, &stdout, &stderr)
	if err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("error executing tar: %v\nstderr: %s", err, stderr.String())
		}
		return fmt.Errorf("error executing tar: %v", err)
	}

	// Extract tar to local destination
	return o.extractTar(&stdout, dest.File)
}

// copyToPod copies files from local filesystem to a pod
func (o *CopyOptions) copyToPod(src, dest *fileSpec) error {
	// Get the pod
	pod, err := o.Clientset.CoreV1().Pods(dest.PodNamespace).Get(
		context.TODO(),
		dest.PodName,
		metav1.GetOptions{},
	)
	if err != nil {
		return err
	}

	// Find container using same pattern as exec command
	containerName := o.Container
	if len(containerName) == 0 {
		container, err := podcmd.FindOrDefaultContainerByName(pod, containerName, false, o.IOStreams.ErrOut)
		if err != nil {
			return err
		}
		containerName = container.Name
	}

	// Create tar archive of source
	var stdin bytes.Buffer
	err = o.createTar(src.File, &stdin, dest.File)
	if err != nil {
		return fmt.Errorf("error creating tar: %v", err)
	}

	// Prepare untar command in pod
	destDir := path.Dir(dest.File)
	command := []string{"tar", "xf", "-", "-C", destDir}

	// Check if destination directory exists, if not create it
	mkdirCmd := []string{"mkdir", "-p", destDir}
	var mkdirStderr bytes.Buffer
	err = o.executeRemote(pod, containerName, mkdirCmd, nil, io.Discard, &mkdirStderr)
	if err != nil {
		return fmt.Errorf("error creating destination directory: %v\nstderr: %s", err, mkdirStderr.String())
	}

	// Execute the untar command using rexec endpoint
	var stderr bytes.Buffer
	err = o.executeRemote(pod, containerName, command, &stdin, io.Discard, &stderr)
	if err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("error executing tar: %v\nstderr: %s", err, stderr.String())
		}
		return fmt.Errorf("error executing tar: %v", err)
	}

	fmt.Fprintf(o.IOStreams.Out, "Copied %s to %s:%s\n", src.File, dest.PodName, dest.File)
	return nil
}

// executeRemote executes a command in a pod using the rexec endpoint
func (o *CopyOptions) executeRemote(pod *corev1.Pod, container string, command []string, stdin io.Reader, stdout, stderr io.Writer) error {
	// Create REST client
	restClient, err := restclient.RESTClientFor(o.ClientConfig)
	if err != nil {
		return err
	}

	// Build request using the rexec custom API endpoint
	// We use the same audit.adyen.internal API
	req := restClient.Post().
		RequestURI(fmt.Sprintf("apis/audit.adyen.internal/v1beta1/namespaces/%s/pods/%s/exec", pod.Namespace, pod.Name))

	req.VersionedParams(&corev1.PodExecOptions{
		Container: container,
		Command:   command,
		Stdin:     stdin != nil,
		Stdout:    stdout != nil,
		Stderr:    stderr != nil,
		TTY:       false,
	}, scheme.ParameterCodec)

	// Execute using SPDY/WebSocket
	exec, err := remotecommand.NewSPDYExecutor(o.ClientConfig, "POST", req.URL())
	if err != nil {
		return err
	}

	// Stream the command
	return exec.StreamWithContext(context.TODO(), remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		Tty:    false,
	})
}

// createTar creates a tar archive from a local path
func (o *CopyOptions) createTar(srcPath string, writer io.Writer, destPath string) error {
	tarWriter := tar.NewWriter(writer)
	defer tarWriter.Close()

	// Clean the source path
	srcPath = filepath.Clean(srcPath)

	// Get file info
	info, err := os.Stat(srcPath)
	if err != nil {
		return err
	}

	// Get the base name for the archive
	baseName := filepath.Base(destPath)

	if info.IsDir() {
		// Walk the directory
		return filepath.Walk(srcPath, func(file string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Create tar header
			header, err := tar.FileInfoHeader(fi, fi.Name())
			if err != nil {
				return err
			}

			// Update the name to be relative
			relPath, err := filepath.Rel(srcPath, file)
			if err != nil {
				return err
			}

			// Use the destination base name as prefix
			if relPath == "." {
				header.Name = baseName
			} else {
				header.Name = filepath.Join(baseName, relPath)
			}

			// Normalize path separators for tar
			header.Name = filepath.ToSlash(header.Name)

			if o.NoPreserve {
				header.Uid = 0
				header.Gid = 0
			}

			// Write header
			if err := tarWriter.WriteHeader(header); err != nil {
				return err
			}

			// If not a regular file, we are done
			if !fi.Mode().IsRegular() {
				return nil
			}

			// Open and copy file content
			f, err := os.Open(file)
			if err != nil {
				return err
			}
			defer f.Close()

			_, err = io.Copy(tarWriter, f)
			return err
		})
	}

	// Single file
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}

	header.Name = baseName

	if o.NoPreserve {
		header.Uid = 0
		header.Gid = 0
	}

	if err := tarWriter.WriteHeader(header); err != nil {
		return err
	}

	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(tarWriter, f)
	return err
}

// extractTar extracts a tar archive to a local path
func (o *CopyOptions) extractTar(reader io.Reader, destPath string) error {
	tarReader := tar.NewReader(reader)

	// Clean and get absolute destination path for security checks
	destPath = filepath.Clean(destPath)
	destPathAbs, err := filepath.Abs(destPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %v", err)
	}

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// SECURITY: Check the header name BEFORE processing
		// Prevent path traversal by checking for ".." or absolute paths
		if strings.Contains(header.Name, "..") {
			return fmt.Errorf("illegal file path in tar: %s (path traversal attempt)", header.Name)
		}
		if filepath.IsAbs(header.Name) && !strings.HasPrefix(filepath.Clean(header.Name), destPathAbs) {
			return fmt.Errorf("illegal file path in tar: %s (absolute path outside destination)", header.Name)
		}

		// Strip the leading path from the tar header name
		// The tar contains the full path (e.g., "/tmp/from-pod.txt")
		// We want to extract just the filename to destPath
		fileName := filepath.Base(header.Name)

		// Determine the target path
		var target string
		fi, statErr := os.Stat(destPath)
		if statErr == nil && fi.IsDir() {
			// Destination is a directory, extract into it
			target = filepath.Join(destPath, fileName)
		} else {
			// Destination is a file path, use it as-is
			target = destPath
		}

		// Additional security check: ensure target is within destPath
		target = filepath.Clean(target)
		targetAbs, err := filepath.Abs(target)
		if err != nil {
			return fmt.Errorf("failed to get absolute path for target: %v", err)
		}

		// Check if target is within destPath
		if statErr == nil && fi.IsDir() {
			if !strings.HasPrefix(targetAbs, destPathAbs+string(os.PathSeparator)) &&
				targetAbs != destPathAbs {
				return fmt.Errorf("illegal file path in tar: %s (path traversal attempt)", header.Name)
			}
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// For directories, create them
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return err
			}

		case tar.TypeReg:
			// Create parent directories if needed
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}

			// Create file
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return err
			}

			// Copy content
			if _, err := io.Copy(f, tarReader); err != nil {
				f.Close()
				return err
			}
			f.Close()

		default:
			fmt.Fprintf(o.IOStreams.ErrOut, "Warning: ignoring unsupported type %c for %s\n", header.Typeflag, header.Name)
		}
	}

	return nil
}

// parseFileSpec parses a file spec string into a fileSpec struct
// Format: [namespace/]pod:path or just path for local files
func parseFileSpec(spec string, defaultNamespace string) (*fileSpec, error) {
	// Check if it's a remote spec (contains :)
	if !strings.Contains(spec, ":") {
		// Local file
		return &fileSpec{
			File: spec,
		}, nil
	}

	// Remote spec
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid file spec: %s", spec)
	}

	podSpec := parts[0]
	filePath := parts[1]

	// Check for namespace prefix
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

// isDestDir checks if destination is a directory
func isDestDir(dest string) bool {
	if strings.HasSuffix(dest, "/") {
		return true
	}
	fi, err := os.Stat(dest)
	if err != nil {
		return false
	}
	return fi.IsDir()
}
