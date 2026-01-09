package plugin

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/kubectl/pkg/cmd"
	cmdexec "k8s.io/kubectl/pkg/cmd/exec"
	"k8s.io/kubectl/pkg/cmd/plugin"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/cmd/util/podcmd"
	"k8s.io/kubectl/pkg/scheme"
	"k8s.io/kubectl/pkg/util/completion"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"
	"k8s.io/kubectl/pkg/util/term"
)

// We dont do much here, mostly implementing the same exec command
// as in upstream, with the difference in the path we are calling

var MatchVersionKubeConfigFlags *cmdutil.MatchVersionFlags

const (
	defaultPodExecTimeout = 60 * time.Second
)

func Rexec() {
	ioStreams := genericiooptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr}
	warningsAsErrors := false

	kubectlOptions := cmd.KubectlOptions{

		PluginHandler: cmd.NewDefaultPluginHandler(plugin.ValidPluginFilenamePrefixes),
		Arguments:     os.Args,
		ConfigFlags:   genericclioptions.NewConfigFlags(true).WithDeprecatedPasswordFlag().WithDiscoveryBurst(300).WithDiscoveryQPS(50.0).WithWarningPrinter(ioStreams),
		IOStreams:     ioStreams,
	}

	cmds := &cobra.Command{
		Use:   "rexec",
		Short: i18n.T("rexec plugin for kubectl exec"),
		Long: templates.LongDesc(`
      provides audited way to perform kubectl exec.`),
	}

	cmds.SetGlobalNormalizationFunc(cliflag.WarnWordSepNormalizeFunc)

	flags := cmds.PersistentFlags()

	flags.BoolVar(&warningsAsErrors, "warnings-as-errors", warningsAsErrors, "Treat warnings received from the server as errors and exit with a non-zero exit code")

	kubectlOptions.ConfigFlags.AddFlags(flags)

	MatchVersionKubeConfigFlags = cmdutil.NewMatchVersionFlags(kubectlOptions.ConfigFlags)
	MatchVersionKubeConfigFlags.AddFlags(flags)

	f := cmdutil.NewFactory(MatchVersionKubeConfigFlags)

	originalExec := cmdexec.NewCmdExec(f, kubectlOptions.IOStreams)

	options := &cmdexec.ExecOptions{
		StreamOptions: cmdexec.StreamOptions{
			IOStreams: kubectlOptions.IOStreams,
		},

		Executor: &cmdexec.DefaultRemoteExecutor{},
	}

	roptions := &RexecOptoins{
		ExecOptions: options,
	}

	newExec := &cobra.Command{
		Use:                   originalExec.Use,
		DisableFlagsInUseLine: originalExec.DisableFlagsInUseLine,
		Short:                 originalExec.Short,
		Long:                  originalExec.Long,
		Example:               originalExec.Example,
		ValidArgsFunction:     originalExec.ValidArgsFunction,
		Run: func(cmd *cobra.Command, args []string) {
			argsLenAtDash := cmd.ArgsLenAtDash()
			cmdutil.CheckErr(roptions.ExecOptions.Complete(f, cmd, args, argsLenAtDash))
			cmdutil.CheckErr(roptions.ExecOptions.Validate())
			cmdutil.CheckErr(roptions.rexecRun())
		},
	}

	cmdutil.AddPodRunningTimeoutFlag(newExec, defaultPodExecTimeout)
	cmdutil.AddJsonFilenameFlag(newExec.Flags(), &options.FilenameOptions.Filenames, "to use to exec into the resource")

	cmdutil.AddContainerVarFlags(newExec, &options.ContainerName, options.ContainerName)
	cmdutil.CheckErr(newExec.RegisterFlagCompletionFunc("container", completion.ContainerCompletionFunc(f)))

	newExec.Flags().BoolVarP(&roptions.ExecOptions.Stdin, "stdin", "i", roptions.ExecOptions.Stdin, "Pass stdin to the container")
	newExec.Flags().BoolVarP(&roptions.ExecOptions.TTY, "tty", "t", roptions.ExecOptions.TTY, "Stdin is a TTY")
	newExec.Flags().BoolVarP(&roptions.ExecOptions.Quiet, "quiet", "q", roptions.ExecOptions.Quiet, "Only print output from the remote session")

	cmds.AddCommand(newExec)

	cmds.Execute()
}

type RexecOptoins struct {
	*cmdexec.ExecOptions
}

// terminalSizeQueueAdapter is an adapter for the terminal size queue to the remotecommand.TerminalSizeQueue interface
type terminalSizeQueueAdapter struct {
	delegate term.TerminalSizeQueue
}

// Next returns the next terminal size
func (a *terminalSizeQueueAdapter) Next() *remotecommand.TerminalSize {
	next := a.delegate.Next()
	if next == nil {
		return nil
	}
	return &remotecommand.TerminalSize{
		Width:  next.Width,
		Height: next.Height,
	}
}

func NewRexecOptions(e *cmdexec.ExecOptions) *RexecOptoins {
	r := RexecOptoins{e}
	return &r
}

// mostly copy paste of the upstream Run() command
// with the minimal adjustment to call a different
// endpoint
func (r *RexecOptoins) rexecRun() error {
	var err error
	if len(r.PodName) != 0 {
		r.Pod, err = r.PodClient.Pods(r.ExecOptions.Namespace).Get(context.TODO(), r.ExecOptions.PodName, metav1.GetOptions{})
		if err != nil {
			return err
		}
	} else {
		builder := r.ExecOptions.Builder().
			WithScheme(scheme.Scheme, scheme.Scheme.PrioritizedVersionsAllGroups()...).
			FilenameParam(r.ExecOptions.EnforceNamespace, &r.ExecOptions.FilenameOptions).
			NamespaceParam(r.ExecOptions.Namespace).DefaultNamespace()
		if len(r.ExecOptions.ResourceName) > 0 {
			builder = builder.ResourceNames("pods", r.ExecOptions.ResourceName)
		}

		obj, err := builder.Do().Object()
		if err != nil {
			return err
		}

		if meta.IsListType(obj) {
			return fmt.Errorf("cannot exec into multiple objects at a time")
		}

		r.ExecOptions.Pod, err = r.ExecutablePodFn(MatchVersionKubeConfigFlags, obj, r.ExecOptions.GetPodTimeout)
		if err != nil {
			return err
		}
	}

	pod := r.ExecOptions.Pod

	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return fmt.Errorf("cannot exec into a container in a completed pod; current phase is %s", pod.Status.Phase)
	}

	containerName := r.ExecOptions.ContainerName
	if len(containerName) == 0 {
		container, err := podcmd.FindOrDefaultContainerByName(pod, containerName, r.ExecOptions.Quiet, r.ExecOptions.ErrOut)
		if err != nil {
			return err
		}
		containerName = container.Name
	}

	t := r.ExecOptions.SetupTTY()

	var sizeQueue remotecommand.TerminalSizeQueue
	if t.Raw {
		sizeQueue = &terminalSizeQueueAdapter{delegate: t.MonitorSize(t.GetSize())}

		r.ExecOptions.ErrOut = nil
	}

	fn := func() error {
		restClient, err := restclient.RESTClientFor(r.Config)
		if err != nil {
			return err
		}

		req := restClient.Post().RequestURI(fmt.Sprintf("apis/audit.adyen.internal/v1beta1/namespaces/%s/pods/%s/exec", pod.Namespace, pod.Name))
		req.VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   r.ExecOptions.Command,
			Stdin:     r.ExecOptions.Stdin,
			Stdout:    r.ExecOptions.Out != nil,
			Stderr:    r.ExecOptions.ErrOut != nil,
			TTY:       t.Raw,
		}, scheme.ParameterCodec)

		return r.ExecOptions.Executor.Execute(req.URL(), r.ExecOptions.Config, r.ExecOptions.In, r.ExecOptions.Out, r.ExecOptions.ErrOut, t.Raw, sizeQueue)
	}

	if err := t.Safe(fn); err != nil {
		return err
	}

	return nil
}
