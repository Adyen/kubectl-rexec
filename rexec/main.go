package main

import (
	"github.com/adyen/kubectl-rexec/rexec/server"
	"github.com/spf13/cobra"
)

var deprByPassedUsers []string
var deprSecretSauce string

func main() {

	cmd := &cobra.Command{
		Use: "rexec-server",
		Run: func(cmd *cobra.Command, args []string) {
			server.ByPassedUsers = append(server.ByPassedUsers, deprByPassedUsers...)
			if server.SecretSauce == "" {
				server.SecretSauce = deprSecretSauce
			}
			server.Init()
			server.Server()
		},
	}
	cmd.Flags().BoolVar(&server.AuditFullTraceLog, "audit-trace", false, "if set all keystrokes will be logged")
	cmd.Flags().BoolVar(&server.SysDebugLog, "sys-debug", false, "if set more system logs will be produces")
	cmd.Flags().StringArrayVar(&server.ByPassedUsers, "bypass-user", []string{}, "allow user to bypass webhook restriction")
	cmd.Flags().StringVar(&server.SecretSauce, "bypass-shared-key", "", "shared key between apiservice and validatingwebhook")
	cmd.Flags().StringArrayVar(&deprByPassedUsers, "by-pass-user", nil, "allow user to bypass webhook restriction")
	cmd.Flags().StringVar(&deprSecretSauce, "by-pass-shared-key", "", "shared key between apiservice and validatingwebhook")
	_ = cmd.Flags().MarkDeprecated("by-pass-user", "use --bypass-user instead")
	_ = cmd.Flags().MarkDeprecated("by-pass-shared-key", "use --bypass-shared-key instead")
	cmd.Flags().IntVar(&server.MaxStokesPerLine, "max-strokes-per-line", 0, "set how much keystores can be held in the async audit before flush")
	cmd.Flags().StringVar(&server.ClusterDomain, "cluster-domain", "", "cluster DNS domain (default: detect or cluster.local)")
	err := cmd.Execute()
	if err != nil {
		server.SysLogger.Fatal().Msg(err.Error())
	}
}
