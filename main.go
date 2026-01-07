package main

import (
	"github.com/adyen/kubectl-rexec/rexec/server"
	"github.com/spf13/cobra"
)

func main() {

	cmd := &cobra.Command{
		Use: "rexec-server",
		Run: func(cmd *cobra.Command, args []string) {
			server.Init()
			server.Server()
		},
	}
	cmd.Flags().BoolVar(&server.AuditFullTraceLog, "audit-trace", false, "if set all keystrokes will be logged")
	cmd.Flags().BoolVar(&server.SysDebugLog, "sys-debug", false, "if set more system logs will be produces")
	cmd.Flags().StringArrayVar(&server.ByPassedUsers, "by-pass-user", []string{}, "allow user to bypass webhook restriction")
	cmd.Flags().StringVar(&server.SecretSauce, "by-pass-shared-key", "", "shared key between apiservice and validatingwebhook")
	cmd.Flags().IntVar(&server.MaxStokesPerLine, "max-strokes-per-line", 0, "set how much keystores can be held in the async audit before flush")
	err := cmd.Execute()
	if err != nil {
		server.SysLogger.Fatal().Msg(err.Error())
	}
}
