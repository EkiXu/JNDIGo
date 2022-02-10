package cmd

import (
	"fmt"
	"github.com/op/go-logging"
	"github.com/spf13/cobra"
	"os"
)

var logger = logging.MustGetLogger("JNDIGo")

var rootCmd = &cobra.Command{
	Use:   "JNDIGo",
	Short: "JNDIGo is a penetration test tool for JNDI",
	Long:  `A lightweight and zero java dependency jndi vulnerability scan tool write in Golang`,
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here

	},
}

func init() {
	rootCmd.AddCommand(ldapCmd)
	rootCmd.AddCommand(rmiCmd)
	ldapCmd.Flags().StringP("codebase", "c", "", "Use CodeBase")
	ldapCmd.Flags().BoolP("list", "l", false, "Show All Payloads")
	rmiCmd.Flags().StringP("codebase", "c", "", "Use CodeBase")
	rmiCmd.Flags().BoolP("list", "l", false, "Show All Payloads")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
