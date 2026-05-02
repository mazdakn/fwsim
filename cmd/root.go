package main

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	inputDir string
	rootCmd  = &cobra.Command{
		Use:   "fwsim",
		Short: "Firewall simulator",
		Long:  `fwsim is a firewall simulator that processes rules and packets from an input directory.`,
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&inputDir, "dir", "d", "", "base input directory with tables/, sets/, and packets/ subdirectories")
	if err := rootCmd.MarkPersistentFlagRequired("dir"); err != nil {
		panic(err)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
