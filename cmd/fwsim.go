package main

import (
	"os"

	"github.com/mazdakn/fwsim/pkg/engine"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	defaultInputFile = "rules.yaml"
)

var (
	inputFile string
	rootCmd   = &cobra.Command{
		Use:   "fwsim",
		Short: "Firewall simulator",
		Long:  `fwsim is a firewall simulator that processes rules and packets from an input file.`,
		Run:   run,
	}
)

func init() {
	rootCmd.Flags().StringVarP(&inputFile, "input", "i", defaultInputFile, "input file with all rules and packets")
}

func run(cmd *cobra.Command, args []string) {
	if len(inputFile) == 0 {
		logrus.Errorf("No input file")
		os.Exit(1)
	}

	e := engine.New()

	err := e.ConfigFromFile(inputFile)
	if err != nil {
		logrus.WithError(err).Errorf("failed to load config %s", inputFile)
		os.Exit(1)
	}

	if err := e.Run(); err != nil {
		logrus.WithError(err).Errorf("failed to run the engine")
		os.Exit(1)
	}

	os.Exit(0)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		logrus.WithError(err).Error("Failed to execute command")
		os.Exit(1)
	}
}
