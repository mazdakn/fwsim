package main

import (
	"fmt"
	"os"

	"github.com/mazdakn/fwsim/pkg/config"
	"github.com/mazdakn/fwsim/pkg/engine"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run packets from a file against firewall rules",
	Long:  `Load packets from an input file and evaluate each one against firewall rules.`,
	Run:   runPackets,
}

func init() {
	rootCmd.AddCommand(runCmd)
}

func runPackets(cmd *cobra.Command, args []string) {
	// Create engine and load rules
	r, err := config.ConfigFromFile(config.Config{
		InputDir:    inputDir,
		LoadIntents: true,
	})
	if err != nil {
		logrus.WithError(err).Errorf("failed to load resources from %s", inputDir)
		os.Exit(1)
	}
	e := engine.New(r)

	// Evaluate each packet
	for _, m := range e.RunTests() {
		printResult(m)
		printIntentResult(m)
		fmt.Println()
	}

	// Run and print validations.
	printValidations(e.Validate())
}
