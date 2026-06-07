package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mazdakn/fwsim/pkg/config"
	"github.com/mazdakn/fwsim/pkg/engine"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var pcapFile string

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run YAML intents or pcap packets against firewall rules",
	Long:  `Load packets from intents/ YAML files or a pcap capture and evaluate each one against firewall rules.`,
	Run:   runPackets,
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVar(&pcapFile, "pcap", "", "pcap file to evaluate instead of intents/ YAML files")
}

func runPackets(cmd *cobra.Command, args []string) {
	// Create engine and load rules
	r, err := config.ConfigFromFile(config.Config{
		InputDir: inputDir,
	})
	if err != nil {
		logrus.WithError(err).Errorf("failed to load resources from %s", inputDir)
		os.Exit(1)
	}

	r.Intents, err = loadRunIntents()
	if err != nil {
		logrus.WithError(err).Error("failed to load packets to evaluate")
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

func loadRunIntents() ([]*config.Intent, error) {
	if pcapFile != "" {
		return config.ConfigIntentsFromPCAPFile(pcapFile)
	}
	return config.ConfigIntentsFromDir(filepath.Join(inputDir, "intents"))
}
