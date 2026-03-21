package main

import (
	"fmt"
	"os"

	"github.com/mazdakn/fwsim/internal/model"
	"github.com/mazdakn/fwsim/internal/traffic"
	"github.com/mazdakn/fwsim/pkg/engine"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	defaultInputFile   = "rules.yaml"
	defaultPacketsFile = "packets.yaml"
)

var (
	inputFile   string
	packetsFile string
	rootCmd     = &cobra.Command{
		Use:   "fwsim",
		Short: "Firewall simulator",
		Long:  `fwsim is a firewall simulator that processes rules and packets from an input file.`,
	}
	evaluateCmd = &cobra.Command{
		Use:   "evaluate",
		Short: "Evaluate a packet against firewall rules",
		Long:  `Evaluate a packet against firewall rules and return a verdict.`,
		Run:   runEvaluate,
	}
	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run packets from a file against firewall rules",
		Long:  `Load packets from an input file and evaluate each one against firewall rules.`,
		Run:   runPackets,
	}
)

// Flags for evaluate command
var (
	srcAddr string
	dstAddr string
	proto   uint
	srcPort uint
	dstPort uint
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&inputFile, "file", "f", defaultInputFile, "input file with all rules and packets")

	// Add evaluate subcommand
	rootCmd.AddCommand(evaluateCmd)

	// Add flags for evaluate command
	evaluateCmd.Flags().StringVar(&srcAddr, "src-addr", "", "source IP address")
	evaluateCmd.Flags().StringVar(&dstAddr, "dst-addr", "", "destination IP address")
	evaluateCmd.Flags().UintVar(&proto, "proto", 0, "IP protocol number")
	evaluateCmd.Flags().UintVar(&srcPort, "src-port", 0, "source port")
	evaluateCmd.Flags().UintVar(&dstPort, "dst-port", 0, "destination port")

	// Mark required flags
	if err := evaluateCmd.MarkFlagRequired("src-addr"); err != nil {
		panic(err)
	}
	if err := evaluateCmd.MarkFlagRequired("src-port"); err != nil {
		panic(err)
	}
	if err := evaluateCmd.MarkFlagRequired("dst-addr"); err != nil {
		panic(err)
	}
	if err := evaluateCmd.MarkFlagRequired("dst-port"); err != nil {
		panic(err)
	}
	if err := evaluateCmd.MarkFlagRequired("proto"); err != nil {
		panic(err)
	}

	// Add run subcommand
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVarP(&packetsFile, "packets", "p", defaultPacketsFile, "input file with packet information")
}

func runEvaluate(cmd *cobra.Command, args []string) {
	// Validate protocol value
	if proto > 255 {
		logrus.Errorf("Protocol must be between 0 and 255")
		os.Exit(1)
	}

	// Validate port values
	if srcPort > 65535 {
		logrus.Errorf("Source port must be between 0 and 65535")
		os.Exit(1)
	}
	if dstPort > 65535 {
		logrus.Errorf("Destination port must be between 0 and 65535")
		os.Exit(1)
	}

	// Create engine and load rules
	e := engine.New()
	err := e.ConfigFromFile(inputFile)
	if err != nil {
		logrus.WithError(err).Errorf("failed to load rules from %s", inputFile)
		os.Exit(1)
	}

	// Load rules into engine
	if err := e.LoadRules(); err != nil {
		logrus.WithError(err).Errorf("failed to load rules")
		os.Exit(1)
	}

	// Create packet from parameters
	pkt := traffic.NewPacket(
		traffic.WithSrcAddr(srcAddr),
		traffic.WithDstAddr(dstAddr),
		traffic.WithProto(uint8(proto)),
		traffic.WithSrcPort(uint16(srcPort)),
		traffic.WithDstPort(uint16(dstPort)),
	)

	// Match packet against rules
	res := e.Match(pkt)
	printResult(pkt, res)
	fmt.Println()

	// Run and print validations.
	printValidations(e.Validate())
}

func runPackets(cmd *cobra.Command, args []string) {
	// Create engine and load rules
	e := engine.New()
	if err := e.ConfigFromFile(inputFile); err != nil {
		logrus.WithError(err).Errorf("failed to load rules from %s", inputFile)
		os.Exit(1)
	}
	if err := e.LoadRules(); err != nil {
		logrus.WithError(err).Errorf("failed to load rules")
		os.Exit(1)
	}

	// Load packets from file
	pkts, err := e.PacketsFromFile(packetsFile)
	if err != nil {
		logrus.WithError(err).Errorf("failed to load packets from %s", packetsFile)
		os.Exit(1)
	}

	// Evaluate each packet
	for _, pkt := range pkts {
		res := e.Match(pkt)
		printResult(pkt, res)
		fmt.Println()
	}

	// Run and print validations.
	printValidations(e.Validate())
}

func printResult(pkt *traffic.Packet, res model.Result) {
	fmt.Printf("%s %s:\n", res.Verdict, pkt)
	for _, r := range res.Trace {
		fmt.Printf(" - %s\n", r)
	}
}

func printValidations(validations []string) {
	fmt.Printf("Validations:\n")
	for _, v := range validations {
		fmt.Printf(" - %s\n", v)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
