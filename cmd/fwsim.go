package main

import (
	"fmt"
	"os"

	"github.com/mazdakn/fwsim/pkg/config"
	"github.com/mazdakn/fwsim/pkg/engine"
	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/port"
	"github.com/mazdakn/fwsim/pkg/proto"
	"github.com/mazdakn/fwsim/pkg/validator"
	"github.com/olekukonko/tablewriter"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	inputDir string
	rootCmd  = &cobra.Command{
		Use:   "fwsim",
		Short: "Firewall simulator",
		Long:  `fwsim is a firewall simulator that processes rules and packets from an input directory.`,
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
	srcAddr  string
	dstAddr  string
	protoStr string
	srcPort  uint
	dstPort  uint
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&inputDir, "dir", "d", "", "base input directory with tables/, sets/, and packets/ subdirectories")
	if err := rootCmd.MarkPersistentFlagRequired("dir"); err != nil {
		panic(err)
	}

	// Add evaluate subcommand
	rootCmd.AddCommand(evaluateCmd)

	// Add flags for evaluate command
	evaluateCmd.Flags().StringVar(&srcAddr, "src-addr", "", "source IP address")
	evaluateCmd.Flags().StringVar(&dstAddr, "dst-addr", "", "destination IP address")
	evaluateCmd.Flags().StringVar(&protoStr, "proto", "0", "IP protocol number or name (tcp, udp, icmp)")
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
}

func runEvaluate(cmd *cobra.Command, args []string) {
	p, err := proto.Parse(protoStr)
	if err != nil {
		logrus.WithError(err).Errorf("invalid protocol: %s", protoStr)
		os.Exit(1)
	}

	// TODO: fix validation. Need to validate before initing the struct
	pkt := &config.Packet{
		SrcAddr: srcAddr,
		DstAddr: dstAddr,
		Proto:   *p,
		SrcPort: port.Port{Number: uint16(srcPort)},
		DstPort: port.Port{Number: uint16(dstPort)},
	}

	if err := validator.ValidateStructFields(pkt); err != nil {
		logrus.WithError(err).Errorf("invalid packet configuration")
		os.Exit(1)
	}

	// Create engine and load rules
	resources, err := config.ConfigFromFile(config.Config{
		InputDir: inputDir,
	})
	if err != nil {
		logrus.WithError(err).Errorf("failed to load resources from %s", inputDir)
		os.Exit(1)
	}
	e := engine.New(resources)

	// Match packet against rules
	m := match.NewWithPacket(pkt.ToPacket())
	e.RunTest(m)
	printResult(m)
	fmt.Println()

	// Run and print validations.
	printValidations(e.Validate())
}

func runPackets(cmd *cobra.Command, args []string) {
	// Create engine and load rules
	resources, err := config.ConfigFromFile(config.Config{
		InputDir:    inputDir,
		LoadPackets: true,
	})
	if err != nil {
		logrus.WithError(err).Errorf("failed to load resources from %s", inputDir)
		os.Exit(1)
	}
	e := engine.New(resources)

	// Evaluate each packet
	for _, m := range e.RunTests() {
		printResult(m)
		fmt.Println()
	}

	// Run and print validations.
	printValidations(e.Validate())
}

func printResult(m *match.MatchContext) {
	fmt.Printf("Packet: %s  Verdict: %s\n", m.Packet, m.Verdict)
	if len(m.Trace) == 0 {
		return
	}
	t := tablewriter.NewWriter(os.Stdout)
	t.SetHeader([]string{"Rule", "Action", "Hit Count"})
	t.SetBorder(true)
	t.SetRowLine(true)
	for _, r := range m.Trace {
		t.Append([]string{
			r.String(),
			r.Action.String(),
			fmt.Sprintf("%d", r.PacketCount()),
		})
	}
	t.Render()
}

func printValidations(validations []string) {
	if len(validations) == 0 {
		return
	}
	t := tablewriter.NewWriter(os.Stdout)
	t.SetHeader([]string{"Validations"})
	t.SetBorder(true)
	t.SetRowLine(true)
	for _, v := range validations {
		t.Append([]string{v})
	}
	t.Render()
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
