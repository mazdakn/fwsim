package main

import (
	"fmt"
	"os"

	"github.com/mazdakn/fwsim/pkg/config"
	"github.com/mazdakn/fwsim/pkg/engine"
	"github.com/mazdakn/fwsim/pkg/port"
	"github.com/mazdakn/fwsim/pkg/proto"
	"github.com/mazdakn/fwsim/pkg/validator"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	srcAddr  string
	dstAddr  string
	protoStr string
	srcPort  uint
	dstPort  uint

	evaluateCmd = &cobra.Command{
		Use:   "evaluate",
		Short: "Evaluate a packet against firewall rules",
		Long:  `Evaluate a packet against firewall rules and return a verdict.`,
		Run:   runEvaluate,
	}
)

func init() {
	rootCmd.AddCommand(evaluateCmd)

	evaluateCmd.Flags().StringVar(&srcAddr, "src-addr", "", "source IP address")
	evaluateCmd.Flags().StringVar(&dstAddr, "dst-addr", "", "destination IP address")
	evaluateCmd.Flags().StringVar(&protoStr, "proto", "0", "IP protocol number or name (tcp, udp, icmp)")
	evaluateCmd.Flags().UintVar(&srcPort, "src-port", 0, "source port")
	evaluateCmd.Flags().UintVar(&dstPort, "dst-port", 0, "destination port")

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
	r, err := config.ConfigFromFile(config.Config{
		InputDir: inputDir,
	})
	if err != nil {
		logrus.WithError(err).Errorf("failed to load resources from %s", inputDir)
		os.Exit(1)
	}
	r.Intents = append(r.Intents, &config.Intent{Packet: *pkt})
	e := engine.New(r)

	// Match packet against rules
	results := e.RunTests()
	printResult(results[0])
	fmt.Println()

	// Run and print validations.
	printValidations(e.Validate())
}
