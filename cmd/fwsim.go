package main

import (
	"fmt"
	"os"
	"sort"

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
	showCmd = &cobra.Command{
		Use:   "show",
		Short: "Display loaded firewall resources",
		Long:  `Display tables, sets, and rules loaded from the input directory.`,
	}
	showTablesCmd = &cobra.Command{
		Use:   "tables",
		Short: "Display all tables",
		Long:  `Display a summary of all loaded tables (name, order, default action, chain count, rule count).`,
		Run:   runShowTables,
	}
	showSetsCmd = &cobra.Command{
		Use:   "sets",
		Short: "Display all named sets",
		Long:  `Display a summary of all loaded named sets (name, type, members).`,
		Run:   runShowSets,
	}
	showRulesCmd = &cobra.Command{
		Use:   "rules",
		Short: "Display rules structure",
		Long:  `Display the hierarchical rules structure: tables, their chains, and each chain's rules.`,
		Run:   runShowRules,
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

	// Add show subcommand with its children
	rootCmd.AddCommand(showCmd)
	showCmd.AddCommand(showTablesCmd)
	showCmd.AddCommand(showSetsCmd)
	showCmd.AddCommand(showRulesCmd)
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

func printResult(mc *match.MatchContext) {
	fmt.Printf("Packet: %s  Verdict: %s\n", mc.Packet, mc.Verdict)
	if len(mc.Trace) == 0 {
		return
	}
	t := tablewriter.NewWriter(os.Stdout)
	t.SetHeader([]string{"Rule", "Action", "Hit Count"})
	t.SetBorder(true)
	t.SetRowLine(true)
	for _, r := range mc.Trace {
		t.Append([]string{
			r.String(),
			r.Action.String(),
			fmt.Sprintf("%d", r.PacketCount()),
		})
	}
	t.Render()
}

func printIntentResult(mc *match.MatchContext) {
	if mc.ExpectedVerdict != nil {
		if mc.VerdictMatches() {
			fmt.Printf("  [OK] Verdict matches expected: %s\n", mc.ExpectedVerdict)
		} else {
			fmt.Printf("  [FAIL] Verdict mismatch: expected %s, got %s\n", mc.ExpectedVerdict, mc.Verdict)
		}
	}
	if mc.HitByRule != "" {
		if mc.RuleMatches() {
			fmt.Printf("  [OK] Rule matched as expected: %s\n", mc.HitByRule)
		} else {
			fmt.Printf("  [FAIL] Rule mismatch: expected rule %q to match, but it did not\n", mc.HitByRule)
		}
	}
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

func runShowTables(cmd *cobra.Command, args []string) {
	r, err := config.ConfigFromFile(config.Config{InputDir: inputDir})
	if err != nil {
		logrus.WithError(err).Errorf("failed to load resources from %s", inputDir)
		os.Exit(1)
	}

	t := tablewriter.NewWriter(os.Stdout)
	t.SetHeader([]string{"Table", "Order", "Default Action", "Chains", "Rules"})
	t.SetBorder(true)
	t.SetRowLine(true)
	for _, tbl := range r.Tables {
		totalRules := 0
		for _, c := range tbl.Chains {
			totalRules += len(c.Rules)
		}
		defaultAction := "none"
		if tbl.DefaultRule != nil {
			defaultAction = tbl.DefaultRule.Action.String()
		}
		t.Append([]string{
			tbl.Name,
			fmt.Sprintf("%d", tbl.Order),
			defaultAction,
			fmt.Sprintf("%d", len(tbl.Chains)),
			fmt.Sprintf("%d", totalRules),
		})
	}
	t.Render()
}

func runShowSets(cmd *cobra.Command, args []string) {
	r, err := config.ConfigFromFile(config.Config{InputDir: inputDir})
	if err != nil {
		logrus.WithError(err).Errorf("failed to load resources from %s", inputDir)
		os.Exit(1)
	}

	if len(r.Sets) == 0 {
		fmt.Println("No named sets loaded.")
		return
	}

	names := make([]string, 0, len(r.Sets))
	for name := range r.Sets {
		names = append(names, name)
	}
	sort.Strings(names)

	t := tablewriter.NewWriter(os.Stdout)
	t.SetHeader([]string{"Name", "Type", "Members"})
	t.SetBorder(true)
	t.SetRowLine(true)
	for _, name := range names {
		s := r.Sets[name]
		members := ""
		if stringer, ok := s.(fmt.Stringer); ok {
			members = stringer.String()
		}
		t.Append([]string{name, string(s.Type()), members})
	}
	t.Render()
}

func runShowRules(cmd *cobra.Command, args []string) {
	r, err := config.ConfigFromFile(config.Config{InputDir: inputDir})
	if err != nil {
		logrus.WithError(err).Errorf("failed to load resources from %s", inputDir)
		os.Exit(1)
	}

	if len(r.Tables) == 0 {
		fmt.Println("No tables loaded.")
		return
	}

	for _, tbl := range r.Tables {
		defaultAction := "none"
		if tbl.DefaultRule != nil {
			defaultAction = tbl.DefaultRule.Action.String()
		}
		fmt.Printf("Table: %s  (order: %d, default action: %s)\n", tbl.Name, tbl.Order, defaultAction)

		chainNames := make([]string, 0, len(tbl.Chains))
		for name := range tbl.Chains {
			chainNames = append(chainNames, name)
		}
		// Place the entry chain first; all others follow in alphabetical order.
		entryChain := tbl.EntryChain()
		sort.SliceStable(chainNames, func(i, j int) bool {
			if chainNames[i] == entryChain {
				return true
			}
			if chainNames[j] == entryChain {
				return false
			}
			return chainNames[i] < chainNames[j]
		})

		for _, chainName := range chainNames {
			chain := tbl.Chains[chainName]
			label := chain.Name
			if chain.Name == entryChain {
				label += "  [entry]"
			}
			fmt.Printf("  Chain: %s\n", label)

			if len(chain.Rules) == 0 {
				fmt.Println("    (no rules)")
				continue
			}

			tw := tablewriter.NewWriter(os.Stdout)
			tw.SetHeader([]string{"Order", "Name", "Action", "Match"})
			tw.SetBorder(true)
			tw.SetRowLine(true)
			for _, rl := range chain.Rules {
				tw.Append([]string{
					fmt.Sprintf("%d", rl.Order),
					rl.Name,
					rl.Action.String(),
					rl.MatchConditions(),
				})
			}
			tw.Render()
		}
		fmt.Println()
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
