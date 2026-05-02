package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/mazdakn/fwsim/pkg/config"
	"github.com/olekukonko/tablewriter"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
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

func init() {
	rootCmd.AddCommand(showCmd)
	showCmd.AddCommand(showTablesCmd)
	showCmd.AddCommand(showSetsCmd)
	showCmd.AddCommand(showRulesCmd)
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
