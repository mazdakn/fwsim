package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/mazdakn/fwsim/pkg/config"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var graphCmd = &cobra.Command{
	Use:   "graph",
	Short: "Export firewall structure as a DOT graph",
	Long: `Export tables, chains, and rules as a directed graph in DOT format.

The output can be rendered by Graphviz (dot, neato, etc.) or any tool that
understands the DOT language (e.g. xdot, Gephi, yEd with DOT import).

Example usage:
  fwsim graph -d ./examples | dot -Tsvg -o rules.svg`,
	Run: runGraph,
}

func init() {
	rootCmd.AddCommand(graphCmd)
}

func runGraph(cmd *cobra.Command, args []string) {
	r, err := config.ConfigFromFile(config.Config{InputDir: inputDir})
	if err != nil {
		logrus.WithError(err).Errorf("failed to load resources from %s", inputDir)
		os.Exit(1)
	}

	if len(r.Tables) == 0 {
		fmt.Println("// No tables loaded.")
		return
	}

	fmt.Println("digraph fwsim {")
	fmt.Println(`  rankdir=LR;`)
	fmt.Println(`  node [fontname="Helvetica"];`)
	fmt.Println(`  edge [fontname="Helvetica",fontsize=10];`)
	fmt.Println()

	for i, tbl := range r.Tables {
		entryChain := tbl.EntryChain()

		// Each table becomes a labelled cluster subgraph.
		fmt.Printf("  subgraph cluster_%d {\n", i)
		fmt.Printf("    label=%q;\n", fmt.Sprintf("Table: %s  (order: %d)", tbl.Name, tbl.Order))
		fmt.Println(`    style=filled;`)
		fmt.Println(`    color=lightgrey;`)
		fmt.Println(`    node [style=filled,color=white];`)
		fmt.Println()

		// Sort chain names for deterministic output; entry chain first.
		chainNames := make([]string, 0, len(tbl.Chains))
		for name := range tbl.Chains {
			chainNames = append(chainNames, name)
		}
		sort.SliceStable(chainNames, func(a, b int) bool {
			if chainNames[a] == entryChain {
				return true
			}
			if chainNames[b] == entryChain {
				return false
			}
			return chainNames[a] < chainNames[b]
		})

		for _, chainName := range chainNames {
			nodeID := chainNodeID(tbl.Name, chainName)
			if chainName == entryChain {
				// Entry chain rendered with a double-circle to make it stand out.
				fmt.Printf("    %s [label=%q,shape=doublecircle,color=lightblue,style=filled];\n",
					nodeID, chainName+" [entry]")
			} else {
				fmt.Printf("    %s [label=%q,shape=box];\n", nodeID, chainName)
			}
		}
		fmt.Println("  }")
		fmt.Println()

		// Per-table default-action terminal node (outside the cluster so it is
		// visually distinct from regular chains).
		defaultAction := "none"
		if tbl.DefaultRule != nil {
			defaultAction = tbl.DefaultRule.Action.String()
		}
		defaultNodeID := fmt.Sprintf("node_%d_default", i)
		defaultColor := terminalColor(defaultAction)
		fmt.Printf("  %s [label=%q,shape=diamond,style=filled,color=%s];\n",
			defaultNodeID,
			fmt.Sprintf("%s\ndefault: %s", tbl.Name, defaultAction),
			defaultColor)
		fmt.Println()

		// Edges: Jump rules create directed edges between chains; all chains
		// that fall through without a terminal verdict point to the default node.
		for _, chainName := range chainNames {
			chain := tbl.Chains[chainName]
			srcNodeID := chainNodeID(tbl.Name, chainName)

			for _, rl := range chain.Rules {
				if rl.Action != rule.Jump {
					continue
				}
				dstNodeID := chainNodeID(tbl.Name, rl.JumpTarget)
				edgeLabel := rl.Name
				if edgeLabel == "" {
					edgeLabel = rl.MatchConditions()
				}
				fmt.Printf("  %s -> %s [label=%q];\n", srcNodeID, dstNodeID, edgeLabel)
			}

			// Dashed fall-through edge from each chain to the table's default action.
			fmt.Printf("  %s -> %s [style=dashed,label=\"fall-through\"];\n", srcNodeID, defaultNodeID)
		}
		fmt.Println()
	}

	fmt.Println("}")
}

// chainNodeID returns a safe DOT node identifier for a chain within a table.
func chainNodeID(tableName, chainName string) string {
	return fmt.Sprintf("%q", tableName+"__"+chainName)
}

// terminalColor returns a fill color suitable for a terminal-action node.
func terminalColor(action string) string {
	switch action {
	case "Accept":
		return "palegreen"
	case "Drop":
		return "lightcoral"
	default:
		return "lightyellow"
	}
}
