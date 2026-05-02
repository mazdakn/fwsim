package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

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

// crossEdge holds a directed edge that crosses subgraph cluster boundaries.
// DOT requires such edges to be declared outside all clusters.
type crossEdge struct {
	src, dst, label, style, color string
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

	// Cross-cluster edges are collected during the subgraph pass and emitted
	// afterwards; DOT does not handle intra-cluster edge declarations for edges
	// that cross cluster boundaries.
	var crossEdges []crossEdge

	for i, tbl := range r.Tables {
		entryChain := tbl.EntryChain()
		defaultAction := "none"
		if tbl.DefaultRule != nil {
			defaultAction = tbl.DefaultRule.Action.String()
		}
		defNodeID := tableDefaultNodeID(tbl.Name)

		// Each table becomes a labelled cluster subgraph.
		fmt.Printf("  subgraph cluster_t%d {\n", i)
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

		for j, chainName := range chainNames {
			chain := tbl.Chains[chainName]
			headerID := chainHeaderNodeID(tbl.Name, chainName)

			// Each chain becomes a nested cluster containing its rule nodes.
			fmt.Printf("    subgraph cluster_t%d_c%d {\n", i, j)
			chainLabel := "Chain: " + chainName
			if chainName == entryChain {
				chainLabel += " [entry]"
			}
			fmt.Printf("      label=%q;\n", chainLabel)
			fmt.Println(`      style=filled;`)
			fmt.Println(`      color=lightyellow;`)
			fmt.Println()

			// Chain header node – acts as the entry point for incoming jump edges.
			headerShape := "circle"
			headerColor := "lightblue"
			if chainName == entryChain {
				headerShape = "doublecircle"
			}
			fmt.Printf("      %s [label=%q,shape=%s,color=%s,style=filled];\n",
				headerID, chainName, headerShape, headerColor)

			if len(chain.Rules) > 0 {
				prevID := headerID
				for k, rl := range chain.Rules {
					rID := ruleNodeID(tbl.Name, chainName, k)
					fmt.Printf("      %s [label=%q,shape=box,color=%s,style=filled];\n",
						rID, ruleNodeLabel(rl), actionNodeColor(rl.Action))

					// Sequential flow edge within the chain cluster.
					fmt.Printf("      %s -> %s;\n", prevID, rID)
					prevID = rID

					// Jump edges cross cluster boundaries – defer until after subgraphs.
					if rl.Action == rule.Jump {
						crossEdges = append(crossEdges, crossEdge{
							src:   rID,
							dst:   chainHeaderNodeID(tbl.Name, rl.JumpTarget),
							label: "jump -> " + rl.JumpTarget,
							style: "bold",
							color: "blue",
						})
					}
				}

				// Fall-through edge from the last rule to the table default node.
				crossEdges = append(crossEdges, crossEdge{
					src:   prevID,
					dst:   defNodeID,
					label: "fall-through",
					style: "dashed",
					color: "black",
				})
			} else {
				// Empty chain falls straight through to the table default.
				crossEdges = append(crossEdges, crossEdge{
					src:   headerID,
					dst:   defNodeID,
					label: "fall-through",
					style: "dashed",
					color: "black",
				})
			}

			fmt.Println("    }")
			fmt.Println()
		}

		fmt.Println("  }")
		fmt.Println()

		// Per-table default-action terminal node (outside the cluster so it is
		// visually distinct from regular chains).
		defColor := terminalColor(defaultAction)
		fmt.Printf("  %s [label=%q,shape=diamond,style=filled,color=%s];\n",
			defNodeID,
			fmt.Sprintf("%s\ndefault: %s", tbl.Name, defaultAction),
			defColor)
		fmt.Println()
	}

	// Emit cross-cluster edges after all subgraphs have been declared.
	for _, e := range crossEdges {
		fmt.Printf("  %s -> %s [label=%q,style=%s,color=%s];\n",
			e.src, e.dst, e.label, e.style, e.color)
	}

	fmt.Println("}")
}

// chainHeaderNodeID returns a unique DOT node identifier for the entry point
// of a chain (the synthetic header node that incoming jump edges target).
func chainHeaderNodeID(tableName, chainName string) string {
	return fmt.Sprintf("ch_%s__%s", sanitizeDOTID(tableName), sanitizeDOTID(chainName))
}

// ruleNodeID returns a unique DOT node identifier for the k-th rule of a chain.
func ruleNodeID(tableName, chainName string, k int) string {
	return fmt.Sprintf("rule_%s__%s__%d", sanitizeDOTID(tableName), sanitizeDOTID(chainName), k)
}

// tableDefaultNodeID returns a unique DOT node identifier for a table's
// default-action terminal node.
func tableDefaultNodeID(tableName string) string {
	return fmt.Sprintf("def_%s", sanitizeDOTID(tableName))
}

// sanitizeDOTID replaces every character that is not alphanumeric with an
// underscore so the result is safe to use as an unquoted DOT identifier.
func sanitizeDOTID(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, s)
}

// ruleNodeLabel builds a compact multi-line label for a rule node.
func ruleNodeLabel(rl *rule.Rule) string {
	name := rl.Name
	if name == "" {
		name = fmt.Sprintf("#%d", rl.Order)
	}
	action := rl.Action.String()
	if rl.Action == rule.Jump {
		action = "Jump -> " + rl.JumpTarget
	}
	return fmt.Sprintf("%s\n%s\n%s", name, action, rl.MatchConditions())
}

// actionNodeColor returns the fill color for a rule node based on its action.
func actionNodeColor(a rule.Action) string {
	switch a {
	case rule.Accept:
		return "palegreen"
	case rule.Drop:
		return "lightcoral"
	case rule.Jump:
		return "lightblue"
	case rule.Return:
		return "lightyellow"
	case rule.Pass:
		return "lightsalmon"
	default:
		return "white"
	}
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
