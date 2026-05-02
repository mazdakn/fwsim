package main

import (
	"fmt"
	"os"

	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/olekukonko/tablewriter"
)

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
