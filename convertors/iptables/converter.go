// Package iptables converts iptables-save output into the fwsim internal
// policy model ([]*table.Table).
//
// Supported iptables-save constructs:
//   - Table declarations:  *tablename
//   - Chain policies:      :CHAINNAME POLICY [packets:bytes]
//   - Append rules:        -A CHAINNAME [options]
//   - COMMIT directive
//
// Supported per-rule flags:
//
//	-p / ! -p          protocol (tcp, udp, icmp, or numeric)
//	-s / ! -s          source address (CIDR or plain IP)
//	-d / ! -d          destination address (CIDR or plain IP)
//	-i / ! -i          input (ingress) interface
//	-o / ! -o          output (egress) interface
//	--sport / ! --sport  source port (number, range start:end, or service name)
//	--dport / ! --dport  destination port
//	-m multiport --sports  comma-separated source ports/ranges
//	-m multiport --dports  comma-separated destination ports/ranges
//	-j TARGET          jump target (ACCEPT, DROP, RETURN, or chain name)
package iptables

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mazdakn/fwsim/pkg/proto"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/table"
)

// Convert parses iptables-save formatted text and returns one *table.Table per
// iptables table found in the input. Rules within each chain are ordered by
// their line of appearance in the input.
func Convert(input string) ([]*table.Table, error) {
	type chainEntry struct {
		policy string // ACCEPT, DROP, RETURN, or empty
		rules  []*rule.Rule
	}
	type tableEntry struct {
		chains map[string]*chainEntry
		order  []string // chain insertion order
	}

	tables := map[string]*tableEntry{}
	tableOrder := []string{}
	var currentTable string
	ruleOrder := uint64(0)

	scanner := bufio.NewScanner(strings.NewReader(input))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		switch {
		case strings.HasPrefix(line, "*"):
			// Table declaration: *filter
			currentTable = line[1:]
			if _, exists := tables[currentTable]; !exists {
				tables[currentTable] = &tableEntry{
					chains: map[string]*chainEntry{},
				}
				tableOrder = append(tableOrder, currentTable)
			}

		case strings.HasPrefix(line, ":"):
			// Chain policy: :INPUT ACCEPT [0:0]
			if currentTable == "" {
				return nil, fmt.Errorf("chain policy before table declaration: %q", line)
			}
			parts := strings.Fields(line[1:]) // drop the leading ':'
			if len(parts) < 2 {
				return nil, fmt.Errorf("malformed chain policy line: %q", line)
			}
			chainName := parts[0]
			policy := parts[1]
			tbl := tables[currentTable]
			if _, exists := tbl.chains[chainName]; !exists {
				tbl.chains[chainName] = &chainEntry{policy: policy}
				tbl.order = append(tbl.order, chainName)
			} else {
				tbl.chains[chainName].policy = policy
			}

		case strings.HasPrefix(line, "-A "):
			// Rule: -A CHAINNAME [options]
			if currentTable == "" {
				return nil, fmt.Errorf("rule before table declaration: %q", line)
			}
			tokens := tokenize(line[3:]) // strip "-A "
			if len(tokens) == 0 {
				return nil, fmt.Errorf("malformed rule line: %q", line)
			}
			chainName := tokens[0]
			ruleOrder++
			r, err := parseRule(tokens[1:], ruleOrder)
			if err != nil {
				return nil, fmt.Errorf("rule in chain %q: %w", chainName, err)
			}
			tbl := tables[currentTable]
			if _, exists := tbl.chains[chainName]; !exists {
				tbl.chains[chainName] = &chainEntry{}
				tbl.order = append(tbl.order, chainName)
			}
			tbl.chains[chainName].rules = append(tbl.chains[chainName].rules, r)

		case line == "COMMIT":
			currentTable = ""
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading iptables input: %w", err)
	}

	// Build table.Table objects preserving declaration order.
	result := make([]*table.Table, 0, len(tableOrder))
	for i, tblName := range tableOrder {
		entry := tables[tblName]

		// Determine default action from the first chain's policy, falling back
		// to Accept when no chain policy is declared.
		defaultAction := rule.Accept
		if len(entry.order) > 0 {
			firstChain := entry.chains[entry.order[0]]
			if da, err := iptablesActionToInternal(firstChain.policy); err == nil {
				defaultAction = da
			}
		}

		tbl := table.New(tblName, uint64(i), defaultAction)

		for _, chainName := range entry.order {
			chain := table.NewChain(chainName)
			for _, r := range entry.chains[chainName].rules {
				chain.AddRule(r)
			}
			tbl.AddChain(chain)
		}

		result = append(result, tbl)
	}

	return result, nil
}

// tokenize splits a rule line into tokens.
func tokenize(s string) []string {
	return strings.Fields(s)
}

// parseRule converts the option tokens of a single iptables rule (everything
// after "-A CHAINNAME") into a *rule.Rule.
func parseRule(tokens []string, order uint64) (*rule.Rule, error) {
	r := rule.New(rule.WithOrder(order))

	// We pre-scan for any bare "!" that immediately precedes a flag to set the
	// negate flag for the following option.
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]

		negate := false
		if tok == "!" {
			negate = true
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("trailing '!' with no flag")
			}
			tok = tokens[i]
		}

		switch tok {
		case "-p", "--protocol":
			val, err := next(tokens, &i, tok)
			if err != nil {
				return nil, err
			}
			p, err := proto.Parse(val)
			if err != nil {
				return nil, fmt.Errorf("invalid protocol %q: %w", val, err)
			}
			if negate {
				if r.NotProto == nil {
					r.NotProto = set.NewProtoSet()
				}
				if err := r.NotProto.Add(*p); err != nil {
					return nil, err
				}
			} else {
				if r.Proto == nil {
					r.Proto = set.NewProtoSet()
				}
				if err := r.Proto.Add(*p); err != nil {
					return nil, err
				}
			}

		case "-s", "--source", "--src":
			val, err := next(tokens, &i, tok)
			if err != nil {
				return nil, err
			}
			cidr, err := normalizeCIDR(val)
			if err != nil {
				return nil, fmt.Errorf("invalid source address %q: %w", val, err)
			}
			if negate {
				if r.NotSource.Net == nil {
					r.NotSource.Net = set.NewIPSet()
				}
				if err := r.NotSource.Net.Add(cidr); err != nil {
					return nil, err
				}
			} else {
				if r.Source.Net == nil {
					r.Source.Net = set.NewIPSet()
				}
				if err := r.Source.Net.Add(cidr); err != nil {
					return nil, err
				}
			}

		case "-d", "--destination", "--dst":
			val, err := next(tokens, &i, tok)
			if err != nil {
				return nil, err
			}
			cidr, err := normalizeCIDR(val)
			if err != nil {
				return nil, fmt.Errorf("invalid destination address %q: %w", val, err)
			}
			if negate {
				if r.NotDestination.Net == nil {
					r.NotDestination.Net = set.NewIPSet()
				}
				if err := r.NotDestination.Net.Add(cidr); err != nil {
					return nil, err
				}
			} else {
				if r.Destination.Net == nil {
					r.Destination.Net = set.NewIPSet()
				}
				if err := r.Destination.Net.Add(cidr); err != nil {
					return nil, err
				}
			}

		case "-i", "--in-interface":
			val, err := next(tokens, &i, tok)
			if err != nil {
				return nil, err
			}
			if negate {
				if r.NotSource.Iface == nil {
					r.NotSource.Iface = set.NewIfaceSet()
				}
				if err := r.NotSource.Iface.Add(val); err != nil {
					return nil, err
				}
			} else {
				if r.Source.Iface == nil {
					r.Source.Iface = set.NewIfaceSet()
				}
				if err := r.Source.Iface.Add(val); err != nil {
					return nil, err
				}
			}

		case "-o", "--out-interface":
			val, err := next(tokens, &i, tok)
			if err != nil {
				return nil, err
			}
			if negate {
				if r.NotDestination.Iface == nil {
					r.NotDestination.Iface = set.NewIfaceSet()
				}
				if err := r.NotDestination.Iface.Add(val); err != nil {
					return nil, err
				}
			} else {
				if r.Destination.Iface == nil {
					r.Destination.Iface = set.NewIfaceSet()
				}
				if err := r.Destination.Iface.Add(val); err != nil {
					return nil, err
				}
			}

		case "--sport", "--source-port":
			val, err := next(tokens, &i, tok)
			if err != nil {
				return nil, err
			}
			ports, err := parsePorts(val)
			if err != nil {
				return nil, fmt.Errorf("invalid source port %q: %w", val, err)
			}
			if negate {
				if r.NotSource.Port == nil {
					r.NotSource.Port = set.NewPortSet()
				}
				for _, p := range ports {
					if err := r.NotSource.Port.Add(p); err != nil {
						return nil, err
					}
				}
			} else {
				if r.Source.Port == nil {
					r.Source.Port = set.NewPortSet()
				}
				for _, p := range ports {
					if err := r.Source.Port.Add(p); err != nil {
						return nil, err
					}
				}
			}

		case "--dport", "--destination-port":
			val, err := next(tokens, &i, tok)
			if err != nil {
				return nil, err
			}
			ports, err := parsePorts(val)
			if err != nil {
				return nil, fmt.Errorf("invalid destination port %q: %w", val, err)
			}
			if negate {
				if r.NotDestination.Port == nil {
					r.NotDestination.Port = set.NewPortSet()
				}
				for _, p := range ports {
					if err := r.NotDestination.Port.Add(p); err != nil {
						return nil, err
					}
				}
			} else {
				if r.Destination.Port == nil {
					r.Destination.Port = set.NewPortSet()
				}
				for _, p := range ports {
					if err := r.Destination.Port.Add(p); err != nil {
						return nil, err
					}
				}
			}

		case "--sports", "--source-ports":
			// -m multiport --sports port1,port2,...
			val, err := next(tokens, &i, tok)
			if err != nil {
				return nil, err
			}
			if negate {
				if r.NotSource.Port == nil {
					r.NotSource.Port = set.NewPortSet()
				}
				if err := addMultiports(r.NotSource.Port, val); err != nil {
					return nil, fmt.Errorf("invalid source ports %q: %w", val, err)
				}
			} else {
				if r.Source.Port == nil {
					r.Source.Port = set.NewPortSet()
				}
				if err := addMultiports(r.Source.Port, val); err != nil {
					return nil, fmt.Errorf("invalid source ports %q: %w", val, err)
				}
			}

		case "--dports", "--destination-ports":
			// -m multiport --dports port1,port2,...
			val, err := next(tokens, &i, tok)
			if err != nil {
				return nil, err
			}
			if negate {
				if r.NotDestination.Port == nil {
					r.NotDestination.Port = set.NewPortSet()
				}
				if err := addMultiports(r.NotDestination.Port, val); err != nil {
					return nil, fmt.Errorf("invalid destination ports %q: %w", val, err)
				}
			} else {
				if r.Destination.Port == nil {
					r.Destination.Port = set.NewPortSet()
				}
				if err := addMultiports(r.Destination.Port, val); err != nil {
					return nil, fmt.Errorf("invalid destination ports %q: %w", val, err)
				}
			}

		case "-j", "--jump":
			val, err := next(tokens, &i, tok)
			if err != nil {
				return nil, err
			}
			action, err := iptablesActionToInternal(val)
			if err != nil {
				// Unknown action → treat as a jump to a user-defined chain.
				r.Action = rule.Jump
				r.JumpTarget = val
			} else {
				r.Action = action
			}

		case "-m", "--match":
			// Module name; skip the value — the module's own flags are parsed
			// when we encounter them (--sport, --dport, --sports, --dports).
			if _, err := next(tokens, &i, tok); err != nil {
				return nil, err
			}

		case "--tcp-flags", "--syn", "--tcp-option",
			"--icmp-type", "--icmpv6-type",
			"--state", "--ctstate", "--conntrack",
			"--uid-owner", "--gid-owner",
			"--limit", "--limit-burst",
			"--log-prefix", "--log-level",
			"--to-destination", "--to-source", "--to-ports",
			"--set-xmark", "--restore-mark", "--save-mark",
			"--comment":
			// Recognised but unsupported flags: consume value token(s) and
			// continue so we don't error on rules that use them.
			if i+1 < len(tokens) && !strings.HasPrefix(tokens[i+1], "-") && tokens[i+1] != "!" {
				i++
				// --tcp-flags takes two value tokens
				if tok == "--tcp-flags" && i+1 < len(tokens) && !strings.HasPrefix(tokens[i+1], "-") {
					i++
				}
			}

		default:
			// Silently skip unrecognised flags that start with '-'; consume
			// any following non-flag token as the flag's argument.
			if strings.HasPrefix(tok, "-") {
				if i+1 < len(tokens) && !strings.HasPrefix(tokens[i+1], "-") && tokens[i+1] != "!" {
					i++
				}
			}
		}
	}

	return r, nil
}

// next advances i by 1 and returns the token at that position, or an error if
// there is no next token.
func next(tokens []string, i *int, flag string) (string, error) {
	*i++
	if *i >= len(tokens) {
		return "", fmt.Errorf("flag %q requires an argument", flag)
	}
	return tokens[*i], nil
}

// iptablesActionToInternal maps an iptables target name to an internal Action.
func iptablesActionToInternal(target string) (rule.Action, error) {
	switch strings.ToUpper(target) {
	case "ACCEPT":
		return rule.Accept, nil
	case "DROP", "REJECT":
		return rule.Drop, nil
	case "RETURN":
		return rule.Return, nil
	default:
		return rule.Accept, fmt.Errorf("unknown target: %s", target)
	}
}

// normalizeCIDR ensures an IP address or CIDR string has a prefix length,
// returning a *net.IPNet.
func normalizeCIDR(s string) (*net.IPNet, error) {
	// Already in CIDR notation.
	if strings.Contains(s, "/") {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		return ipnet, nil
	}
	// Plain IP — determine address family and append host prefix.
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", s)
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	_, ipnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", s, bits))
	if err != nil {
		return nil, err
	}
	return ipnet, nil
}

// parsePorts parses a single port value as used by --sport/--dport.
// iptables uses ":" as the range separator; we normalise to the internal
// "start-end" format understood by set.PortSet.Add.
// Returns a slice of strings suitable for PortSet.Add.
func parsePorts(s string) ([]string, error) {
	if strings.Contains(s, ":") {
		// Range: convert "1024:65535" → "1024-65535"
		parts := strings.SplitN(s, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid port range: %s", s)
		}
		start, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid range start %q: %w", parts[0], err)
		}
		end, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid range end %q: %w", parts[1], err)
		}
		return []string{fmt.Sprintf("%d-%d", start, end)}, nil
	}
	return []string{s}, nil
}

// addMultiports adds comma-separated ports/ranges from a multiport match to ps.
func addMultiports(ps *set.PortSet, val string) error {
	for _, part := range strings.Split(val, ",") {
		ports, err := parsePorts(strings.TrimSpace(part))
		if err != nil {
			return err
		}
		for _, p := range ports {
			if err := ps.Add(p); err != nil {
				return err
			}
		}
	}
	return nil
}
