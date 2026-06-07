fwsim
=====

fwsim is a Go-based firewall simulator for evaluating traffic against YAML-defined
tables, chains, rules, named sets, and ordered intents.

At a high level, the codebase provides:
- a CLI for evaluating single packets or ordered intent sequences
- a CLI path for replaying packets from `.pcap` captures through the rule engine
- a rule engine with table/chain traversal, named sets, and verdict tracing
- configuration loaders and validators for firewall resources
- optional connection tracking for `new` and `established` flow matching

Repository layout:
- `cmd/` - CLI commands and terminal output
- `pkg/` - engine, config parsing, rule matching, sets, validation, conntrack
- `hack/` - sample inputs, including a stateful conntrack example
- `tests/` - integration-style behavior tests

For command usage, configuration reference, examples, and connection-tracking
details, see [docs.md](docs.md).
