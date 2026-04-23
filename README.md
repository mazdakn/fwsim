fwsim
=====

fwsim is a small firewall simulator written in Go.
It loads firewall rules, named sets, and packets from YAML files, evaluates
traffic, and prints verdicts with rule hit traces.

Features
--------
- Evaluate one packet from CLI flags (evaluate command)
- Run multiple packets from YAML files (run command)
- YAML-based rules, sets, and packet definitions
- Named sets for IPs, ports, protocols, and IP:port tuples
- Validation output for rules that were never matched

Requirements
------------
- Go 1.24+

Project Layout
--------------
  cmd/fwsim.go            CLI entrypoint
  pkg/                    Engine, parser, matcher, sets, rules
  hack/sample/            Example input data
    tables/
    sets/
    packets/

Input Directory Structure
-------------------------
fwsim expects an input directory with:

  <dir>/
    tables/     # one or more .yaml/.yml files (required)
    sets/       # optional .yaml/.yml files
    packets/    # .yaml/.yml files (required for "run")

Build
-----
From the repo root:

  go build -o bin/fwsim ./cmd/fwsim.go

Or via Make:

  make build

Run Tests
---------
  go test ./... -vet=all -race -cover

Or via Make:

  make test

CLI Usage
---------
Base flag (required for all commands):

  -d, --dir <path>   input directory containing tables/, sets/, packets/

Commands
--------

1) Evaluate a single packet from flags:

  fwsim -d ./hack/sample evaluate \
    --src-addr 192.168.1.5 \
    --src-port 30000 \
    --dst-addr 1.1.1.1 \
    --dst-port 80 \
    --proto tcp

2) Evaluate packets from YAML files:

  fwsim -d ./hack/sample run

Protocol values:
  - Name:   tcp, udp, icmp
  - Number: 0-255

Table Config (tables/*.yaml)
----------------------------
Top-level keys:
  name: table name
  order: table evaluation order (lower first, default 0)
  default_action: Accept | Drop | Pass
                 (Pass means continue evaluation in the next table)
  rules: list of rule entries

Each rule may include:
  name        Human-readable label
  order       Evaluation order (lower first)
  action      Accept | Drop | Pass
              (Pass means "continue evaluation in the next table")
  src / dst:
    net:          list of CIDRs
    port:         list of port numbers
    sets:         list of named sets (ip, port, ip:port) that must all match
  not_src / not_dst  (same shape as src/dst – negate the match)
  proto:      list of protocol names or numbers
  not_proto:  list of protocols to exclude

Tables are loaded from every YAML file under `tables/` and sorted by `order`
ascending. Packet evaluation continues table-by-table until a rule/default
returns Accept or Drop; if all tables return Pass, the final verdict is `no match`.

Example (hack/sample/tables/simple.yaml):

  name: main
  order: 10
  rules:
    - name: allow-192.168-to-1.1.1.1
      src:
        net: [192.168.1.0/24]
        port: [30000]
      dst:
        net: [1.1.1.1/32]
        port: [80]
      proto: [tcp]
      action: Accept
    - name: deny-access-http
      dst:
        net: [1.1.1.1/32]
        port: [80]
      proto: [tcp]
      action: Drop
  default_action: Accept

Set Config (sets/*.yaml)
------------------------
One set per file:

  name:    <set-name>
  type:    ip | port | proto | ipport
  members: [values...]

Examples:

  # IP set
  name: trusted-ips
  type: ip
  members:
    - 192.168.1.0/24
    - 10.0.0.0/8

  # Port set
  name: web-ports
  type: port
  members: ["80", "443", "8080"]

  # Protocol set
  name: allowed-protos
  type: proto
  members: [tcp, udp]

Packet Config (packets/*.yaml)
------------------------------
One packet per file:

  metadata:
    name: <human-readable label>
  src_addr: <IP>
  dst_addr: <IP>
  proto:    <name or number>
  src_port: <number>
  dst_port: <number>

Example (hack/sample/packets/access-app1.yaml):

  metadata:
    name: access app1
  src_addr: 10.0.0.1
  dst_addr: 2.2.2.2
  proto: tcp
  src_port: 12345
  dst_port: 8080

Output
------
For each packet fwsim prints:

  Packet: <summary>   Verdict: Accept|Drop|no match

  +--------------------------+--------+-----------+
  | Rule                     | Action | Hit Count |
  +--------------------------+--------+-----------+
  | allow-192.168-to-1.1.1.1 | Accept | 1         |
  +--------------------------+--------+-----------+

After all packets, a validation table lists any rules that were never matched:

  +------------------+
  | Validations      |
  +------------------+
  | Rule 2 not used  |
  +------------------+
