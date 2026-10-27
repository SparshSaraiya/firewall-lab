# Firewall fundamentals lab

Hands-on iptables lab built for a Cyber Defense (firewall / vulnerability management) internship interview.
Everything runs in three Linux network namespaces (client, firewall, server) inside WSL2. Nothing touches the host network.

| Exercise | Topic | Script | Evidence |
|---|---|---|---|
| 1 | Default deny, SSH from one IP, HTTPS only, nmap before/after | `notes.md` | `notes.md` |
| 2 | Stateful vs stateless filtering | `scripts/ex2_stateful.sh` | `evidence/ex2_stateful.txt` |
| 3 | Rule order / shadowed rules | `scripts/ex3_rule_order.sh` | `evidence/ex3_rule_order.txt` |
| 4 | Egress filtering | `scripts/ex4_egress.sh` | `evidence/ex4_egress.txt` |
| 5 | Logging dropped packets | `scripts/ex5_logging.sh` | `evidence/ex5_logging.txt`, `samples/fw-drops.log` |
| 6 | Troubleshooting method | `TROUBLESHOOTING.md` | |
| 7 | Log parser + ruleset auditor | `scripts/parse_fw_logs.py`, `scripts/audit_rules.py` | `evidence/ex7_*.txt` |

Build the lab: `wsl -d Ubuntu -u root -- bash -s < lab-up.sh`
Run the tools: `python scripts/parse_fw_logs.py samples/fw-drops.log` and `python scripts/audit_rules.py samples/risky.rules`
