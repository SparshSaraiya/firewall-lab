# Firewall Lab Notes

Status: all lab runs and scripts are built and their output is saved in `evidence/`.
**Not yet done: the practice round** (writing rules yourself, quizzes, Exercise 6 troubleshooting). Sections for the interview and weak spots stay empty until then, on purpose.

## Lab setup
- WSL2 + Ubuntu on Windows 11 (installed for this lab; Windows firewall and network settings untouched, Vultr servers untouched).
- Three Linux network namespaces joined by veth pairs, built by `lab-up.sh`:
  - `client` 10.0.1.10 (admin IP), 10.0.1.20 (other), plus 10.0.1.30/.40/.50 added in Ex5 as extra "attackers"
  - `fw` 10.0.1.1 | 10.0.2.1, ip_forward=1, iptables (nf_tables backend), rules live on the FORWARD chain
  - `server` 10.0.2.2: nginx on 80/443/8080, sshd 22, dummy listeners on 3306 and 23 (the "forgotten services")
- Tools: nmap, curl, netcat-openbsd, tcpdump, conntrack, iptables.
- Run anything in the lab: `wsl -d Ubuntu -u root -- ip netns exec <client|fw|server> <cmd>`
- Re-run an exercise: `cat scripts/common.sh scripts/ex2_stateful.sh | wsl -d Ubuntu -u root -- bash -s`

## Exercise 1: Default deny, SSH from one IP, HTTPS only
Baseline nmap (client -> server, no firewall): open 22, 23, 80, 443, 3306, 8080; rest `closed` (RST).

```
iptables -P FORWARD DROP
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -s 10.0.1.10 -d 10.0.2.2 -p tcp --dport 22  -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -d 10.0.2.2 -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
```
After:
- from 10.0.1.10: 22 + 443 open, everything else `filtered` (no response).
- from 10.0.1.20: only 443 open.
- `curl https://app.lab` works, `curl http://` (80) times out.
Key point: `closed` = something answered with a RST; `filtered` = silence (DROP). Scan time rose (waiting on timeouts).

## Exercise 2: Stateful vs stateless (`evidence/ex2_stateful.txt`)
- Stateful: `conntrack -L` shows the flow `10.0.1.10:45546 <-> 10.0.2.2:443 [ASSURED]`. One rule (`ESTABLISHED,RELATED`) lets all replies back.
- Deleted that rule: curl times out. tcpdump on the firewall shows the SYN go through, the SYN-ACK arrive from the server, and the firewall drop it; the client retransmits the SYN.
- Stateless "fix" (`-s server -p tcp ! --syn -j ACCEPT`): web works again, but unsolicited ACK probes from the server crossed the firewall to the client. Stateless rules can't tell a reply from a forged reply.
- Back to stateful: same probe never arrives.

## Exercise 3: Rule order (`evidence/ex3_rule_order.txt`)
- Broad `ACCEPT -s 10.0.1.0/24 -d 10.0.2.2 -p tcp` above `DROP -s 10.0.1.20 ... --dport 22`: .20 still reached SSH, the DROP rule's counter stayed 0 (shadowed).
- Fix: `iptables -I FORWARD 2 -s 10.0.1.20 ... -j DROP` above the broad rule: .20 blocked (counter rises), .10 still allowed.
- Takeaway: first match wins; specific before broad; read counters with `iptables -L -n -v --line-numbers`.

## Exercise 4: Egress filtering (`evidence/ex4_egress.txt`)
- With `-s 10.0.2.2 -j ACCEPT` (allow all outbound): server -> client:4444 CONNECTED (simulated reverse shell).
- With egress allow-list (`udp/53` and `tcp/443` NEW only): :4444 blocked, :443 works.
- Tighter: 443 only to one named destination; a second destination on 443 was blocked.
- Why: a compromised server can only call home over what egress allows. Remaining gap: 443 to anywhere still permits C2 over HTTPS, so restrict destinations/proxy too.

## Exercise 5: Logging (`evidence/ex5_logging.txt`, `samples/fw-drops.log`)
```
iptables -A FORWARD -m limit --limit 1000/min --limit-burst 2000 -j LOG --log-prefix "FW-DROP: " --log-level 4
```
- The LOG rule goes last (before the default policy drop) so it only sees what would be dropped. Rate-limited so a flood can't fill the disk.
- Needed `sysctl net.netfilter.nf_log_all_netns=1` for namespaced firewalls to write to the kernel log. Read with `dmesg | grep FW-DROP`.
- 17 drops captured from 5 sources. Fields: IN/OUT, SRC/DST, PROTO, SPT/DPT, SYN flag.

## Exercise 6: Troubleshooting
Pending. Method is in `TROUBLESHOOTING.md`. The scenario is hidden until the practice round.

## Exercise 7: Python scripts (`evidence/ex7_*.txt`)
- `scripts/parse_fw_logs.py`: counts drops by source IP, by dest port, by (IP, port) pair; flags sources hitting >= 3 distinct ports as possible scanners; `--json` for automation. Result on the sample: 10.0.1.20 = 6, 10.0.1.30 = 4, 10.0.1.50 = 4; port 22 hit 5 times.
- `scripts/audit_rules.py`: reads `iptables-save`; flags allow-all, sensitive ports (22, 3389, DBs...) open to 0.0.0.0/0, huge port ranges, sources wider than /16, ACCEPT chain policy, and shadowed rules. `--fail-on high` returns exit code 1 for CI. On `samples/risky.rules` it found 9 issues; on our lab ruleset it correctly found only the open INPUT policy on the firewall host.
- Known limits (say these in an interview): IPv4 iptables only, no nftables/cloud security group formats, no hostname resolution, `!` negations are treated conservatively.

## What I can truthfully say in the interview
Empty until the practice round. Only things you did yourself and explained correctly get added.

## Weak spots
Empty until the practice round.
