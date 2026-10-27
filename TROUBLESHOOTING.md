# "The app can't reach the server": method

Work outward from the client, one layer at a time. Stop at the first layer that fails.

| # | Question | Command (from the client) | Meaning |
|---|---|---|---|
| 1 | Does the name resolve? | `getent hosts app.lab` / `dig app.lab` | Fails -> DNS/hosts problem, not the firewall |
| 2 | Is there a route to the destination? | `ip route get 10.0.2.2`, `ping -c1 10.0.2.2` | No route / no reply -> routing or L3 block (ping may also be filtered on purpose) |
| 3 | Is the port reachable? | `nc -zv 10.0.2.2 443`, `curl -vk https://app.lab` | **timeout** = silent drop (firewall DROP, or no route back). **refused** = host answered RST, service down or REJECT rule |
| 4 | Is the service up on the server? | `ss -tlnp` (on server) | Not listening -> app problem, not the firewall |
| 5 | What is the firewall seeing? | log: `dmesg \| grep FW-DROP`; live: `tcpdump -ni any host 10.0.2.2 and port 443` | Packet appears in the DROP log, or SYN enters but nothing leaves = firewall |
| 6 | Which rule matches? | `iptables -L FORWARD -n -v --line-numbers`, then re-run the test and watch the counters | The rule whose packet counter rises is the one deciding. A DROP above an ACCEPT = misordered rule |
| 7 | Fix, retest, document | `iptables -D`/`-I <position>` ... | Re-run step 3 and confirm the counters/log are quiet |

Rule of thumb: timeout vs refused tells you almost everything. Counters tell you which rule.
