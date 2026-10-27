hdr "EX5: logging dropped packets"
sysctl -qw net.netfilter.nf_log_all_netns=1   # let non-root network namespaces use the kernel log (WSL-only lab setting)
# extra 'attacker' source IPs on the client side so the log has variety
for i in 30 40 50; do ip -n client addr add 10.0.1.$i/24 dev c-fw 2>/dev/null || true; done
baseline
hdr "5a. Log rule goes LAST, just before the default DROP. Rate-limited so a flood cannot fill the disk."
run "$F iptables -A FORWARD -m limit --limit 1000/min --limit-burst 2000 -j LOG --log-prefix 'FW-DROP: ' --log-level 4"
run "$F iptables -S FORWARD"
dmesg -C
hdr "5b. Generate blocked traffic from several sources"
scanfrom(){ $C nmap -Pn -n -T4 --max-retries 0 -S $1 -e c-fw -p $2 10.0.2.2 >/dev/null; }
scanfrom 10.0.1.20 22,23,80,3306        # non-admin trying ssh/telnet/http/mysql
scanfrom 10.0.1.30 22,3389,445          # worm-ish ports
scanfrom 10.0.1.30 22,22,22
scanfrom 10.0.1.40 23,23,2323
scanfrom 10.0.1.50 8080,3306,5432,6379
$C nc -zw1 -s 10.0.1.20 10.0.2.2 22 || true
$C nc -zw1 -s 10.0.1.20 10.0.2.2 22 || true
$S nc -zw1 10.0.1.10 4444 || true      # egress attempt (server -> client)
$C curl -sk --max-time 3 https://app.lab >/dev/null && echo "(legit https still works)"
hdr "5c. Read the log"
dmesg | grep 'FW-DROP' > /tmp/fw-drops.log
echo "$(wc -l < /tmp/fw-drops.log) log lines. First 5:"
head -5 /tmp/fw-drops.log
echo; echo "Anatomy of one line: IN=interface it arrived on, OUT=interface it would leave, SRC/DST, PROTO, SPT/DPT=source/dest port, SYN=flag"
hdr "5d. Quick triage with grep/awk (what the Python script automates)"
echo "Top sources:";      grep -o 'SRC=[0-9.]*' /tmp/fw-drops.log | sort | uniq -c | sort -rn
echo "Top dest ports:";   grep -o 'DPT=[0-9]*' /tmp/fw-drops.log | sort | uniq -c | sort -rn
cat /tmp/fw-drops.log
