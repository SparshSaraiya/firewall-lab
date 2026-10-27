hdr "EX2: stateful vs stateless"
client_listen 4444
baseline
hdr "2a. Stateful baseline: HTTPS works, conntrack remembers the flow"
run "$C curl -sk --max-time 3 https://app.lab"
run "$F conntrack -L 2>/dev/null | grep 'dport=443' | head -3"

hdr "2b. Delete the ESTABLISHED,RELATED rule (rule #1) -> replies have no permission"
run "$F iptables -D FORWARD 1"
run "$F iptables -S FORWARD"
( timeout 5 $F tcpdump -ni any -c 8 'tcp port 443' 2>&1 | grep -E 'IP ' ) &
sleep 1
run "$C curl -sk --max-time 3 https://app.lab || echo 'curl FAILED (timeout)'"
wait
echo "^ SYN reaches the server side, SYN-ACK comes back but fw drops it: client never completes the handshake"

hdr "2c. Stateless 'fix' (pre-conntrack style): allow any server->client TCP packet that is not a SYN"
run "$F iptables -A FORWARD -s 10.0.2.2 -p tcp ! --syn -j ACCEPT"
run "$C curl -sk --max-time 3 https://app.lab"
echo "Works. But the rule only looks at flags, not at who started the conversation. Test: SERVER sends unsolicited ACK probes; we sniff on the CLIENT side:"
probe(){ ( timeout 4 $C tcpdump -ni c-fw -c 3 'tcp dst port 4444' 2>&1 | grep -E 'IP ' || echo "(nothing arrived at client)" ) & sleep 1; $S nmap -Pn -n -sA -p 4444 10.0.1.10 >/dev/null; wait; }
probe
echo "^ the unsolicited ACK crossed the firewall and reached the client (nmap shows 'filtered' only because the client's RST reply can't come back). A stateless rule lets anyone craft packets that look like replies."

hdr "2d. Back to stateful: same probe"
baseline
probe
echo "^ nothing arrives: no conntrack entry for this packet -> INVALID/NEW -> default DROP"
run "$C curl -sk --max-time 3 https://app.lab"
