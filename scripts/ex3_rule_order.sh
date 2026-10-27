hdr "EX3: rule order (first match wins)"
sshtest(){ echo "\$ ssh-port test from $1"; $C nc -zvw2 -s $1 10.0.2.2 22 2>&1 | tail -1 || true; }
hdr "3a. WRONG order: broad ACCEPT for the whole /24 sits above the specific DROP for .20"
$F iptables -F; $F iptables -P FORWARD DROP
run "$F iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
run "$F iptables -A FORWARD -s 10.0.1.0/24 -d 10.0.2.2 -p tcp -j ACCEPT"
run "$F iptables -A FORWARD -s 10.0.1.20 -d 10.0.2.2 -p tcp --dport 22 -j DROP"
sshtest 10.0.1.20
run "$F iptables -L FORWARD -n -v --line-numbers"
echo "^ .20 reached SSH. Rule 3's counter is 0: it is shadowed, it can never match because rule 2 already took the packet."

hdr "3b. FIX: specific rule first (insert at position 2, above the broad rule)"
run "$F iptables -D FORWARD 3"
run "$F iptables -I FORWARD 2 -s 10.0.1.20 -d 10.0.2.2 -p tcp --dport 22 -j DROP"
run "$F iptables -Z"
sshtest 10.0.1.20
sshtest 10.0.1.10
run "$F iptables -L FORWARD -n -v --line-numbers"
echo "^ .20 blocked on 22 (rule 2 counter > 0), .10 still gets in via the broad rule 3."
echo "Note the broad rule itself is still bad practice (whole /24, all ports). Exercise 1's tight ruleset is the better design."
