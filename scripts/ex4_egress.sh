hdr "EX4: egress filtering (server initiating outbound connections)"
client_listen 4444 443
# 'internet' stand-in = client namespace (10.0.1.10). Server-initiated traffic = egress.
etest(){ printf "server -> 10.0.1.10:%s  " $1; $S nc -zw2 10.0.1.10 $1 >/dev/null 2>&1 && echo "CONNECTED" || echo "blocked/timeout"; }
hdr "4a. Common misconfig: inbound locked down, but the server may talk OUT to anywhere"
baseline
run "$F iptables -A FORWARD -s 10.0.2.2 -j ACCEPT"
etest 4444
etest 443
echo "^ A compromised server can call home on ANY port (reverse shell on 4444, C2, data exfil)."

hdr "4b. Egress allow-list: server may only start DNS (udp/53) and HTTPS (tcp/443) outbound; default-drop the rest"
baseline
run "$F iptables -A FORWARD -s 10.0.2.2 -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT"
run "$F iptables -A FORWARD -s 10.0.2.2 -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT"
etest 4444
etest 443
run "$F iptables -S FORWARD"
echo "^ Reverse shell on 4444 is dead; patching/updates over 443 still work. Replies to inbound traffic still flow via ESTABLISHED."
echo "Limit: 443 is still open to anyone, so C2 over 443 survives. Real fix = allow only specific destination IPs/proxy (here: -d <update mirror>) plus DNS/proxy inspection."
hdr "4c. Tighten further: allow 443 only to one named destination"
baseline
run "$F iptables -A FORWARD -s 10.0.2.2 -d 10.0.1.10 -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT"
etest 443
$S nc -zw2 -s 10.0.2.2 10.0.1.20 443 >/dev/null 2>&1 && echo "server -> 10.0.1.20:443 CONNECTED" || echo "server -> 10.0.1.20:443 blocked (not on allow-list)"
