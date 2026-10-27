# Sourced/concatenated before every exercise script. Runs INSIDE WSL as root.
F="ip netns exec fw"; C="ip netns exec client"; S="ip netns exec server"
hdr(){ echo; echo "### $*"; }
run(){ echo "\$ $*"; eval "$@"; }
# Exercise 1 ruleset = our known-good baseline
baseline(){
  $F iptables -F; $F iptables -X; $F iptables -P FORWARD DROP
  $F iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  $F iptables -A FORWARD -s 10.0.1.10 -d 10.0.2.2 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
  $F iptables -A FORWARD -d 10.0.2.2 -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
}
# listener helper for the client side ("internet" stand-in)
client_listen(){ for p in "$@"; do $C setsid -f python3 /srv/lab/listen.py $p >/dev/null 2>&1 </dev/null; done; }
