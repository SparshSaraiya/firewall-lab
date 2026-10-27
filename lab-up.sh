#!/bin/bash
# Firewall lab: three network namespaces, all inside WSL. Nothing touches Windows.
#   client (10.0.1.10 admin, 10.0.1.20 other) -- fw (10.0.1.1 | 10.0.2.1) -- server (10.0.2.2)
set -e
for n in client fw server; do ip netns del $n 2>/dev/null || true; done
pkill -f "nginx: master.*lab" 2>/dev/null || true
for n in client fw server; do ip netns add $n; ip netns exec $n ip link set lo up; done

ip link add c-fw type veth peer name fw-c
ip link set c-fw netns client; ip link set fw-c netns fw
ip link add s-fw type veth peer name fw-s
ip link set s-fw netns server; ip link set fw-s netns fw

ip -n client addr add 10.0.1.10/24 dev c-fw
ip -n client addr add 10.0.1.20/24 dev c-fw
ip -n client link set c-fw up
ip -n client route add default via 10.0.1.1

ip -n fw addr add 10.0.1.1/24 dev fw-c
ip -n fw addr add 10.0.2.1/24 dev fw-s
ip -n fw link set fw-c up; ip -n fw link set fw-s up
ip netns exec fw sysctl -qw net.ipv4.ip_forward=1

ip -n server addr add 10.0.2.2/24 dev s-fw
ip -n server link set s-fw up
ip -n server route add default via 10.0.2.1

# name resolution for the client (per-namespace hosts file)
mkdir -p /etc/netns/client
echo "10.0.2.2 app.lab" > /etc/netns/client/hosts

# --- server services: web (80, 443), ssh (22), plus "forgotten" ones (8080, 3306, 23)
mkdir -p /srv/lab && echo "hello from app.lab" > /srv/lab/index.html
[ -f /srv/lab/key.pem ] || openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=app.lab \
  -keyout /srv/lab/key.pem -out /srv/lab/cert.pem 2>/dev/null
cat > /srv/lab/nginx.conf <<'EOF'
pid /srv/lab/nginx.pid;
error_log /srv/lab/nginx.err;
events {}
http {
  access_log off;
  server { listen 80;  root /srv/lab; }
  server { listen 443 ssl; ssl_certificate /srv/lab/cert.pem; ssl_certificate_key /srv/lab/key.pem; root /srv/lab; }
  server { listen 8080; root /srv/lab; }
}
EOF
mkdir -p /run/sshd
ip netns exec server nginx -c /srv/lab/nginx.conf
ip netns exec server /usr/sbin/sshd -o PidFile=/srv/lab/sshd.pid
cat > /srv/lab/listen.py <<'EOF'
import socket,sys
s=socket.socket(); s.setsockopt(1,2,1); s.bind(("0.0.0.0",int(sys.argv[1]))); s.listen(5)
while True:
    c,_=s.accept(); c.close()
EOF
for p in 3306 23; do ip netns exec server setsid -f python3 /srv/lab/listen.py $p >/dev/null 2>&1 </dev/null; done
echo "lab up"
