#!/usr/bin/env python3
"""Audit an iptables ruleset (iptables-save format) for risky rules.

  iptables-save | audit_rules.py
  audit_rules.py samples/risky.rules --fail-on high     # exit 1 if HIGH/CRITICAL found (CI-friendly)

Checks:
  CRITICAL  ACCEPT with no source, destination, protocol or port restriction
  HIGH      ACCEPT from anywhere (0.0.0.0/0 or unset) to an admin/sensitive port (22, 3389, 23, DBs, ...)
  HIGH      ACCEPT of a huge port range (> 1000 ports)
  HIGH      chain policy ACCEPT on INPUT/FORWARD
  MEDIUM    ACCEPT from a source wider than /16
  MEDIUM    ACCEPT from anywhere on every port of a protocol
  MEDIUM    shadowed rule: an earlier rule already matches all of this rule's traffic (it never fires)
"""
import argparse
import ipaddress
import re
import shlex
import sys

SENSITIVE = {22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB", 135: "RPC", 139: "NetBIOS",
             1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
             5900: "VNC", 9200: "Elasticsearch"}
ANY = ipaddress.ip_network("0.0.0.0/0")
SEV = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}


class Rule:
    def __init__(self, num, chain, line):
        self.num, self.chain, self.line = num, chain, line
        self.src = self.dst = None      # ip_network, or None meaning "any"
        self.proto = None
        self.ports = None               # set of (lo, hi) dport ranges, None = any port
        self.target = None
        self.negated = False            # rule uses '!' : analysed conservatively
        self.extra_match = False        # conntrack/limit/etc.: restricted by something we do not model
        self._parse(shlex.split(line))

    @staticmethod
    def _net(v):
        try:
            return ipaddress.ip_network(v, strict=False)
        except ValueError:
            return None                 # hostname etc.: left unresolved

    @staticmethod
    def _range(s):
        lo, _, hi = s.replace(":", "-").partition("-")
        return (int(lo), int(hi or lo))

    def _parse(self, t):
        neg = False
        i = 0
        while i < len(t):
            a = t[i]
            nxt = t[i + 1] if i + 1 < len(t) else ""
            if a == "!":
                neg = self.negated = True
                i += 1
                continue
            if a in ("-s", "--source"):
                self.src = None if neg else self._net(nxt)
                i += 1
            elif a in ("-d", "--destination"):
                self.dst = None if neg else self._net(nxt)
                i += 1
            elif a in ("-p", "--protocol"):
                self.proto = nxt.lower()
                i += 1
            elif a in ("--dport", "--destination-port"):
                self.ports = {self._range(nxt)}
                i += 1
            elif a == "--dports":
                self.ports = {self._range(x) for x in nxt.split(",")}
                i += 1
            elif a in ("-m", "--match") and nxt not in ("tcp", "udp", "multiport", "comment", "icmp"):
                self.extra_match = True
                i += 1
            elif a in ("-j", "-g"):
                self.target = nxt
                i += 1
            neg = False
            i += 1

    @property
    def any_src(self):
        return self.src is None or self.src == ANY

    @property
    def unrestricted(self):
        return not (self.src or self.dst or self.proto or self.ports) and not (self.negated or self.extra_match)

    def covers(self, other):
        """True if every packet matching `other` also matches self (self is at least as broad)."""
        if self.negated or other.negated or self.extra_match or self.chain != other.chain:
            return False
        for mine, theirs in ((self.src, other.src), (self.dst, other.dst)):
            if mine is not None and mine != ANY:
                if theirs is None or theirs.version != mine.version or not theirs.subnet_of(mine):
                    return False
        if self.proto and self.proto != other.proto:
            return False
        if self.ports is not None:
            if other.ports is None:
                return False
            if not all(any(lo <= a and b <= hi for lo, hi in self.ports) for a, b in other.ports):
                return False
        return True


def parse(text):
    policies, rules = {}, []
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"^:(\w+)\s+(ACCEPT|DROP|REJECT)", line)
        if m:
            policies[m.group(1)] = m.group(2)
        elif line.startswith("-A "):
            rules.append(Rule(len(rules) + 1, line.split()[1], line))
    return policies, rules


def audit(policies, rules):
    findings = []

    def add(sev, rule, msg):
        findings.append((sev, rule.num, rule.line, msg))

    for chain in ("INPUT", "FORWARD"):
        if policies.get(chain) == "ACCEPT":
            findings.append(("HIGH", 0, ":" + chain + " ACCEPT",
                             chain + " chain policy is ACCEPT (default allow, not default deny)"))

    for r in rules:
        if r.target != "ACCEPT":
            continue
        if r.unrestricted:
            add("CRITICAL", r, "ACCEPT with no source, destination, protocol or port restriction (allows everything)")
        if r.ports:
            for lo, hi in sorted(r.ports):
                span = hi - lo + 1
                hits = sorted(p for p in SENSITIVE if lo <= p <= hi)
                if span > 1000:
                    extra = ", includes sensitive ports " + str(hits) if hits else ""
                    who = "any source" if r.any_src else str(r.src)
                    add("HIGH", r, "port range %d-%d (%d ports) open to %s%s" % (lo, hi, span, who, extra))
                elif r.any_src:
                    for p in hits:
                        add("HIGH", r, "%s (port %d) open to any source (0.0.0.0/0); restrict the source" % (SENSITIVE[p], p))
        if r.src and r.src != ANY and r.src.prefixlen < 16:
            add("MEDIUM", r, "source range %s is wider than /16 (%s addresses)" % (r.src, format(r.src.num_addresses, ",")))
        if r.any_src and r.ports is None and r.proto in ("tcp", "udp") and not r.negated:
            add("MEDIUM", r, "any source allowed on every %s port" % r.proto)

    for j, later in enumerate(rules):
        for earlier in rules[:j]:
            if earlier.target and earlier.covers(later):
                add("MEDIUM", later, "shadowed by rule #%d (%s): the earlier rule already matches all of this rule's "
                                     "traffic, so this one never fires" % (earlier.num, earlier.target))
                break

    findings.sort(key=lambda f: (-SEV[f[0]], f[1]))
    return findings


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("rulefile", nargs="?", help="iptables-save output (default: stdin)")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium"],
                    help="exit 1 if a finding at or above this level exists")
    a = ap.parse_args()
    text = open(a.rulefile, errors="replace").read() if a.rulefile else sys.stdin.read()
    policies, rules = parse(text)
    findings = audit(policies, rules)
    print("%d rules audited, %d finding(s)\n" % (len(rules), len(findings)))
    for sev, num, line, msg in findings:
        print("[%s] rule #%d: %s\n         %s" % (sev, num, msg, line))
    if not findings:
        print("No risky rules found.")
    if a.fail_on and any(SEV[f[0]] >= SEV[a.fail_on.upper()] for f in findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
