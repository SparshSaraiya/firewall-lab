#!/usr/bin/env python3
"""Count blocked attempts in iptables LOG output by source IP and destination port.

Reads kernel-log lines such as
  [ 612.04] FW-DROP: IN=fw-c OUT=fw-s SRC=10.0.1.20 DST=10.0.2.2 PROTO=TCP SPT=63561 DPT=22 ...
from a file or stdin (e.g. `dmesg | parse_fw_logs.py`).

  parse_fw_logs.py samples/fw-drops.log
  parse_fw_logs.py samples/fw-drops.log --prefix FW-DROP --top 5 --json
"""
import argparse
import json
import re
import sys
from collections import Counter

KV = re.compile(r"\b([A-Z]+)=(\S*)")


def parse_line(line, prefix):
    """Return a dict of KEY=VALUE fields for a firewall log line, or None."""
    if prefix not in line:
        return None
    fields = dict(KV.findall(line))
    if "SRC" not in fields:
        return None
    return fields


def summarize(lines, prefix="FW-DROP"):
    by_src, by_port, by_pair, ports_per_src = Counter(), Counter(), Counter(), {}
    total = skipped = 0
    for line in lines:
        f = parse_line(line, prefix)
        if f is None:
            skipped += 1
            continue
        total += 1
        src = f["SRC"]
        # ICMP and friends have no ports; bucket them by protocol so nothing is silently lost
        port = f.get("DPT") or f.get("PROTO", "?").lower()
        proto = f.get("PROTO", "?")
        by_src[src] += 1
        by_port[(proto, port)] += 1
        by_pair[(src, proto, port)] += 1
        ports_per_src.setdefault(src, set()).add(port)
    return {"total": total, "skipped": skipped, "by_src": by_src, "by_port": by_port,
            "by_pair": by_pair, "ports_per_src": ports_per_src}


def render(s, top, scan_threshold):
    out = [f"{s['total']} blocked packets parsed ({s['skipped']} non-matching lines ignored)", ""]
    out.append("Blocked attempts by source IP")
    for ip, n in s["by_src"].most_common(top):
        out.append(f"  {ip:<16} {n}")
    out += ["", "Blocked attempts by destination port"]
    for (proto, port), n in s["by_port"].most_common(top):
        out.append(f"  {proto}/{port:<8} {n}")
    out += ["", "Top source IP + port pairs"]
    for (ip, proto, port), n in s["by_pair"].most_common(top):
        out.append(f"  {ip:<16} {proto}/{port:<6} {n}")
    scanners = [(ip, len(p)) for ip, p in s["ports_per_src"].items() if len(p) >= scan_threshold]
    if scanners:
        out += ["", f"Possible port scans (>= {scan_threshold} distinct ports from one source)"]
        for ip, n in sorted(scanners, key=lambda x: -x[1]):
            out.append(f"  {ip:<16} {n} distinct ports")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logfile", nargs="?", help="log file (default: stdin)")
    ap.add_argument("--prefix", default="FW-DROP", help="--log-prefix used in the LOG rule")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--scan-threshold", type=int, default=3, help="distinct ports that flag a source as a scanner")
    ap.add_argument("--json", action="store_true", help="machine-readable output for automation/SIEM")
    a = ap.parse_args()
    fh = open(a.logfile, errors="replace") if a.logfile else sys.stdin
    with fh:
        s = summarize(fh, a.prefix)
    if a.json:
        print(json.dumps({
            "total": s["total"],
            "by_src": dict(s["by_src"].most_common(a.top)),
            "by_port": {f"{p}/{d}": n for (p, d), n in s["by_port"].most_common(a.top)},
            "scanners": sorted(ip for ip, p in s["ports_per_src"].items() if len(p) >= a.scan_threshold),
        }, indent=2))
    else:
        print(render(s, a.top, a.scan_threshold))


if __name__ == "__main__":
    main()
