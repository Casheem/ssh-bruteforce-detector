#!/usr/bin/env python3
"""SSH brute-force detector: parses auth.log and flags suspicious IPs."""
import argparse, csv, json, re, sys
from collections import defaultdict
from datetime import datetime, timedelta
MIN_FAILS_FOR_COMPROMISE = 5

# Syslog line: "Oct 27 03:12:01 host sshd[123]: Failed password for invalid user admin from 203.0.113.5 port 4242 ssh2"
LINE = re.compile(r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s\S+\ssshd\[\d+\]:\s(?P<msg>.*)$")
FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)")
ACCEPTED = re.compile(r"Accepted \w+ for (?P<user>\S+) from (?P<ip>[\d.]+)")

def parse_ts(s, year):
    return datetime.strptime(f"{year} {' '.join(s.split())}", "%Y %b %d %H:%M:%S")

def analyze(path, year, threshold, window_min):
    fails = defaultdict(list)      # ip -> [timestamps]
    users = defaultdict(set)       # ip -> usernames tried
    successes = defaultdict(list)  # ip -> [(ts, user)]
    skipped = 0
    with open(path, errors="replace") as f:
        for raw in f:
            m = LINE.match(raw.strip())
            if not m:
                skipped += 1
                continue
            ts, msg = parse_ts(m["ts"], year), m["msg"]
            if (x := FAILED.search(msg)):
                fails[x["ip"]].append(ts); users[x["ip"]].add(x["user"])
            elif (x := ACCEPTED.search(msg)):
                successes[x["ip"]].append((ts, x["user"]))

    results = []
    win = timedelta(minutes=window_min)
    for ip, times in fails.items():
        times.sort()
        # sliding window: max failures inside any window_min span
        peak, j = 0, 0
        for i, t in enumerate(times):
            while t - times[j] > win:
                j += 1
            peak = max(peak, i - j + 1)
        if len(times) < threshold and peak < threshold:
            continue
        # CRITICAL: did this IP get in after failing?
        compromised = [u for (t, u) in successes.get(ip, []) if t >= times[0] and u in users[ip] and len(times) >= MIN_FAILS_FOR_COMPROMISE]
        results.append({
            "ip": ip, "attempts": len(times), "peak_in_window": peak,
            "unique_users": len(users[ip]),
            "first_seen": times[0].isoformat(" "), "last_seen": times[-1].isoformat(" "),
            "success_after_failures": bool(compromised),
        })
    results.sort(key=lambda r: (r["success_after_failures"], r["attempts"]), reverse=True)
    return results, skipped

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("logfile")
    p.add_argument("--year", type=int, default=datetime.now().year, help="auth.log has no year")
    p.add_argument("--threshold", type=int, default=5, help="min failures to flag")
    p.add_argument("--window", type=int, default=10, help="burst window in minutes")
    p.add_argument("--format", choices=["table", "json", "csv"], default="table")
    a = p.parse_args()
    res, skipped = analyze(a.logfile, a.year, a.threshold, a.window)
    if a.format == "json":
        print(json.dumps(res, indent=2))
    elif a.format == "csv":
        w = csv.DictWriter(sys.stdout, fieldnames=res[0].keys() if res else ["ip"]); w.writeheader(); w.writerows(res)
    else:
        print(f"{'IP':<16}{'FAILS':>6}{'PEAK':>6}{'USERS':>6}  {'FIRST':<20}{'LAST':<20}COMPROMISED?")
        for r in res:
            flag = "!!! YES" if r["success_after_failures"] else "no"
            print(f"{r['ip']:<16}{r['attempts']:>6}{r['peak_in_window']:>6}{r['unique_users']:>6}  {r['first_seen']:<20}{r['last_seen']:<20}{flag}")
        print(f"\n{len(res)} IP(s) flagged. {skipped} non-sshd/unparsed lines skipped.", file=sys.stderr)

if __name__ == "__main__":
    main()
