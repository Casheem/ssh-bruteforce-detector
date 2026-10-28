# SSH Brute-Force Detector

Parses a Linux `auth.log`, finds IPs hammering SSH, and answers the question a SOC analyst actually cares about: **did any of them get in?**

## Why this matters for SOC work
Failed-login triage is Tier-1 bread and butter. Raw counts are noise; what escalates an alert is:
1. **Burst rate** – many failures in a short window (automated attack)
2. **Username spray** – one IP trying many accounts
3. **Success after failures** – the IP that finally logged in. This is an incident, not an alert.

## Usage
```bash
python3 analyzer.py sample_auth.log --year 2026
python3 analyzer.py /var/log/auth.log --threshold 10 --window 5 --format json
```
Flags: `--threshold` min failures, `--window` burst window (minutes), `--format table|json|csv`.

## Sample output
```
IP               FAILS  PEAK USERS  FIRST               LAST                COMPROMISED?
203.0.113.45        12    12    10  2026-10-25 03:12:00 2026-10-25 03:12:33 !!! YES
198.51.100.23        7     1     1  2026-10-25 08:05:00 2026-10-25 14:05:00 !!! YES
```
## Limitations
- Syslog timestamps have no year; pass `--year`.
- Only OpenSSH password failures. No key-auth, no `lastb`, no journald.
- Thresholds are static; real tooling baselines per environment.
- Sample log is synthetic (RFC 5737 documentation IPs).

## Next
GeoIP/ASN enrichment, AbuseIPDB lookup, Sigma-style rule output, unit tests.
