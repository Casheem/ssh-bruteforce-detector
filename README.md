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
On Windows, use python instead of python3.

Flags: `--threshold` min failures, `--window` burst window (minutes), `--format table|json|csv`.

## Sample output
```
IP               FAILS  PEAK USERS  FIRST               LAST                COMPROMISED?
203.0.113.45        12    12    10  2026-10-25 03:12:00 2026-10-25 03:12:33 !!! YES
198.51.100.23        7     1     1  2026-10-25 08:05:00 2026-10-25 14:05:00 !!! YES
```
198.51.100.23 is flagged compromised because the sample log contains a successful `root` login from that IP after 7 failed `root` attempts.

## How "compromised" is decided
An IP is marked `!!! YES` only if **all three** are true for a successful login:
1. It happened after that IP's first failed attempt.
2. The username that got in is one that IP had failed against.
3. The IP had at least 5 failures (`MIN_FAILS_FOR_COMPROMISE`), so a user who mistypes a password twice is not reported as an incident.

If any one condition fails, the IP may still be listed as suspicious, but it is not marked compromised.

## Run the tests
    python -m pip install pytest
    python -m pytest -v

## Limitations
- Syslog timestamps have no year; pass `--year`.
- Only OpenSSH password failures. No key-auth, no `lastb`, no journald.
- Thresholds are static; real tooling baselines per environment.
- Sample log is synthetic (RFC 5737 documentation IPs).
- Rule 1 has no time limit: a login hours after the last failure still counts as compromise.

## Next
- Test against a real internet-facing auth.log
- GeoIP/ASN enrichment
- AbuseIPDB lookup
- Support for key-based logins and journald

