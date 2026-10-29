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

## Real-data test
The analyzer was also run on the `OpenSSH_2k.log` sample from [Loghub](https://github.com/logpai/loghub), real logs collected from an OpenSSH server in a lab over 28+ days. The log has no year, so `--year 2015` was passed as an assumed value. The dataset is not redistributed in this repo.

Citation: Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu, Michael R. Lyu. *Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics.* IEEE International Symposium on Software Reliability Engineering (ISSRE), 2023.

**Result:** 10 IPs were flagged and none were marked compromised. The sample contains a single successful login, from an IP that was not flagged, so the success-after-failures check is only demonstrated on the synthetic `sample_auth.log`.

```
IP               FAILS  PEAK USERS  FIRST               LAST                COMPROMISED?
183.62.140.xxx    286   279    10  2015-12-10 10:54:29 2015-12-10 11:04:43  no
187.141.143.xxx    80    80    28  2015-12-10 09:12:48 2015-12-10 09:20:02  no
103.99.0.xxx       46    30    19  2015-12-10 09:11:21 2015-12-10 11:04:45  no
112.95.230.xxx     26    26     3  2015-12-10 07:27:52 2015-12-10 07:28:51  no
5.188.10.xxx       17    17     6  2015-12-10 08:24:45 2015-12-10 08:26:24  no
185.190.58.xxx     17    17     3  2015-12-10 09:07:58 2015-12-10 09:12:59  no
123.235.32.xxx     7     7      1  2015-12-10 07:32:27 2015-12-10 07:34:23  no
119.4.203.xxx      6     6      1  2015-12-10 10:14:01 2015-12-10 10:14:13  no
52.80.34.xxx       5     1      3  2015-12-10 07:07:45 2015-12-10 10:21:09  no
60.2.12.xxx        5     5      1  2015-12-10 10:04:54 2015-12-10 10:05:22  no
```

10 IP(s) flagged. 0 non-sshd/unparsed lines skipped.
## Next
- GeoIP/ASN enrichment
- AbuseIPDB lookup
- Support for key-based logins and journald

