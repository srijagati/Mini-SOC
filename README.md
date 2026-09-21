# Mini SOC

My first attempt at a mini Security Operations Center (SOC). A SOC does continuous monitoring, detecting, analyzing and responding to cybersecurity threats. This project simulates that workflow end to end on Windows Security event logs, using only the Python standard library.

## What it does

1. Generates a synthetic Windows event log (`data/windows_events.csv`) with normal staff activity plus four planted attacks.
2. Detects failed logins and attack patterns with rule-based detections.
3. Generates security alerts, each mapped to a MITRE ATT&CK technique.
4. Creates incident tickets, grouping related alerts by source with a recommended response.
5. Produces a security report in Markdown (`output/report.md`) plus `alerts.json` and `incidents.json`.

## Detection rules

| Rule | Trigger | Severity |
|---|---|---|
| BRUTE_FORCE | 10+ failed logons (4625) from one IP in one burst | High |
| PASSWORD_SPRAY | one IP failing against 8+ different accounts in one burst | High |
| COMPROMISED_ACCOUNT | successful logon (4624) from an attacking IP after its failures | Critical |
| REPEATED_FAILED_LOGIN | 5+ failures against one account, not part of an attack | Low / Medium |
| ACCOUNT_LOCKOUT | event 4740 | Medium |

A burst is a run of events with no gap longer than 5 minutes. Thresholds live at the top of `scripts/detector.py`.

## Run it

```bash
python scripts/main.py                 # generate logs, detect, alert, ticket, report
python scripts/main.py --seed 7        # a different synthetic dataset
python scripts/main.py --use-existing-log --log path/to/your_events.csv
python -m unittest discover -s tests   # run the tests
```

Custom logs need these CSV columns: `TimeCreated, EventID, Computer, TargetUserName, IpAddress, LogonType, SubStatus`.

## Project layout

```
scripts/
  main.py           pipeline entry point
  log_generator.py  synthetic Windows event logs
  detector.py       parsing and detection rules
  incidents.py      alert -> incident ticket
  reporter.py       JSON and Markdown output
tests/              unit and end-to-end tests
data/  output/      generated files
```

## Skills practiced

- Python in cybersecurity
- Windows event log analysis
- Detection engineering and MITRE ATT&CK mapping
- Git and GitHub

## Ideas for next steps

- Parse real EVTX files (for example EVTX-ATTACK-SAMPLES)
- Enrich IPs with GeoIP / threat-intel lookups
- Add a small Flask dashboard
