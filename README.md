# WebLogHunter

Day 21 — 100 Days • 100 Cybersecurity Projects

Offline Python utility for triaging authorized Apache/Nginx access logs. Flags suspicious request patterns and repeated authentication/error responses; exports JSON and CSV reports.

## Features
- Parses common combined access-log entries
- Heuristic indicators for SQL injection-like, XSS-like, and path traversal patterns
- Flags TRACE, TRACK, and CONNECT methods
- Detects per-IP bursts of authentication failures and HTTP errors
- Evidence, severity, recommendations, JSON/CSV output
- Python standard library only

## Run (Python 3.10+)
~~~bash
python webloghunter.py --input samples/access.log
python webloghunter.py --input samples/access.log --threshold 3 --json-out findings.json --csv-out findings.csv
python -m unittest discover -s tests -v
~~~

The sample log uses synthetic data and documentation-only IP ranges. Findings are heuristic indicators, not proof of compromise. Use only logs you are authorized to inspect; investigate findings in context. No scanning, exploitation, or automatic blocking.
