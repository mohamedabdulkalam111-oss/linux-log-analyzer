# Linux Log Analyzer

## Project Overview
A Python-based cybersecurity tool that analyzes Linux authentication logs to identify failed login attempts and potential suspicious activity.

## Features
- Counts successful and failed login attempts.
- Tracks failed attempts by IP address and username.
- Identifies IP addresses with the highest number of failed attempts.
- Flags IP addresses based on a configurable alert threshold.
- Validates IPv4 addresses and skips invalid addresses.
- Generates text and CSV security reports.
- Handles missing files, invalid thresholds, and empty log files.

## Technologies Used
- Python 3
- Linux / Ubuntu
- Python modules: `csv`, `ipaddress`, `datetime`, `sys`, `unittest`

## Project Files
- `analyzer.py` — Main analysis program.
- `auth.log` — Sample authentication log.
- `report.txt` — Security analysis report.
- `suspicious_ips.txt` — Suspicious IP report.
- `security_report.csv` — Results in CSV format.
- `test_analyzer.py` — Unit tests.

## How to Run

Run the analyzer with the sample log:

```bash
python3 analyzer.py auth.log
```

Set a custom alert threshold:

```bash
python3 analyzer.py auth.log 3
```

Run unit tests:

```bash
python3 test_analyzer.py
```

## Learning Objectives
This project demonstrates basic Python programming, Linux log analysis, input validation, error handling, CSV report generation, and unit testing.

## Disclaimer
This project is intended for educational purposes and uses sample authentication logs. Alerts indicate activity that may need investigation; they do not prove that an attack occurred.


## Sample Output

Example results from the sample authentication log:

```text
Security Status: REVIEW REQUIRED

Total Log Lines: 15
Successful Logins: 3
Failed Logins: 12
Total Login Events: 15
Failure Percentage: 80.00%

Failed Login Attempts by IP:
192.168.1.10 -> 5 attempts
192.168.1.20 -> 4 attempts
192.168.1.30 -> 3 attempts

IP with highest failed attempts: 192.168.1.10
Number of attempts: 5
```

**Note:** These are results from sample data for educational purposes. A warning indicates activity that may require investigation; it does not prove an attack occurred.
