#!/usr/bin/env python3
"""Offline, heuristic web access-log triage."""
import argparse, csv, json, re
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import unquote

LOG_RE = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^]]+)\] "(?P<method>[A-Z]+) (?P<target>.*?) HTTP/[^"]+" (?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?.*$')

@dataclass
class AccessEvent:
    line: int
    ip: str
    timestamp: str
    method: str
    target: str
    status: int
    user_agent: str

@dataclass
class Finding:
    rule_id: str
    severity: str
    source_ip: str
    count: int
    evidence: str
    recommendation: str

def parse_line(raw, line_no):
    m = LOG_RE.match(raw.strip())
    if not m: return None
    d = m.groupdict()
    return AccessEvent(line_no, d["ip"], d["time"], d["method"], d["target"], int(d["status"]), d.get("ua") or "")

def analyze(events, threshold=5):
    findings, by_ip = [], defaultdict(list)
    patterns = [
        ("WEB_SQLI", re.compile(r"(union(?:%20|\s)+select|select.+from|or(?:%20|\s)+1=1|sleep\()", re.I), "HIGH", "Review request and input validation."),
        ("WEB_XSS", re.compile(r"(<script|%3cscript|javascript:|onerror=)", re.I), "HIGH", "Inspect output encoding and request context."),
        ("WEB_PATH_TRAVERSAL", re.compile(r"(\.\./|%2e%2e%2f|%2e%2e\\)", re.I), "HIGH", "Review path normalization and file-access controls."),
    ]
    for e in events:
        if e is None: continue
        by_ip[e.ip].append(e)
        target = e.target
        decoded = unquote(target)
        for rule, pat, severity, rec in patterns:
            if pat.search(decoded) or pat.search(target):
                findings.append(Finding(rule, severity, e.ip, 1, f"line {e.line}: {e.method} {target} [{e.status}]", rec))
                break
        if e.method in {"TRACE", "TRACK", "CONNECT"}:
            findings.append(Finding("WEB_RARE_METHOD", "MEDIUM", e.ip, 1, f"line {e.line}: method={e.method} target={target}", "Confirm the method is required; disable it if not."))
    for ip, rows in by_ip.items():
        auth = [e for e in rows if e.status in (401, 403) and re.search(r"login|signin|auth|admin", e.target, re.I)]
        if len(auth) >= threshold:
            findings.append(Finding("WEB_AUTH_FAILURE_BURST", "HIGH", ip, len(auth), f"{len(auth)} 401/403 responses on authentication paths; example: {auth[0].target}", "Correlate identity-provider logs and consider rate limiting."))
        errors = [e for e in rows if e.status >= 400]
        if len(errors) >= threshold:
            findings.append(Finding("WEB_HTTP_ERROR_BURST", "MEDIUM", ip, len(errors), f"{len(errors)} HTTP error responses; example: {errors[0].target}", "Check for broken clients, scanning, or application errors."))
    return findings

def main():
    p = argparse.ArgumentParser(description="Analyze authorized Apache/Nginx access logs.")
    p.add_argument("--input", required=True)
    p.add_argument("--threshold", type=int, default=5)
    p.add_argument("--json-out", default="findings.json")
    p.add_argument("--csv-out", default="findings.csv")
    a = p.parse_args()
    if a.threshold < 1: p.error("--threshold must be >= 1")
    events, skipped = [], 0
    for i, raw in enumerate(Path(a.input).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        e = parse_line(raw, i)
        if e: events.append(e)
        elif raw.strip(): skipped += 1
    findings = analyze(events, a.threshold)
    Path(a.json_out).write_text(json.dumps([asdict(f) for f in findings], indent=2), encoding="utf-8")
    with Path(a.csv_out).open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(Finding.__dataclass_fields__))
        w.writeheader(); w.writerows(asdict(f) for f in findings)
    print(f"WebLogHunter: parsed={len(events)} skipped={skipped} findings={len(findings)}")
    print(f"Reports: {a.json_out}, {a.csv_out}")
    for f in findings: print(f"[{f.severity}] {f.rule_id} | {f.source_ip} | {f.evidence}")

if __name__ == "__main__": main()
