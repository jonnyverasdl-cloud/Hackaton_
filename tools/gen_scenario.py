"""Build the synthetic NovaBanco scenario: 8 attack alerts + 42 noise alerts.

Spec: docs/prep/01-escenario.md. All data is synthetic: `.example` domains,
documentation IPs (203.0.113.0/24 external, 10.20.0.0/16 internal).

Each alert is a *raw* vendor-style record (field names differ per source, the
normalizer maps them). The `_truth` key is ground truth for tests only; it is
stripped before an alert is posted to the API.

Usage:
    python tools/gen_scenario.py --dump [PATH]           # write scenario.json
    python tools/gen_scenario.py --replay --speed 40     # POST /alerts, compressed time
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

DEFAULT_DATE = "2026-10-24"
TZ = timezone(timedelta(hours=-6))
SEED = 20261024
DOMAIN = "novabanco.example"
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DUMP = REPO_ROOT / "scenario.json"

# Internal hosts (10.20.0.0/16) used anywhere in the scenario.
HOST_IPS = {
    "WS-FIN-07": "10.20.4.17",
    "SRV-FILES-01": "10.20.1.10",
    "DC-01": "10.20.1.2",
    "SCAN-01": "10.20.9.5",
    "PRN-02": "10.20.7.32",
    "WS-MKT-03": "10.20.5.23",
    "WS-HR-02": "10.20.6.12",
    "WS-OPS-11": "10.20.3.41",
    "WS-OPS-04": "10.20.3.34",
    "WS-LEG-01": "10.20.8.11",
    "WS-IT-09": "10.20.2.59",
    "WS-RISK-05": "10.20.4.65",
    "WS-CX-14": "10.20.5.84",
    "WS-AUD-02": "10.20.8.42",
    "WS-TRS-06": "10.20.4.96",
    "SRV-APP-02": "10.20.1.22",
    "SRV-SQL-01": "10.20.1.31",
    "SRV-WEB-03": "10.20.1.43",
}

C2_DOMAIN = "cdn-update-sync.example"
C2_IP = "203.0.113.77"


def _ts(day: date, hhmm: str, second: int = 0) -> datetime:
    h, m = (int(x) for x in hhmm.split(":"))
    return datetime(day.year, day.month, day.day, h, m, second, tzinfo=TZ)


def _attack(day: date) -> list[dict]:
    """The 8-step intrusion (A1-A8), exactly as in 01-escenario.md."""
    fin, srv = "WS-FIN-07", "SRV-FILES-01"
    return [
        {
            "_truth": {"attack": True, "step": "A1"},
            "source": "email_gateway", "timestamp": _ts(day, "14:02", 11),
            "rule": "Macro-enabled attachment delivered", "severity": "medium",
            "recipient": f"maria.lopez@{DOMAIN}", "recipient_host": fin,
            "sender": "billing@nb-suppliers.example", "subject": "Overdue invoice 8841",
            "attachment": "Invoice_8841.docm", "delivery": "delivered",
        },
        {
            "_truth": {"attack": True, "step": "A2"},
            "source": "edr", "timestamp": _ts(day, "14:06", 12),
            "rule": "Suspicious child process of Office application", "severity": "high",
            "device": fin, "device_ip": HOST_IPS[fin], "account": "maria.lopez",
            "process": "powershell.exe", "parent_process": "WINWORD.EXE",
            "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
            "signed": False, "action_taken": "none",
        },
        {
            "_truth": {"attack": True, "step": "A3"},
            "source": "proxy", "timestamp": _ts(day, "14:07", 3),
            "rule": "Connection to newly registered domain", "severity": "medium",
            "client_host": fin, "client_ip": HOST_IPS[fin], "user": "maria.lopez",
            "dest_host": C2_DOMAIN, "dest_ip": C2_IP, "method": "CONNECT",
            "url": f"https://{C2_DOMAIN}/api/v2/sync", "category": "uncategorized",
            "domain_age_days": 2, "bytes_out": 48211,
        },
        {
            "_truth": {"attack": True, "step": "A4"},
            "source": "edr", "timestamp": _ts(day, "14:09", 40),
            "rule": "Scheduled task created", "severity": "medium",
            "device": fin, "device_ip": HOST_IPS[fin], "account": "maria.lopez",
            "process": "schtasks.exe", "parent_process": "powershell.exe",
            "command_line": 'schtasks.exe /create /tn "OneDriveSyncHelper" /tr "%APPDATA%\\sync.exe" /sc onlogon',
            "task_name": "OneDriveSyncHelper", "file_path": "%APPDATA%\\sync.exe",
            "signed": False, "action_taken": "none",
        },
        {
            "_truth": {"attack": True, "step": "A5"},
            "source": "auth", "timestamp": _ts(day, "14:15", 20),
            "rule": "Multiple failed logons from single source", "severity": "high",
            "outcome": "failure", "logon_type": 3,
            "src_host": fin, "src_ip": HOST_IPS[fin], "target_host": "DC-01",
            "account": None, "failure_count": 40, "distinct_accounts": 12, "window_seconds": 90,
            "target_accounts": [
                "svc_backup", "svc_sql", "svc_web", "admin.ops", "jose.ramirez", "ana.torres",
                "luis.fernandez", "sofia.castro", "diego.morales", "valeria.rios",
                "pedro.vargas", "camila.ortiz",
            ],
        },
        {
            "_truth": {"attack": True, "step": "A6"},
            "source": "auth", "timestamp": _ts(day, "14:18", 5),
            "rule": "Successful logon from new source host", "severity": "medium",
            "outcome": "success", "logon_type": 3,
            "src_host": fin, "src_ip": HOST_IPS[fin], "target_host": srv,
            "account": "svc_backup", "first_seen_source": True,
        },
        {
            "_truth": {"attack": True, "step": "A7"},
            "source": "edr", "timestamp": _ts(day, "14:20", 31),
            "rule": "Domain group enumeration", "severity": "medium",
            "device": srv, "device_ip": HOST_IPS[srv], "account": "svc_backup",
            "process": "net.exe", "parent_process": "cmd.exe",
            "command_line": 'net group "Domain Admins" /domain',
            "signed": True, "action_taken": "none",
        },
        {
            "_truth": {"attack": True, "step": "A8"},
            "source": "edr", "timestamp": _ts(day, "14:22", 47),
            "rule": "Shadow copy deletion", "severity": "critical",
            "device": srv, "device_ip": HOST_IPS[srv], "account": "svc_backup",
            "process": "vssadmin.exe", "parent_process": "cmd.exe",
            "command_line": "vssadmin delete shadows /all /quiet",
            "signed": True, "action_taken": "none",
        },
    ]


def _noise(day: date, rng: random.Random) -> list[dict]:
    """42 benign alerts in 13:50-14:30 (01-escenario.md, noise table)."""
    start = _ts(day, "13:50")

    def at(minute: float) -> datetime:
        return start + timedelta(minutes=minute, seconds=rng.randint(0, 59))

    out: list[dict] = []

    # 12 x scheduled vulnerability scan from SCAN-01 (svc_nessus).
    scan_targets = ["WS-HR-02", "WS-OPS-11", "WS-OPS-04", "WS-LEG-01", "WS-IT-09", "WS-RISK-05",
                    "WS-CX-14", "WS-AUD-02", "WS-TRS-06", "SRV-APP-02", "SRV-SQL-01", "SRV-WEB-03"]
    scan_sigs = ["Nessus scanner activity", "SMB version probe", "TLS cipher enumeration",
                 "HTTP directory probe"]
    for i, target in enumerate(scan_targets):
        out.append({
            "_truth": {"attack": False, "noise": "vuln_scan"},
            "source": "ids", "timestamp": at(2 + i * 3),
            "rule": "Vulnerability scan detected", "severity": "low",
            "sensor": "IDS-CORE-1", "signature": scan_sigs[i % len(scan_sigs)],
            "src_host": "SCAN-01", "src_ip": HOST_IPS["SCAN-01"], "account": "svc_nessus",
            "dst_host": target, "dst_ip": HOST_IPS[target], "dst_port": rng.choice([22, 80, 443, 445, 3389]),
            "scan_job": "weekly-internal-scan",
        })

    # 10 x isolated failed logons (1-2 attempts). Trap: 2 are maria.lopez at 13:55
    # from her own host, before the attack (forgot password).
    for second in (8, 41):
        out.append({
            "_truth": {"attack": False, "noise": "auth_failed", "trap": "maria_early_failed_logon"},
            "source": "auth", "timestamp": _ts(day, "13:55", second),
            "rule": "Failed logon", "severity": "low",
            "outcome": "failure", "logon_type": 2,
            "src_host": "WS-FIN-07", "src_ip": HOST_IPS["WS-FIN-07"], "target_host": "WS-FIN-07",
            "account": "maria.lopez", "failure_count": 1, "failure_reason": "bad password",
        })
    failed = [("jose.ramirez", "WS-HR-02", 4), ("ana.torres", "WS-OPS-11", 9),
              ("luis.fernandez", "WS-LEG-01", 13), ("sofia.castro", "WS-RISK-05", 17),
              ("diego.morales", "WS-CX-14", 21), ("valeria.rios", "WS-AUD-02", 26),
              ("pedro.vargas", "WS-TRS-06", 31), ("camila.ortiz", "WS-OPS-04", 36)]
    for user, host, minute in failed:
        out.append({
            "_truth": {"attack": False, "noise": "auth_failed"},
            "source": "auth", "timestamp": at(minute),
            "rule": "Failed logon", "severity": "low",
            "outcome": "failure", "logon_type": 2,
            "src_host": host, "src_ip": HOST_IPS[host], "target_host": host,
            "account": user, "failure_count": rng.randint(1, 2), "failure_reason": "bad password",
        })

    # 6 x Windows Update / scheduled reboot (signed Microsoft process).
    update_hosts = ["SRV-APP-02", "SRV-SQL-01", "WS-IT-09", "WS-LEG-01", "WS-AUD-02", "WS-CX-14"]
    for i, host in enumerate(update_hosts):
        proc = "TiWorker.exe" if i % 2 == 0 else "shutdown.exe"
        out.append({
            "_truth": {"attack": False, "noise": "system_update"},
            "source": "edr", "timestamp": at(5 + i * 6),
            "rule": "Windows Update installation / scheduled reboot", "severity": "info",
            "device": host, "device_ip": HOST_IPS[host], "account": None,
            "process": proc, "parent_process": "svchost.exe",
            "command_line": "TiWorker.exe -Embedding" if proc == "TiWorker.exe" else "shutdown.exe /r /t 600 /d p:2:17",
            "signed": True, "signer": "Microsoft Windows", "action_taken": "none",
        })

    # 2 x antivirus detected and cleaned adware on WS-MKT-03.
    for minute, name in ((12, "PUA:Win32/BrowseFox"), (12.5, "PUA:Win32/BrowseFox.B")):
        out.append({
            "_truth": {"attack": False, "noise": "av_cleaned"},
            "source": "edr", "timestamp": at(minute),
            "rule": "Antivirus detection - remediated", "severity": "low",
            "device": "WS-MKT-03", "device_ip": HOST_IPS["WS-MKT-03"], "account": "carlos.mendez",
            "process": "setup_browsefox.exe", "parent_process": "explorer.exe",
            "threat_name": name, "signed": False, "action_taken": "cleaned",
        })

    # 8 x browsing to old, uncategorized news domains.
    news = [("WS-HR-02", "jose.ramirez", "daily-ledger-news.example", 3120),
            ("WS-OPS-11", "ana.torres", "metro-briefing.example", 2410),
            ("WS-LEG-01", "luis.fernandez", "legal-wire-today.example", 4380),
            ("WS-RISK-05", "sofia.castro", "markets-digest.example", 1890),
            ("WS-CX-14", "diego.morales", "city-pulse-news.example", 2755),
            ("WS-AUD-02", "valeria.rios", "weekend-review.example", 3640),
            ("WS-TRS-06", "pedro.vargas", "econ-snapshot.example", 1205),
            ("WS-OPS-04", "camila.ortiz", "regional-herald.example", 5010)]
    for i, (host, user, dom, age) in enumerate(news):
        out.append({
            "_truth": {"attack": False, "noise": "proxy_uncategorized"},
            "source": "proxy", "timestamp": at(1 + i * 5),
            "rule": "Access to uncategorized website", "severity": "info",
            "client_host": host, "client_ip": HOST_IPS[host], "user": user,
            "dest_host": dom, "dest_ip": f"203.0.113.{120 + i}", "method": "GET",
            "url": f"https://{dom}/", "category": "uncategorized",
            "domain_age_days": age, "bytes_out": rng.randint(800, 4000),
        })

    # 4 x printer with repeated authentication errors (printer account on PRN-02).
    for i in range(4):
        out.append({
            "_truth": {"attack": False, "noise": "printer_auth"},
            "source": "auth", "timestamp": at(4 + i * 10),
            "rule": "Repeated authentication failure", "severity": "low",
            "outcome": "failure", "logon_type": 3,
            "src_host": "PRN-02", "src_ip": HOST_IPS["PRN-02"], "target_host": "DC-01",
            "account": "printer.prn02", "failure_count": 3, "failure_reason": "expired password",
        })
    return out


def build_scenario(day: str = DEFAULT_DATE, seed: int = SEED) -> list[dict]:
    """Return all raw alerts sorted by time, with ids ALT-000001.. in that order."""
    d = date.fromisoformat(day)
    rng = random.Random(seed)
    alerts = sorted(_attack(d) + _noise(d, rng), key=lambda a: a["timestamp"])
    out = []
    for i, a in enumerate(alerts, start=1):
        rec = {"id": f"ALT-{i:06d}", **a, "timestamp": a["timestamp"].isoformat()}
        out.append(rec)
    return out


def public_view(alert: dict) -> dict:
    """What gets posted to the API: everything except hidden ground truth."""
    return {k: v for k, v in alert.items() if not k.startswith("_")}


def dump(alerts: list[dict], path: Path) -> None:
    path.write_text(json.dumps({
        "scenario": "Pre-ransomware intrusion at NovaBanco",
        "synthetic": True,
        "note": "Synthetic data only. Domains use .example; IPs are documentation/private ranges.",
        "alerts": alerts,
    }, indent=2), encoding="utf-8")


def replay(alerts: Iterable[dict], base_url: str, speed: float, client=None,
           sleep: Callable[[float], None] = time.sleep) -> int:
    """POST each alert to /alerts, sleeping the scenario gap divided by `speed`."""
    import httpx

    own = client is None
    client = client or httpx.Client(base_url=base_url, timeout=10)
    sent, prev = 0, None
    try:
        for a in alerts:
            ts = datetime.fromisoformat(a["timestamp"])
            if prev is not None and speed > 0:
                sleep(max(0.0, (ts - prev).total_seconds() / speed))
            prev = ts
            r = client.post("/alerts", json=public_view(a))
            r.raise_for_status()
            sent += 1
            print(f"[{sent:02d}] {a['id']} {a['source']:<13} {a['rule']}")
    finally:
        if own:
            client.close()
    return sent


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Synthetic NovaBanco alert scenario")
    p.add_argument("--dump", nargs="?", const=str(DEFAULT_DUMP), metavar="PATH",
                   help=f"write scenario JSON (default {DEFAULT_DUMP.name})")
    p.add_argument("--replay", action="store_true", help="POST alerts to the backend")
    p.add_argument("--speed", type=float, default=40, help="time compression factor (40: 40 min -> 60 s)")
    p.add_argument("--url", default="http://127.0.0.1:8000", help="backend base URL")
    p.add_argument("--date", default=DEFAULT_DATE, help="scenario day, YYYY-MM-DD")
    args = p.parse_args(argv)

    alerts = build_scenario(args.date)
    if not args.dump and not args.replay:
        args.dump = str(DEFAULT_DUMP)
    if args.dump:
        dump(alerts, Path(args.dump))
        print(f"Wrote {len(alerts)} synthetic alerts to {args.dump}")
    if args.replay:
        n = replay(alerts, args.url, args.speed)
        print(f"Replayed {n} alerts to {args.url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
