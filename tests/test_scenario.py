import ipaddress
import json
import re
from collections import Counter
from datetime import datetime

import httpx
import pytest

from tools import gen_scenario as gs

EXTERNAL = ipaddress.ip_network("203.0.113.0/24")
INTERNAL = ipaddress.ip_network("10.20.0.0/16")


@pytest.fixture(scope="module")
def alerts():
    return gs.build_scenario()


def attack(alerts):
    return [a for a in alerts if a["_truth"]["attack"]]


def test_total_count(alerts):
    assert 45 <= len(alerts) <= 55


def test_exactly_eight_attack_alerts_in_order(alerts):
    steps = [a["_truth"]["step"] for a in attack(alerts)]
    assert steps == [f"A{i}" for i in range(1, 9)]


def test_attack_times_and_sources_match_spec(alerts):
    expected = {
        "A1": ("14:02", "email_gateway"), "A2": ("14:06", "edr"), "A3": ("14:07", "proxy"),
        "A4": ("14:09", "edr"), "A5": ("14:15", "auth"), "A6": ("14:18", "auth"),
        "A7": ("14:20", "edr"), "A8": ("14:22", "edr"),
    }
    for a in attack(alerts):
        hhmm, source = expected[a["_truth"]["step"]]
        assert datetime.fromisoformat(a["timestamp"]).strftime("%H:%M") == hhmm
        assert a["source"] == source
    by_step = {a["_truth"]["step"]: a for a in attack(alerts)}
    assert by_step["A3"]["dest_host"] == "cdn-update-sync.example"
    assert by_step["A3"]["dest_ip"] == "203.0.113.77"
    assert by_step["A6"]["src_host"] == "WS-FIN-07"
    assert by_step["A6"]["target_host"] == "SRV-FILES-01"
    assert by_step["A6"]["account"] == "svc_backup"
    assert "vssadmin delete shadows" in by_step["A8"]["command_line"]


def test_noise_breakdown(alerts):
    noise = Counter(a["_truth"]["noise"] for a in alerts if not a["_truth"]["attack"])
    assert noise == {"vuln_scan": 12, "auth_failed": 10, "system_update": 6,
                     "av_cleaned": 2, "proxy_uncategorized": 8, "printer_auth": 4}


def test_maria_trap_failed_logons_before_attack(alerts):
    trap = [a for a in alerts if a["_truth"].get("trap") == "maria_early_failed_logon"]
    assert len(trap) == 2
    for a in trap:
        assert a["account"] == "maria.lopez" and a["src_host"] == "WS-FIN-07"
        assert a["outcome"] == "failure" and a["failure_count"] <= 2
        assert datetime.fromisoformat(a["timestamp"]).strftime("%H:%M") == "13:55"


def test_window_and_ids(alerts):
    times = [datetime.fromisoformat(a["timestamp"]) for a in alerts]
    assert times == sorted(times)
    assert all("13:50" <= t.strftime("%H:%M") < "14:30" for t in times)
    assert [a["id"] for a in alerts] == [f"ALT-{i:06d}" for i in range(1, len(alerts) + 1)]


def _strings(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)
    elif isinstance(obj, str):
        yield obj


def test_synthetic_only(alerts):
    for s in _strings(alerts):
        for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", s):
            addr = ipaddress.ip_address(ip)
            assert addr in EXTERNAL or addr in INTERNAL, ip
    # Every field that carries a domain (URL host, email domain, proxy dest) uses .example.
    domains = []
    for a in alerts:
        if "dest_host" in a:
            domains.append(a["dest_host"])
        if "url" in a:
            domains.append(re.match(r"https?://([^/]+)", a["url"]).group(1))
        domains += [a[k].split("@")[1] for k in ("sender", "recipient") if k in a]
    assert len(domains) >= 18
    assert all(d.endswith(".example") for d in domains), domains


def test_deterministic():
    assert gs.build_scenario() == gs.build_scenario()


def test_public_view_strips_truth(alerts):
    assert all("_truth" not in gs.public_view(a) for a in alerts)


def test_dump_roundtrip(tmp_path, alerts):
    path = tmp_path / "scenario.json"
    gs.dump(alerts, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["synthetic"] is True and data["alerts"] == alerts


def test_replay_posts_all_without_truth(alerts):
    bodies = []

    def handler(request):
        assert request.url.path == "/alerts"
        bodies.append(json.loads(request.content))
        return httpx.Response(201, json={"ok": True})

    slept = []
    client = httpx.Client(base_url="http://test", transport=httpx.MockTransport(handler))
    sent = gs.replay(alerts, "http://test", speed=40, client=client, sleep=slept.append)
    assert sent == len(alerts) == len(bodies)
    assert all("_truth" not in b for b in bodies)
    span = (datetime.fromisoformat(alerts[-1]["timestamp"])
            - datetime.fromisoformat(alerts[0]["timestamp"])).total_seconds()
    assert sum(slept) == pytest.approx(span / 40)
    assert sum(slept) <= 60
