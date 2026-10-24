import json
import time
from datetime import date

import pytest
from fastapi.testclient import TestClient

from backend.app import ai
from backend.app.ai import AIConfig, Narrator, build_prompt, load_config, prompt_hash, verify_entities
from backend.app.main import create_app
from backend.app.store import Store
from tools import gen_scenario as gs

RAW = gs.build_scenario()
ATTACK_IDS = {r["id"] for r in RAW if r["_truth"]["attack"]}
TODAY = date(2026, 10, 24)

GOOD = {
    "narrative": ("At 14:02 maria.lopez on WS-FIN-07 received Invoice_8841.docm from billing@nb-suppliers.example. "
                  "At 14:06 WINWORD.EXE spawned powershell.exe. At 14:07 WS-FIN-07 contacted "
                  "cdn-update-sync.example (203.0.113.77). At 14:18 svc_backup logged on to SRV-FILES-01 "
                  "(ALT-000038, INC-0003), technique T1021.002. At 14:22 shadow copies were deleted."),
    "hypothesis": "Pre-encryption stage of a ransomware intrusion.",
    "recommended_actions": ["Isolate WS-FIN-07 and SRV-FILES-01", "Disable svc_backup",
                            "Block cdn-update-sync.example and 203.0.113.77"],
    "confidence": 0.9,
}


class Resp:
    def __init__(self, text):
        self.text = text


class FakeClient:
    """Stands in for genai.Client: records calls, answers with `behavior(prompt)`."""

    def __init__(self, behavior):
        self.calls = []
        outer = self

        class Models:
            def generate_content(self, model, contents, config):
                outer.calls.append({"model": model, "contents": contents, "config": config})
                return behavior(contents)

        self.models = Models()


def narrator(behavior, timeout_s=2.0):
    client = FakeClient(behavior)
    return Narrator(AIConfig(mode="vertex", model="gemini-test", timeout_s=timeout_s), client=client,
                    today=TODAY), client


@pytest.fixture(scope="module")
def attack_incident():
    s = Store(window_min=30)
    for r in RAW:
        s.ingest(gs.public_view(r))
    return next(i for i in s.incidents.values() if ATTACK_IDS & set(i["alerts"]))


# --- calls, trace, prompt -----------------------------------------------------

def test_successful_call_has_full_trace(attack_incident):
    n, client = narrator(lambda p: Resp(json.dumps(GOOD)))
    block = n.narrate(attack_incident)
    assert block["generated_by"] == "gemini-test"
    assert block["narrative"] == GOOD["narrative"] and block["confidence"] == 0.9
    trace = block["trace"]
    assert trace["model"] == "gemini-test" and trace["error"] is None
    assert trace["raw_response"] == json.dumps(GOOD)
    assert trace["prompt_sha256"] == prompt_hash(build_prompt(attack_incident, TODAY))
    assert len(trace["prompt_sha256"]) == 64 and isinstance(trace["latency_ms"], int)
    assert block["flags"] == []  # everything GOOD mentions is in the incident
    assert len(client.calls) == 1 and n.calls == 1


def test_prompt_contract(attack_incident):
    n, client = narrator(lambda p: Resp(json.dumps(GOOD)))
    n.narrate(attack_incident)
    call = client.calls[0]
    assert call["model"] == "gemini-test"
    assert call["contents"].startswith("Today's date is 2026-10-24.")
    facts = json.loads(call["contents"].split("Incident JSON:\n", 1)[1])
    assert [e["alert_id"] for e in facts["timeline"]] == attack_incident["alerts"]
    assert "raw" not in json.dumps(facts)  # only the finished incident, no raw vendor data
    cfg = call["config"]
    assert cfg.response_mime_type == "application/json" and cfg.system_instruction == ai.SYSTEM_PROMPT
    assert "Never invent hosts, users, IP addresses, domains" in ai.SYSTEM_PROMPT
    assert "Do not change the verdict" in ai.SYSTEM_PROMPT


# --- fallbacks -----------------------------------------------------------------

def test_timeout_falls_back_to_stub(attack_incident):
    def slow(prompt):
        time.sleep(1.5)
        return Resp(json.dumps(GOOD))

    n, _ = narrator(slow, timeout_s=0.3)
    started = time.perf_counter()
    block = n.narrate(attack_incident)
    assert time.perf_counter() - started < 1.2  # the caller is not held for the slow call
    assert block["generated_by"] == "stub" and block["trace"]["error"] == "timeout after 0.3 s"
    assert block["trace"]["model"] == "gemini-test" and block["narrative"].startswith("At 14:02,")


def test_default_timeout_is_30s():
    assert ai.TIMEOUT_S == 30 and AIConfig(mode="vertex").timeout_s == 30


@pytest.mark.parametrize("behavior,error", [
    (lambda p: (_ for _ in ()).throw(ConnectionError("network down")), "ConnectionError"),
    (lambda p: Resp("not json at all"), "JSONDecodeError"),
    (lambda p: Resp(json.dumps({"narrative": "x"})), "ValueError"),
    (lambda p: Resp(json.dumps({**GOOD, "recommended_actions": "isolate"})), "ValueError"),
])
def test_errors_fall_back_to_stub(attack_incident, behavior, error):
    n, _ = narrator(behavior)
    block = n.narrate(attack_incident)
    assert block["generated_by"] == "stub" and block["trace"]["error"] == error  # type only
    assert n.last_error == block["trace"]["error"]


def test_raw_response_kept_even_when_unparseable(attack_incident):
    n, _ = narrator(lambda p: Resp("{broken"))
    assert n.narrate(attack_incident)["trace"]["raw_response"] == "{broken"


# --- entity verification ---------------------------------------------------------

def test_invented_entities_are_flagged(attack_incident):
    out = {"narrative": ("At 03:15 on 2025-01-01, WS-EVIL-99 (198.51.100.7) beaconed to evil.example; "
                         "john.doe and svc_payroll were used. Mail from x@phish.example."),
           "hypothesis": "", "recommended_actions": ["Isolate WS-FIN-07"], "confidence": 0.5}
    flags = {(f["type"], f["value"]) for f in verify_entities(out, attack_incident, TODAY)}
    assert flags == {("unknown_time", "03:15"), ("unknown_date", "2025-01-01"), ("unknown_host", "WS-EVIL-99"),
                     ("unknown_ip", "198.51.100.7"), ("unknown_domain", "evil.example"),
                     ("unknown_user", "john.doe"), ("unknown_user", "svc_payroll"),
                     ("unknown_domain", "phish.example")}


def test_known_entities_and_evidence_details_not_flagged(attack_incident):
    out = {**GOOD, "narrative": GOOD["narrative"] + " Confidence 0.9, e.g. T1566.001 on 2026-10-24."}
    assert verify_entities(out, attack_incident, TODAY) == []


def test_flags_attach_to_the_ai_block(attack_incident):
    n, _ = narrator(lambda p: Resp(json.dumps({**GOOD, "hypothesis": "Pivot to DC-02 next."})))
    flags = n.narrate(attack_incident)["flags"]
    assert flags == [{"type": "unknown_host", "value": "DC-02", "field": "hypothesis"}]


def test_stub_never_invents(attack_incident):
    block = Narrator(AIConfig(mode="stub", reason="test"), today=TODAY).narrate(attack_incident)
    assert block["generated_by"] == "stub" and block["flags"] == []
    assert block["trace"]["model"] == "stub" and block["trace"]["error"] == "test"


# --- config -----------------------------------------------------------------------

def test_no_credentials_means_stub(monkeypatch):
    for k in ("AI_DISABLED", "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT", "AI_MODEL"):
        monkeypatch.delenv(k, raising=False)
    cfg = load_config()
    assert cfg.mode == "stub" and cfg.model == "gemini-2.5-flash" and "credentials" in cfg.reason


def test_credentials_file_gives_project(monkeypatch, tmp_path):
    creds = tmp_path / "sa.json"
    creds.write_text(json.dumps({"project_id": "demo-project", "private_key": "unused"}), encoding="utf-8")
    monkeypatch.delenv("AI_DISABLED", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(creds))
    monkeypatch.setenv("AI_MODEL", "gemini-2.5-flash")
    cfg = load_config()
    assert (cfg.mode, cfg.project, cfg.location, cfg.model) == ("vertex", "demo-project", "us-central1",
                                                                 "gemini-2.5-flash")


def test_ai_disabled_wins(monkeypatch):
    monkeypatch.setenv("AI_DISABLED", "1")
    assert load_config().mode == "stub"


# --- store + API integration --------------------------------------------------------

def _store_with(n, ai_async=False):
    s = Store(window_min=30, narrator=n, ai_async=ai_async)
    for r in RAW:
        s.ingest(gs.public_view(r))
    return s


def _attack(s):
    return next(i for i in s.incidents.values() if ATTACK_IDS & set(i["alerts"]))


def test_ai_calls_are_audited():
    n, client = narrator(lambda p: Resp(json.dumps(GOOD)))
    s = _store_with(n)
    entries = [e for e in s.audit if e["action"] == "ai_narrative"]
    assert len(entries) == len(client.calls) > 0
    assert all(e["executed_by"] == "ai:gemini-test" and "prompt sha256" in e["reason"] for e in entries)
    assert _attack(s)["ai"]["generated_by"] == "gemini-test"


def test_fallbacks_are_audited_too():
    n, _ = narrator(lambda p: Resp("nope"))
    s = _store_with(n)
    entries = [e for e in s.audit if e["action"] == "ai_narrative"]
    assert entries and all(e["executed_by"] == "ai:stub" and "fallback: JSONDecodeError" in e["reason"]
                           for e in entries)


def test_closed_noise_gets_stub_without_a_model_call():
    n, client = narrator(lambda p: Resp(json.dumps(GOOD)))
    s = _store_with(n)
    closed = [i for i in s.incidents.values() if i["status"] == "closed"]
    assert closed and all(i["ai"]["generated_by"] == "stub" for i in closed)
    called_for = {json.loads(c["contents"].split("Incident JSON:\n", 1)[1])["incident_id"] for c in client.calls}
    assert called_for == {_attack(s)["incident_id"]}


def test_ai_output_never_changes_actions():
    hostile = {**GOOD, "recommended_actions": ["wipe_disk WS-FIN-07", "isolate_host DC-01", "Disable all users"]}
    with_ai = _attack(_store_with(narrator(lambda p: Resp(json.dumps(hostile)))[0]))
    without = _attack(_store_with(Narrator(AIConfig(mode="stub"))))
    strip = lambda acts: [{k: v for k, v in a.items() if k not in ("executed_at", "wall_time")} for a in acts]
    assert strip(with_ai["actions"]) == strip(without["actions"])
    assert with_ai["ai"]["recommended_actions"] == hostile["recommended_actions"]  # shown, never executed
    assert {"type": "unknown_host", "value": "DC-01", "field": "recommended_actions"} in with_ai["ai"]["flags"]


def test_async_worker_fills_ai_without_blocking_ingest():
    def slow(prompt):
        time.sleep(0.2)
        return Resp(json.dumps(GOOD))

    n, _ = narrator(slow)
    started = time.perf_counter()
    s = _store_with(n, ai_async=True)
    assert time.perf_counter() - started < 3  # 50 ingests did not wait for the model
    deadline = time.time() + 10
    while time.time() < deadline:
        with s.lock:
            block = _attack(s)["ai"]
            if block and block["generated_by"] == "gemini-test" and block["alerts_covered"] == 8:
                break
        time.sleep(0.05)
    assert block["generated_by"] == "gemini-test" and block["alerts_covered"] == 8


def test_health_reports_ai_mode():
    n, _ = narrator(lambda p: Resp(json.dumps(GOOD)))
    c = TestClient(create_app(Store(window_min=30, narrator=n)))
    h = c.get("/health").json()
    assert h["mode"] == "rules+ai" and h["ai_model"] == "gemini-test" and h["ai"]["mode"] == "vertex"
    stub = TestClient(create_app(Store(window_min=30))).get("/health").json()
    assert stub["mode"] == "rules-only" and stub["ai_model"] == "stub"


def test_ai_block_matches_schema():
    from jsonschema import Draft202012Validator, FormatChecker
    from pathlib import Path
    schema = json.loads((Path(__file__).parent.parent / "contracts" / "incident.schema.json").read_text(encoding="utf-8"))
    v = Draft202012Validator({**schema, "$ref": "#/$defs/incident"}, format_checker=FormatChecker())
    hallucinating = {**GOOD, "hypothesis": "Next target is DC-02."}
    for behavior in (lambda p: Resp(json.dumps(hallucinating)), lambda p: Resp("bad")):
        s = _store_with(narrator(behavior)[0])
        for inc in s.incidents.values():
            v.validate(inc)
        assert _attack(s)["ai"]["trace"]["prompt_sha256"]


def _facts(call):
    """The incident JSON the model was given in one recorded call."""
    return json.loads(call["contents"].split("Incident JSON:\n", 1)[1])


def test_no_duplicate_call_when_unrelated_alerts_arrive_mid_call():
    def slow(prompt):
        time.sleep(0.4)
        return Resp(json.dumps(GOOD))

    n, client = narrator(slow)
    s = Store(window_min=30, narrator=n, ai_async=True)
    last_attack = max(i for i, r in enumerate(RAW) if r["_truth"]["attack"])
    for r in RAW[:last_attack + 1]:
        s.ingest(gs.public_view(r))
    deadline = time.time() + 5  # wait until the call for the full 8-alert state has started
    while time.time() < deadline and not any(len(_facts(c)["timeline"]) == 8 for c in client.calls):
        time.sleep(0.02)
    for r in RAW[last_attack + 1:]:  # unrelated noise arrives meanwhile
        s.ingest(gs.public_view(r))
    time.sleep(1.5)
    attack_id = _attack(s)["incident_id"]
    prompts = [c["contents"] for c in client.calls if f'"incident_id": "{attack_id}"' in c["contents"]]
    assert len(prompts) == len(set(prompts)), "same incident state narrated twice"


# --- follow-up: secrets in errors (#6), entity false positives (#5), reset race (#4) ---

SECRET_ERROR = ("403 Permission denied on resource project demo-proj-123 for "
                "storyline-sa@demo-proj-123.iam.gserviceaccount.com")


def test_vertex_error_text_never_leaves_the_server(attack_incident, caplog):
    def denied(prompt):
        raise PermissionError(SECRET_ERROR)

    n, _ = narrator(denied)
    s = Store(window_min=30, narrator=n)
    with caplog.at_level("WARNING", logger="storyline.ai"):
        for r in RAW:
            s.ingest(gs.public_view(r))
    attack = _attack(s)
    assert attack["ai"]["trace"]["error"] == "PermissionError" and n.last_error == "PermissionError"
    public = json.dumps([attack, s.audit, s.audit_view()])
    assert "gserviceaccount" not in public and "demo-proj-123" not in public
    health = TestClient(create_app(s)).get("/health").text
    assert "gserviceaccount" not in health and "demo-proj-123" not in health
    assert SECRET_ERROR in caplog.text  # full text only in the server log


def test_no_false_flags_for_cve_hashes_files_and_case(attack_incident):
    text = ("The macro may exploit CVE-2017-11882; SHA-256 and MD5 of invoice.pdf, payload.bin and "
            "README.txt were collected; System.Net.WebClient fetched sync.exe. Maria.Lopez and "
            "SVC_BACKUP on ws-fin-07 / Srv-Files-01 (ALT-000038, INC-0003).")
    out = {"narrative": text, "hypothesis": "", "recommended_actions": [], "confidence": 0.5}
    assert verify_entities(out, attack_incident, TODAY) == []


def test_invented_entities_still_flagged_next_to_cves(attack_incident):
    out = {"narrative": ("CVE-2021-40444 on WS-EVIL-99 by john.doe via evil.example; beacons to "
                         "c2.badsite.de, update-cdn.co.uk and evil.sh as j.smith2."), "hypothesis": "",
           "recommended_actions": [], "confidence": 0.5}
    flags = {(f["type"], f["value"]) for f in verify_entities(out, attack_incident, TODAY)}
    assert flags == {("unknown_host", "WS-EVIL-99"), ("unknown_user", "john.doe"),
                     ("unknown_domain", "evil.example"), ("unknown_domain", "c2.badsite.de"),
                     ("unknown_domain", "update-cdn.co.uk"), ("unknown_domain", "evil.sh"),
                     ("unknown_user", "j.smith2")}


class GatedClient:
    """Fake client whose calls block until released: deterministic, no sleeps."""

    def __init__(self):
        import threading
        self.calls, self.started, self.release = [], threading.Event(), threading.Event()
        outer = self

        class Models:
            def generate_content(self, model, contents, config):
                outer.calls.append(contents)
                outer.started.set()
                outer.release.wait(5)
                return Resp(json.dumps(GOOD))

        self.models = Models()


def test_reset_during_call_drops_stale_result_and_audit():
    client = GatedClient()
    n = Narrator(AIConfig(mode="vertex", model="gemini-test"), client=client, today=TODAY)
    s = Store(window_min=30, narrator=n, ai_async=True)
    for r in RAW:
        s.ingest(gs.public_view(r))
    assert client.started.wait(5)  # a call is now in flight
    s.reset()
    assert s.audit == [] and s.incidents == {}
    for r in RAW:  # the demo is replayed: the same incident exists again
        s.ingest(gs.public_view(r))
    client.release.set()  # only now does the pre-reset call return
    deadline = time.time() + 5
    while time.time() < deadline:
        with s.lock:
            block = _attack(s)["ai"]
            if block and block["alerts_covered"] == 8:
                break
        time.sleep(0.05)
    with s.lock:
        ai_entries = [e for e in s.audit if e["action"] == "ai_narrative"]
        prompts = [c for c in client.calls[1:]]
    assert block["generated_by"] == "gemini-test" and block["alerts_covered"] == 8
    assert len(prompts) == len(set(prompts)), "a state was narrated twice after reset"
    assert len(ai_entries) == len(client.calls) - 1  # the pre-reset call left no audit entry


# --- follow-up 3: warm-up route, prompt date, prose false positives ----------------

def test_warmup_through_the_backend_client():
    n, client = narrator(lambda p: Resp("OK"))
    c = TestClient(create_app(Store(window_min=30, narrator=n)))
    warm = c.post("/ai/warmup").json()
    assert warm["ok"] is True and warm["model"] == "gemini-test" and warm["error"] is None
    assert client.calls and "Incident JSON" not in client.calls[0]["contents"]  # no incident data sent
    assert c.get("/health").json()["ai"]["warm_up"] == warm
    assert n.calls == 0  # narration counter untouched


def test_warmup_failure_exposes_only_the_type(caplog):
    def denied(prompt):
        raise PermissionError(SECRET_ERROR)

    n, _ = narrator(denied)
    c = TestClient(create_app(Store(window_min=30, narrator=n)))
    with caplog.at_level("WARNING", logger="storyline.ai"):
        warm = c.post("/ai/warmup").json()
    assert warm == {"ok": False, "model": "gemini-test", "latency_ms": warm["latency_ms"], "error": "PermissionError"}
    assert "demo-proj-123" not in c.get("/health").text and SECRET_ERROR in caplog.text


def test_warmup_in_stub_mode_makes_no_call():
    warm = TestClient(create_app(Store(window_min=30))).post("/ai/warmup").json()
    assert warm["ok"] is False and warm["model"] == "stub"


def test_prompt_date_comes_from_the_store_clock():
    n, client = narrator(lambda p: Resp(json.dumps(GOOD)))
    n._today = None
    s = Store(window_min=30, narrator=n, clock=lambda: "2031-02-03T09:00:00-06:00")
    for r in RAW:
        s.ingest(gs.public_view(r))
    attack = _attack(s)
    assert all(c["contents"].startswith("Today's date is 2031-02-03.") for c in client.calls)
    assert attack["ai"]["trace"]["prompt_sha256"] == prompt_hash(build_prompt(attack, date(2031, 2, 3)))
    assert attack["ai"]["trace"]["called_at"] == "2031-02-03T09:00:00-06:00"


def test_prose_without_spaces_and_scripts_not_flagged(attack_incident):
    text = ("Credentials were sprayed against the password.Then lateral movement followed to the domain.It "
            "ran loader.py and Office.Interop automation.")
    out = {"narrative": text, "hypothesis": "", "recommended_actions": [], "confidence": 0.5}
    assert verify_entities(out, attack_incident, TODAY) == []


def test_lowercase_hosts_and_new_tlds_flagged(attack_incident):
    out = {"narrative": "Then ws-fin-99 and srv-dc-01 reached x.onion and evil.cloud; a pre-ransomware stage.",
           "hypothesis": "", "recommended_actions": [], "confidence": 0.5}
    flags = {(f["type"], f["value"]) for f in verify_entities(out, attack_incident, TODAY)}
    assert flags == {("unknown_host", "ws-fin-99"), ("unknown_host", "srv-dc-01"),
                     ("unknown_domain", "x.onion"), ("unknown_domain", "evil.cloud")}


# --- last good narrative is kept when a later call fails ---------------------------

def _flaky(fail_calls):
    count = {"n": 0}

    def behave(prompt):
        count["n"] += 1
        if count["n"] in fail_calls:
            raise PermissionError("quota exceeded for demo-proj-123")
        return Resp(json.dumps(GOOD))
    return behave


def test_later_failure_keeps_last_good_narrative():
    n, client = narrator(_flaky(fail_calls=range(2, 100)))  # only the first call succeeds
    s = Store(window_min=30, narrator=n)
    for r in RAW:
        s.ingest(gs.public_view(r))
    attack = _attack(s)
    assert len(client.calls) > 1
    assert attack["ai"]["generated_by"] != "stub" and attack["ai"]["narrative"] == GOOD["narrative"]
    uf = attack["ai"]["update_failed"]
    assert uf["error"] == "PermissionError" and uf["alerts"] == len(attack["alerts"])
    assert "demo-proj-123" not in json.dumps(attack["ai"])
    assert any(e["action"] == "ai_narrative" and e["executed_by"] == "ai:stub" for e in s.audit)  # still audited


def test_success_after_failure_clears_the_mark():
    n, client = narrator(_flaky(fail_calls={2}))
    s = Store(window_min=30, narrator=n)
    for r in RAW:
        s.ingest(gs.public_view(r))
    attack = _attack(s)
    assert len(client.calls) > 2
    assert attack["ai"]["generated_by"] != "stub" and "update_failed" not in attack["ai"]


def test_first_failure_still_shows_the_stub():
    n, _ = narrator(_flaky(fail_calls=range(1, 100)))
    s = Store(window_min=30, narrator=n)
    for r in RAW:
        s.ingest(gs.public_view(r))
    attack = _attack(s)
    assert attack["ai"]["generated_by"] == "stub" and "update_failed" not in attack["ai"]
