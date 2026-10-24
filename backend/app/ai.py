"""AI layer: narrative + hypothesis + recommended actions for a FINISHED incident.

Gemini via Vertex AI (google-genai). The AI never correlates, scores or executes:
it reads the incident and writes text. Every call leaves a trace (model, prompt
hash, latency, raw response) and its output is checked against the incident's own
entities; anything it mentions that is not in the incident becomes a flag.
No credentials, a timeout, an error or bad JSON -> deterministic stub
(generated_by "stub"), so the demo never depends on the network.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

log = logging.getLogger("storyline.ai")

DEFAULT_MODEL = "gemini-2.5-flash"
DEFAULT_LOCATION = "us-central1"
TIMEOUT_S = 30

SYSTEM_PROMPT = """You are a SOC analyst assistant. You receive ONE security incident that a
deterministic rules engine has already correlated and scored. Write for a human analyst.

Hard rules:
- Use only facts present in the incident JSON. Never invent hosts, users, IP addresses, domains,
  files, times or dates that are not in it.
- Do not change the verdict, risk score or severity. Do not claim any action was taken unless the
  incident's actions list says it was executed.
- narrative: chronological, 5 to 8 sentences, each tied to timeline entries (use their HH:MM times).
- hypothesis: one sentence, the most likely attacker objective given the techniques.
- recommended_actions: 3 to 5 concrete, prioritized steps naming the exact hosts, accounts,
  domains or IPs from the incident.
- confidence: a number from 0 to 1 for the hypothesis.
- Output JSON only, matching the schema. English only."""

RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "narrative": {"type": "STRING"},
        "hypothesis": {"type": "STRING"},
        "recommended_actions": {"type": "ARRAY", "items": {"type": "STRING"}},
        "confidence": {"type": "NUMBER"},
    },
    "required": ["narrative", "hypothesis", "recommended_actions", "confidence"],
}


@dataclass
class AIConfig:
    mode: str  # "vertex" or "stub"
    model: str = DEFAULT_MODEL
    project: str | None = None
    location: str = DEFAULT_LOCATION
    timeout_s: float = TIMEOUT_S
    reason: str = ""  # why stub, for /health


def _project_from_credentials(path: str | None) -> str | None:
    """Read only `project_id` from the service-account file; nothing else is touched."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8")).get("project_id") if path else None
    except (OSError, ValueError):
        return None


def load_config() -> AIConfig:
    model = os.getenv("AI_MODEL") or DEFAULT_MODEL
    if os.getenv("AI_DISABLED") == "1":
        return AIConfig(mode="stub", model=model, reason="AI disabled by AI_DISABLED=1")
    creds = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if not creds or not Path(creds).is_file():
        return AIConfig(mode="stub", model=model, reason="no Vertex AI credentials configured")
    project = os.getenv("GOOGLE_CLOUD_PROJECT") or _project_from_credentials(creds)
    if not project:
        return AIConfig(mode="stub", model=model, reason="no Google Cloud project configured")
    return AIConfig(mode="vertex", model=model, project=project,
                    location=os.getenv("GOOGLE_CLOUD_LOCATION") or DEFAULT_LOCATION)


def _vertex_client(cfg: AIConfig):
    from google import genai
    from google.genai import types

    return genai.Client(vertexai=True, project=cfg.project, location=cfg.location,
                        http_options=types.HttpOptions(timeout=int(cfg.timeout_s * 1000)))


# --- prompt -------------------------------------------------------------------

def incident_facts(incident: dict) -> dict:
    """The only input the model sees: the finished incident, minus bookkeeping."""
    return {
        "incident_id": incident["incident_id"], "title": incident["title"],
        "verdict": incident["verdict"], "risk_score": incident["risk_score"],
        "window": incident["window"], "entities": incident["entities"],
        "tactics_covered": incident["tactics_covered"], "timeline": incident["timeline"],
        "correlation_reasons": incident["correlation_reasons"], "signals": incident["signals"],
        "actions": [{"id": a["id"], "label": a["label"], "status": a["status"]} for a in incident["actions"]],
    }


def build_prompt(incident: dict, today: date | None = None) -> str:
    today = today or date.today()
    return (f"Today's date is {today.isoformat()}. The data below is a synthetic training scenario.\n"
            f"Incident JSON:\n{json.dumps(incident_facts(incident), indent=1)}")


def prompt_hash(prompt: str) -> str:
    return hashlib.sha256((SYSTEM_PROMPT + "\n" + prompt).encode("utf-8")).hexdigest()


# --- entity verification ---------------------------------------------------------

_FILE_EXT = tuple("." + e for e in (
    "exe dll sys msi lnk ps1 psm1 bat cmd js vbs hta wsf scr docm docx doc xlsm xlsx xls pptm pptx pdf "
    "txt log csv json xml yml yaml ini cfg conf dat bin tmp iso img zip rar 7z gz tar png jpg gif html htm "
    "eml msg").split())  # not .sh/.py: those are also real TLDs
_NOT_ENTITY = re.compile(r"\b(?:CVE-\d{4}-\d+|SHA-?\d+|MD5|ALT-\d+|INC-\d+)\b", re.IGNORECASE)
_FIRST_LAST = re.compile(r"[a-z]+\.[a-z]+", re.IGNORECASE)  # user shape: first.last
_TLDS = frozenset("example com net org io ru cn info biz xyz top de uk co us su sh me cc tk ml ga cf gq pw "
                  "online site club app dev ai zip mov ws to".split())
_CODE_NAMESPACES = ("system.", "microsoft.", "windows.", "net.", "java.", "javax.", "org.apache.")
_EMAIL = re.compile(r"\b[\w.+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", re.IGNORECASE)
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DOTTED = re.compile(r"\b[a-z0-9][a-z0-9_-]*(?:\.[a-z0-9_-]+)+\b", re.IGNORECASE)  # domain, user or file
_SVC_USER = re.compile(r"\b(?:svc|adm|admin)_[a-z0-9_]+\b", re.IGNORECASE)
_HOST = re.compile(r"\b[A-Z]{2,}(?:-[A-Z0-9]+)+\b")
_TIME = re.compile(r"\b(?:[01]\d|2[0-3]):[0-5]\d\b")
_DATE = re.compile(r"\b20\d\d-\d\d-\d\d\b")


def verify_entities(output: dict, incident: dict, today: date | None = None) -> list[dict]:
    """Flag every host, user, IP, domain, time or date in the AI text that is not in the incident."""
    ents = incident["entities"]
    times = {datetime.fromisoformat(e["timestamp"]).strftime("%H:%M") for e in incident["timeline"]}
    times |= {datetime.fromisoformat(incident["window"][k]).strftime("%H:%M") for k in ("start", "end")}
    dates = {datetime.fromisoformat(e["timestamp"]).date().isoformat() for e in incident["timeline"]}
    dates.add((today or date.today()).isoformat())
    hosts, users = {h.upper() for h in ents["hosts"]}, {u.lower() for u in ents["users"]}
    domains, ips = {d.lower() for d in ents["domains"]}, set(ents["ips"])
    flags: list[dict] = []

    def flag(kind: str, value: str, field: str) -> None:
        item = {"type": kind, "value": value, "field": field}
        if item not in flags:
            flags.append(item)

    fields = {"narrative": output.get("narrative", ""), "hypothesis": output.get("hypothesis", ""),
              "recommended_actions": " \n".join(output.get("recommended_actions", []))}
    for field, text in fields.items():
        for m in _EMAIL.finditer(text):
            if m.group(1).lower() not in domains:
                flag("unknown_domain", m.group(1), field)
        text = _EMAIL.sub(" ", text)
        for ip in _IP.findall(text):
            if ip not in ips:
                flag("unknown_ip", ip, field)
        text = _IP.sub(" ", text)
        text = _NOT_ENTITY.sub(" ", text)  # CVE ids, hash names, alert/incident ids
        for token in _DOTTED.findall(text):
            low = token.lower().rstrip(".")
            if low.endswith(_FILE_EXT) or not re.search(r"[a-z]{2}", low):
                continue  # file names, numbers, "e.g", technique ids: not entities
            labels = low.split(".")
            if low in domains or low in users or low.startswith(_CODE_NAMESPACES):
                continue  # known entity, or code like System.Net.WebClient
            if labels[-1] in _TLDS or (len(labels) >= 3 and labels[-1].isalpha()):
                flag("unknown_domain", token, field)  # evil.sh, c2.badsite.de, update-cdn.co.uk
            elif len(labels) == 2 and re.fullmatch(r"[a-z][a-z0-9_-]*", labels[-1]):
                flag("unknown_user", token, field)  # john.doe, j.smith2
        text = _DOTTED.sub(" ", text)
        for u in _SVC_USER.findall(text):
            if u.lower() not in users:
                flag("unknown_user", u, field)
        for h in _HOST.findall(text):
            if h.upper() not in hosts:
                flag("unknown_host", h, field)
        for t in _TIME.findall(text):
            if t not in times:
                flag("unknown_time", t, field)
        for d in _DATE.findall(text):
            if d not in dates:
                flag("unknown_date", d, field)
    return flags


# --- stub ---------------------------------------------------------------------

def stub_output(incident: dict) -> dict:
    """Deterministic, rules-only text built from the timeline. Never invents anything."""
    lines = [f"At {datetime.fromisoformat(e['timestamp']):%H:%M}, {e['summary']}." for e in incident["timeline"][:8]]
    pending = [a["label"] for a in incident["actions"] if a["status"] == "pending"]
    done = [a["label"] for a in incident["actions"] if a["status"] == "executed"]
    recommended = (pending + done)[:5] or ["Review the timeline and confirm the verdict"]
    return {
        "narrative": " ".join(lines),
        "hypothesis": f"{incident['title']} ({incident['verdict']}, score {incident['risk_score']}).",
        "recommended_actions": recommended,
        "confidence": round(incident["risk_score"] / 100, 2),
    }


# --- narrator -----------------------------------------------------------------

def _parse(text: str) -> dict:
    data = json.loads(text)
    ok = (isinstance(data, dict) and isinstance(data.get("narrative"), str) and data["narrative"].strip()
          and isinstance(data.get("hypothesis"), str)
          and isinstance(data.get("recommended_actions"), list)
          and all(isinstance(x, str) for x in data["recommended_actions"])
          and isinstance(data.get("confidence"), (int, float)))
    if not ok:
        raise ValueError("response does not match the required JSON shape")
    return {"narrative": data["narrative"].strip(), "hypothesis": data["hypothesis"].strip(),
            "recommended_actions": [x.strip() for x in data["recommended_actions"] if x.strip()][:5],
            "confidence": max(0.0, min(1.0, float(data["confidence"])))}


class Narrator:
    def __init__(self, config: AIConfig | None = None, client=None, today=None):
        self.config = config or load_config()
        self._client = client
        self._today = today
        self.calls = 0
        self.last_error: str | None = None
        self.last_latency_ms: int | None = None

    @property
    def live(self) -> bool:
        return self.config.mode == "vertex" or self._client is not None

    def _get_client(self):
        if self._client is None:
            self._client = _vertex_client(self.config)
        return self._client

    def _call(self, prompt: str) -> str:
        from google.genai import types

        response = self._get_client().models.generate_content(
            model=self.config.model, contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT, temperature=0.2,
                response_mime_type="application/json", response_schema=RESPONSE_SCHEMA))
        return response.text or ""

    def narrate(self, incident: dict, called_at: str | None = None, today: date | None = None) -> dict:
        """Return the incident's `ai` block: output + generated_by + trace + flags.

        `called_at` lets the caller stamp the trace with its own clock (the store's).
        """
        today = today or self._today or date.today()
        prompt = build_prompt(incident, today)
        trace = {"model": self.config.model if self.live else "stub", "prompt_sha256": prompt_hash(prompt),
                 "latency_ms": 0, "raw_response": None, "error": None,
                 "called_at": called_at or datetime.now().astimezone().isoformat(timespec="seconds")}
        output, generated_by = None, "stub"
        if self.live:
            self.calls += 1
            start = time.perf_counter()
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            try:
                raw = pool.submit(self._call, prompt).result(timeout=self.config.timeout_s)
                trace["raw_response"] = raw
                output, generated_by = _parse(raw), self.config.model
            except concurrent.futures.TimeoutError:
                trace["error"] = f"timeout after {self.config.timeout_s:g} s"
            except Exception as exc:  # network, auth, quota, bad JSON: fall back, never crash
                # Vertex error text can name the project or service account: only the type
                # reaches the trace, panel and /audit; the full text stays in the server log.
                trace["error"] = type(exc).__name__
                log.warning("AI call failed for %s: %s: %s", incident["incident_id"], type(exc).__name__, exc)
            finally:
                pool.shutdown(wait=False, cancel_futures=True)
                trace["latency_ms"] = int((time.perf_counter() - start) * 1000)
            self.last_latency_ms, self.last_error = trace["latency_ms"], trace["error"]
        else:
            trace["error"] = self.config.reason or None
        if output is None:
            output = stub_output(incident)
        return {**output, "generated_by": generated_by, "trace": trace,
                "flags": verify_entities(output, incident, today),
                "alerts_covered": len(incident["alerts"])}
