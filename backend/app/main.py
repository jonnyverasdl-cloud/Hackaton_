"""FastAPI routes (docs/prep/02-esquema.md). State is in memory; synthetic data only.

Run: .venv\\Scripts\\python.exe -m uvicorn backend.app.main:app --port 8000
The panel is served at /panel/ (same origin as the API).
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import Body, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .ai import Narrator
from .store import ApprovalError, Store

PANEL_DIR = Path(__file__).resolve().parents[2] / "panel"


class ApproveRequest(BaseModel):
    approved_by: str = Field(min_length=1, max_length=80)


def create_app(store: Store | None = None) -> FastAPI:
    load_dotenv()  # never overrides variables that are already set
    store = store or Store(window_min=int(os.getenv("CORRELATION_WINDOW_MIN", "30")),
                           narrator=Narrator(), ai_async=True)
    app = FastAPI(title="Storyline — alert correlation & incident timeline (synthetic data)")
    app.state.store = store
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

    @app.get("/health")
    def health():
        n = store.narrator
        return {"status": "ok", "synthetic": True,
                "ai_model": n.config.model if n.live else "stub",
                "mode": "rules+ai" if n.live else "rules-only",
                "ai": {"mode": n.config.mode, "reason": n.config.reason or None, "calls": n.calls,
                       "last_latency_ms": n.last_latency_ms, "last_error": n.last_error},
                "counts": store.counts()}

    @app.post("/alerts", status_code=201)
    def post_alert(payload: dict = Body(...)):
        if not payload.get("source") or not payload.get("timestamp"):
            raise HTTPException(422, "alert needs 'source' and 'timestamp'")
        try:
            alert, duplicate = store.ingest(payload)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"alert_id": alert["alert_id"], "duplicate": duplicate,
                "incident_id": store.alert_incident.get(alert["alert_id"])}

    @app.get("/alerts")
    def get_alerts():
        return store.alert_view()

    @app.get("/incidents")
    def get_incidents():
        return store.summaries()

    @app.get("/incidents/{incident_id}")
    def get_incident(incident_id: str):
        with store.lock:
            if incident_id not in store.incidents:
                raise HTTPException(404, f"{incident_id} not found")
            return store.incidents[incident_id]

    @app.post("/incidents/{incident_id}/approve")
    def approve(incident_id: str, body: ApproveRequest):
        if not body.approved_by.strip():
            raise HTTPException(422, "approved_by must not be blank")
        try:
            return store.approve(incident_id, body.approved_by.strip())
        except KeyError as exc:
            raise HTTPException(404, f"{incident_id} not found") from exc
        except ApprovalError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/audit")
    def audit():
        return store.audit_view()

    @app.post("/reset")
    def reset():
        store.reset()
        return {"status": "reset"}

    if PANEL_DIR.is_dir():
        app.mount("/panel", StaticFiles(directory=PANEL_DIR, html=True), name="panel")

        @app.get("/", include_in_schema=False)
        def root():
            return RedirectResponse("/panel/")

    return app


app = create_app()
