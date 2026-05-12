"""SafeGSA — Federal AI Compliance Toolkit MVP.

Stack chosen deliberately (not a default):
    Python 3.12 + Flask + Jinja2 + Tailwind (CDN) + vanilla JS islands
    Reason: government contractors trust "boring" Python; the front door is
    content-heavy (signal + offer + assessment) with one small interactive
    classifier — no SPA needed. Single small process is cheaper to ship and
    audit than a Node bundle, and the value-prop demo is the focus.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import os
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, Response, g, jsonify, render_template, request
from flask_compress import Compress

APP_NAME = "SafeGSA"
APP_TAGLINE = "AI safeguarding compliance for federal contractors"
SITE_URL = os.environ.get("SAFEGSA_SITE_URL", "https://safegsa.com")
DATA_DIR = Path(os.environ.get("SAFEGSA_DATA_DIR", "/app/data"))
LEAD_FILE = DATA_DIR / "leads.jsonl"
ASSESS_FILE = DATA_DIR / "assessments.jsonl"
ADMIN_TOKEN = os.environ.get("SAFEGSA_ADMIN_TOKEN", "").strip()

# Build identity — lets ops correlate /health output with a specific deploy
# without running git inside the container. Set by Dockerfile/CI; falls back
# to "dev" so local runs still serve the endpoint cleanly.
APP_VERSION = os.environ.get("SAFEGSA_VERSION", "dev")
START_TS = time.time()

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["JSON_SORT_KEYS"] = False

# ---------------------------------------------------------------------------
# Gzip compression — Flask-Compress watches the Accept-Encoding header and
# compresses text/HTML/JSON/XML/CSS/JS responses above ~500 bytes. For the
# marketing landing + Tailwind-from-CDN setup, this typically cuts HTML
# payload 65–75% with no measurable CPU cost at our request rates.
# Skip CSV downloads (already large/binary-ish) and short responses.
# ---------------------------------------------------------------------------
app.config["COMPRESS_MIMETYPES"] = [
    "text/html",
    "text/css",
    "text/xml",
    "text/plain",
    "application/json",
    "application/javascript",
    "application/xml",
    "application/x-yaml",
]
app.config["COMPRESS_LEVEL"] = 6
app.config["COMPRESS_MIN_SIZE"] = 500
app.config["COMPRESS_ALGORITHM"] = ["br", "gzip"]
Compress(app)


# ---------------------------------------------------------------------------
# Structured JSON access log — one line per request, written to stdout so it
# can be scraped by Datadog / Loki / Fly Log Shipper without an agent in the
# container. Tracks request_id, route, status, latency, and a hashed IP so we
# preserve anomaly-detection signal without persisting raw addresses to logs.
# Tied to the existing /api/* security model — never logs request bodies.
# ---------------------------------------------------------------------------

_ACCESS_LOGGER = logging.getLogger("safegsa.access")
if not _ACCESS_LOGGER.handlers:
    _h = logging.StreamHandler(stream=sys.stdout)
    _h.setFormatter(logging.Formatter("%(message)s"))
    _ACCESS_LOGGER.addHandler(_h)
    _ACCESS_LOGGER.setLevel(logging.INFO)
    _ACCESS_LOGGER.propagate = False

# Salt for IP hashing — defaults to a per-process random salt so two containers
# in a load balancer can't trivially be joined to deanonymize. Operators can
# pin it via env to keep correlation stable across deploys (for outage triage).
_IP_SALT = os.environ.get("SAFEGSA_IP_SALT") or uuid.uuid4().hex


def _hash_ip(ip: str) -> str:
    return hashlib.sha256((_IP_SALT + ip).encode("utf-8")).hexdigest()[:16]


@app.before_request
def _begin_request_log():
    g._safegsa_req_started = time.perf_counter()
    # X-Request-ID conventional; generate one if absent so traces correlate
    # across reverse-proxy hops without forcing edge config.
    g._safegsa_request_id = (
        request.headers.get("x-request-id")
        or uuid.uuid4().hex[:16]
    )


@app.after_request
def _emit_access_log(resp: Response) -> Response:
    try:
        started = getattr(g, "_safegsa_req_started", None)
        latency_ms = int((time.perf_counter() - started) * 1000) if started else 0
        ip = _client_ip()
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": "info",
            "logger": "access",
            "request_id": getattr(g, "_safegsa_request_id", ""),
            "method": request.method,
            "path": request.path,
            "status": resp.status_code,
            "latency_ms": latency_ms,
            "ip_hash": _hash_ip(ip),
            "ua": (request.headers.get("user-agent") or "")[:160],
            "ref": (request.headers.get("referer") or "")[:160],
            "size": resp.calculate_content_length() or 0,
            "version": APP_VERSION,
        }
        _ACCESS_LOGGER.info(json.dumps(record, separators=(",", ":")))
        resp.headers.setdefault("X-Request-ID", record["request_id"])
    except Exception as err:  # pragma: no cover — logging must never break a response
        app.logger.warning("access log emit failed: %s", err)
    return resp


# ---------------------------------------------------------------------------
# In-memory rate limiter (token-bucket per IP).
# Resets on cold start. Single-instance MVP; Redis is the multi-instance path.
# ---------------------------------------------------------------------------

_RL_LOCK = threading.Lock()
_RL_BUCKETS: dict[tuple[str, str], dict[str, float]] = {}


def _take_token(scope: str, ip: str, max_per_window: int, window_s: int) -> tuple[bool, int]:
    """Return (allowed, retry_after_seconds_if_blocked)."""
    now = time.time()
    key = (scope, ip)
    with _RL_LOCK:
        b = _RL_BUCKETS.get(key)
        if not b or b["reset_at"] <= now:
            _RL_BUCKETS[key] = {"count": 1, "reset_at": now + window_s}
            return True, 0
        if b["count"] >= max_per_window:
            return False, max(1, int(b["reset_at"] - now))
        b["count"] += 1
        return True, 0


def _client_ip() -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.headers.get("x-real-ip") or request.remote_addr or "unknown"


# ---------------------------------------------------------------------------
# CSRF — Origin/Referer check on state-changing requests.
# We don't issue session cookies, so a same-origin enforcement on POSTs is the
# right MVP defense: a victim's browser will send the attacker's Origin when
# auto-posting a forged form, and we reject it. Tokens are the upgrade path
# once we add authenticated sessions.
# Allow-list extra origins (e.g., a preview environment) via env. Tests can
# opt out by setting SAFEGSA_ORIGIN_CHECK=off.
# ---------------------------------------------------------------------------

_ORIGIN_CHECK_ENABLED = os.environ.get("SAFEGSA_ORIGIN_CHECK", "on").strip().lower() != "off"
_ORIGIN_ALLOWLIST = {
    o.strip().rstrip("/").lower()
    for o in os.environ.get("SAFEGSA_ALLOWED_ORIGINS", "").split(",")
    if o.strip()
}


def _allowed_origin(origin: str) -> bool:
    """Match an Origin/Referer-derived origin against host + env allow-list."""
    if not origin:
        return False
    origin = origin.rstrip("/").lower()
    # Match this request's own host (covers http vs https + non-standard ports).
    host_url = request.host_url.rstrip("/").lower()
    if origin == host_url:
        return True
    # Also match the bare scheme://host form regardless of trailing path.
    if origin.startswith(host_url + "/") or host_url.startswith(origin + "/"):
        return True
    return origin in _ORIGIN_ALLOWLIST


def _check_csrf_origin() -> Response | None:
    """Return a 403 Response if the POST's Origin/Referer is cross-origin.

    Order: prefer the Origin header (sent by browsers on POST/PUT/DELETE).
    Fall back to Referer-derived origin. If neither is present we permit the
    request — server-to-server callers (curl, CI smoke tests, monitoring
    probes) won't send Origin and shouldn't be blocked by this check.
    """
    if not _ORIGIN_CHECK_ENABLED:
        return None
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None

    origin = (request.headers.get("origin") or "").strip()
    if not origin:
        ref = (request.headers.get("referer") or "").strip()
        if ref:
            # Derive scheme://host[:port] from the Referer.
            try:
                from urllib.parse import urlsplit
                parts = urlsplit(ref)
                if parts.scheme and parts.netloc:
                    origin = f"{parts.scheme}://{parts.netloc}"
            except Exception:  # pragma: no cover — defensive
                origin = ""

    if not origin:
        # No Origin and no Referer — likely a non-browser client. Permit.
        return None

    if _allowed_origin(origin):
        return None

    app.logger.warning("csrf origin reject path=%s origin=%s", request.path, origin)
    resp = jsonify({"ok": False, "error": "Cross-origin request denied"})
    resp.status_code = 403
    return resp


# ---------------------------------------------------------------------------
# Risk classifier — a small, defensible heuristic the demo runs server-side.
# Real product: LLM + retrieval over GSAR/NIST AI RMF/EO 14110. This stub gives
# stakeholders a concrete artifact today.
# ---------------------------------------------------------------------------

# Question bank used by /assess. Each answer carries a weight; total maps to a
# tier under GSAR 552.239-7001 + NIST AI RMF taxonomy.
QUESTIONS: list[dict[str, Any]] = [
    {
        "id": "domain",
        "label": "Where is the AI system used?",
        "options": [
            {"value": "internal_back_office", "label": "Internal back-office (ops, HR, finance)", "weight": 1},
            {"value": "decision_support", "label": "Decision support to government personnel", "weight": 3},
            {"value": "public_facing", "label": "Public-facing (citizens / claimants interact directly)", "weight": 5},
            {"value": "safety_critical", "label": "Safety-critical (defense, medical, infrastructure)", "weight": 8},
        ],
    },
    {
        "id": "data",
        "label": "What data does the system process?",
        "options": [
            {"value": "synthetic_only", "label": "Synthetic / public data only", "weight": 1},
            {"value": "cui", "label": "Controlled Unclassified Information (CUI)", "weight": 4},
            {"value": "pii", "label": "Personally Identifiable Information (PII)", "weight": 5},
            {"value": "classified", "label": "Classified or PHI", "weight": 8},
        ],
    },
    {
        "id": "autonomy",
        "label": "How autonomous is the system?",
        "options": [
            {"value": "human_in_loop", "label": "Human reviews every output", "weight": 1},
            {"value": "human_on_loop", "label": "Human spot-checks", "weight": 3},
            {"value": "supervised_autonomous", "label": "Supervised autonomous", "weight": 5},
            {"value": "fully_autonomous", "label": "Fully autonomous, no human review", "weight": 8},
        ],
    },
    {
        "id": "vendor",
        "label": "Where does the model run?",
        "options": [
            {"value": "fedramp_high", "label": "FedRAMP High / IL5+ enclave", "weight": 1},
            {"value": "fedramp_moderate", "label": "FedRAMP Moderate", "weight": 3},
            {"value": "commercial_cloud", "label": "Commercial cloud (no FedRAMP)", "weight": 6},
            {"value": "third_party_api", "label": "Third-party hosted API", "weight": 7},
        ],
    },
]


def classify(answers: dict[str, str]) -> dict[str, Any]:
    """Score answers, map to GSAR 552.239-7001 risk tier, list required artifacts."""
    score = 0
    chosen_labels: list[str] = []
    for q in QUESTIONS:
        ans = answers.get(q["id"])
        match = next((o for o in q["options"] if o["value"] == ans), None)
        if match is not None:
            score += int(match["weight"])
            chosen_labels.append(f"{q['label']} → {match['label']}")
    if score <= 8:
        tier = "Low"
        tier_class = "low"
        summary = "Minimal safeguarding obligations. Lightweight documentation track."
    elif score <= 16:
        tier = "Limited"
        tier_class = "limited"
        summary = "Standard documentation + bias testing. Annual review."
    elif score <= 24:
        tier = "High"
        tier_class = "high"
        summary = "Full GSAR 552.239-7001 documentation, continuous monitoring, incident reporting."
    else:
        tier = "Critical"
        tier_class = "critical"
        summary = "Pre-deployment ATO + ongoing monitoring + dedicated AI safety officer."

    artifacts = [
        {"id": "ai_use_case_inventory", "name": "AI Use-Case Inventory entry (EO 14110 §10.1(b))",
         "required_at": "Low"},
        {"id": "model_card", "name": "Model card / system datasheet",
         "required_at": "Limited"},
        {"id": "bias_testing", "name": "Pre-deployment bias and disparate-impact testing",
         "required_at": "Limited"},
        {"id": "data_provenance", "name": "Training-data provenance attestation",
         "required_at": "High"},
        {"id": "monitoring_plan", "name": "Continuous monitoring plan with drift triggers",
         "required_at": "High"},
        {"id": "incident_playbook", "name": "AI incident response playbook",
         "required_at": "High"},
        {"id": "ato", "name": "Pre-deployment Authority To Operate (ATO)",
         "required_at": "Critical"},
        {"id": "safety_officer", "name": "Designated AI Safety Officer + escalation tree",
         "required_at": "Critical"},
    ]
    tier_order = ["Low", "Limited", "High", "Critical"]
    cur_index = tier_order.index(tier)
    for a in artifacts:
        a["applies"] = tier_order.index(a["required_at"]) <= cur_index

    return {
        "score": score,
        "tier": tier,
        "tier_class": tier_class,
        "summary": summary,
        "answers": chosen_labels,
        "artifacts": artifacts,
    }


# ---------------------------------------------------------------------------
# Mock dashboard fixtures — what a contractor sees after onboarding three
# AI systems. Static demo so the page is deterministic in screenshots.
# ---------------------------------------------------------------------------

DASHBOARD_FIXTURES = {
    "contract": "GS-35F-XYZ12 · Treasury",
    "score": 84,
    "trend": "+6 in last 30 days",
    "next_audit": "2026-08-14",
    "systems": [
        {
            "name": "Claims Triage Assistant",
            "tier": "High",
            "tier_class": "high",
            "owner": "K. Patel",
            "status": "Compliant",
            "status_class": "ok",
            "last_attested": "2026-04-29",
            "drift": "0.04",
        },
        {
            "name": "Procurement Document Summarizer",
            "tier": "Limited",
            "tier_class": "limited",
            "owner": "M. Rodriguez",
            "status": "2 findings",
            "status_class": "warn",
            "last_attested": "2026-05-02",
            "drift": "0.12",
        },
        {
            "name": "Citizen Chatbot (FAQ tier)",
            "tier": "Limited",
            "tier_class": "limited",
            "owner": "J. Chen",
            "status": "Compliant",
            "status_class": "ok",
            "last_attested": "2026-05-04",
            "drift": "0.02",
        },
    ],
    "audit_events": [
        {"at": "2026-05-06 14:11Z", "actor": "system", "event": "Bias testing report regenerated for Claims Triage Assistant"},
        {"at": "2026-05-05 09:02Z", "actor": "K. Patel", "event": "Acknowledged drift alert (PII leakage probe, score 0.04 — under threshold)"},
        {"at": "2026-05-03 17:48Z", "actor": "system", "event": "Summarizer model card refreshed against new GSAR 552.239-7001 amendment (May 1)"},
        {"at": "2026-05-01 08:30Z", "actor": "J. Chen", "event": "Submitted quarterly attestation for Citizen Chatbot"},
    ],
    "deadlines": [
        {"due": "2026-05-15", "what": "Annual NIST AI RMF self-attestation"},
        {"due": "2026-06-01", "what": "Drift baseline refresh — Procurement Summarizer"},
        {"due": "2026-08-14", "what": "GSA on-site audit"},
    ],
}


# ---------------------------------------------------------------------------
# Persistence helpers — leads + saved assessments append to JSONL on a
# named volume so signups survive container rebuilds.
# ---------------------------------------------------------------------------

def _append_jsonl(path: Path, entry: dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    return render_template(
        "index.html",
        app_name=APP_NAME,
        tagline=APP_TAGLINE,
        questions=QUESTIONS,
    )


@app.get("/dashboard")
def dashboard():
    return render_template(
        "dashboard.html",
        app_name=APP_NAME,
        d=DASHBOARD_FIXTURES,
    )


@app.get("/assess")
def assess_view():
    return render_template(
        "assess.html",
        app_name=APP_NAME,
        questions=QUESTIONS,
    )


# ---------------------------------------------------------------------------
# Static reference content surfaced as a real route — gives federal-procurement
# audiences a deep-link they can paste into RFP responses, and lets the
# model-card generator's tier policy be inspected without running an assessment.
# ---------------------------------------------------------------------------

# Tier policy reference. Numbers must stay in sync with the model-card
# generator (re-test cadence, log retention, CO notification window).
TIERS_POLICY: list[dict[str, Any]] = [
    {
        "name": "Low",
        "subhead": "Internal back-office, fully supervised",
        "badge": "L",
        "badge_class": "bg-emerald-100 text-emerald-800",
        "summary": "Routine internal use with a human in the loop on every output. Failure mode is inconvenience, not harm to the public or the mission.",
        "facts": [
            ("Re-test cadence", "Annual"),
            ("Audit-log retention", "90 days"),
            ("CO notification window", "72 hours"),
            ("ATO posture", "Lightweight self-attestation"),
            ("Model-card depth", "8-section short form"),
        ],
    },
    {
        "name": "Medium",
        "subhead": "Mission-supporting, human-in-loop",
        "badge": "M",
        "badge_class": "bg-amber-100 text-amber-800",
        "summary": "Affects mission decisions or supervised contractor workflows. Human review on consequential outputs; occasional public exposure.",
        "facts": [
            ("Re-test cadence", "Quarterly"),
            ("Audit-log retention", "180 days"),
            ("CO notification window", "48 hours"),
            ("ATO posture", "Documented controls + drift monitoring"),
            ("Model-card depth", "8-section + bias-testing appendix"),
        ],
    },
    {
        "name": "High",
        "subhead": "Public-facing or autonomous",
        "badge": "H",
        "badge_class": "bg-flag-red/15 text-flag-red",
        "summary": "Public-facing decisions, sensitive PII, or supervised-autonomous behavior. Failures can harm citizens, beneficiaries, or contracting officers.",
        "facts": [
            ("Re-test cadence", "Monthly"),
            ("Audit-log retention", "365 days"),
            ("CO notification window", "24 hours"),
            ("ATO posture", "Full ATO with continuous monitoring"),
            ("Model-card depth", "Full GSAR/NIST 8-section + incident plan"),
        ],
    },
]

# Side-by-side comparison rows. Each `cells` array aligns with TIERS_POLICY.
TIERS_MATRIX: list[dict[str, Any]] = [
    {"label": "Re-test cadence", "cells": ["Annual", "Quarterly", "Monthly"]},
    {"label": "Audit log retention", "cells": ["90 days", "180 days", "365 days"]},
    {"label": "CO notification window", "cells": ["72 hours", "48 hours", "24 hours"]},
    {"label": "Bias / fairness testing", "cells": ["Annual sample", "Quarterly + drift", "Monthly + adversarial probes"]},
    {"label": "Training-data provenance", "cells": ["Inventory", "Inventory + lineage", "Inventory + lineage + DPIA"]},
    {"label": "Continuous monitoring", "cells": ["Optional", "Required (drift)", "Required (drift + safety probes)"]},
    {"label": "Incident response plan", "cells": ["Documented", "Documented + tabletop /yr", "Documented + tabletop /qtr"]},
    {"label": "Authorization to Operate (ATO)", "cells": ["Self-attested", "Documented controls", "Full ATO"]},
    {"label": "Public-facing exposure", "cells": ["No", "Limited / supervised", "Yes"]},
]


@app.get("/tiers")
def tiers_view():
    return render_template(
        "tiers.html",
        app_name=APP_NAME,
        tiers=TIERS_POLICY,
        matrix=TIERS_MATRIX,
    )


# ---------------------------------------------------------------------------
# /about — trust-signal + lead-capture surface. Federal-procurement buyers
# expect to vet the people behind a tool before sharing program data; this
# page closes that gap without requiring a sales call.
# ---------------------------------------------------------------------------

ABOUT_PRINCIPLES: list[dict[str, str]] = [
    {
        "title": "Built around the actual rule text",
        "body": "Every artifact maps to a line in GSAR 552.239-7001, NIST AI RMF 1.0, or EO 14110 §10. We don't invent a new framework — we make the existing one auditable.",
    },
    {
        "title": "Documentation in minutes, not weeks",
        "body": "A four-question intake produces a tier classification, model card, and required artifact list immediately. Contracting officers receive evidence the same day a system goes live.",
    },
    {
        "title": "No agency data leaves your tenant",
        "body": "Assessment inputs are persisted to the contractor's own data volume. We never train on submitted answers, and admin export endpoints are token-gated and disabled by default.",
    },
    {
        "title": "Designed for small primes and subs",
        "body": "If you carry compliance work without a dedicated CISO or compliance counsel, SafeGSA collapses a binder of work into a single review surface your CO can read in under ten minutes.",
    },
]

ABOUT_FAQ: list[dict[str, str]] = [
    {
        "q": "Is SafeGSA on the FedRAMP marketplace?",
        "a": "Not yet — we're targeting FedRAMP Tailored / Moderate sponsorship through a launch partner in FY27. Today's MVP is appropriate for documenting Low and Limited tier systems; High and Critical tier deployments should keep their artifacts inside the agency's authorized boundary.",
    },
    {
        "q": "Does SafeGSA generate the model card itself, or is it a checklist?",
        "a": "It generates the card. POST a system spec and the classifier answers to /api/generate/model-card and you get an 8-section GSAR/NIST-shaped Markdown artifact with tier-aware text — re-test cadence, log retention, and CO notification windows all scale with risk tier.",
    },
    {
        "q": "How is this different from a Vanta-style SOC 2 tool?",
        "a": "Vanta and Drata are oriented around commercial controls (SOC 2, ISO 27001). SafeGSA targets the federal AI safeguarding stack — GSAR 552.239-7001, NIST AI RMF, EO 14110, OMB M-24-10 — and produces the artifacts a contracting officer expects, not the artifacts an auditor for a private board expects.",
    },
    {
        "q": "What happens if the guidance changes?",
        "a": "When a clause amendment or new agency directive lands, the underlying classifier and model-card template are versioned and re-deployed. Existing audit binders stay valid as point-in-time evidence; new assessments inherit the updated text.",
    },
]


@app.get("/about")
def about_view():
    return render_template(
        "about.html",
        app_name=APP_NAME,
        principles=ABOUT_PRINCIPLES,
        faq=ABOUT_FAQ,
    )


@app.post("/api/assess")
def api_assess():
    csrf = _check_csrf_origin()
    if csrf is not None:
        return csrf
    ip = _client_ip()
    ok, retry_after = _take_token("assess", ip, max_per_window=12, window_s=60)
    if not ok:
        resp = jsonify({"ok": False, "error": "Too many requests."})
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        return resp

    payload = request.get_json(silent=True) or {}

    # Honeypot — bots fill every input. The field name is innocuous so they
    # don't skip it. Real users never see this in /assess (we render no input
    # named company_name on the form).
    if isinstance(payload.get("company_name"), str) and payload["company_name"].strip():
        return jsonify({"ok": True, "result": {"tier": "Low", "score": 0,
                                               "summary": "", "answers": [],
                                               "artifacts": []}, "id": "bot"})

    answers = payload.get("answers") or {}
    if not isinstance(answers, dict):
        return jsonify({"ok": False, "error": "answers must be an object"}), 400
    if len(answers) > 32:
        return jsonify({"ok": False, "error": "too many answers"}), 400

    result = classify({str(k): str(v) for k, v in answers.items()})
    entry = {
        "id": uuid.uuid4().hex[:12],
        "at": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "answers": answers,
        "score": result["score"],
        "tier": result["tier"],
    }
    try:
        _append_jsonl(ASSESS_FILE, entry)
    except OSError as err:
        app.logger.warning("assessment persist failed: %s", err)
    return jsonify({"ok": True, "result": result, "id": entry["id"]})


@app.post("/api/lead")
def api_lead():
    csrf = _check_csrf_origin()
    if csrf is not None:
        return csrf
    ip = _client_ip()
    ok, retry_after = _take_token("lead", ip, max_per_window=5, window_s=60)
    if not ok:
        resp = jsonify({"ok": False, "error": "Too many requests."})
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        return resp

    payload = request.get_json(silent=True) or {}
    email = (payload.get("email") or "").strip().lower()
    org = (payload.get("organization") or "").strip()[:120]
    role = (payload.get("role") or "").strip()[:80]
    # Honeypot
    if (payload.get("company_name") or "").strip():
        return jsonify({"ok": True})
    if "@" not in email or len(email) > 254:
        return jsonify({"ok": False, "error": "Invalid email"}), 400
    entry = {
        "at": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "email": email,
        "organization": org,
        "role": role,
    }
    try:
        _append_jsonl(LEAD_FILE, entry)
    except OSError as err:
        app.logger.warning("lead persist failed: %s", err)
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Model card generator — the killer artifact promised on /how. POSTs an
# assessment payload + system metadata, returns a Markdown model card the
# contractor can paste into their compliance binder.
# ---------------------------------------------------------------------------

def _render_model_card(meta: dict[str, Any], result: dict[str, Any]) -> str:
    """Render a GSAR/NIST-shaped model card from a system spec + classifier output."""
    name = (meta.get("name") or "Untitled AI System")[:120]
    purpose = (meta.get("purpose") or "Not specified")[:600]
    owner = (meta.get("owner") or "Not specified")[:120]
    contract = (meta.get("contract") or "Not specified")[:120]
    model = (meta.get("model") or "Not specified")[:120]
    deployed_at = (meta.get("deployed_at") or "TBD")[:40]

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    tier = result.get("tier", "Unclassified")
    score = result.get("score", 0)
    summary = result.get("summary") or ""
    answers = result.get("answers") or []
    artifacts = result.get("artifacts") or []

    answer_lines = "\n".join(f"- {a}" for a in answers) or "- _Not provided._"
    artifact_lines = "\n".join(
        f"- [{'x' if a.get('applies') else ' '}] {a['name']} _(required at {a['required_at']})_"
        for a in artifacts
    ) or "- _No artifacts mapped._"

    return f"""# Model Card — {name}

> Generated by **{APP_NAME}** on {today}.
> This is a draft artifact aligned to **GSAR 552.239-7001**, **NIST AI RMF 1.0**, and **EO 14110 §10**. It is informational and is **not** legal advice.

## 1. System metadata

| Field | Value |
| --- | --- |
| System name | {name} |
| Primary purpose | {purpose} |
| System owner | {owner} |
| Contract / vehicle | {contract} |
| Underlying model | {model} |
| Deployment date | {deployed_at} |

## 2. Risk classification

- **Tier:** {tier}  (score {score})
- **Summary:** {summary}

### Inputs to classification

{answer_lines}

## 3. Required artifacts

{artifact_lines}

## 4. Bias & disparate-impact testing

- Methodology: _describe pre-deployment bias testing approach (e.g., demographic parity, equalized odds across protected attributes)._
- Results: _attach last evaluation report; cite minimum sample sizes and confidence intervals._
- Re-test cadence: every {('quarter' if tier in ('High', 'Critical') else 'six months')}.

## 5. Training-data provenance

- Sources: _list all training and fine-tuning data sources, including license terms and any restrictions on government use._
- Sensitive data screening: _describe PII / CUI redaction pipeline and audit log._
- Vendor attestations: _link to model card / data card from the upstream provider, if applicable._

## 6. Continuous monitoring plan

- Drift signals: input distribution drift, output toxicity rate, refusal rate.
- Alert thresholds: _set per system; escalate to system owner ({owner})._
- Logging: every prompt / response is retained for {('365' if tier in ('High', 'Critical') else '90')} days in the agency's authorized audit store.

## 7. Incident response

- Trigger: any safeguarding finding above the alert threshold or a reported harm.
- Playbook: contain → notify CO within {('24' if tier in ('High', 'Critical') else '72')} hours → file an incident note in the audit trail.
- Post-mortem: due within 10 business days, attached to this model card.

## 8. Authority To Operate (ATO)

- Status: _draft / in review / authorized / expired_.
- Last review date: _yyyy-mm-dd_.
- Next review due: _yyyy-mm-dd_.

---
*{APP_NAME} · {today} · ID: {meta.get("assessment_id", "ad-hoc")}*
"""


@app.post("/api/generate/model-card")
def api_generate_model_card():
    csrf = _check_csrf_origin()
    if csrf is not None:
        return csrf
    ip = _client_ip()
    ok, retry_after = _take_token("model_card", ip, max_per_window=8, window_s=60)
    if not ok:
        resp = jsonify({"ok": False, "error": "Too many requests."})
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        return resp

    payload = request.get_json(silent=True) or {}
    meta = payload.get("system") or {}
    if not isinstance(meta, dict):
        return jsonify({"ok": False, "error": "system must be an object"}), 400

    answers = payload.get("answers") or {}
    if not isinstance(answers, dict):
        return jsonify({"ok": False, "error": "answers must be an object"}), 400

    result = classify({str(k): str(v) for k, v in answers.items()})
    if payload.get("assessment_id"):
        meta = {**meta, "assessment_id": str(payload["assessment_id"])[:32]}

    md = _render_model_card(meta, result)

    if (request.args.get("format") or "").lower() == "md":
        # Direct download of the Markdown file.
        filename = f"model-card-{(meta.get('name') or 'system').lower().replace(' ', '-')[:40]}.md"
        return Response(
            md,
            mimetype="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return jsonify({
        "ok": True,
        "tier": result["tier"],
        "score": result["score"],
        "model_card_markdown": md,
    })


# ---------------------------------------------------------------------------
# Admin exports — token-guarded read of the persisted JSONL stores. Disabled
# entirely when SAFEGSA_ADMIN_TOKEN is unset.
# ---------------------------------------------------------------------------

def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append({"_raw": line})
    return rows


def _admin_check() -> Response | None:
    if not ADMIN_TOKEN:
        resp = jsonify({"ok": False, "error": "Admin endpoint disabled"})
        resp.status_code = 404
        return resp
    auth = request.headers.get("authorization", "")
    if auth != f"Bearer {ADMIN_TOKEN}":
        resp = jsonify({"ok": False, "error": "Unauthorized"})
        resp.status_code = 401
        return resp
    return None


@app.get("/api/admin/leads")
def api_admin_leads():
    check = _admin_check()
    if check is not None:
        return check
    rows = _read_jsonl(LEAD_FILE)
    return jsonify({"ok": True, "count": len(rows), "leads": rows})


@app.get("/api/admin/assessments")
def api_admin_assessments():
    check = _admin_check()
    if check is not None:
        return check
    rows = _read_jsonl(ASSESS_FILE)
    if request.args.get("summary") == "1":
        counts: dict[str, int] = {}
        for r in rows:
            tier = str(r.get("tier", "_unknown"))
            counts[tier] = counts.get(tier, 0) + 1
        return jsonify({"ok": True, "total": len(rows), "by_tier": counts})
    # CSV export — compliance teams paste this straight into Excel / SharePoint
    # for audit binders. Each saved answer becomes its own column so analysts
    # can pivot by domain, autonomy, etc., without unpacking nested JSON.
    if request.args.get("format") == "csv":
        answer_keys: list[str] = []
        seen: set[str] = set()
        for r in rows:
            for k in (r.get("answers") or {}).keys():
                if k not in seen:
                    seen.add(k)
                    answer_keys.append(k)
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["id", "at", "ip", "tier", "score", *[f"answer_{k}" for k in answer_keys]])
        for r in rows:
            answers = r.get("answers") or {}
            writer.writerow([
                r.get("id", ""),
                r.get("at", ""),
                r.get("ip", ""),
                r.get("tier", ""),
                r.get("score", ""),
                *[answers.get(k, "") for k in answer_keys],
            ])
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return Response(
            buf.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="safegsa-assessments-{ts}.csv"'},
        )
    return jsonify({"ok": True, "count": len(rows), "assessments": rows})


def _count_jsonl_lines(path: Path) -> int:
    """Cheap line count for /health diagnostics. Returns 0 on any I/O error."""
    if not path.exists():
        return 0
    try:
        with path.open("rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def _data_dir_writable() -> bool:
    """Probe write access without persisting state. Used by /health."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        probe = DATA_DIR / f".healthcheck-{uuid.uuid4().hex[:6]}"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except OSError:
        return False


@app.get("/health")
def health():
    """Liveness + lightweight diagnostics.

    JSON shape designed for Datadog / Prometheus / Fly health probes — every
    field is either a primitive or a small flat object so monitoring agents
    can scrape without unwrapping nested structures. status=ok always means
    the process is up; downstream checks (data dir writable, persistence
    counters) are reported separately so a degraded disk doesn't cascade
    into a process restart.
    """
    now = time.time()
    storage_ok = _data_dir_writable()
    body = {
        "status": "ok",
        "app": APP_NAME,
        "version": APP_VERSION,
        "ts": datetime.now(timezone.utc).isoformat(),
        "uptime_s": int(now - START_TS),
        "checks": {
            "data_dir_writable": storage_ok,
        },
        "metrics": {
            "leads": _count_jsonl_lines(LEAD_FILE),
            "assessments": _count_jsonl_lines(ASSESS_FILE),
        },
        "config": {
            "admin_token_configured": bool(ADMIN_TOKEN),
            "origin_check_enabled": _ORIGIN_CHECK_ENABLED,
            "compression_enabled": True,
            "data_dir": str(DATA_DIR),
        },
    }
    return jsonify(body)


# ---------------------------------------------------------------------------
# Sitemap + branded errors + security headers (production hardening)
# ---------------------------------------------------------------------------

@app.get("/sitemap.xml")
def sitemap():
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    paths = [
        ("/", "1.0"),
        ("/dashboard", "0.7"),
        ("/assess", "0.9"),
        ("/tiers", "0.8"),
        ("/about", "0.6"),
    ]
    urls = "\n".join(
        f"  <url><loc>{SITE_URL.rstrip('/')}{p}</loc><lastmod>{today}</lastmod><priority>{prio}</priority></url>"
        for p, prio in paths
    )
    body = f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n{urls}\n</urlset>\n'
    return Response(body, mimetype="application/xml")


@app.errorhandler(404)
def not_found(_err):
    return render_template("404.html", app_name=APP_NAME), 404


@app.errorhandler(500)
def server_error(_err):
    return render_template("500.html", app_name=APP_NAME), 500


# Security headers — applied to every response. Tailwind CDN + the inline
# Tailwind config script require 'unsafe-inline' for now; tighten to a nonce
# once we self-host the CSS bundle (post-MVP).
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; "
        "style-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'"
    ),
}


@app.after_request
def _apply_security_headers(resp: Response) -> Response:
    for k, v in _SECURITY_HEADERS.items():
        resp.headers.setdefault(k, v)
    return resp


# ---------------------------------------------------------------------------
# Cache-Control — route-aware caching policy. CDN-friendly long-lived caching
# for immutable static assets; short-lived browser caching for HTML; explicit
# no-store for API and admin endpoints so an upstream cache never serves a
# stale lead/assessment payload (or a credentialed admin response).
# ---------------------------------------------------------------------------

@app.after_request
def _apply_cache_control(resp: Response) -> Response:
    path = request.path or ""

    # /static/ — Flask's default static handler sets `no-cache`, which is
    # appropriate during development but defeats CDN caching in prod. We
    # override here. Filenames are stable + low-churn marketing assets, and
    # a hard reload still works for cache invalidation.
    if path.startswith("/static/") and resp.status_code < 400:
        resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return resp

    # Don't override an explicit Cache-Control set by a route handler.
    if resp.headers.get("Cache-Control"):
        return resp

    # Errors / redirects — let clients refetch quickly.
    if resp.status_code >= 400:
        resp.headers["Cache-Control"] = "no-store"
        return resp

    if path.startswith("/api/") or path in ("/health", "/metrics"):
        # Never cache API, lead/assess writes, or monitoring scrapes.
        resp.headers["Cache-Control"] = "no-store"
        return resp

    if path in ("/sitemap.xml", "/robots.txt"):
        # Crawler hints — refresh hourly is plenty.
        resp.headers["Cache-Control"] = "public, max-age=3600"
        return resp

    # HTML routes (/, /dashboard, /assess, /tiers, /about, etc.) — short cache,
    # always revalidate. Lets a CDN absorb burst traffic without freezing the
    # content for users when we ship copy edits.
    resp.headers["Cache-Control"] = "public, max-age=300, must-revalidate"
    return resp


# ---------------------------------------------------------------------------
# Prometheus / OpenMetrics scrape endpoint — exposes the same counters as
# /health, but in the line-based text format Datadog Agent + Prometheus +
# Grafana Agent can ingest without a JSON parser. Adds tier-bucketed
# assessment counters so the SOC dashboard can spot a spike in
# High/Critical-tier intake (the most likely fraud or anomaly signal).
# Intentionally returns text/plain; CSP allows it, caches are bypassed.
# ---------------------------------------------------------------------------

def _assessments_by_tier() -> dict[str, int]:
    """Cheap counter — scans the JSONL once per /metrics scrape.

    At expected scrape cadence (15–60s) and assessment volume (<10k rows for
    months), this is faster than maintaining a separate index and survives a
    container restart without warm-up. Once the row count justifies it, swap
    in a sqlite materialized counter; the interface stays the same.
    """
    counts = {"Low": 0, "Limited": 0, "High": 0, "Critical": 0, "_unknown": 0}
    if not ASSESS_FILE.exists():
        return counts
    try:
        with ASSESS_FILE.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    counts["_unknown"] += 1
                    continue
                tier = str(rec.get("tier") or "_unknown")
                if tier not in counts:
                    counts["_unknown"] += 1
                else:
                    counts[tier] += 1
    except OSError:
        pass
    return counts


@app.get("/metrics")
def metrics():
    now = time.time()
    storage_ok = 1 if _data_dir_writable() else 0
    leads_total = _count_jsonl_lines(LEAD_FILE)
    assess_total = _count_jsonl_lines(ASSESS_FILE)
    by_tier = _assessments_by_tier()

    lines: list[str] = []

    def add(name: str, help_text: str, mtype: str, samples: list[tuple[str, float]]) -> None:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {mtype}")
        for labels, value in samples:
            suffix = f"{{{labels}}}" if labels else ""
            # Render ints without a decimal so Prom parsers stay happy with counts.
            if isinstance(value, int) or float(value).is_integer():
                lines.append(f"{name}{suffix} {int(value)}")
            else:
                lines.append(f"{name}{suffix} {value}")

    add(
        "safegsa_info",
        "Build identity (always 1).",
        "gauge",
        [(f'version="{APP_VERSION}",app="{APP_NAME}"', 1)],
    )
    add(
        "safegsa_uptime_seconds",
        "Seconds since the worker started.",
        "gauge",
        [("", int(now - START_TS))],
    )
    add(
        "safegsa_data_dir_writable",
        "1 if the data volume accepts writes, 0 otherwise.",
        "gauge",
        [("", storage_ok)],
    )
    add(
        "safegsa_leads_total",
        "Total lead submissions persisted to JSONL.",
        "counter",
        [("", leads_total)],
    )
    add(
        "safegsa_assessments_total",
        "Total risk-classifier assessments persisted to JSONL.",
        "counter",
        [("", assess_total)],
    )
    add(
        "safegsa_assessments_by_tier_total",
        "Assessments persisted, bucketed by GSAR/NIST risk tier.",
        "counter",
        [(f'tier="{t}"', n) for t, n in by_tier.items()],
    )

    body = "\n".join(lines) + "\n"
    return Response(
        body,
        mimetype="text/plain; version=0.0.4; charset=utf-8",
        headers={"Cache-Control": "no-store"},
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
