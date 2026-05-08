# SafeGSA — Federal AI Compliance Toolkit

MVP for the Factory opportunity OPP-74 (Federal AI Compliance Toolkit).

## Why this exists

GSA published draft clause **GSAR 552.239-7001** in March 2026, requiring AI
safeguarding documentation, monitoring, and incident reporting from every
contractor on a Multiple Award Schedule. DOE's $293M Genesis Mission opens with
strict compliance gates. Vanta/Drata cover SOC 2 but ship none of the
AI-specific artifacts (model cards, drift monitoring, training-data
provenance). SafeGSA fills that gap for the small/mid GovCon firms that don't
have an in-house compliance team.

## Stack — chosen for the audience, not by default

- **Python 3.12 + Flask + Jinja** — government contractors trust boring Python
- **Tailwind via CDN** — zero front-end build step, ships pixels in minutes
- **Vanilla JS islands** — only the lead form + risk classifier are interactive
- **Gunicorn + Docker** — single small process, named volume for persisted leads/assessments

Distinctly *not* Next.js — that boilerplate already runs the WedgeOps build.

## Run it

```bash
docker compose up --build -d
open http://localhost:3848
```

## Routes

| Path             | What                                                                 |
|------------------|----------------------------------------------------------------------|
| `/`              | Marketing landing — signal, value prop, lead capture                 |
| `/dashboard`     | Demo workspace — three AI systems, audit trail, deadlines            |
| `/assess`        | 4-question risk classifier → tier + required artifacts list          |
| `/api/lead`      | POST lead capture (JSONL, honeypot-protected)                        |
| `/api/assess`    | POST classifier (writes to JSONL, returns tier + artifact checklist) |
| `/health`        | Liveness probe                                                       |

## Persistence

`SAFEGSA_DATA_DIR=/app/data` mounted as the named volume `safegsa-data`. Leads
land in `leads.jsonl`, assessments in `assessments.jsonl`. Both survive
container rebuilds.
