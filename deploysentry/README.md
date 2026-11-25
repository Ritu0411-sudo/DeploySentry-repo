# DeploySentry — Agentic Real-Time DAST (VoyageHack 4.0, Round 2)

An autonomous security agent that tests a live, production-like travel
platform in near real time: it notices what changed, learns the app and
builds an API inventory with no documentation, plans targeted attacks,
executes them safely, proves each finding with minimal evidence, triages
it in business context, reports it ticket-ready, and retests after a fix.

The target is the **AstraTravel** demo platform (`../platform/`) — a mock
B2B travel API running locally with synthetic data and deliberately
planted vulnerabilities. DeploySentry never touches any real system.

## Setup

Nothing to install — DeploySentry uses **only the Python 3 standard
library**, so there is no dependency step for the judges:

```bash
cd deploysentry
python3 --version   # 3.10+ works
```

The demo platform needs its own venv (already set up in `../platform/`).
The runner starts it automatically if it is not already running.

## Run the full loop

```bash
python3 run.py --auto-approve
```

This runs the whole loop end to end (about a minute):
1. Resets the platform to a fresh seed (v2.3.0)
2. Change Watcher takes the baseline; Discovery maps the API from the
   portal JavaScript, recorded traffic and probing; Inventory labels
   endpoints active / zombie / shadow from 30 days of gateway traffic
3. Attack Planner picks targeted tests; Executors run them; the Verifier
   confirms each hit; Triage scores severity and assigns owners
4. **Live change event:** v2.4.0 deploys mid-run; the watcher detects it,
   the agent plans tests for the new endpoint and finds the fresh IDOR —
   with measured timings
5. Reporter writes the findings and dashboard
6. Retest Agent rolls the platform back and proves the fresh flaw is
   gone, closing that finding

Without `--auto-approve`, the two risky tests (fare tampering, privilege
escalation) are **skipped** and listed as "awaiting human approval" — the
approval gate is real, not decorative. `--auto-approve` runs them and
records the approval in the audit log.

Other flags: `--base-url` (default `http://127.0.0.1:8000`),
`--no-start` (fail if the platform is not already running),
`--no-retest` (skip the retest phase).

## What it finds (ground truth)

| ID | Finding | Severity |
|---|---|---|
| DS-xxx | Fare tampering — book at Rs. 1 | Critical |
| DS-xxx | Sub-agent promotes self to agency_admin | Critical |
| DS-xxx | Cross-agency booking read (IDOR) | High |
| DS-xxx | Cancel twice, refunded twice | High |
| DS-xxx | Zombie API serves PII without auth | High |
| DS-xxx | Forged JWT accepted (weak secret) | High |
| DS-xxx | Cross-agency fare rewrite, fresh IDOR (v2.4.0) | High |
| DS-xxx | Pay Rs. 0 marks booking PAID (bonus) | High |
| DS-xxx | Single-use coupon applied twice | Medium |
| DS-xxx | Shadow API, no authorisation check | Medium |
| DS-xxx | No rate limiting on login | Low |

Plus two negative controls the agent must NOT flag: the list endpoint
enforces its agency filter (403), and search requires a login (200
logged in, 401 anonymous). Precision is measured on verified findings
vs false positives filtered by the Verifier.

## Outputs (in `reports/`)

| File | What it is |
|---|---|
| `findings.json` | The whole run as machine-readable data |
| `findings.md` | Ticket-ready findings: evidence, impact, severity, owner, fix |
| `dashboard.html` | Self-contained dashboard: API map, inventory, findings, timings |
| `openapi-generated.json` | OpenAPI spec inferred by the Discovery Agent (bonus point) |
| `audit.log` | JSONL log of EVERY request the agent sent, for replay |

## How the code maps to the judging criteria

| Criterion (weight) | Where it lives |
|---|---|
| Valid findings & severity — 30% | `executors.py` + `verifier.py` + `triage.py` |
| Precision & noise control — 20% | `verifier.py` (minimal proof), negative controls, `triage.py` dedup |
| Safety & scope discipline — 20% | `safety.py` (allowlist, rate limit, audit, approval gate) + `client.py` |
| Speed after change — 10% | `watcher.py` + the measured timings in the run summary |
| Report quality & actionability — 10% | `reporter.py` |
| Discovery & API inventory — 10% | `discovery.py` + `inventory.py` (+ OpenAPI export) |

## Files

| File | What it does |
|---|---|
| `run.py` | The full loop, end to end, with measured timings |
| `safety.py` | Scope allowlist, rate limit, audit log, human-approval gate, test-account vault |
| `client.py` | The one audited, throttled HTTP client every request goes through |
| `watcher.py` | Change Watcher — polls the deploy feed, diffs the API snapshot |
| `discovery.py` | Discovery Agent — portal JS + HAR + probing → knowledge graph + OpenAPI |
| `inventory.py` | Inventory Agent — gateway-log analysis, active/zombie/shadow labels |
| `planner.py` | Attack Planner — targeted tests per endpoint, no payload spraying |
| `executors.py` | Specialist Executors — one per vulnerability class |
| `verifier.py` | Verifier — minimal proof for every candidate |
| `triage.py` | Triage — dedup, business severity, owner |
| `reporter.py` | Reporter — findings.json / .md + HTML dashboard |
| `retest.py` | Retest Agent — re-proves after a fix/rollback, closes findings |

## Safety contract (from the problem statement)

- Scope allowlist: `localhost:8000` only — any other URL is refused
  before a request is sent (`safety.py`)
- Max 5 requests/second, with back-off on 429 or a slow health check
- Test accounts only (`Test@1234`, demo accounts from the spec)
- No destructive actions; verification reads at most 2 records per check
- Evidence is PII-redacted by construction (ids and counts only)
- Every request is written to `reports/audit.log` for replay
