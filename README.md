# DeploySentry — VoyageHack 4.0, Round 2

**Team Sunny** (Ritu Yadav + Aditay Kumar) · TBO Security Hackathon 2026 ·
Problem statement: **Agentic Real-Time DAST**

DeploySentry is a change-aware agentic security testing system for travel APIs.
It notices what changed on a live travel platform, learns the API with no
documentation, plans targeted attacks, executes them safely, proves each finding
with minimal evidence, triages it in business context, reports it ticket-ready,
and retests after a fix.

## Verified results (measured 2026-11-25, real runs)

- **11 findings verified, 0 false positives, 100% precision**
- **Change detected in 0.6s; fresh vulnerability verified 1.0s after deploy**
- 2/2 negative controls passed (the agent does not flag correct behaviour)
- 14 endpoints discovered with no docs (10 active, 1 zombie, 2 shadow);
  inferred OpenAPI spec generated as a by-product
- Every request audit-logged; max 5 req/sec inside the allowed scope;
  human approval required for risky tests

## Layout

| Path | What it is |
|---|---|
| `platform/` | AstraTravel — the mock B2B travel platform the agent tests (FastAPI, synthetic data, planted vulnerabilities) |
| `deploysentry/` | The DeploySentry agent system (Python stdlib only) |
| `data/` | Seed data, 30 days of gateway traffic, deploy feed, HAR samples |
| `problem-statements/` | The official TBO problem-statement documents |
| `ROUND2_PLAN.md` | Round 2 build plan and milestones |
| `DEMO_PLATFORM_SPEC.md` | Demo platform contract (endpoints, planted flaws, ground truth) |
| `EXPLAINER_VIDEO_SCRIPT.md` | Script for the Round 2 explainer video |
| `ROUND3_PREP_DRAFT.md` | Grand Finale pitch outline and Q&A bank |

## Run the demo

```bash
# 1. Start the demo travel platform
cd platform && ./run.sh            # http://localhost:8000

# 2. Run the full agent loop (in another terminal)
cd ../deploysentry && python3 run.py --auto-approve
```

The run resets the platform to a fresh seed, maps the API, finds and verifies
the planted vulnerabilities, deploys v2.4.0 live mid-run, catches the fresh
flaw within seconds, writes ticket-ready findings to `deploysentry/reports/`,
and retests after the fix. Without `--auto-approve`, the two risky tests are
skipped and listed as awaiting human approval.

## Run the checks

```bash
cd platform && python3 verify.py   # 13/13 checks: every planted flaw + controls
```

## Submission (Round 2, due 24 Dec 2026, 11:59 PM IST)

- 10-slide presentation (PDF) — `../your_files/deploysentry-round2-deck/`
- This repo (code + documentation)
- Explainer video — see `EXPLAINER_VIDEO_SCRIPT.md`

## Safety

Everything here runs locally against synthetic data. The agent only ever talks
to `localhost:8000`, uses test accounts, rate-limits itself, and logs every
request for replay. No real systems, no real data.
