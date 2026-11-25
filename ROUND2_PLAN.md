# DeploySentry — Round 2 Plan (VoyageHack 4.0)

Team "sunny" (Ritu Yadav + Aditay Kumar) · Problem statement: Agentic Real-Time DAST (TBO Security)
Round 2 window: 26 Nov 2026, 12:00 PM IST → 24 Dec 2026, 11:59 PM IST

## What Round 2 requires

- 10-slide presentation (PDF, max 50 MB, one submission per team)
- Code on GitHub — well-structured, functional, with documentation to run and understand it
- Explainer video demonstrating the workflow
- Live demo / walkthrough recommended
- Any language (their FAQ recommends Go; Python is our recommendation for build speed)

## Judging weights (from the problem statement)

| Criterion | Weight | What it means for the build |
|---|---|---|
| Valid findings and severity | 30% | The prototype must find REAL, reproducible vulns in the demo platform, especially business-logic ones |
| Precision and noise control | 20% | Few false positives and duplicates — verification and dedup must be demonstrable |
| Safety and scope discipline | 20% | Allowlist, rate limits, health checks, audit log, human approval — shown, not just claimed |
| Speed after change | 10% | Time from deploy to verified finding, measured in minutes |
| Report quality and actionability | 10% | Ticket-ready findings: evidence, impact, severity, owner, fix, retest |
| Discovery and API inventory | 10% | Accurate API map built with no docs; zombie/shadow labels; bonus for generated OpenAPI spec |

Rules of engagement (breaking these disqualifies the submission): stay in the approved
scope, test accounts and synthetic data only, rate-limit, no DoS or destructive tests,
prove findings with minimum evidence, log every request.

## What we are building

Two parts, both running locally (or on a small hosted VM for the demo):

### A. Demo travel platform ("AstraTravel" — a mock B2B travel staging environment)

A TBO-like B2B travel API + portal, deliberately built with planted vulnerabilities.
No OpenAPI docs are provided to the agent — it must discover the API itself, exactly
as the problem statement requires.

**Entities:** agencies (at least 2), users/roles (agency admin, sub-agent, finance,
platform admin), bookings (with a TBOH-style reference), flights/hotels inventory,
fares/markups, coupons, payments, refunds, travellers (PII).

**Core endpoints:** login, search, fare quote, hold, book, pay, get/list bookings,
cancel/refund, apply coupon, user/role management, supplier callback.

**Planted vulnerabilities (each mapped to a judging point):**
1. IDOR — `GET /bookings/{id}` does not check agency ownership (cross-agency read)
2. Fare tampering — booking accepts a client-supplied fare/total (book at ₹1)
3. Coupon reuse — a single-use coupon can be applied repeatedly / stacked
4. Refund abuse — cancel + rebook flow pays a refund twice
5. Sub-agent → admin escalation — role-update endpoint allows privilege escalation
6. Zombie API — `/v1/bookings` still live with no auth, returns full traveller PII
7. Shadow API — `/internal/supplier-sync` used by the front end but undocumented
8. JWT flaw — weak signing secret, forgeable token (stretch goal)
9. Missing rate limit on login / coupon endpoints (API hygiene)

**Seeded inputs for the agent:** 30 days of gateway traffic logs (drives zombie/shadow
classification), sample HAR/proxy logs of normal journeys, CI/CD deploy events with
release notes, DNS/cert records, asset ownership data.

**Change feed:** versioned releases. Release 2.4.0 ships a NEW endpoint (fare-modify)
with a fresh IDOR — the agent must catch it within minutes of the deploy. This is the
centrepiece of the demo.

### B. DeploySentry — the agent system

Implements the full loop from the problem statement:

- **Change Watcher** — polls the deploy feed, diffs the API snapshot, raises a change event
- **Discovery Agent** — crawls the portal, reads front-end JS for routes, records traffic,
  probes for hidden paths, builds the app knowledge graph (endpoints, params, roles, flows)
  and exports an inferred OpenAPI spec (bonus points)
- **Inventory Agent** — compares the knowledge graph against 30 days of traffic logs;
  labels each endpoint active / zombie / shadow with last-traffic date, auth status,
  data exposed, owner, and a recommendation (decommission / restrict / update)
- **Attack Planner** — picks targeted tests per endpoint from its parameters, roles and
  business purpose instead of spraying payloads
- **Specialist Executors** — one per vuln class (access control, business logic, auth,
  injection, API hygiene), using plain HTTP probes plus nuclei-style checks where useful
- **Verifier** — confirms each hit with a minimal, clean proof (e.g. second account
  re-check) so only real issues survive
- **Triage** — dedups, scores severity in business context (bookings / payments / PII /
  supplier access), maps each finding to an owner
- **Reporter** — ticket-ready findings (evidence, impact, severity, owner, suggested fix)
  plus an HTML dashboard
- **Retest Agent** — reruns the proof after a fix and closes the finding
- **Safety Layer** — scope allowlist, rate limiter, health monitor (backs off if the app
  strains), test-credential vault, audit log of every request, human-approval gate for
  risky tests

## The demo story (what the judges will see)

1. **Baseline:** the agent maps the API with no docs, labels zombie/shadow endpoints,
   and finds the pre-existing planted vulns.
2. **The change event:** Release 2.4.0 deploys a new endpoint. The agent detects the
   change in under 2 minutes, plans tests, finds the fresh IDOR, verifies it with
   minimal proof, and files a ticket with severity, owner and fix.
3. **Fix + retest:** the flaw is fixed; the agent retests and closes the finding.
4. **The numbers:** time-to-detect, time-to-verify, findings vs false positives,
   coverage of the loop — all measured from real runs, not claimed.

## Milestones

| Week | Dates | Work |
|---|---|---|
| 1 | 26 Nov – 2 Dec | Demo platform + seed data + traffic logs + deploy/change feed |
| 2 | 3 – 9 Dec | Discovery + inventory + planner + executors (access control and business logic first) |
| 3 | 10 – 16 Dec | Verifier, triage, reporter, dashboard, retest loop, end-to-end change-event demo, OpenAPI export |
| 4 | 17 – 24 Dec | 10-slide deck, explainer video, README, GitHub, submission (target: submit by 22 Dec, 2 days buffer) |

## Deliverables checklist

- [ ] Working demo platform with planted vulns + seeded traffic
- [ ] DeploySentry agent implementing the full loop
- [ ] Measured results: detection/verification times, precision numbers
- [ ] GitHub repo with README (setup, demo accounts, how to run the change event)
- [ ] 10-slide deck (PDF, ≤ 50 MB)
- [ ] Explainer video (workflow demo)
- [ ] Submission via the Unstop portal

## Open questions

- Stack: Python + FastAPI (recommended) vs Go (their FAQ recommendation) — awaiting Ritu's pick
- GitHub repo: whose account, and push access for the build
- Aditay's role in the build vs Ritu carrying it
- Video presenter for Round 2 (Ritu presented Round 1)
