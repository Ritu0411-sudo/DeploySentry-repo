# AstraTravel — Demo Platform Spec (DeploySentry Round 2)

A mock B2B travel staging environment for the DeploySentry prototype. It plays the
role of the "production-like travel platform" from the TBO problem statement: the
agent gets NO API documentation and must discover everything itself.

Base URL (local): `http://localhost:8000` — the agent's scope allowlist covers this
origin only. All data is synthetic. No real customer data, no external calls.

## Agencies and test accounts

| Agency | ID | Users (role) |
|---|---|---|
| SkyWays Travel | `ag_skyways` | `sky_admin` (agency_admin), `sky_agent1`, `sky_agent2` (sub_agent), `sky_fin` (finance) |
| GlobeTrek Holidays | `ag_globetrek` | `globe_admin` (agency_admin), `globe_agent1` (sub_agent), `globe_fin` (finance) |
| TBO platform | — | `platform_admin` (platform_admin) |

All test passwords: `Test@1234` (documented in the README; demo-only).
Auth: JWT (HS256) returned by `POST /auth/login`, claims: `sub`, `agency_id`, `role`.
One planted auth flaw (stretch): the signing secret is weak (`travel123`) — a forged
token test is part of the agent's auth checks.

## Core endpoints

| Method + path | Auth | Purpose | Planted flaw |
|---|---|---|---|
| `POST /auth/login` | none | username/password → JWT | No rate limiting (API hygiene) |
| `GET /search/flights?from&to&date` | JWT | flight search | — |
| `GET /fares/quote?flight_id` | JWT | fare + markup quote | — |
| `POST /bookings/hold` | JWT | hold a seat (body: flight_id, travellers) | — |
| `POST /bookings` | JWT | create booking (body: hold_id, fare, total, coupon_code) | **Fare tampering**: server trusts client-supplied `total` |
| `GET /bookings/{id}` | JWT | booking detail incl. traveller PII | **IDOR**: no agency-ownership check |
| `GET /bookings?agency_id=` | JWT | list agency bookings | List enforces agency filter (control: agent must NOT flag this) |
| `POST /bookings/{id}/pay` | JWT | pay (body: amount, method) | Skipped-payment check is a stretch flaw (pay with amount 0) |
| `POST /bookings/{id}/cancel` | JWT | cancel → refund | **Refund abuse**: cancel after rebook pays twice |
| `POST /coupons/apply` | JWT | apply coupon to a booking | **Coupon reuse**: single-use coupon applies repeatedly |
| `POST /admin/users/{id}/role` | platform_admin | change a user's role | **Privilege escalation**: any agency_admin can call it (missing role check) |
| `GET /v1/bookings/{id}` | none | legacy booking lookup | **Zombie API**: live, unauthenticated, full PII |
| `POST /internal/supplier-sync` | JWT | supplier inventory sync | **Shadow API**: used by the front end, undocumented, no auth check beyond JWT |
| `GET /health` | none | liveness probe for the agent's health monitor | — |

Front end: a minimal portal (search → hold → book → pay → cancel) whose JavaScript
calls the same API — the Discovery Agent reads its JS bundles for routes, as the
problem statement suggests.

## Seed data

- 2 agencies, 8 users (above), 40 bookings split across agencies, 12 flights,
  6 coupons (2 single-use, 2 multi-use, 2 expired), fare/markup rules per agency.
- Traveller PII is synthetic (generated names, passport-style IDs, test card tokens).
- Booking references look like `AST-1001` (TBOH-style).

## Traffic logs (for zombie/shadow classification)

`gateway.log` — 30 days of JSONL access logs (~50k lines) in a realistic mix:
search, quote, hold, book, pay, cancel, coupon, admin calls. Deliberately:
- `/v1/bookings/{id}` appears in the log 0 times in 30 days but still responds 200
  → zombie.
- `/internal/supplier-sync` appears ~400 times but is absent from every discovered
  route list / JS bundle → shadow.
- All other endpoints appear regularly → active.
The Inventory Agent must produce, per endpoint: last-seen traffic date, auth status,
data exposed, likely owner, and a recommendation (decommission / restrict / update).

## Change feed (the centrepiece)

`releases.json` — versioned deploys the Change Watcher polls:

- `v2.3.0` (baseline, already deployed at demo start)
- `v2.4.0` (deployed live during the demo): adds `POST /v2/bookings/{id}/fare-modify`
  (change a booking's fare after payment) with a fresh **IDOR** — any agency's agent
  can modify another agency's booking fare. The agent must detect the change, plan
  tests, find the flaw, verify with minimal proof, and file a ticket — measured
  end to end in minutes.

## Ground truth (what the agent must find — used to score precision)

| # | Finding | Class | Severity (business) | Owner |
|---|---|---|---|---|
| 1 | Cross-agency booking read (IDOR) | Access control | High — PII + booking data of another agency | API team |
| 2 | Fare tampering at booking | Business logic | Critical — direct revenue loss | Payments team |
| 3 | Single-use coupon reuse | Business logic | Medium — revenue leakage | Pricing team |
| 4 | Double refund on cancel-rebook | Business logic | High — direct revenue loss | Payments team |
| 5 | Sub-agent → admin escalation | Access control | Critical — full agency takeover | IAM team |
| 6 | Zombie `/v1/bookings` unauthenticated PII | Zombie API + data exposure | High — PII exposure, decommission | API team |
| 7 | Shadow `/internal/supplier-sync` | Shadow API | Medium — undocumented, restrict | Platform team |
| 8 | JWT weak secret (forgeable token) | Auth | High — auth bypass (stretch) | IAM team |
| 9 | No rate limit on login / coupon | API hygiene | Low–Medium | API team |
| 10 | Fresh IDOR in v2.4.0 fare-modify | Access control | High — the change-event catch | API team |

Negative controls (the agent must NOT report these): `GET /bookings?agency_id=` list
correctly enforces the agency filter; `GET /search/flights` is intentionally public
to logged-in users. These exist so precision can be measured, not just recall.

## Safety contract for the agent

- Scope allowlist: `localhost:8000` only; stop at anything outside it.
- Rate limit: max 5 req/sec against the demo platform; back off on 429 or when
  `/health` latency degrades.
- Test accounts only (above); no destructive actions (no deletes, no bulk reads —
  verification uses at most 2 records per check).
- Every request logged (method, path, account, timestamp, result) for replay.

## Files the build will produce

- `platform/` — the demo travel API + portal + seed scripts
- `deploysentry/` — change watcher, discovery, inventory, planner, executors,
  verifier, triage, reporter, retest, safety layer, dashboard
- `data/` — seed data, 30-day gateway log, HAR samples, releases.json
- `docs/` — README, demo script, architecture diagram
- `reports/` — sample ticket-ready findings + dashboard output
