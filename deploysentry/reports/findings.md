# DeploySentry — findings report

Run: 2026-11-25T11:30:40  |  Target: http://127.0.0.1:8000  |  Baseline: v2.3.0  |  Change event: v2.4.0

## Summary

- Verified findings: **10** (+ 1 bonus)  
- Candidates rejected by the verifier (false positives filtered): **0**  
- Precision: **100.0%**  
- Negative controls passed: 2/2  
- Time from deploy to detection: 0.6s  
- Time from deploy to verified finding: 1.0s  
- Endpoints discovered: 14 (10 active, 1 zombie, 2 shadow, 1 infra)

## Findings (ticket-ready)

### DS-001 — Book at Rs. 1 (fare tampering) [Critical]

- **Endpoint:** `POST /bookings`
- **Class:** business-logic
- **Owner:** Payments team
- **Status:** verified
- **Business impact:** Direct revenue loss: any agent can book any flight for Rs. 1 by sending a client-supplied total. The fare is money — trusting the client is trusting the attacker.
- **Evidence:**
  - POST /bookings {hold_id, total: 1} -> 200, booking AST-1041 created with total=1
  - Server trusted the client-supplied total instead of recomputing the fare
- **Verified by:** Re-read AST-1041: total=1 stored server-side
- **Suggested fix:** Recompute fare and total server-side from the hold and fare rules; ignore client-supplied totals.

### DS-002 — Sub-agent promotes self to agency_admin [Critical]

- **Endpoint:** `POST /admin/users/{id}/role`
- **Class:** access-control
- **Owner:** IAM team
- **Status:** verified
- **Business impact:** Full agency takeover: any sub-agent can promote herself to agency_admin and then change other users, bookings and refunds. One request breaks the whole role model.
- **Evidence:**
  - sky_agent2 (sub_agent) POST /admin/users/sky_agent2/role {role: agency_admin} -> 200
  - Response role=agency_admin — the endpoint never checked the caller's role
- **Verified by:** Fresh login as sky_agent2: token claims role=agency_admin; role restored to sub_agent
- **Suggested fix:** Require platform_admin (or the agency's own admin) on the role endpoint, and audit every role change.

### DS-003 — Cancel twice, refunded twice [High]

- **Endpoint:** `POST /bookings/{id}/cancel`
- **Class:** business-logic
- **Owner:** Payments team
- **Status:** verified
- **Business impact:** Direct revenue loss: cancelling the same booking twice pays the refund twice. A cancel-rebook loop can drain money on every trip.
- **Evidence:**
  - Booking AST-1043 (total 10400): 1st cancel -> refunds_issued=1, 2nd cancel -> refunds_issued=2
  - The endpoint never checks whether a refund was already issued
- **Verified by:** Booking record shows 2 refunds of Rs. 10400 each
- **Suggested fix:** Make refunds idempotent — one refund per booking — and record the refund before returning success.

### DS-004 — Cross-agency booking read (IDOR) [High]

- **Endpoint:** `GET /bookings/{id}`
- **Class:** access-control
- **Owner:** API team
- **Status:** verified
- **Business impact:** Any agency's agent can read any other agency's bookings, including traveller names and passport numbers. Cross-agency data exposure; a trust and compliance failure for a B2B platform.
- **Evidence:**
  - sky_agent1 (ag_skyways) GET /bookings/AST-1004 -> 200
  - Response agency_id=ag_globetrek, 2 travellers returned (names/passports withheld from evidence)
- **Verified by:** sky_agent2 read a second GlobeTrek booking (AST-1005) -> 200; agency_id in response = ag_globetrek
- **Suggested fix:** Enforce the agency-ownership check on GET /bookings/{id} (same check the list endpoint already has).

### DS-005 — Cross-agency fare rewrite (fresh IDOR, v2.4.0) [High]

- **Endpoint:** `POST /v2/bookings/{id}/fare-modify`
- **Class:** access-control
- **Owner:** API team
- **Status:** closed — fixed by rollback (retest passed)
- **Business impact:** A brand-new endpoint shipped with no agency-ownership check: any agency can rewrite another agency's booking fare after payment. This is the change the agent caught within minutes of the deploy.
- **Evidence:**
  - sky_agent1 (ag_skyways) POST /v2/bookings/AST-1004/fare-modify {new_fare: 5} -> 200
  - Response fare=5 on a GlobeTrek booking — no agency-ownership check on the new endpoint
- **Verified by:** Re-read AST-1004: fare=5 stored server-side
- **Suggested fix:** Add the same agency-ownership check as the other booking endpoints, and add the endpoint to the API inventory.

### DS-006 — Forged JWT accepted (weak secret) [High]

- **Endpoint:** `GET /bookings/{id}`
- **Class:** auth
- **Owner:** IAM team
- **Status:** verified
- **Business impact:** The JWT signing secret is a guessable word ('travel123'). Anyone who guesses it can mint a token for any user, including platform_admin — full authentication bypass, no password needed.
- **Evidence:**
  - A token minted with secret 'travel123' for platform_admin was accepted (200)
  - Anyone who guesses the weak secret can mint any identity — no password needed
- **Verified by:** Wrong-secret token -> 401 (expected 401); forged token with 'travel123' -> 200 (expected 200)
- **Suggested fix:** Rotate the secret to a long random value from the vault, and invalidate all tokens issued under the old secret.

### DS-007 — Pay Rs. 0 marks booking PAID (bonus) [High]

- **Endpoint:** `POST /bookings/{id}/pay`
- **Class:** business-logic
- **Owner:** Payments team
- **Status:** verified
- **Business impact:** Skipped payment: paying Rs. 0 marks a booking PAID. The payment step can be walked past, so bookings can be confirmed without any money moving.
- **Evidence:**
  - POST /bookings/AST-1044/pay {amount: 0} -> 200, status=PAID, paid_amount=0
  - The endpoint never checks the amount against the total
- **Verified by:** Re-read AST-1044: status=PAID, paid_amount=0
- **Suggested fix:** Validate the paid amount against the booking total server-side; reject zero and under-payments.

### DS-008 — Zombie API serves PII without auth [High]

- **Endpoint:** `GET /v1/bookings/{id}`
- **Class:** zombie-api
- **Owner:** API team
- **Status:** verified
- **Business impact:** An old, forgotten endpoint still serves full booking PII with no authentication at all. Anyone on the internet can read traveller data; it has had zero legitimate traffic in 30 days.
- **Evidence:**
  - GET /v1/bookings/AST-1004 with NO token -> 200
  - Full booking returned, 2 travellers with PII (withheld from evidence)
- **Verified by:** GET /v1/bookings/AST-1005 with no token -> 200, PII returned
- **Suggested fix:** Decommission GET /v1/bookings/{id} immediately; remove the route and confirm no client still calls it.

### DS-009 — Shadow API accepts calls with no authorisation check [Medium]

- **Endpoint:** `POST /internal/supplier-sync`
- **Class:** shadow-api
- **Owner:** Platform team
- **Status:** verified
- **Business impact:** An undocumented route is live and does no authorisation beyond 'has a token'. It is in real traffic, so it is load-bearing — but nobody owns it, and nobody reviewed it.
- **Evidence:**
  - POST /internal/supplier-sync as sky_agent1 (sub_agent) -> 200, status=synced
  - Route is undocumented, never in the discovered map, yet performs no authorisation beyond 'has a token'
- **Verified by:** Repeat call -> 200 synced; route is live and undocumented
- **Suggested fix:** Document the route, restrict it to service accounts, and add it to the API inventory with an owner.

### DS-010 — Single-use coupon applied twice [Medium]

- **Endpoint:** `POST /coupons/apply`
- **Class:** business-logic
- **Owner:** Pricing team
- **Status:** verified
- **Business impact:** Revenue leakage: single-use coupons can be applied repeatedly to the same booking, stacking discounts the pricing team never approved.
- **Evidence:**
  - FLY10 applied to AST-1042: 1st use -> total 9360, 2nd use -> total 8424, times_applied=2
  - Single-use coupon was never marked used
- **Verified by:** Booking record shows FLY10 applied 2x
- **Suggested fix:** Mark a single-use coupon used after its first successful application; enforce it in the database, not in the UI.

### DS-011 — No rate limiting on login [Low]

- **Endpoint:** `POST /auth/login`
- **Class:** api-hygiene
- **Owner:** API team
- **Status:** verified
- **Business impact:** Login accepts unlimited attempts with no throttling or lockout, so passwords can be guessed at full speed. Low on its own — it needs a further attack to matter — but it must be fixed.
- **Evidence:**
  - 20 failed logins in a row: statuses [401], no 429 anywhere
  - Unlimited guessing is possible — no throttling, no lockout
- **Verified by:** Recorded burst: 20 attempts, statuses [401], no 429
- **Suggested fix:** Rate-limit login (and coupon) attempts per account and IP, and add a short lockout after repeated failures.

## API inventory

| Endpoint | Label | Traffic (30d) | Last seen | Auth | Owner | Recommendation |
|---|---|---|---|---|---|---|
| `GET /bookings` | **active** | 1917 | 2026-11-24T23:46:00 | jwt | API team | Keep — monitored. |
| `GET /bookings/{id}` | **active** | 798 | 2026-11-24T23:24:14 | jwt | API team | Keep — monitored. |
| `GET /demo/releases` | **n/a** | 0 | never | none | Platform team | Infrastructure endpoint — not part of the business API inventory; not expected in gateway traffic. |
| `GET /fares/quote` | **active** | 7452 | 2026-11-24T23:54:13 | jwt | Pricing team | Keep — monitored. |
| `GET /search/flights` | **active** | 11236 | 2026-11-24T23:54:39 | jwt | API team | Keep — monitored. |
| `GET /v1/bookings/{id}` | **zombie** | 0 | never | none | API team | Decommission — still live with zero legitimate traffic in 30 days. |
| `POST /admin/users/{id}/role` | **shadow** | 38 | 2026-11-24T12:02:12 | jwt | IAM team | Restrict to service accounts, document it, or decommission — in use but never mapped. |
| `POST /auth/login` | **active** | 1858 | 2026-11-24T23:58:53 | none | IAM team | Keep — monitored. |
| `POST /bookings` | **active** | 4524 | 2026-11-24T23:59:48 | jwt | API team | Keep — monitored. |
| `POST /bookings/hold` | **active** | 3636 | 2026-11-24T23:58:02 | jwt | API team | Keep — monitored. |
| `POST /bookings/{id}/cancel` | **active** | 1896 | 2026-11-24T23:39:52 | jwt | API team | Keep — monitored. |
| `POST /bookings/{id}/pay` | **active** | 3705 | 2026-11-24T23:51:17 | jwt | API team | Keep — monitored. |
| `POST /coupons/apply` | **active** | 1871 | 2026-11-24T23:07:11 | jwt | Pricing team | Keep — monitored. |
| `POST /internal/supplier-sync` | **shadow** | 365 | 2026-11-24T22:05:25 | jwt | Platform team | Restrict to service accounts, document it, or decommission — in use but never mapped. |

## Negative controls (correct behaviour, not findings)

- control-list-filter: PASS — sky_agent1 listing ag_globetrek -> 403 (expected 403)
- control-search-auth: PASS — logged-in 200 (2 results), anonymous 401 (expected 401)

## Retest after fix/rollback

- fare-modify-idor: **closed** — After rollback to v2.3.0 the endpoint returns 404 — the flaw no longer reproduces. Finding closed.
- control-list-filter: **still-enforced** — List filter after rollback: 403 (expected 403)

## Safety

All requests were scoped to http://127.0.0.1:8000 at max 5 req/sec, using test accounts only. Every request is in `audit.log` for replay.