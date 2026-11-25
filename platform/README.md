# AstraTravel — Demo Travel Platform

A mock B2B travel platform built for the **DeploySentry** prototype
(VoyageHack 4.0, Round 2 — problem statement: *Agentic Real-Time DAST*,
TBO Security). It plays the role of the "production-like travel platform"
that the DeploySentry agent tests.

> **Demo only.** Everything here is synthetic and runs on your own machine
> (`http://localhost:8000`). The app deliberately contains planted security
> flaws (listed below) so the agent has real vulnerabilities to find. Never
> deploy it publicly, never point it at real data, and never copy these
> patterns into production code.

## What it is

- A FastAPI travel API + a small agent portal (search → hold → book → pay →
  cancel) at `http://localhost:8000/`
- Two agencies (SkyWays Travel, GlobeTrek Holidays), 8 test users, 40 seeded
  bookings, 12 flights, 6 coupons — loaded from `../data/seed.json`
- A change feed (`GET /demo/releases`) and a live deploy switch for the
  v2.4.0 change event — the centrepiece of the demo
- The auto-generated OpenAPI docs are **deliberately disabled**: the agent
  must discover the API from the portal, traffic and probing, exactly as the
  TBO problem statement requires. (The agent generating an OpenAPI spec is a
  bonus scoring point.)

## Setup

```bash
cd platform
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

## Run

```bash
./run.sh
# or: venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000
```

Open http://localhost:8000/ for the portal, or `GET /health` to check it is up.

## Demo accounts

Every test account uses the password **`Test@1234`** (demo only).

| Username | Agency | Role |
|---|---|---|
| `sky_admin` | SkyWays Travel | agency_admin |
| `sky_agent1`, `sky_agent2` | SkyWays Travel | sub_agent |
| `sky_fin` | SkyWays Travel | finance |
| `globe_admin` | GlobeTrek Holidays | agency_admin |
| `globe_agent1` | GlobeTrek Holidays | sub_agent |
| `globe_fin` | GlobeTrek Holidays | finance |
| `platform_admin` | — (platform) | platform_admin |

Log in with `POST /auth/login` → JWT (HS256). Example:

```bash
curl -s -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"sky_agent1","password":"Test@1234"}'
```

## Endpoints

| Method + path | Auth | Notes |
|---|---|---|
| `POST /auth/login` | none | username/password → JWT. **No rate limiting** (flaw #9) |
| `GET /search/flights?from&to&date` | JWT | Open to any logged-in user (negative control) |
| `GET /fares/quote?flight_id` | JWT | Base fare + 5% markup |
| `POST /bookings/hold` | JWT | Hold a seat, returns `hold_id` |
| `POST /bookings` | JWT | Create booking. **Trusts client `total`** (flaw #2) |
| `GET /bookings/{id}` | JWT | Booking detail + PII. **No agency check — IDOR** (flaw #1) |
| `GET /bookings?agency_id=` | JWT | **Enforces** the agency filter — 403 otherwise (negative control) |
| `POST /bookings/{id}/pay` | JWT | Accepts any amount, including 0 (stretch flaw) |
| `POST /bookings/{id}/cancel` | JWT | Refunds the full total **every time** (flaw #4) |
| `POST /coupons/apply` | JWT | **Single-use coupons apply repeatedly** (flaw #3) |
| `POST /admin/users/{id}/role` | JWT (any) | **No role check** — any user can escalate (flaw #5) |
| `GET /v1/bookings/{id}` | **none** | **Zombie API** — live, unauthenticated, full PII (flaw #6) |
| `POST /internal/supplier-sync` | JWT | **Shadow API** — undocumented, minimal checks (flaw #7) |
| `POST /v2/bookings/{id}/fare-modify` | JWT | Only after v2.4.0 deploys. **Fresh IDOR** (flaw #10) |
| `GET /health` | none | Liveness probe |
| `GET /demo/releases` | none | Change feed the agent polls |
| `POST /demo/deploy` | platform_admin | Deploy a release live (see below) |
| `POST /demo/reset` | platform_admin | Restore seed data + roll back to v2.3.0 |

## The v2.4.0 change event (demo centrepiece)

The platform starts on **v2.3.0**. During the demo, deploy v2.4.0 live:

```bash
# 1. Log in as platform_admin, save the token
TOKEN=$(curl -s -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"platform_admin","password":"Test@1234"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 2. Deploy v2.4.0 — the new endpoint goes live immediately
curl -s -X POST localhost:8000/demo/deploy \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"version":"v2.4.0"}'

# 3. The agent should now detect POST /v2/bookings/{id}/fare-modify and find
#    that any agency's agent can rewrite another agency's booking fare.
# 4. Reset when done:
curl -s -X POST localhost:8000/demo/reset \
  -H "Authorization: Bearer $TOKEN"
```

## Planted vulnerabilities (ground truth — 10 findings)

1. **IDOR** — `GET /bookings/{id}` has no agency-ownership check
2. **Fare tampering** — `POST /bookings` trusts the client-supplied `total`
3. **Coupon reuse** — single-use coupons apply repeatedly
4. **Double refund** — `POST /bookings/{id}/cancel` refunds every time
5. **Privilege escalation** — `POST /admin/users/{id}/role` has no role check
6. **Zombie API** — `GET /v1/bookings/{id}` live with no auth, returns PII
7. **Shadow API** — `POST /internal/supplier-sync` undocumented, minimal checks
8. **Weak JWT secret** — HS256 secret is the guessable string `travel123`;
   a forged token is accepted
9. **No rate limiting** — login / coupon endpoints accept unlimited attempts
10. **Fresh IDOR** — `POST /v2/bookings/{id}/fare-modify` after v2.4.0

Negative controls (correct behaviour — the agent must NOT flag these):
`GET /bookings?agency_id=` enforces the agency filter; `GET /search/flights`
is open to any logged-in user.

## Verify

`verify.py` proves every finding above with real HTTP calls (and starts the
server itself if it is not already running):

```bash
python3 verify.py
```

It prints a PASS/FAIL line per check and exits non-zero if anything fails.
It leaves the platform reset to a clean state (seed data, v2.3.0).

## Files

| File | What it is |
|---|---|
| `app.py` | The whole API + in-memory store (seeded from `../data/seed.json`) |
| `static/index.html`, `app.js`, `style.css` | The agent portal; the JS calls the API with literal route strings so the discovery agent can find them (the shadow route is assembled at runtime) |
| `verify.py` | Ground-truth verification against the live server |
| `requirements.txt` | fastapi, uvicorn, PyJWT |
| `run.sh` | Convenience launcher |
| `venv/` | Python virtual environment (created at setup) |
