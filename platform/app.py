"""
AstraTravel — demo B2B travel platform for the DeploySentry prototype
(VoyageHack 4.0, Round 2).

This is a MOCK platform that runs locally with SYNTHETIC data only. It exists so
the DeploySentry security agent has a realistic target to test.

================================================================================
WARNING — PLANTED VULNERABILITIES
================================================================================
This app DELIBERATELY contains security flaws, exactly as specified in
../DEMO_PLATFORM_SPEC.md. They are intentional, authorised by the team for this
hackathon demo ONLY, and each one is marked in the code with "PLANTED FLAW".
Never deploy this app anywhere public, never point it at real data, and never
copy these patterns into production code.

Planted flaws (ground truth, 10 findings):
  1. IDOR — GET /bookings/{id} has no agency-ownership check
  2. Fare tampering — POST /bookings trusts the client-supplied `total`
  3. Coupon reuse — POST /coupons/apply never enforces single-use
  4. Double refund — POST /bookings/{id}/cancel refunds every time, even twice
  5. Privilege escalation — POST /admin/users/{id}/role has no role check
  6. Zombie API — GET /v1/bookings/{id} is live with NO auth, returns full PII
  7. Shadow API — POST /internal/supplier-sync is undocumented, minimal checks
  8. Weak JWT secret — HS256 secret is the guessable string "travel123"
  9. No rate limiting — login / coupon endpoints accept unlimited attempts
 10. Fresh IDOR — POST /v2/bookings/{id}/fare-modify (only after v2.4.0 deploys)

Negative controls (correct behaviour the agent must NOT flag):
  - GET /bookings?agency_id= enforces the agency filter (403 otherwise)
  - GET /search/flights is open to any LOGGED-IN user (401 when anonymous)

Other deliberate design choices:
  - The auto-generated OpenAPI docs are DISABLED (docs_url=None etc.) so the
    agent must genuinely discover the API from the portal, traffic and probing —
    exactly as the TBO problem statement requires. The agent is expected to
    generate an OpenAPI spec as a by-product (bonus points).
  - All state lives in memory and is seeded from ../data/seed.json on startup.
    POST /demo/reset restores the seed (demo convenience, platform_admin only).
"""

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR.parent / "data"

# PLANTED FLAW #8 — weak, guessable JWT signing secret (demo only).
# A real app would use a long random secret from a vault. Here the weak secret
# is the point: the agent must prove a forged token is accepted.
JWT_SECRET = "travel123"  # noqa: S105  (intentional, see module docstring)
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24

DEMO_PASSWORD = "Test@1234"  # same password for every test account (demo only)

# The demo platform runs on one origin only; the agent's scope allowlist is
# limited to this origin.
PORT = 8000

# ---------------------------------------------------------------------------
# In-memory store, seeded from ../data/seed.json
# ---------------------------------------------------------------------------

store = {
    "agencies": {},   # id -> {id, name}
    "users": {},      # username -> {username, agency_id, role}
    "flights": {},    # flight_id -> {flight_id, from, to, base_fare}
    "bookings": {},   # booking_id -> booking dict
    "coupons": {},    # code -> {code, discount_pct, single_use, status}
    "holds": {},      # hold_id -> {hold_id, flight_id, travellers, user, fare_estimate}
    "next_booking": 1041,
    "next_hold": 1000,
    "next_refund": 500,
}

# Release state — the change feed. v2.3.0 is the baseline; v2.4.0 is deployed
# live during the demo via POST /demo/deploy.
release_state = {
    "current_version": "v2.3.0",
    "v240_deployed": False,
    "v240_deployed_at": None,
}


def load_seed() -> None:
    """(Re)load all seed data. Called at startup and by POST /demo/reset."""
    seed = json.loads((DATA_DIR / "seed.json").read_text())
    store["agencies"] = {a["id"]: dict(a) for a in seed["agencies"]}
    store["users"] = {u["username"]: dict(u) for u in seed["users"]}
    store["flights"] = {f["flight_id"]: dict(f) for f in seed["flights"]}
    store["bookings"] = {}
    for b in seed["bookings"]:
        booking = dict(b)
        booking["paid_amount"] = None
        booking["coupons_applied"] = []
        booking["refunds"] = []
        store["bookings"][booking["id"]] = booking
    store["coupons"] = {c["code"]: dict(c) for c in seed["coupons"]}
    store["holds"] = {}
    store["next_booking"] = 1041
    store["next_hold"] = 1000
    store["next_refund"] = 500
    release_state["current_version"] = "v2.3.0"
    release_state["v240_deployed"] = False
    release_state["v240_deployed_at"] = None


# ---------------------------------------------------------------------------
# App setup — auto OpenAPI docs deliberately disabled (see module docstring)
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AstraTravel (demo)",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Tiny request log on stdout so the demo audience can see traffic live."""
    started = time.time()
    response = await call_next(request)
    ms = int((time.time() - started) * 1000)
    print(f"{request.method} {request.url.path} -> {response.status_code} ({ms}ms)",
          flush=True)
    return response


# ---------------------------------------------------------------------------
# Auth — JWT (HS256). The weak secret is PLANTED FLAW #8.
# ---------------------------------------------------------------------------

def make_token(user: dict) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user["username"],
        "agency_id": user["agency_id"],
        "role": user["role"],
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_current_user(request: Request) -> dict:
    """Decode the Bearer token. Any token signed with the secret is accepted —
    including forged ones, because the secret is weak (PLANTED FLAW #8)."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    try:
        claims = jwt.decode(auth[7:], JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = store["users"].get(claims.get("sub", ""))
    if user is None:
        raise HTTPException(status_code=401, detail="Unknown user")
    # Trust the role/agency from the TOKEN, not the stored user — this is what
    # makes a forged token powerful: the claims ARE the identity.
    return {"username": claims["sub"],
            "agency_id": claims.get("agency_id"),
            "role": claims.get("role")}


def require_platform_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "platform_admin":
        raise HTTPException(status_code=403, detail="platform_admin only")
    return user


def _owns_booking(user: dict, booking: dict) -> bool:
    """True if the caller may act on this booking: same agency, or platform."""
    return user["role"] == "platform_admin" or \
        user["agency_id"] == booking["agency_id"]


# ---------------------------------------------------------------------------
# Public / utility endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    """Liveness probe for the agent's health monitor. No auth."""
    return {"status": "ok", "service": "astratravel-demo",
            "version": release_state["current_version"]}


@app.get("/")
def portal():
    """The agent portal front end (search -> hold -> book -> pay -> cancel)."""
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/demo/releases")
def releases():
    """The change feed the Change Watcher polls. Public (CI/CD-style feed)."""
    base = json.loads((DATA_DIR / "releases.json").read_text())["releases"]
    out = []
    for rel in base:
        rel = dict(rel)
        if rel["version"] == "v2.4.0" and release_state["v240_deployed"]:
            rel["deployed_at"] = release_state["v240_deployed_at"]
        out.append(rel)
    return {"current_version": release_state["current_version"],
            "releases": out}


@app.post("/demo/deploy")
def deploy(body: dict, user: dict = Depends(require_platform_admin)):
    """Deploy a release live during the demo (platform_admin only).

    Example: POST /demo/deploy {"version": "v2.4.0"}
    This flips on the new endpoint POST /v2/bookings/{id}/fare-modify, which
    carries a fresh IDOR (PLANTED FLAW #10) — the centrepiece of the demo.
    """
    version = body.get("version")
    if version != "v2.4.0":
        raise HTTPException(status_code=400, detail="only v2.4.0 can be deployed")
    if release_state["v240_deployed"]:
        return {"status": "already deployed", **release_state}
    release_state["v240_deployed"] = True
    release_state["v240_deployed_at"] = datetime.now(timezone.utc).isoformat()
    release_state["current_version"] = "v2.4.0"
    print("DEPLOYED v2.4.0 — new endpoint live: "
          "POST /v2/bookings/{id}/fare-modify", flush=True)
    return {"status": "deployed", **release_state}


@app.post("/demo/reset")
def reset(user: dict = Depends(require_platform_admin)):
    """Restore all seed data and roll back to v2.3.0 (demo convenience)."""
    load_seed()
    return {"status": "reset", "version": "v2.3.0"}


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@app.post("/auth/login")
def login(body: dict):
    """Username + password -> JWT.

    PLANTED FLAW #9 — no rate limiting: unlimited login attempts are accepted.
    """
    username = body.get("username", "")
    password = body.get("password", "")
    user = store["users"].get(username)
    if user is None or password != DEMO_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": make_token(user), "token_type": "bearer",
            "user": {"username": user["username"],
                     "agency_id": user["agency_id"], "role": user["role"]}}


# ---------------------------------------------------------------------------
# Travel: search, quote, hold, book, pay, cancel
# ---------------------------------------------------------------------------

@app.get("/search/flights")
def search_flights(from_: str = "", to: str = "", date: str = "",
                   user: dict = Depends(get_current_user)):
    """Flight search.

    NEGATIVE CONTROL: open to any LOGGED-IN user (any role, any agency).
    Anonymous requests get 401 from the auth dependency above.
    """
    results = [f for f in store["flights"].values()
               if (not from_ or f["from"] == from_)
               and (not to or f["to"] == to)]
    return {"date": date, "results": results}


@app.get("/fares/quote")
def fare_quote(flight_id: str, user: dict = Depends(get_current_user)):
    flight = store["flights"].get(flight_id)
    if flight is None:
        raise HTTPException(status_code=404, detail="Unknown flight")
    markup_pct = 5
    markup = flight["base_fare"] * markup_pct // 100
    return {"flight_id": flight_id, "base_fare": flight["base_fare"],
            "markup_pct": markup_pct, "markup": markup,
            "total": flight["base_fare"] + markup}


@app.post("/bookings/hold")
def hold_seat(body: dict, user: dict = Depends(get_current_user)):
    flight = store["flights"].get(body.get("flight_id", ""))
    if flight is None:
        raise HTTPException(status_code=404, detail="Unknown flight")
    travellers = int(body.get("travellers", 1))
    store["next_hold"] += 1
    hold_id = f"HLD-{store['next_hold']}"
    hold = {"hold_id": hold_id, "flight_id": flight["flight_id"],
            "travellers": travellers, "user": user["username"],
            "fare_estimate": flight["base_fare"] * travellers}
    store["holds"][hold_id] = hold
    return hold


@app.post("/bookings")
def create_booking(body: dict, user: dict = Depends(get_current_user)):
    """Create a booking from a hold.

    PLANTED FLAW #2 — fare tampering: the server trusts the client-supplied
    `total` (and `fare`) instead of recomputing the price. A caller can book
    any flight for Rs. 1 by sending {"total": 1}.
    """
    hold = store["holds"].get(body.get("hold_id", ""))
    if hold is None:
        raise HTTPException(status_code=404, detail="Unknown hold")
    booking_id = f"AST-{store['next_booking']}"
    store["next_booking"] += 1
    flight = store["flights"][hold["flight_id"]]
    travellers = [{"name": f"Traveller {i + 1}",
                    "passport": f"X{9000000 + store['next_booking'] * 7 + i}"}
                   for i in range(hold["travellers"])]
    booking = {
        "id": booking_id,
        "agency_id": user["agency_id"],
        "flight_id": hold["flight_id"],
        "travellers": travellers,
        "fare": body.get("fare", flight["base_fare"] * hold["travellers"]),
        "total": body.get("total",
                          flight["base_fare"] * hold["travellers"]),
        "status": "CONFIRMED",
        "created": datetime.now(timezone.utc).isoformat(),
        "paid_amount": None,
        "coupons_applied": [],
        "refunds": [],
    }
    if body.get("coupon_code"):
        booking["coupons_applied"].append(body["coupon_code"])
    store["bookings"][booking_id] = booking
    return booking


@app.get("/bookings")
def list_bookings(agency_id: str = "", user: dict = Depends(get_current_user)):
    """List bookings for an agency.

    NEGATIVE CONTROL: the agency filter is ENFORCED. A caller may only list
    their own agency's bookings (platform_admin may list any). Asking for
    another agency returns 403 — the agent must NOT flag this endpoint.
    """
    target = agency_id or user["agency_id"]
    if user["role"] != "platform_admin" and target != user["agency_id"]:
        raise HTTPException(
            status_code=403,
            detail="Cannot list another agency's bookings")
    return {"agency_id": target,
            "bookings": [b for b in store["bookings"].values()
                         if b["agency_id"] == target]}


@app.get("/bookings/{booking_id}")
def get_booking(booking_id: str, user: dict = Depends(get_current_user)):
    """Booking detail, including traveller PII.

    PLANTED FLAW #1 — IDOR: there is deliberately NO agency-ownership check
    here. Any logged-in user of ANY agency can read ANY booking.
    """
    booking = store["bookings"].get(booking_id)
    if booking is None:
        raise HTTPException(status_code=404, detail="Unknown booking")
    return booking


@app.post("/bookings/{booking_id}/pay")
def pay_booking(booking_id: str, body: dict,
                user: dict = Depends(get_current_user)):
    """Pay for a booking. (Stretch flaw: amount 0 is accepted — a skipped
    payment. The amount is taken as given, never checked against the total.)"""
    booking = store["bookings"].get(booking_id)
    if booking is None:
        raise HTTPException(status_code=404, detail="Unknown booking")
    if not _owns_booking(user, booking):
        raise HTTPException(status_code=403,
                            detail="Booking belongs to another agency")
    amount = int(body.get("amount", booking["total"]))
    booking["paid_amount"] = amount
    booking["status"] = "PAID"
    return {"booking_id": booking_id, "paid_amount": amount,
            "method": body.get("method", "card"), "status": "PAID"}


@app.post("/bookings/{booking_id}/cancel")
def cancel_booking(booking_id: str, body: dict,
                   user: dict = Depends(get_current_user)):
    """Cancel a booking and issue a refund of the full total.

    PLANTED FLAW #4 — double refund: the endpoint never checks whether a
    refund was already issued for this booking. Cancelling twice (for example
    after re-booking the same trip) pays the refund twice.
    """
    booking = store["bookings"].get(booking_id)
    if booking is None:
        raise HTTPException(status_code=404, detail="Unknown booking")
    if not _owns_booking(user, booking):
        raise HTTPException(status_code=403,
                            detail="Booking belongs to another agency")
    store["next_refund"] += 1
    refund = {"refund_id": f"RFD-{store['next_refund']}",
              "amount": booking["total"],
              "reason": body.get("reason", "cancelled"),
              "issued_at": datetime.now(timezone.utc).isoformat()}
    booking["refunds"].append(refund)
    booking["status"] = "CANCELLED"
    return {"booking_id": booking_id, "status": "CANCELLED", "refund": refund,
            "refunds_issued": len(booking["refunds"])}


# ---------------------------------------------------------------------------
# Coupons
# ---------------------------------------------------------------------------

@app.post("/coupons/apply")
def apply_coupon(body: dict, user: dict = Depends(get_current_user)):
    """Apply a coupon to a booking.

    PLANTED FLAW #3 — coupon reuse: single-use coupons are never marked used,
    so the same code can be applied again and again (and to many bookings).
    PLANTED FLAW #9 — no rate limiting on this endpoint either.
    """
    coupon = store["coupons"].get(body.get("code", ""))
    if coupon is None:
        raise HTTPException(status_code=404, detail="Unknown coupon")
    if coupon["status"] == "expired":
        raise HTTPException(status_code=400, detail="Coupon expired")
    booking = store["bookings"].get(body.get("booking_id", ""))
    if booking is None:
        raise HTTPException(status_code=404, detail="Unknown booking")
    if not _owns_booking(user, booking):
        raise HTTPException(status_code=403,
                            detail="Booking belongs to another agency")
    discount = booking["total"] * coupon["discount_pct"] // 100
    booking["total"] -= discount
    booking["coupons_applied"].append(coupon["code"])
    return {"booking_id": booking["id"], "code": coupon["code"],
            "discount_pct": coupon["discount_pct"],
            "discount_amount": discount, "new_total": booking["total"],
            "times_applied": booking["coupons_applied"].count(coupon["code"])}


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

@app.post("/admin/users/{username}/role")
def change_role(username: str, body: dict,
                user: dict = Depends(get_current_user)):
    """Change a user's role.

    PLANTED FLAW #5 — privilege escalation: there is deliberately NO role
    check on this endpoint. Any authenticated user — even a sub-agent — can
    promote themselves (or anyone) to agency_admin.
    """
    target = store["users"].get(username)
    if target is None:
        raise HTTPException(status_code=404, detail="Unknown user")
    new_role = body.get("role", "")
    if new_role not in ("sub_agent", "finance", "agency_admin",
                        "platform_admin"):
        raise HTTPException(status_code=400, detail="Unknown role")
    target["role"] = new_role
    return {"username": username, "role": new_role,
            "changed_by": user["username"]}


# ---------------------------------------------------------------------------
# Zombie and shadow APIs
# ---------------------------------------------------------------------------

@app.get("/v1/bookings/{booking_id}")
def legacy_get_booking(booking_id: str):
    """Legacy v1 booking lookup.

    PLANTED FLAW #6 — zombie API: this old endpoint is still live, needs NO
    authentication at all, and returns the full booking including traveller
    PII. It has had zero legitimate traffic in 30 days (see gateway.log) but
    was never decommissioned.
    """
    booking = store["bookings"].get(booking_id)
    if booking is None:
        raise HTTPException(status_code=404, detail="Unknown booking")
    return booking


@app.post("/internal/supplier-sync")
def supplier_sync(body: dict, user: dict = Depends(get_current_user)):
    """Supplier inventory sync.

    PLANTED FLAW #7 — shadow API: undocumented, not in any route list, and it
    performs no authorisation beyond "has a valid token". The portal calls it
    (URL assembled at runtime in app.js), and it appears ~400 times in the
    gateway log — but it was never mapped in any API inventory.
    """
    items = body.get("inventory", [])
    return {"status": "synced",
            "supplier": body.get("supplier", "unknown"),
            "items_updated": len(items) if isinstance(items, list) else 0,
            "synced_by": user["username"]}


# ---------------------------------------------------------------------------
# v2.4.0 — only live after POST /demo/deploy {"version": "v2.4.0"}
# ---------------------------------------------------------------------------

@app.post("/v2/bookings/{booking_id}/fare-modify")
def fare_modify(booking_id: str, body: dict,
                user: dict = Depends(get_current_user)):
    """Change a booking's fare after payment (added in release v2.4.0).

    PLANTED FLAW #10 — fresh IDOR: no agency-ownership check, so any agency's
    agent can rewrite another agency's booking fare. Until v2.4.0 is deployed
    this endpoint behaves as if it does not exist (404).
    """
    if not release_state["v240_deployed"]:
        raise HTTPException(status_code=404, detail="Not found")
    booking = store["bookings"].get(booking_id)
    if booking is None:
        raise HTTPException(status_code=404, detail="Unknown booking")
    new_fare = int(body.get("new_fare", booking["fare"]))
    booking["fare"] = new_fare
    booking["total"] = new_fare
    return booking


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

load_seed()
print(f"AstraTravel demo ready — {len(store['bookings'])} bookings, "
      f"{len(store['users'])} users, version "
      f"{release_state['current_version']} (v2.4.0 NOT deployed)", flush=True)
