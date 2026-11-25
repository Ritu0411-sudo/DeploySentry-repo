"""Verifier — confirms each hit with a minimal, clean proof.

A candidate from an executor is only a *claim*. The verifier re-runs the
proof in the smallest possible way — a second account, a re-read of the
same record, a wrong-secret control — and only then does the candidate
become a finding. A candidate that does not reproduce is dropped and
counted as a filtered false positive. That is the precision story:
findings the agent stands behind, not raw scanner output.

Verification never does bulk reads: at most one extra record per check.
Where a test mutated state, the verifier also cleans up (the privilege
escalation test restores the victim's role).
"""

from client import decode_claims
from executors import _forge_token


def _read_booking(client, account, token, booking_id):
    status, data = client.get(f"/bookings/{booking_id}", token=token,
                              account=account, note="verify: re-read booking")
    return status, data


def verify(candidate, client, session) -> dict | None:
    """Re-run the minimal proof for one candidate.

    Returns the verified finding dict (candidate + "verified_by" + "status")
    or None when the proof does not reproduce.
    """
    test_id = candidate["test_id"]
    raw = candidate.get("raw", {})
    sky = client.login("sky_agent1")
    check = _VERIFIERS.get(test_id)
    if check is None:
        return None
    ok, proof = check(candidate, client, session, sky)
    if not ok:
        return None
    finding = dict(candidate)
    finding["status"] = "verified"
    finding["verified_by"] = proof
    return finding


def _v_idor_read(cand, client, session, sky):
    # Second cross-agency pair, different booking: systematic, not a fluke.
    bid = session["globe_booking_id_2"]
    status, data = client.get(f"/bookings/{bid}",
                              token=client.login("sky_agent2"),
                              account="sky_agent2",
                              note="verify: 2nd cross-agency pair")
    ok = status == 200 and data.get("agency_id") == "ag_globetrek"
    return ok, ("sky_agent2 read a second GlobeTrek booking "
                f"({bid}) -> {status}; agency_id in response "
                f"= {data.get('agency_id')}" if ok else "did not reproduce")


def _v_fare_tampering(cand, client, session, sky):
    # Re-read the booking from the server: the Rs. 1 total must be stored.
    status, data = _read_booking(client, "sky_agent1", sky,
                                 cand["raw"]["booking_id"])
    ok = status == 200 and data.get("total") == 1
    return ok, (f"Re-read {cand['raw']['booking_id']}: total=1 stored "
                f"server-side" if ok else "did not reproduce")


def _v_coupon_reuse(cand, client, session, sky):
    status, data = _read_booking(client, "sky_agent1", sky,
                                 cand["raw"]["booking_id"])
    count = data.get("coupons_applied", []).count("FLY10") if status == 200 \
        else 0
    return count == 2, (f"Booking record shows FLY10 applied {count}x"
                        if count == 2 else "did not reproduce")


def _v_double_refund(cand, client, session, sky):
    status, data = _read_booking(client, "sky_agent1", sky,
                                 cand["raw"]["booking_id"])
    refunds = data.get("refunds", []) if status == 200 else []
    return len(refunds) == 2, (f"Booking record shows {len(refunds)} "
                               f"refunds of Rs. {refunds[0]['amount']} each"
                               if len(refunds) == 2 else "did not reproduce")


def _v_privilege_escalation(cand, client, session, sky):
    # Fresh login as the promoted user: the new token must carry the new role.
    token = client.login("sky_agent2", force=True)
    claims = decode_claims(token)
    ok = claims.get("role") == "agency_admin"
    # Clean up: restore the victim's role via the platform admin.
    admin = client.login("platform_admin")
    client.post("/admin/users/sky_agent2/role", {"role": "sub_agent"},
                token=admin, account="platform_admin",
                note="cleanup: restore sky_agent2 to sub_agent")
    client.login("sky_agent2", force=True)  # drop the escalated token
    return ok, ("Fresh login as sky_agent2: token claims role="
                f"{claims.get('role')}; role restored to sub_agent"
                if ok else "did not reproduce")


def _v_zombie_unauth(cand, client, session, sky):
    # Second booking, still no token.
    bid = session["globe_booking_id_2"]
    status, data = client.get(f"/v1/bookings/{bid}", account="anonymous",
                              note="verify: 2nd booking, no token")
    ok = status == 200 and bool(data.get("travellers"))
    return ok, (f"GET /v1/bookings/{bid} with no token -> {status}, PII "
                f"returned" if ok else "did not reproduce")


def _v_shadow_undocumented(cand, client, session, sky):
    status, data = client.post(
        "/internal/supplier-sync",
        {"supplier": "amadeus", "inventory": ["AI-302"]},
        token=sky, account="sky_agent1", note="verify: repeat shadow call")
    ok = status == 200 and data.get("status") == "synced"
    return ok, ("Repeat call -> 200 synced; route is live and "
                "undocumented" if ok else "did not reproduce")


def _v_forged_jwt(cand, client, session, sky):
    # Control: a token signed with a WRONG secret must fail (401) — this
    # proves the acceptance is about the secret, not a missing check.
    bid = session["globe_booking_id"]
    bad = _forge_token("definitely-wrong-secret")
    s_bad, _ = client.get(f"/bookings/{bid}", token=bad,
                          account="forged-token",
                          note="verify: wrong-secret control")
    good = _forge_token(cand["raw"]["secret"])
    s_good, _ = client.get(f"/bookings/{bid}", token=good,
                           account="forged-token",
                           note="verify: repeat forged token")
    ok = s_bad == 401 and s_good == 200
    return ok, (f"Wrong-secret token -> {s_bad} (expected 401); forged "
                f"token with {cand['raw']['secret']!r} -> {s_good} "
                f"(expected 200)" if ok else "did not reproduce")


def _v_no_rate_limit(cand, client, session, sky):
    # Self-verifying: the recorded burst already is the proof.
    codes = cand["raw"]["statuses"]
    ok = 429 not in codes and all(c == 401 for c in codes)
    return ok, (f"Recorded burst: {len(codes)} attempts, "
                f"statuses {sorted(set(codes))}, no 429"
                if ok else "did not reproduce")


def _v_pay_zero(cand, client, session, sky):
    status, data = _read_booking(client, "sky_agent1", sky,
                                 cand["raw"]["booking_id"])
    ok = status == 200 and data.get("status") == "PAID" \
        and data.get("paid_amount") == 0
    return ok, (f"Re-read {cand['raw']['booking_id']}: status=PAID, "
                f"paid_amount=0" if ok else "did not reproduce")


def _v_fare_modify_idor(cand, client, session, sky):
    status, data = _read_booking(client, "sky_agent1", sky,
                                 cand["raw"]["booking_id"])
    ok = status == 200 and data.get("fare") == 5
    return ok, (f"Re-read {cand['raw']['booking_id']}: fare=5 stored "
                f"server-side" if ok else "did not reproduce")


_VERIFIERS = {
    "idor-read": _v_idor_read,
    "fare-tampering": _v_fare_tampering,
    "coupon-reuse": _v_coupon_reuse,
    "double-refund": _v_double_refund,
    "privilege-escalation": _v_privilege_escalation,
    "zombie-unauth": _v_zombie_unauth,
    "shadow-undocumented": _v_shadow_undocumented,
    "forged-jwt": _v_forged_jwt,
    "no-rate-limit": _v_no_rate_limit,
    "pay-zero": _v_pay_zero,
    "fare-modify-idor": _v_fare_modify_idor,
}
