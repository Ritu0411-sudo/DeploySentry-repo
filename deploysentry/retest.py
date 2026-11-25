"""Retest Agent — reruns a proof after a fix and closes the finding.

The demo has no "fix this flaw" endpoint, so the fix we can demonstrate
honestly is the platform's own rollback: POST /demo/reset restores the
seed data and rolls the platform back to v2.3.0, which removes the
v2.4.0 endpoint entirely. The retest then proves the fresh IDOR no longer
reproduces (404) and closes that finding as fixed-by-rollback. It also
re-checks a negative control, to prove the rollback did not break correct
behaviour.

A finding is only marked "closed" when the proof stops reproducing.
"""

from client import AgentClient


def retest_agent(client: AgentClient, session: dict, audit,
                 findings: list) -> list:
    """Roll back, re-run the proofs, update finding statuses in place."""
    outcomes = []
    admin = client.login("platform_admin")
    status, _ = client.post("/demo/reset", {},
                            token=admin, account="platform_admin",
                            note="retest: roll back to v2.3.0")
    if status != 200:
        outcomes.append({"finding": "fare-modify-idor",
                         "result": "retest-error",
                         "detail": f"Reset failed ({status}); could not "
                                   f"retest."})
        return outcomes

    # 1. The fresh IDOR must be gone: the endpoint no longer exists.
    bid = session["globe_booking_id"]
    status, _ = client.post(
        f"/v2/bookings/{bid}/fare-modify", {"new_fare": 5},
        token=client.login("sky_agent1"), account="sky_agent1",
        note="retest: fare-modify after rollback")
    if status == 404:
        outcomes.append({
            "finding": "fare-modify-idor", "result": "closed",
            "detail": "After rollback to v2.3.0 the endpoint returns 404 — "
                      "the flaw no longer reproduces. Finding closed."})
        for f in findings:
            if f["test_id"] == "fare-modify-idor":
                f["status"] = "closed — fixed by rollback (retest passed)"
    else:
        outcomes.append({
            "finding": "fare-modify-idor", "result": "still-open",
            "detail": f"Endpoint still answers ({status}) after rollback — "
                      f"finding stays open."})

    # 2. The negative control must still hold after the rollback.
    status, _ = client.get(
        "/bookings?agency_id=ag_globetrek",
        token=client.login("sky_agent1"), account="sky_agent1",
        note="retest: control re-check after rollback")
    outcomes.append({
        "finding": "control-list-filter",
        "result": "still-enforced" if status == 403 else "REGRESSION",
        "detail": f"List filter after rollback: {status} "
                  f"(expected 403)"})
    audit.event("retest-complete", "retest",
                outcomes=[(o["finding"], o["result"]) for o in outcomes])
    return outcomes
