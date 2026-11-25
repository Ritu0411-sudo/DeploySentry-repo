"""Triage — dedup, score severity in business context, assign owners.

Severity here is judged by what the endpoint means for the business
(bookings, payments, PII, supplier access) — not by a generic scanner
score. That is what the TBO problem statement asks for: a fare-tampering
flaw is Critical because it is direct revenue loss, while a missing rate
limit on login is Low because it needs a further attack to matter.

Owners come from the inventory's route families (API team, Payments team,
Pricing team, IAM team, Platform team).
"""

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# test_id -> (severity, business impact, suggested fix, owner)
TRIAGE_TABLE = {
    "idor-read": (
        "High",
        "Any agency's agent can read any other agency's bookings, "
        "including traveller names and passport numbers. Cross-agency "
        "data exposure; a trust and compliance failure for a B2B platform.",
        "Enforce the agency-ownership check on GET /bookings/{id} "
        "(same check the list endpoint already has).",
        "API team"),
    "fare-tampering": (
        "Critical",
        "Direct revenue loss: any agent can book any flight for Rs. 1 by "
        "sending a client-supplied total. The fare is money — trusting the "
        "client is trusting the attacker.",
        "Recompute fare and total server-side from the hold and fare "
        "rules; ignore client-supplied totals.",
        "Payments team"),
    "coupon-reuse": (
        "Medium",
        "Revenue leakage: single-use coupons can be applied repeatedly to "
        "the same booking, stacking discounts the pricing team never "
        "approved.",
        "Mark a single-use coupon used after its first successful "
        "application; enforce it in the database, not in the UI.",
        "Pricing team"),
    "double-refund": (
        "High",
        "Direct revenue loss: cancelling the same booking twice pays the "
        "refund twice. A cancel-rebook loop can drain money on every trip.",
        "Make refunds idempotent — one refund per booking — and record "
        "the refund before returning success.",
        "Payments team"),
    "privilege-escalation": (
        "Critical",
        "Full agency takeover: any sub-agent can promote herself to "
        "agency_admin and then change other users, bookings and refunds. "
        "One request breaks the whole role model.",
        "Require platform_admin (or the agency's own admin) on the role "
        "endpoint, and audit every role change.",
        "IAM team"),
    "zombie-unauth": (
        "High",
        "An old, forgotten endpoint still serves full booking PII with no "
        "authentication at all. Anyone on the internet can read traveller "
        "data; it has had zero legitimate traffic in 30 days.",
        "Decommission GET /v1/bookings/{id} immediately; remove the route "
        "and confirm no client still calls it.",
        "API team"),
    "shadow-undocumented": (
        "Medium",
        "An undocumented route is live and does no authorisation beyond "
        "'has a token'. It is in real traffic, so it is load-bearing — "
        "but nobody owns it, and nobody reviewed it.",
        "Document the route, restrict it to service accounts, and add it "
        "to the API inventory with an owner.",
        "Platform team"),
    "forged-jwt": (
        "High",
        "The JWT signing secret is a guessable word ('travel123'). Anyone "
        "who guesses it can mint a token for any user, including "
        "platform_admin — full authentication bypass, no password needed.",
        "Rotate the secret to a long random value from the vault, and "
        "invalidate all tokens issued under the old secret.",
        "IAM team"),
    "no-rate-limit": (
        "Low",
        "Login accepts unlimited attempts with no throttling or lockout, "
        "so passwords can be guessed at full speed. Low on its own — it "
        "needs a further attack to matter — but it must be fixed.",
        "Rate-limit login (and coupon) attempts per account and IP, and "
        "add a short lockout after repeated failures.",
        "API team"),
    "pay-zero": (
        "High",
        "Skipped payment: paying Rs. 0 marks a booking PAID. The payment "
        "step can be walked past, so bookings can be confirmed without "
        "any money moving.",
        "Validate the paid amount against the booking total server-side; "
        "reject zero and under-payments.",
        "Payments team"),
    "fare-modify-idor": (
        "High",
        "A brand-new endpoint shipped with no agency-ownership check: any "
        "agency can rewrite another agency's booking fare after payment. "
        "This is the change the agent caught within minutes of the deploy.",
        "Add the same agency-ownership check as the other booking "
        "endpoints, and add the endpoint to the API inventory.",
        "API team"),
}


def triage(verified: list) -> list:
    """Dedup, score and assign owners. Returns findings sorted by severity.

    Dedup key is (endpoint, class): the same flaw found twice is one
    finding, with the extra evidence merged in.
    """
    by_key = {}
    for finding in verified:
        key = (finding["endpoint"], finding["class"])
        if key in by_key:
            by_key[key]["evidence"].extend(finding["evidence"])
            continue
        severity, impact, fix, owner = TRIAGE_TABLE[finding["test_id"]]
        by_key[key] = {
            "title": finding["title"],
            "test_id": finding["test_id"],
            "class": finding["class"],
            "endpoint": finding["endpoint"],
            "severity": severity,
            "impact": impact,
            "fix": fix,
            "owner": owner,
            "evidence": list(finding["evidence"]),
            "verified_by": finding.get("verified_by", ""),
            "status": finding.get("status", "verified"),
        }
    findings = sorted(by_key.values(),
                      key=lambda f: (SEVERITY_ORDER[f["severity"]],
                                     f["title"]))
    for i, finding in enumerate(findings, start=1):
        finding["id"] = f"DS-{i:03d}"
    return findings
