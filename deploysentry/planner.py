"""Attack Planner — picks targeted tests per endpoint.

The planner reasons over the knowledge graph (parameters, roles, business
purpose) and chooses the tests that make sense for each endpoint — it never
sprays every payload at every endpoint. Each test names its executor, its
vulnerability class, and whether it is risky (needs a human approval).

Two entries are *controls*, not attacks: they check behaviour that must be
CORRECT (the agency filter on the list endpoint, and search requiring a
login). A good agent proves the safe behaviour too — that is how precision
is measured, not just recall.
"""

# Test definitions. "executor" names the function in executors.py.
# "risky" tests need a human approval (see safety.ApprovalGate).
TEST_RULES = [
    # -- access control -------------------------------------------------
    {"id": "idor-read", "title": "Cross-agency booking read (IDOR)",
     "class": "access-control", "endpoint": "GET /bookings/{id}",
     "risky": False, "executor": "idor_read",
     "why": "Booking detail returns traveller PII; the endpoint takes an "
            "id in the path, so test whether another agency's id is served."},
    {"id": "privilege-escalation",
     "title": "Sub-agent promotes self to agency_admin",
     "class": "access-control", "endpoint": "POST /admin/users/{id}/role",
     "risky": True, "executor": "privilege_escalation",
     "why": "Role changes are the highest-privilege action in the system; "
            "test whether the endpoint checks the caller's role."},
    {"id": "fare-modify-idor",
     "title": "Cross-agency fare rewrite (fresh IDOR, v2.4.0)",
     "class": "access-control",
     "endpoint": "POST /v2/bookings/{id}/fare-modify",
     "risky": False, "executor": "fare_modify_idor",
     "why": "New endpoint from the v2.4.0 deploy; a fare change after "
            "payment touches money, so test the ownership check first."},
    # -- business logic ---------------------------------------------------
    {"id": "fare-tampering", "title": "Book at Rs. 1 (fare tampering)",
     "class": "business-logic", "endpoint": "POST /bookings",
     "risky": True, "executor": "fare_tampering",
     "why": "The booking call accepts a client-supplied total; test "
            "whether the server recomputes the price or trusts the client."},
    {"id": "coupon-reuse", "title": "Single-use coupon applied twice",
     "class": "business-logic", "endpoint": "POST /coupons/apply",
     "risky": False, "executor": "coupon_reuse",
     "why": "Single-use coupons must be marked used; test whether the "
            "same code applies again to the same booking."},
    {"id": "double-refund", "title": "Cancel twice, refunded twice",
     "class": "business-logic", "endpoint": "POST /bookings/{id}/cancel",
     "risky": False, "executor": "double_refund",
     "why": "A refund must be issued at most once per booking; test "
            "whether a second cancel pays again."},
    {"id": "pay-zero", "title": "Pay Rs. 0 marks booking PAID (bonus)",
     "class": "business-logic", "endpoint": "POST /bookings/{id}/pay",
     "risky": False, "executor": "pay_zero",
     "why": "Payment must check the amount against the total; test "
            "whether zero is accepted. Bonus finding (stretch flaw)."},
    # -- zombie / shadow (findings from discovery + inventory) ----------
    {"id": "zombie-unauth", "title": "Zombie API serves PII without auth",
     "class": "zombie-api", "endpoint": "GET /v1/bookings/{id}",
     "risky": False, "executor": "zombie_unauth",
     "why": "The v1 endpoint is live but had zero traffic in 30 days; "
            "test whether it answers without any token."},
    {"id": "shadow-undocumented",
     "title": "Shadow API accepts calls with no authorisation check",
     "class": "shadow-api", "endpoint": "POST /internal/supplier-sync",
     "risky": False, "executor": "shadow_undocumented",
     "why": "The route is in traffic but undocumented; test what it "
            "accepts from an ordinary sub-agent token."},
    # -- auth -------------------------------------------------------------
    {"id": "forged-jwt", "title": "Forged JWT accepted (weak secret)",
     "class": "auth", "endpoint": "GET /bookings/{id}",
     "risky": False, "executor": "forged_jwt",
     "why": "Tokens are HS256; test whether the signing secret is a "
            "guessable word from a small weak-secret list."},
    # -- API hygiene --------------------------------------------------------
    {"id": "no-rate-limit", "title": "No rate limiting on login",
     "class": "api-hygiene", "endpoint": "POST /auth/login",
     "risky": False, "executor": "no_rate_limit",
     "why": "Login takes a password with no throttling; send a small "
            "burst of bad logins and watch for a 429."},
    # -- controls (correct behaviour — must NOT become findings) ---------
    {"id": "control-list-filter",
     "title": "Control: list enforces the agency filter",
     "class": "control", "endpoint": "GET /bookings",
     "risky": False, "executor": "control_list_filter",
     "why": "Control — listing another agency's bookings must return 403."},
    {"id": "control-search-auth",
     "title": "Control: search needs a login",
     "class": "control", "endpoint": "GET /search/flights",
     "risky": False, "executor": "control_search_auth",
     "why": "Control — search must work logged in (200) and fail "
            "anonymously (401)."},
]


def build_plan(graph: dict) -> list:
    """Build the test plan from the knowledge graph.

    Only tests whose endpoint is actually in the discovered map are
    included — the planner tests what exists, and the v2.4.0 endpoint is
    added to the plan only after the change event brings it into the map.
    """
    known = {(e["method"], e["path"]) for e in graph["endpoints"]}
    plan = []
    for rule in TEST_RULES:
        method, path = rule["endpoint"].split(" ", 1)
        if rule["class"] == "auth":
            # The forged-JWT test rides on an existing endpoint.
            plan.append(dict(rule))
        elif (method, path) in known:
            plan.append(dict(rule))
    return plan
