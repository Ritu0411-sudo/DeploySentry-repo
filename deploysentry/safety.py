"""Safety layer for DeploySentry.

This module is the part of the agent the judges should read first: it is what
keeps an autonomous security agent inside its rules of engagement.

Rules enforced here (from the TBO problem statement — breaking them
disqualifies a submission):
  * Scope allowlist — the agent may only talk to the demo platform origin.
    Any other URL is refused before a request is sent.
  * Test accounts only — credentials come from a small vault of the demo
    test accounts (spec: DEMO_PLATFORM_SPEC.md). No other identity is used.
  * Rate limiting — at most 5 requests/second, with back-off when the target
    answers 429 or its health check slows down.
  * Audit log — EVERY request (and every approval decision) is written to a
    JSONL audit log so reviewers can replay exactly what the agent did.
  * Human approval — tests that mutate state in a risky way (privilege
    escalation, fare tampering) need a human's go-ahead. By default the agent
    SKIPS them; the demo run passes --auto-approve, which records the
    approval in the audit log instead of pretending it did not happen.

Nothing in this module touches the network. The HTTP client in client.py
calls into it.
"""

import json
import time
from pathlib import Path

# --- Scope allowlist -------------------------------------------------------
# The demo platform is the ONLY allowed target. Add an origin here only when
# the test scope officially changes.
ALLOWED_ORIGINS = {
    "http://127.0.0.1:8000",
    "http://localhost:8000",
}

# --- Rate limit ------------------------------------------------------------
MAX_REQUESTS_PER_SECOND = 5          # the safety contract in the spec
MIN_INTERVAL_SECONDS = 1.0 / MAX_REQUESTS_PER_SECOND
HEALTHY_LATENCY_MS = 1000            # slower than this -> back off
BACKOFF_SECONDS = 2.0

# --- Test accounts (the "credential vault") --------------------------------
# Demo-only accounts from DEMO_PLATFORM_SPEC.md. Every account uses the same
# demo password; in a real deployment these would come from a secrets vault.
DEMO_PASSWORD = "Test@1234"

TEST_ACCOUNTS = {
    # username -> (agency_id, role)
    "sky_admin": ("ag_skyways", "agency_admin"),
    "sky_agent1": ("ag_skyways", "sub_agent"),
    "sky_agent2": ("ag_skyways", "sub_agent"),
    "sky_fin": ("ag_skyways", "finance"),
    "globe_admin": ("ag_globetrek", "agency_admin"),
    "globe_agent1": ("ag_globetrek", "sub_agent"),
    "globe_fin": ("ag_globetrek", "finance"),
    "platform_admin": (None, "platform_admin"),
}

# Tests that mutate state in a risky way. They need a human approval before
# they run (see ApprovalGate below).
RISKY_TESTS = {
    "fare-tampering",       # creates a booking for Rs. 1 (mutates money state)
    "privilege-escalation",  # promotes a user to agency_admin (mutates access)
}


class ScopeError(Exception):
    """Raised when the agent tries to leave its approved scope."""


def check_scope(url: str) -> None:
    """Refuse any URL outside the allowlist, before a request is sent."""
    for origin in ALLOWED_ORIGINS:
        if url.startswith(origin):
            return
    raise ScopeError(
        f"OUT OF SCOPE — refusing to contact {url!r}. "
        f"Allowed origins: {sorted(ALLOWED_ORIGINS)}")


class AuditLog:
    """Append-only JSONL log of everything the agent does.

    Two kinds of lines:
      {"type": "request", ...}  one per HTTP request the agent sends
      {"type": "event", ...}    decisions: approvals, detections, phase marks
    Reviewers can replay the whole run from this file alone.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self.path.open("a", encoding="utf-8")

    def _write(self, record: dict) -> None:
        record.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%S"))
        self._file.write(json.dumps(record) + "\n")
        self._file.flush()

    def request(self, method: str, path: str, account: str, status: int,
                ms: int, component: str, note: str = "") -> None:
        self._write({
            "type": "request", "method": method, "path": path,
            "account": account, "status": status, "ms": ms,
            "component": component, "note": note,
        })

    def event(self, event: str, component: str, **fields) -> None:
        record = {"type": "event", "event": event, "component": component}
        record.update(fields)
        self._write(record)

    def close(self) -> None:
        self._file.close()


class ApprovalGate:
    """Human-approval gate for risky tests.

    Default: risky tests are SKIPPED and reported as 'awaiting approval'.
    Demo runs pass --auto-approve, which runs them but records the approval
    (who, what, when) in the audit log — the approval is explicit, never
    silent.
    """

    def __init__(self, audit: AuditLog, auto_approve: bool = False,
                 approver: str = "demo-runner"):
        self.audit = audit
        self.auto_approve = auto_approve
        self.approver = approver
        self.decisions = {}  # test_id -> "approved" | "skipped"

    def check(self, test_id: str, description: str) -> bool:
        """Return True if the test may run. Log the decision either way."""
        if test_id not in RISKY_TESTS:
            return True
        if self.auto_approve:
            self.decisions[test_id] = "approved"
            self.audit.event("approval-granted", "safety",
                             test=test_id, description=description,
                             approver=self.approver,
                             note="--auto-approve flag: approval recorded "
                                  "for the demo run")
            return True
        self.decisions[test_id] = "skipped"
        self.audit.event("approval-required-skipped", "safety",
                         test=test_id, description=description,
                         note="Risky test skipped: needs a human approval. "
                              "Re-run with --auto-approve to run it.")
        return False


class HealthMonitor:
    """Watches the target's health and backs off if it shows strain.

    The safety contract says: back off if the application shows strain.
    We treat a slow /health response (>1s) or a non-200 as strain.
    """

    def __init__(self, audit: AuditLog):
        self.audit = audit
        self.strain_events = 0

    def check(self, latency_ms: int, status: int, component: str) -> None:
        if status != 200 or latency_ms > HEALTHY_LATENCY_MS:
            self.strain_events += 1
            self.audit.event("health-strain", "safety",
                             latency_ms=latency_ms, status=status,
                             component=component,
                             note=f"Backing off {BACKOFF_SECONDS}s")
            time.sleep(BACKOFF_SECONDS)
