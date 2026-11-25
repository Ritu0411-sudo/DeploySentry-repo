"""Audited, rate-limited HTTP client for DeploySentry.

Every request the agent sends goes through this one class, so the safety
rules (scope allowlist, 5 req/sec, audit log, back-off on 429) cannot be
bypassed by accident. Only the Python standard library is used — no install
step for the judges.

Usage:
    client = AgentClient("http://127.0.0.1:8000", audit, component="discovery")
    token = client.login("sky_agent1")          # test account from the vault
    status, data = client.get("/bookings/AST-1001", token=token,
                              account="sky_agent1")
"""

import base64
import json
import time
import urllib.error
import urllib.request

from safety import (BACKOFF_SECONDS, MIN_INTERVAL_SECONDS, check_scope,
                    DEMO_PASSWORD, ScopeError)

# One shared throttle clock: the 5 req/sec limit applies to the whole agent,
# not per component.
_last_request_at = 0.0


def _throttle() -> None:
    """Wait until MIN_INTERVAL_SECONDS have passed since the last request."""
    global _last_request_at
    wait = MIN_INTERVAL_SECONDS - (time.monotonic() - _last_request_at)
    if wait > 0:
        time.sleep(wait)
    _last_request_at = time.monotonic()


def decode_claims(token: str) -> dict:
    """Read the payload of a JWT without verifying it.

    Used only to read back the role/agency of tokens the agent itself just
    received (e.g. to confirm a privilege-escalation test worked). This does
    NOT verify a signature — that is the point of the forged-token test.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)  # restore base64 padding
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


class AgentClient:
    """A single audited HTTP client for one agent component."""

    def __init__(self, base_url: str, audit, component: str = "agent"):
        self.base_url = base_url.rstrip("/")
        self.audit = audit
        self.component = component
        self._tokens = {}  # username -> token

    # -- low-level ------------------------------------------------------
    def request(self, method: str, path: str, token: str = None,
                body: dict = None, account: str = "anonymous",
                note: str = ""):
        """Send one request. Returns (status, parsed-json-or-text).

        Scope-checked, throttled, timed, and written to the audit log.
        A 429 response triggers a back-off and one retry.
        """
        url = self.base_url + path
        check_scope(url)  # raises ScopeError outside the allowlist
        _throttle()
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        started = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read().decode()
                status = resp.status
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            status = e.code
        except urllib.error.URLError as e:
            raise ConnectionError(f"cannot reach {url}: {e}") from e
        ms = int((time.monotonic() - started) * 1000)
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = raw
        self.audit.request(method, path, account, status, ms,
                           self.component, note)
        if status == 429:  # server asked us to slow down: obey, then retry
            self.audit.event("rate-limited-429", self.component,
                             path=path, note=f"Backing off {BACKOFF_SECONDS}s")
            time.sleep(BACKOFF_SECONDS)
            return self.request(method, path, token, body, account, note)
        return status, parsed

    def get(self, path, token=None, account="anonymous", note=""):
        return self.request("GET", path, token=token, account=account,
                            note=note)

    def post(self, path, body, token=None, account="anonymous", note=""):
        return self.request("POST", path, token=token, body=body,
                            account=account, note=note)

    # -- auth -----------------------------------------------------------
    def login(self, username: str, force: bool = False) -> str:
        """Log in with a test account from the vault; cache the token.

        force=True drops the cached token and logs in again — needed after
        a role change, when the old token still carries the old claims.
        """
        if username in self._tokens and not force:
            return self._tokens[username]
        status, data = self.post("/auth/login",
                                 {"username": username,
                                  "password": DEMO_PASSWORD},
                                 account=username, note="login")
        if status != 200:
            raise RuntimeError(f"login failed for {username}: {data}")
        self._tokens[username] = data["access_token"]
        return data["access_token"]

    def health(self):
        """GET /health without a token; returns (status, latency_ms)."""
        started = time.monotonic()
        try:
            status, _ = self.get("/health", account="health-check")
        except Exception:
            return 0, -1
        return status, int((time.monotonic() - started) * 1000)
