"""Change Watcher — notices when the platform changes.

In a real deployment this agent would watch CI/CD deploy webhooks, gateway
traffic and front-end bundle diffs. The demo platform exposes the same
signals through two endpoints, so the watcher polls those instead:
  * GET /demo/releases — the deploy feed (CI/CD-style): current version plus
    each release's notes and changed endpoints.
  * GET /health        — returns the currently deployed version.

The watcher keeps a snapshot (version + known endpoints) and reports a
change event whenever the version moves or a new endpoint appears.
"""

import time


class ChangeWatcher:
    """Polls the deploy feed and diffs the API snapshot."""

    def __init__(self, client, poll_interval: float = 2.0):
        self.client = client
        self.poll_interval = poll_interval
        self.snapshot = None  # {"version": str, "releases": [...]}
        self.events = []      # change events, in order

    def snapshot_now(self) -> dict:
        """Read the current deploy state. Returns a snapshot dict."""
        status, releases = self.client.get(
            "/demo/releases", account="watcher", note="poll deploy feed")
        if status != 200:
            raise RuntimeError(f"deploy feed unreadable: {status} {releases}")
        status, health = self.client.get("/health", account="watcher",
                                         note="poll health/version")
        snap = {
            "version": releases.get("current_version"),
            "health_version": health.get("version") if isinstance(health, dict)
                              else None,
            "releases": releases.get("releases", []),
        }
        return snap

    def take_baseline(self) -> dict:
        """Take the baseline snapshot the run starts from."""
        self.snapshot = self.snapshot_now()
        return self.snapshot

    def diff(self, new_snapshot: dict) -> list:
        """Compare a new snapshot with the baseline. Returns change events.

        A change event names the release and every endpoint it added.
        """
        events = []
        old_version = (self.snapshot or {}).get("version")
        new_version = new_snapshot.get("version")
        if old_version and new_version and new_version != old_version:
            changed = []
            for rel in new_snapshot.get("releases", []):
                if rel.get("version") == new_version:
                    changed = rel.get("changed_endpoints", [])
                    notes = rel.get("notes", "")
            events.append({
                "type": "version-change",
                "from": old_version,
                "to": new_version,
                "changed_endpoints": changed,
                "notes": notes,
            })
        return events

    def wait_for_version(self, target: str, timeout: float = 60.0):
        """Poll until the deployed version becomes `target`.

        Returns (found, seconds_waited). This is how time-to-detect is
        measured: the clock starts when the deploy is triggered.
        """
        started = time.monotonic()
        while time.monotonic() - started < timeout:
            snap = self.snapshot_now()
            if snap.get("version") == target:
                return True, time.monotonic() - started, snap
            time.sleep(self.poll_interval)
        return False, time.monotonic() - started, snap
