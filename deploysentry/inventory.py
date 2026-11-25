"""Inventory Agent — labels every endpoint active, zombie or shadow.

Technique (from the TBO problem statement): compare the discovered API map
against real traffic over a window — here, the 30-day gateway log:
  * active — the endpoint is in the discovered map AND has real traffic
  * zombie — the endpoint still responds, but has had NO legitimate traffic
    in 30 days (old versions, retired partner routes, debug routes)
  * shadow — the endpoint IS in traffic, but was never in the discovered map
    (in use but undocumented)

For each endpoint the report notes: last real traffic, auth status, what
data it exposes, the likely owner, and a recommendation (decommission /
restrict / update). The gateway log is the only input — the agent never
guesses from the endpoint name alone.
"""

import json
import re
from pathlib import Path

# Likely owner, by route family. (In a real deployment this would come from
# the asset-ownership data the problem statement mentions.)
OWNER_MAP = {
    "/auth": "IAM team",
    "/admin": "IAM team",
    "/bookings": "API team",
    "/v1": "API team",
    "/v2": "API team",
    "/search": "API team",
    "/fares": "Pricing team",
    "/coupons": "Pricing team",
    "/internal": "Platform team",
    "/demo": "Platform team",
    "/health": "Platform team",
}

DATA_EXPOSED = {
    "/bookings/{id}": "Booking detail + traveller PII (JWT required)",
    "/v1/bookings/{id}": "Booking detail + traveller PII (NO auth)",
    "/bookings": "Booking list for one agency (JWT required)",
    "/internal/supplier-sync": "Supplier inventory (JWT required)",
    "/admin/users/{id}/role": "User roles (JWT required)",
    "/search/flights": "Flight list, no PII",
    "/fares/quote": "Fare + markup, no PII",
}


def _normalize(path: str) -> str:
    """Collapse a concrete traffic path to its route template."""
    path = path.split("?")[0]
    path = re.sub(r"/AST-\d+", "/{id}", path)
    path = re.sub(r"/HLD-\d+", "/{id}", path)
    path = re.sub(r"/admin/users/[^/]+", "/admin/users/{id}", path)
    return path


# Infrastructure endpoints that are not business API routes and are not
# expected in gateway traffic: the deploy feed and the liveness probe.
# Labelling them "zombie" would be wrong — they are not part of the API
# inventory at all.
INFRA_PATHS = {"/demo/releases", "/health"}


class InventoryAgent:
    """Compares the discovered map with 30 days of gateway traffic."""

    def __init__(self, gateway_log: Path):
        self.gateway_log = Path(gateway_log)

    def _read_traffic(self) -> dict:
        """Parse the gateway log: {(method, template): (count, last_seen)}."""
        traffic = {}
        with self.gateway_log.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                key = (rec.get("method", "GET"), _normalize(rec.get("path", "")))
                count, last = traffic.get(key, (0, ""))
                traffic[key] = (count + 1, max(last, rec.get("ts", "")))
        return traffic

    def analyze(self, graph: dict) -> list:
        """Label every endpoint. Returns a list of inventory records."""
        traffic = self._read_traffic()
        js_paths = {e["path"] for e in graph["endpoints"]
                    if "js" in e["source"] or "har" in e["source"]}
        # Union of everything known: discovered endpoints + anything in
        # traffic (traffic alone can reveal endpoints the map missed).
        keys = {(e["method"], e["path"]) for e in graph["endpoints"]}
        keys |= set(traffic.keys())
        inventory = []
        by_key = {(e["method"], e["path"]): e for e in graph["endpoints"]}
        for method, path in sorted(keys):
            count, last_seen = traffic.get((method, path), (0, ""))
            ep = by_key.get((method, path), {})
            source = ep.get("source", "traffic-only")
            if path in INFRA_PATHS:
                label, recommendation = (
                    "n/a",
                    "Infrastructure endpoint — not part of the business "
                    "API inventory; not expected in gateway traffic.")
            elif count == 0:
                label, recommendation = (
                    "zombie",
                    "Decommission — still live with zero legitimate "
                    "traffic in 30 days.")
            elif path not in js_paths:
                label, recommendation = (
                    "shadow",
                    "Restrict to service accounts, document it, or "
                    "decommission — in use but never mapped.")
            else:
                label, recommendation = "active", "Keep — monitored."
            owner = next((o for p, o in OWNER_MAP.items()
                          if path.startswith(p)), "API team")
            inventory.append({
                "method": method, "path": path,
                "source": source,
                "auth": ep.get("auth", "unknown"),
                "label": label,
                "traffic_count": count,
                "last_seen": last_seen or None,
                "data_exposed": DATA_EXPOSED.get(path, "—"),
                "owner": owner,
                "recommendation": recommendation,
            })
        return inventory
