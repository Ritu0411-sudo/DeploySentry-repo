#!/usr/bin/env python3
"""DeploySentry — full agent loop runner (VoyageHack 4.0, Round 2).

Runs the whole loop end to end against the local AstraTravel demo platform:
  1. Reset the platform to a fresh seed (v2.3.0)
  2. Change Watcher takes the baseline snapshot
  3. Discovery Agent maps the API (portal JS + HAR + probing) and exports
     an inferred OpenAPI spec
  4. Inventory Agent labels every endpoint active / zombie / shadow from
     30 days of gateway traffic
  5. Attack Planner picks targeted tests; Specialist Executors run them;
     the Verifier confirms each hit; Triage scores and assigns owners
  6. LIVE CHANGE EVENT: deploy v2.4.0, watch the agent detect it, plan
     tests for the new endpoint, find the fresh IDOR and verify it —
     with measured timings
  7. Reporter writes findings.json, findings.md and dashboard.html
  8. Retest Agent rolls the platform back and proves the fresh flaw is
     gone, closing that finding

Usage:
    python3 run.py [--auto-approve] [--base-url URL] [--no-start]
                   [--no-retest]

    --auto-approve   Run the risky tests (fare tampering, privilege
                     escalation). Without it they are skipped and listed as
                     "awaiting human approval" — the approval is recorded
                     in the audit log either way.
    --no-start       Fail instead of starting the demo platform if it is
                     not already running on localhost:8000.
    --no-retest      Skip the retest phase.

Only the Python standard library is used. No network calls leave the
machine: the scope allowlist permits localhost:8000 only.
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DATA_DIR = ROOT / "data"
PLATFORM_DIR = ROOT / "platform"
REPORTS_DIR = HERE / "reports"

sys.path.insert(0, str(HERE))

from client import AgentClient  # noqa: E402
from discovery import DiscoveryAgent  # noqa: E402
from executors import EXECUTORS  # noqa: E402
from inventory import InventoryAgent  # noqa: E402
from planner import build_plan  # noqa: E402
from reporter import Reporter  # noqa: E402
from retest import retest_agent  # noqa: E402
from safety import ApprovalGate, AuditLog, HealthMonitor  # noqa: E402
from triage import triage  # noqa: E402
from verifier import verify  # noqa: E402
from watcher import ChangeWatcher  # noqa: E402

DEFAULT_BASE_URL = "http://127.0.0.1:8000"


def _raw_get(url: str, timeout: int = 3):
    """A plain GET with no audit/throttle — only for the health check."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def ensure_server(base_url: str, no_start: bool):
    """Make sure the demo platform is up; start it if needed.

    Returns the subprocess (or None if the server was already running).
    The server is left running afterwards so the team can show the portal.
    """
    status, _ = _raw_get(base_url + "/health")
    if status == 200:
        print("Platform already running on", base_url)
        return None
    if no_start:
        print("ERROR: no server on", base_url, "(--no-start given).")
        print("Start it with: cd ../platform && ./run.sh")
        sys.exit(1)
    print("No server running — starting the demo platform …")
    proc = subprocess.Popen(
        [str(PLATFORM_DIR / "venv" / "bin" / "uvicorn"), "app:app",
         "--host", "127.0.0.1", "--port", "8000"],
        cwd=str(PLATFORM_DIR), stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    deadline = time.time() + 20
    while time.time() < deadline:
        status, _ = _raw_get(base_url + "/health")
        if status == 200:
            print("Platform up on", base_url)
            return proc
        time.sleep(0.5)
    print("ERROR: the platform did not come up.")
    proc.terminate()
    sys.exit(1)


def build_session(client: AgentClient) -> dict:
    """Log in the test accounts and learn real booking ids from the API."""
    client.login("sky_agent1")
    client.login("sky_agent2")
    client.login("globe_agent1")
    client.login("platform_admin")
    _, globe = client.get("/bookings?agency_id=ag_globetrek",
                          token=client.login("globe_agent1"),
                          account="globe_agent1",
                          note="learn booking ids (own agency)")
    globe_ids = [b["id"] for b in globe.get("bookings", [])]
    _, sky = client.get("/bookings?agency_id=ag_skyways",
                        token=client.login("sky_agent1"),
                        account="sky_agent1",
                        note="learn booking ids (own agency)")
    sky_ids = [b["id"] for b in sky.get("bookings", [])]
    if len(globe_ids) < 2 or not sky_ids:
        raise RuntimeError("seed data missing — is the platform reset?")
    return {
        "globe_booking_id": globe_ids[0],
        "globe_booking_id_2": globe_ids[1],
        "sky_booking_id": sky_ids[0],
    }


def run_tests(client, gate, session, plan):
    """Run one test plan. Returns (candidates, controls, skipped, clean)."""
    candidates, controls, skipped, clean = [], [], [], []
    for test in plan:
        result = EXECUTORS[test["executor"]](client, session, gate)
        if result is None:
            clean.append({"test_id": test["id"],
                          "detail": "ran clean — no finding"})
        elif result.get("skipped"):
            skipped.append({"test_id": test["id"],
                            "reason": result["reason"]})
        elif result.get("control"):
            controls.append(result)
        else:
            candidates.append(result)
    return candidates, controls, skipped, clean


def verify_all(candidates, client, session):
    """Verify every candidate; returns (verified, rejected)."""
    verified, rejected = [], []
    for cand in candidates:
        finding = verify(cand, client, session)
        if finding is None:
            rejected.append({"test_id": cand["test_id"],
                             "detail": "candidate did not reproduce — "
                                       "filtered as a false positive"})
        else:
            verified.append(finding)
    return verified, rejected


def main() -> int:
    parser = argparse.ArgumentParser(
        description="DeploySentry — full agent loop runner.")
    parser.add_argument("--auto-approve", action="store_true",
                      help="Run risky tests (fare tampering, privilege "
                           "escalation) and record the approval")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--no-start", action="store_true",
                      help="Fail if the platform is not already running")
    parser.add_argument("--no-retest", action="store_true",
                      help="Skip the retest phase")
    opts = parser.parse_args()

    started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    run_started = time.monotonic()
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    audit_path = REPORTS_DIR / "audit.log"
    if audit_path.exists():
        audit_path.unlink()  # fresh run, fresh audit log
    audit = AuditLog(audit_path)
    audit.event("run-started", "runner", started_at=started_at,
                target=opts.base_url, auto_approve=opts.auto_approve)
    reporter = Reporter(REPORTS_DIR)

    proc = ensure_server(opts.base_url, opts.no_start)
    client = AgentClient(opts.base_url, audit, component="runner")
    gate = ApprovalGate(audit, auto_approve=opts.auto_approve)
    health = HealthMonitor(audit)

    # -- Phase 0: fresh platform --------------------------------------
    print("\n== Phase 0: reset the platform to a fresh seed (v2.3.0) ==")
    admin = client.login("platform_admin")
    status, _ = client.post("/demo/reset", {}, token=admin,
                            account="platform_admin",
                            note="reset to fresh seed")
    assert status == 200, "reset failed — is platform_admin working?"
    status, latency = client.health()
    health.check(latency, status, "runner")

    # -- Phase 1: baseline snapshot ------------------------------------
    print("\n== Phase 1: Change Watcher takes the baseline ==")
    watcher = ChangeWatcher(client)
    baseline = watcher.take_baseline()
    print(f"Baseline version: {baseline['version']}")
    session = build_session(client)

    # -- Phase 2: discovery ---------------------------------------------
    print("\n== Phase 2: Discovery Agent maps the API ==")
    discovery = DiscoveryAgent(client, audit, DATA_DIR)
    graph = discovery.run(session["globe_booking_id"])
    print(f"Discovered {len(graph['endpoints'])} endpoints "
          f"({len(graph['hints'])} unresolved hint(s))")
    for hint in graph["hints"]:
        print(f"  hint: {hint['note']} fragments={hint['fragments']}")

    # -- Phase 3: inventory ----------------------------------------------
    print("\n== Phase 3: Inventory Agent labels active/zombie/shadow ==")
    inventory = InventoryAgent(DATA_DIR / "gateway.log").analyze(graph)
    counts = {"active": 0, "zombie": 0, "shadow": 0, "n/a": 0}
    for inv in inventory:
        counts[inv["label"]] += 1
    inv_line = (f"Inventory: {counts['active']} active, "
                f"{counts['zombie']} zombie, {counts['shadow']} shadow")
    if counts["n/a"]:
        inv_line += f", {counts['n/a']} infra (not classified)"
    print(inv_line)
    for inv in inventory:
        if inv["label"] != "active":
            print(f"  {inv['label'].upper()}: {inv['method']} {inv['path']} "
                  f"(traffic {inv['traffic_count']}, "
                  f"last seen {inv['last_seen'] or 'never'})")
    discovery.export_openapi(REPORTS_DIR / "openapi-generated.json",
                             inventory)
    print("Inferred OpenAPI spec written to "
          "reports/openapi-generated.json")

    # -- Phase 4+5: plan, execute, verify, triage (baseline) ------------
    print("\n== Phase 4: Attack Planner builds the test plan ==")
    plan = build_plan(graph)
    print(f"Planned {len(plan)} tests "
          f"({sum(1 for t in plan if t['risky'])} risky, "
          f"{sum(1 for t in plan if t['class'] == 'control')} controls)")
    print("\n== Phase 5: Executors + Verifier (baseline) ==")
    candidates, controls, skipped, clean = run_tests(client, gate, session,
                                                     plan)
    verified, rejected = verify_all(candidates, client, session)
    print(f"Candidates: {len(candidates)}, verified: {len(verified)}, "
          f"rejected: {len(rejected)}, controls: {len(controls)}, "
          f"skipped: {len(skipped)}, clean: {len(clean)}")

    # -- Phase 6: LIVE CHANGE EVENT ---------------------------------------
    print("\n== Phase 6: LIVE CHANGE EVENT — deploy v2.4.0 ==")
    t_deploy = time.monotonic()
    status, _ = client.post("/demo/deploy", {"version": "v2.4.0"},
                            token=admin, account="platform_admin",
                            note="deploy v2.4.0 (change event)")
    assert status == 200, f"deploy failed: {status}"
    found, detect_s, snap = watcher.wait_for_version("v2.4.0")
    if not found:
        print("ERROR: the watcher never saw v2.4.0.")
        return 1
    time_to_detect = time.monotonic() - t_deploy
    events = watcher.diff(snap)
    print(f"Change detected in {time_to_detect:.1f}s: "
          f"{events[0]['from']} -> {events[0]['to']}")
    print(f"  New endpoints: {events[0]['changed_endpoints']}")
    audit.event("change-detected", "watcher", **events[0],
                seconds=time_to_detect)
    # The new endpoint joins the knowledge graph from the release notes.
    for ep in events[0]["changed_endpoints"]:
        method, path = ep.split(" ", 1)
        discovery.add_endpoint(method, path, {"query": [], "body": []},
                               "jwt", "release")
    new_tests = [t for t in build_plan(discovery.graph())
                 if t["id"] not in {p["id"] for p in plan}]
    print(f"Planned {len(new_tests)} new test(s) for the changed surface")
    c2, ctrl2, sk2, cl2 = run_tests(client, gate, session, new_tests)
    v2, r2 = verify_all(c2, client, session)
    time_to_verify = time.monotonic() - t_deploy
    print(f"Fresh finding verified {time_to_verify:.1f}s after the deploy")
    candidates += c2
    controls += ctrl2
    skipped += sk2
    clean += cl2
    verified += v2
    rejected += r2

    # -- Phase 7: triage + report -----------------------------------------
    findings = triage(verified)
    bonus = sum(1 for f in findings if f["test_id"] == "pay-zero")
    run_data = {
        "run": {
            "started_at": started_at,
            "target": opts.base_url,
            "baseline_version": baseline["version"],
            "change_version": "v2.4.0",
            "auto_approve": opts.auto_approve,
        },
        "timings": {
            "time_to_detect_s": round(time_to_detect, 1),
            "time_to_verify_s": round(time_to_verify, 1),
            "total_run_s": round(time.monotonic() - run_started, 1),
        },
        "counts": {
            "verified": len(findings) - bonus,
            "bonus": bonus,
            "rejected": len(rejected),
            "precision_pct": round(
                100 * len(findings) / max(1, len(findings) + len(rejected)), 1),
            "controls_passed": sum(1 for c in controls if c["passed"]),
            "controls_total": len(controls),
            "endpoints": len(graph["endpoints"]),
            "active": counts["active"],
            "zombie": counts["zombie"],
            "shadow": counts["shadow"],
            "infra": counts["n/a"],
        },
        "findings": findings,
        "rejected": rejected,
        "controls": controls,
        "skipped": skipped,
        "clean": clean,
        "inventory": inventory,
        "change_events": events,
        "retest": [],
    }
    print("\n== Phase 7: Reporter writes findings + dashboard ==")
    reporter.write_json(run_data)
    reporter.write_markdown(run_data)
    reporter.write_dashboard(run_data)
    print("Wrote reports/findings.json, findings.md, dashboard.html")

    # -- Phase 8: retest ---------------------------------------------------
    if not opts.no_retest:
        print("\n== Phase 8: Retest Agent (rollback + re-prove) ==")
        outcomes = retest_agent(client, session, audit, findings)
        run_data["retest"] = outcomes
        for outcome in outcomes:
            print(f"  {outcome['finding']}: {outcome['result']}")
        # Findings changed (one closed) — rewrite the reports.
        reporter.write_json(run_data)
        reporter.write_markdown(run_data)
        reporter.write_dashboard(run_data)

    audit.event("run-finished", "runner",
                verified=len(findings), rejected=len(rejected),
                total_s=run_data["timings"]["total_run_s"])
    audit.close()

    # -- Summary ------------------------------------------------------------
    print("\n" + "=" * 60)
    print("DEPLOYSENTRY RUN COMPLETE")
    print("=" * 60)
    print(f"Verified findings: {len(findings) - bonus} (+{bonus} bonus)  |  "
          f"False positives filtered: {len(rejected)}  |  "
          f"Precision: {run_data['counts']['precision_pct']}%")
    print(f"Time to detect the change: {time_to_detect:.1f}s  |  "
          f"Time to verified finding: {time_to_verify:.1f}s")
    print(f"Controls: {run_data['counts']['controls_passed']}/"
          f"{run_data['counts']['controls_total']} passed  |  "
          f"Skipped (awaiting approval): {len(skipped)}")
    for f in findings:
        print(f"  {f['id']} [{f['severity']}] {f['title']} — {f['status']}")
    print(f"\nReports: {REPORTS_DIR}/findings.json, findings.md, "
          f"dashboard.html, openapi-generated.json, audit.log")
    print("Platform left running on", opts.base_url,
          "(reset to v2.3.0 seed).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
