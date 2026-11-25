"""Reporter — ticket-ready findings, dashboard, and run records.

Writes everything a reviewer needs into reports/:
  * findings.json — the whole run as machine-readable data
  * findings.md  — one ticket-ready section per finding (evidence, impact,
    severity, owner, suggested fix) plus inventory, controls and retest
  * dashboard.html — a self-contained HTML dashboard (no external assets)
    with the API map, inventory labels, findings and timings

Evidence in every output is PII-redacted by construction: executors never
copy traveller names or passport numbers into evidence strings.
"""

import html
import json
from pathlib import Path


def _esc(text) -> str:
    return html.escape(str(text))


class Reporter:
    def __init__(self, reports_dir: Path):
        self.dir = Path(reports_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    # -- JSON -----------------------------------------------------------
    def write_json(self, run_data: dict) -> Path:
        path = self.dir / "findings.json"
        path.write_text(json.dumps(run_data, indent=2))
        return path

    # -- Markdown -------------------------------------------------------
    def write_markdown(self, run_data: dict) -> Path:
        lines = ["# DeploySentry — findings report",
                 "",
                 f"Run: {run_data['run']['started_at']}  |  "
                 f"Target: {run_data['run']['target']}  |  "
                 f"Baseline: {run_data['run']['baseline_version']}  |  "
                 f"Change event: {run_data['run']['change_version']}",
                 "",
                 "## Summary",
                 "",
                 f"- Verified findings: **{run_data['counts']['verified']}** "
                 f"(+ {run_data['counts']['bonus']} bonus)  ",
                 f"- Candidates rejected by the verifier (false positives "
                 f"filtered): **{run_data['counts']['rejected']}**  ",
                 f"- Precision: **{run_data['counts']['precision_pct']}%**  ",
                 f"- Negative controls passed: "
                 f"{run_data['counts']['controls_passed']}/"
                 f"{run_data['counts']['controls_total']}  ",
                 f"- Time from deploy to detection: "
                 f"{run_data['timings']['time_to_detect_s']:.1f}s  ",
                 f"- Time from deploy to verified finding: "
                 f"{run_data['timings']['time_to_verify_s']:.1f}s  ",
                 f"- Endpoints discovered: "
                 f"{run_data['counts']['endpoints']} "
                 f"({run_data['counts']['active']} active, "
                 f"{run_data['counts']['zombie']} zombie, "
                 f"{run_data['counts']['shadow']} shadow"
                 f"{', ' + str(run_data['counts'].get('infra', 0)) + ' infra' if run_data['counts'].get('infra') else ''})",
                 "",
                 "## Findings (ticket-ready)",
                 ""]
        for f in run_data["findings"]:
            lines += [
                f"### {f['id']} — {f['title']} [{f['severity']}]",
                "",
                f"- **Endpoint:** `{f['endpoint']}`",
                f"- **Class:** {f['class']}",
                f"- **Owner:** {f['owner']}",
                f"- **Status:** {f['status']}",
                f"- **Business impact:** {f['impact']}",
                f"- **Evidence:**",
            ]
            lines += [f"  - {e}" for e in f["evidence"]]
            lines += [f"- **Verified by:** {f['verified_by']}",
                      f"- **Suggested fix:** {f['fix']}", ""]
        lines += ["## API inventory",
                  "",
                  "| Endpoint | Label | Traffic (30d) | Last seen | Auth | Owner | "
                  "Recommendation |",
                  "|---|---|---|---|---|---|---|"]
        for inv in run_data["inventory"]:
            lines.append(
                f"| `{inv['method']} {inv['path']}` | **{inv['label']}** | "
                f"{inv['traffic_count']} | {inv['last_seen'] or 'never'} | "
                f"{inv['auth']} | {inv['owner']} | {inv['recommendation']} |")
        lines += ["",
                  "## Negative controls (correct behaviour, not findings)",
                  ""]
        for c in run_data["controls"]:
            lines.append(f"- {c['test_id']}: "
                         f"{'PASS' if c['passed'] else 'FAIL'} — {c['detail']}")
        if run_data.get("skipped"):
            lines += ["", "## Skipped (awaiting human approval)", ""]
            for s in run_data["skipped"]:
                lines.append(f"- {s['test_id']}: {s['reason']}")
        if run_data.get("retest"):
            lines += ["", "## Retest after fix/rollback", ""]
            for r in run_data["retest"]:
                lines.append(f"- {r['finding']}: **{r['result']}** — "
                             f"{r['detail']}")
        lines += ["",
                  "## Safety",
                  "",
                  f"All requests were scoped to {run_data['run']['target']} "
                  f"at max 5 req/sec, using test accounts only. Every "
                  f"request is in `audit.log` for replay."]
        path = self.dir / "findings.md"
        path.write_text("\n".join(lines))
        return path

    # -- HTML dashboard ---------------------------------------------------
    def write_dashboard(self, run_data: dict) -> Path:
        sev_color = {"Critical": "#b91c1c", "High": "#c2410c",
                     "Medium": "#a16207", "Low": "#166534"}
        label_color = {"active": "#166534", "zombie": "#b91c1c",
                       "shadow": "#a16207", "n/a": "#6b7280"}
        run = run_data["run"]
        counts = run_data["counts"]
        rows_inv = "".join(
            f"<tr><td><code>{_esc(i['method'])} {_esc(i['path'])}</code></td>"
            f"<td><span class='badge' style='background:"
            f"{label_color.get(i['label'], '#555')}'>{_esc(i['label'])}</span></td>"
            f"<td>{i['traffic_count']}</td>"
            f"<td>{_esc(i['last_seen'] or 'never')}</td>"
            f"<td>{_esc(i['auth'])}</td><td>{_esc(i['owner'])}</td>"
            f"<td>{_esc(i['recommendation'])}</td></tr>"
            for i in run_data["inventory"])
        cards = ""
        for f in run_data["findings"]:
            ev = "".join(f"<li>{_esc(e)}</li>" for e in f["evidence"])
            cards += f"""
            <div class='card'>
              <h3>{_esc(f['id'])} — {_esc(f['title'])}
                <span class='badge' style='background:{sev_color.get(f['severity'], '#555')}'>
                {_esc(f['severity'])}</span></h3>
              <p><code>{_esc(f['endpoint'])}</code> · {_esc(f['class'])} ·
                 Owner: <b>{_esc(f['owner'])}</b> · Status: {_esc(f['status'])}</p>
              <p><b>Impact:</b> {_esc(f['impact'])}</p>
              <p><b>Evidence:</b></p><ul>{ev}</ul>
              <p><b>Verified by:</b> {_esc(f['verified_by'])}</p>
              <p><b>Suggested fix:</b> {_esc(f['fix'])}</p>
            </div>"""
        controls = "".join(
            f"<li>{_esc(c['test_id'])}: "
            f"{'PASS' if c['passed'] else 'FAIL'} — {_esc(c['detail'])}</li>"
            for c in run_data["controls"])
        retest = "".join(
            f"<li>{_esc(r['finding'])}: <b>{_esc(r['result'])}</b> — "
            f"{_esc(r['detail'])}</li>" for r in run_data.get("retest", []))
        html_doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>DeploySentry — run dashboard</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1000px;margin:24px auto;
padding:0 16px;color:#1f2937}}
h1{{font-size:26px}} h2{{border-bottom:2px solid #e5e7eb;padding-bottom:4px}}
table{{border-collapse:collapse;width:100%;font-size:14px}}
th,td{{border:1px solid #e5e7eb;padding:6px 8px;text-align:left}}
th{{background:#f3f4f6}} code{{background:#f3f4f6;padding:1px 4px}}
.badge{{color:#fff;padding:2px 8px;border-radius:999px;font-size:12px}}
.card{{border:1px solid #e5e7eb;border-radius:8px;padding:12px 16px;
margin:12px 0}} .stat{{font-size:18px;margin:4px 0}}
</style></head><body>
<h1>DeploySentry — run dashboard</h1>
<p>Run: {_esc(run['started_at'])} · Target: {_esc(run['target'])} ·
Baseline {_esc(run['baseline_version'])} → {_esc(run['change_version'])}</p>
<h2>Headline numbers</h2>
<p class="stat">Verified findings: <b>{counts['verified']}</b>
(+ {counts['bonus']} bonus) · False positives filtered: {counts['rejected']} ·
Precision: <b>{counts['precision_pct']}%</b></p>
<p class="stat">Time to detect the change: <b>{run_data['timings']['time_to_detect_s']:.1f}s</b> ·
Time to verified finding: <b>{run_data['timings']['time_to_verify_s']:.1f}s</b></p>
<p class="stat">Endpoints discovered: {counts['endpoints']} ·
{counts['active']} active · {counts['zombie']} zombie · {counts['shadow']} shadow
{('· ' + str(counts.get('infra', 0)) + ' infra') if counts.get('infra') else ''}</p>
<h2>Findings</h2>
{cards}
<h2>API inventory</h2>
<table><tr><th>Endpoint</th><th>Label</th><th>Traffic (30d)</th>
<th>Last seen</th><th>Auth</th><th>Owner</th><th>Recommendation</th></tr>
{rows_inv}</table>
<h2>Negative controls</h2>
<ul>{controls}</ul>
<h2>Retest</h2>
<ul>{retest or '<li>No retest run.</li>'}</ul>
<p><small>Every request this run sent is in <code>audit.log</code> for replay.
Evidence is PII-redacted by construction.</small></p>
</body></html>"""
        path = self.dir / "dashboard.html"
        path.write_text(html_doc)
        return path
