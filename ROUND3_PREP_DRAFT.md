# DeploySentry — Round 3 Finale Prep (DRAFT)

Grand Finale: 8 Jan 2027, 10:00 AM – 6:00 PM IST. Shortlisted prototypes present to
a jury panel and TBO leadership, live demo + Q&A. Draft updated 2026-11-25 with
real measured results from the verified Round 2 prototype (11 findings, 100%
precision, 0.6s detection, 1.0s verified finding).

## Finale format (from Unstop)

- Live showcase of the solution to TBO leadership and industry experts.
- Expect: a timed pitch, a live demo, and Q&A. Exact slot length is not published —
  prepare a 5-minute pitch that can stretch to 10, and a demo that works even if
  the network is flaky (run everything locally).

## Pitch structure (mapped to the judging weights)

1. **The problem in one line (30 sec):** travel platforms change daily; periodic
   generic scans miss business-logic flaws, and findings arrive after the code moved on.
2. **The change event, live (2 min):** deploy v2.4.0 on stage; the agent detects the
   new endpoint, tests it, and files a verified finding — show the clock.
   This is the highest-weight proof: valid findings (30%) + speed (10%).
3. **Precision + safety (1 min):** show the verified findings vs the two negative
   controls the agent correctly did NOT flag; show the audit log, rate limiter and
   human-approval gate. Precision (20%) + safety (20%) together are 40% of the score.
4. **Inventory (30 sec):** the API map, zombie/shadow labels, and the generated
   OpenAPI spec as a by-product (10%).
5. **The ticket (30 sec):** one finding end to end — evidence, business severity,
   owner, fix, retest-closed. Report quality (10%).
6. **Close (30 sec):** "Detect what changed. Test what matters. Prove risks safely."
   + what comes next (real staging, more vuln classes, CI/CD webhook triggers).

## Judge Q&A bank (draft answers — update with real numbers)

**"Why agents instead of a normal scanner?"**
Scanners spray the same payloads at every endpoint on a schedule. DeploySentry
tests only what changed, picks tests from each endpoint's parameters, roles and
business purpose, and verifies with a minimal proof — so it catches business-logic
flaws (fare tampering, coupon reuse, cross-agency IDOR) that generic scans miss,
with far fewer false positives.

**"How do you know your findings are real?"**
Every hit is re-checked with a minimal proof (e.g. a second agency account
re-requesting the same booking) and duplicates are removed before reporting.
We also built in negative controls — endpoints that look suspicious but behave
correctly — and the agent correctly clears them. Measured: 11 verified findings,
0 false positives, 100% precision.

**"What stops the agent from breaking the platform?"**
Scope allowlist (demo origin only), 5 req/sec rate limit with backoff on 429 or
degraded health, test accounts and synthetic data only, no destructive actions,
human approval for risky tests, and a full audit log of every request for replay.
Breaking scope rules disqualifies a submission — the safety layer is the design,
not an afterthought.

**"How fast is it, really?"**
Measured end to end in the demo: the change is detected 0.6 seconds after the
deploy, and the fresh vulnerability is verified 1.0 second after the deploy.

**"What about LLM hallucinations / cost?"**
The agent's decisions are rule- and graph-driven (knowledge graph + planner);
LLM-style reasoning is used only where judgement is needed, and every finding
must pass the verifier's minimal proof before it is reported — an unproven claim
never becomes a ticket.

**"Does it handle zombie and shadow APIs?"**
Yes — the inventory agent compares the discovered API map against 30 days of
gateway traffic: endpoints that respond but get no traffic are zombie, endpoints
in traffic but never mapped are shadow. Each gets last-traffic date, auth status,
data exposed, owner, and a decommission/restrict/update recommendation.

**"Can this run on TBO's real staging?"**
The design assumes exactly that input: deploy webhooks, gateway logs, HAR files,
test accounts across agencies, and no API docs. The demo runs the same loop
against a local stand-in, so the only change for real staging is the target and
credentials — the loop, safety layer and reporting are unchanged.

**"What would you build next?"**
CI/CD webhook triggers instead of polling, more specialist executors (JWT/session,
SSRF, injection), and the retest loop wired into the team's actual ticketing —
plus the OpenAPI spec export as a standing by-product of every run.

## Demo failure plan

- If the live change event fails on stage: fall back to the pre-recorded run of
  the same event (screen recording) and narrate over it — never debug live.
- If the venue network blocks localhost: everything runs on the laptop, no
  external calls needed; keep a hotspot as backup.
- Keep the explainer video from Round 2 on a USB stick as a last resort.

## Who presents

Ritu presented Round 1. Assume Ritu presents the finale too unless the team
decides otherwise; Aditay handles the live demo controls or the Q&A on the
implementation, split by who built which part.
