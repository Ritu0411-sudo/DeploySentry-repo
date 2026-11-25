# DeploySentry — Round 2 Explainer Video Script

Target length: ~3.5 minutes. Presenter: Ritu (as in Round 1). Format: screen
recording with voiceover, same style as the Round 1 video.
Record the demo fresh — run the commands below and capture the real output.

## Setup before recording

```bash
cd ~/workspace/bughunt/voyagehack/platform && ./run.sh   # serves http://localhost:8000
cd ~/workspace/bughunt/voyagehack/deploysentry && python3 run.py --auto-approve
```

Keep the terminal, the dashboard (`deploysentry/reports/dashboard.html`) and the
findings report (`deploysentry/reports/findings.md`) open. Record the screen while
you narrate. No real data anywhere — everything is synthetic.

## 0:00–0:20 — Intro (show: title slide of the deck)

> "Hello everyone, we are Team Sunny, participating in VoyageHack 4.0. I am Ritu
> Yadav, and this is DeploySentry — change-aware agentic security testing for
> travel APIs, built for TBO's Agentic Real-Time DAST problem statement."

## 0:20–0:50 — The problem (show: deck slide 2)

> "Travel platforms change every day — new APIs, booking flows, payment changes,
> supplier integrations. Each change can open a vulnerability, and the most
> damaging ones are business-logic flaws: one agency reading another's bookings,
> a fare changed in the request, a refund paid twice. Traditional scanners run on
> a schedule, treat every endpoint the same, and miss exactly these flaws. By the
> time a real finding reaches its owner, the code has already moved on."

## 0:50–1:30 — The solution (show: deck slides 3–4, architecture)

> "DeploySentry is a set of specialised agents that test the platform in near
> real time. The loop is: detect what changed, discover the API with no
> documentation, plan targeted tests, execute them safely, verify every finding
> with a minimal proof, triage it by business impact, report it ticket-ready,
> and retest after the fix. A safety layer sits underneath everything — a scope
> allowlist, rate limits, a full audit log, and human approval for risky tests."

## 1:30–2:10 — Live demo, part 1: baseline (show: terminal running run.py, then the dashboard)

> "Here it is running against our demo travel platform, AstraTravel — a mock B2B
> travel API with two agencies, eight test accounts and forty bookings, and no
> API documentation given to the agent. It mapped fourteen endpoints, labelled
> one zombie API that still serves traveller data with no login, and two shadow
> APIs nobody had documented. Then it found and verified eleven real
> vulnerabilities — including booking a flight for one rupee, a sub-agent
> promoting herself to admin, and a forged login token. Zero false positives."

## 2:10–3:00 — Live demo, part 2: the change event (show: the change-event section of the terminal output)

> "This is the part we are proudest of. Mid-run, version 2.4.0 deploys a brand-new
> endpoint. The agent detects the change in zero point six seconds, tests the new
> endpoint, and has the fresh vulnerability verified one second after the deploy —
> a cross-agency fare rewrite on a booking that was paid for. After the fix, it
> retests and closes the finding. That is the whole idea: from deploy to verified
> finding, in seconds — not in the next scheduled scan."

## 3:00–3:25 — Precision and safety (show: findings.md summary + audit.log)

> "Precision matters as much as finding things. The verifier rejected nothing
> because nothing false survived — one hundred percent precision — and two
> negative controls prove the agent does not flag correct behaviour. Every
> request it sent is in the audit log for replay, and the risky tests wait for a
> human unless approval is given."

## 3:25–3:45 — Close (show: deck slide 10)

> "DeploySentry moves security testing from periodic scanning to continuous,
> change-aware testing. Detect what changed. Test what matters. Prove risks
> safely. Thank you."

## Recording checklist

- [ ] Fresh run recorded (`python3 run.py --auto-approve`) — terminal output legible
- [ ] Dashboard open on screen for the findings section
- [ ] Change-event timings visible (0.6s detection, 1.0s verified finding)
- [ ] No traveller PII visible on screen (evidence is redacted by construction)
- [ ] Length under 5 minutes; export as mp4, keep under 50 MB (Unstop limit)
- [ ] File name: `DeploySentry_VoyageHack_Round2_Explainer.mp4`
