# CyberMNT Remote Team Monitor

A self-hosted attendance + activity monitoring system for remote teams, built for
CyberMNT. Cross-platform agent (Windows / macOS / Linux) + FastAPI backend +
web dashboard.

## What this does

- Tracks session state (login/logout, lock/unlock) and idle vs. active time
  per employee — not just "logged in / logged out."
- Flags missed check-ins (agent stopped reporting, laptop never opened).
- Scores activity by app/window category instead of logging raw keystrokes
  or screen content.
- Raises security-style alerts: agent tampering, after-hours access,
  impossible-travel-style anomalies.
- Enforces a visible consent/compliance layer — the agent will not collect
  data until an employee has acknowledged the monitoring notice.

## What this deliberately does NOT do

No keylogging, no screenshot capture, no reading of personal accounts or
browsing content, no covert/hidden mode. This is a design choice, not a
missing feature — see `SECURITY.md` and the "Legal & ethical notes" section
below for why.

## Project layout

```
cybermnt-monitor/
├── agent/          # Cross-platform Python agent (Win/Mac/Linux)
├── backend/        # FastAPI backend: ingest API, auth, alerts, dashboard API
├── dashboard/       # Static web dashboard (manager/HR/admin views)
├── SECURITY.md      # Threat model, hardening controls, honest limitations
└── .env.example
```

## Quick start (backend)

```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env      # edit secrets before running for real
uvicorn main:app --reload --port 8000
```

This spins up SQLite locally for evaluation. Swap `DATABASE_URL` in `.env`
for Postgres in production (see `SECURITY.md`).

## Quick start (agent)

```bash
cd agent
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp config.example.yaml config.yaml   # fill in server_url, device_token, employee_id
python3 monitor_agent.py
```

The agent refuses to run until `consent_acknowledged: true` is set in
`config.yaml` — that's intentional (see below).

## Dashboard

Open `dashboard/index.html` in a browser. It runs in demo mode with mock
data out of the box; point `API_BASE` at the top of the file to your running
backend to see live data. Access is role-scoped (Admin / Manager / HR) —
the demo lets you switch roles to see how each view differs.

## Legal & ethical notes (read before deploying)

Workplace monitoring is legal in most places but regulated, and rules vary
by country/state. Before rolling this out:

1. **Tell employees, in writing, what is collected and why**, before you
   turn it on — not buried in a handbook. The consent gate in the agent
   config exists so this can't be skipped by accident.
2. **Check local law.** Several jurisdictions (parts of the EU, some US
   states) require advance notice, limit what can be captured, or require
   a documented legitimate business purpose. This project is not legal
   advice — have someone check your specific jurisdictions.
3. **Collect the minimum you need.** The schema here stores app/window
   *categories* and durations, not window titles, URLs, or content, on
   purpose — you can extend it, but that's a real privacy/legal trade-off,
   not a free upgrade.
4. **Restrict who can see what.** RBAC is built in — use it. Raw
   per-employee timelines shouldn't be visible to everyone with dashboard
   access.

## Status

This is a working scaffold, not a finished product: it's structured so you
can run it end-to-end, but treat the crypto/config defaults as
development-only until you've done the hardening pass in `SECURITY.md`.
