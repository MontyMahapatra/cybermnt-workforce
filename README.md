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
├── .github/workflows/  # CI: runs the backend test suite on every push
├── agent/          # Cross-platform Python agent (Win/Mac/Linux)
├── backend/        # FastAPI backend: ingest API, auth, alerts, dashboard API
│   └── tests/      # pytest suite (RBAC isolation, consent gate, replay/signature checks)
├── dashboard/       # Static web dashboard (manager/HR/admin views)
├── SECURITY.md      # Threat model, hardening controls, honest limitations
└── .env.example
```

## Quick start (Docker)

```bash
export JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export FIELD_ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
docker compose up --build
```

> **Honesty note:** `docker-compose.yml` was written but not run in the
> environment this project was built in — there's no Docker there to test
> it against. Treat your first `docker compose up` as the actual test,
> not an assumption that it's already verified.

## Quick start (backend)

**Windows (PowerShell)**
```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy ..\.env.example .env
uvicorn main:app --reload --port 8000
```
If `Activate.ps1` is blocked, PowerShell's script execution policy is off —
see Troubleshooting below.

**Windows (cmd.exe)**
```bat
cd backend
python -m venv venv
venv\Scripts\activate.bat
pip install -r requirements.txt
copy ..\.env.example .env
uvicorn main:app --reload --port 8000
```

**Linux / macOS (bash/zsh)**
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env
uvicorn main:app --reload --port 8000
```

Whichever shell you used, edit `.env` before running for real — the copied
file has placeholder secrets, not usable ones. This spins up SQLite locally
for evaluation. Swap `DATABASE_URL` in `.env` for Postgres in production
(see `SECURITY.md`).

## Quick start (agent)

**Windows (PowerShell)**
```powershell
cd agent
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy config.example.yaml config.yaml
notepad config.yaml   # fill in server_url, device_token, employee_id
python monitor_agent.py
```

**Windows (cmd.exe)**
```bat
cd agent
python -m venv venv
venv\Scripts\activate.bat
pip install -r requirements.txt
copy config.example.yaml config.yaml
notepad config.yaml
python monitor_agent.py
```

**Linux / macOS (bash/zsh)**
```bash
cd agent
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp config.example.yaml config.yaml   # fill in server_url, device_token, employee_id
python3 monitor_agent.py
```

The agent refuses to run until `consent_acknowledged: true` is set in
`config.yaml` — that's intentional (see below).

## Enrolling a new employee's device

There's no self-serve UI for this yet — an admin does it via the API:

```bash
curl -X POST http://localhost:8000/devices/enroll \
  -H "Authorization: Bearer <admin JWT from /auth/login>" \
  -H "Content-Type: application/json" \
  -d '{"employee_id": "emp_0002", "team": "soc"}'
```

This returns a `device_token` **once** — copy it into that employee's
`config.yaml`. Enrollment does *not* set consent — call
`POST /devices/{employee_id}/acknowledge-consent` as a separate step,
only after the employee has actually been shown the monitoring notice.
Ingest requests are rejected server-side until that step happens, even if
the device secret is valid.

## Running the tests

```bash
cd backend
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

Covers signature verification, replay rejection, the consent gate, and —
the one that matters most — that a manager scoped to one team can never
read another team's data, even by guessing an employee ID directly. CI
runs this same suite on every push (see `.github/workflows/`).

## Troubleshooting

**`The token '&&' is not a valid statement separator in this version.`**
You're in PowerShell and ran a bash-style chained command (`a && b`).
PowerShell doesn't support `&&` chaining on older versions (5.1, the
Windows-default one). Use the PowerShell block above — one command per
line — or if you're on PowerShell 7+, `;` chains commands (not `&&`).

**`venv\Scripts\Activate.ps1 cannot be loaded because running scripts is
disabled on this system`**
PowerShell's execution policy is blocking the activation script. Run this
once, in an admin PowerShell, then retry:
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```
Or skip activation entirely and call the venv's Python directly:
```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe -m uvicorn main:app --reload --port 8000
```

**`'python' is not recognized...` / `'python3' is not recognized...`**
Windows installs the launcher as `python`, not `python3` — use `python` in
the Windows blocks above (already reflected there). If that's still not
found, Python isn't on PATH; reinstall from python.org with "Add to PATH"
checked, or use `py -3` instead of `python`.

**Port 8000 already in use**
Something else is bound to it. Either stop that process, or run this
backend on a different port: `uvicorn main:app --reload --port 8001` (and
update `API_BASE` in `dashboard/index.html` to match).

## Dashboard

Open `dashboard/index.html` in a browser. It runs in demo mode with mock
data out of the box; point `API_BASE` at the top of the file to your running
backend to see live data. Access is role-scoped (Admin / Manager / HR) —
the demo lets you switch roles to see how each view differs.

## ⚠️ Demo data is for local evaluation only

`backend/seed_demo_data.py` creates a device with `consent_ack=True`
already set and prints an admin password straight to your terminal. That's
convenient for trying the project out locally. It is **not** something to
run against a real deployment — consent should only ever be flipped true
after an actual employee has actually seen the actual notice, and admin
credentials shouldn't originate from a script's stdout. If you're testing
this project, this script is fine. If you're standing up something real,
skip it and use `POST /devices/enroll` (see above) plus a real admin
account you create deliberately.

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
As of this writing, the agent's platform-specific code (Windows/macOS/Linux)
has been syntax-checked but not run on a real machine of each OS — see
"Known untested areas" below before you call any platform "supported."

## Known untested areas (read this before relying on any of it)

Being direct about exactly what has and hasn't been verified, and by what:

| Area | Verified how | Not yet verified |
|---|---|---|
| Backend API (auth, RBAC, ingest, consent gate, replay/signature checks) | 24 automated tests, run against a real running server over HTTP, plus manual RBAC/isolation checks | Real penetration testing by someone actively trying to break it |
| Windows/macOS/Linux agent code | `py_compile` syntax check only | Never executed on a real Windows, macOS, or Linux machine — the platform-specific idle/active-window code paths (pywin32, Quartz/AppKit, X11 tools) are unverified |
| Windows PowerShell / cmd.exe setup instructions | Written to be syntactically correct PowerShell/cmd | Never run in an actual Windows terminal |
| `docker-compose.yml` / `Dockerfile` | Written following standard patterns | No Docker was available to test this against; unverified |
| Windows `.exe` / installer | Not attempted | No Windows environment available to build or test one |

If you're inviting other testers, the most valuable thing they can do
first is exercise the two rows with no verification at all (Windows
PowerShell setup, and the agent itself on their OS) and report back.

## License

MIT — see `LICENSE`. Chosen for low friction (anyone can use, modify, and
redistribute, including commercially, with attribution). If you'd rather
have explicit patent-grant language given this is security software,
Apache-2.0 is the other common choice — swap it before this gets much
further if that matters to you.
