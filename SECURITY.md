# Security design notes

Honest framing first: "industrial-grade security" for a system like this
means two different things, and it's worth separating them.

1. **Server-side security** — this is where real, strong guarantees are
   possible: encryption, access control, auditability, tamper-evidence of
   records. This scaffold implements real controls here (below).
2. **Client-side tamper-resistance** — this has a hard ceiling. Any agent
   running on a laptop the employee has admin rights over can eventually be
   killed, patched, or inspected by someone determined enough. No amount of
   obfuscation changes that. The honest mitigation is *detection*, not
   prevention: alert loudly and immediately when an agent stops reporting,
   rather than pretending the agent can't be stopped. Don't let anyone sell
   this project internally as "tamper-proof" — it isn't, and no endpoint
   agent from any vendor truly is.

## Controls implemented in this scaffold

**Transport & auth**
- All agent → backend traffic is meant to run over TLS (terminate TLS at a
  reverse proxy in production; `main.py` includes an HSTS header assuming
  that's in place).
- The backend refuses to start at all if `JWT_SECRET` or
  `FIELD_ENCRYPTION_KEY` aren't set — earlier versions silently fell back
  to an insecure hardcoded dev secret, which is exactly the kind of thing
  that quietly ends up running in production. Now it's a startup crash
  with a clear message instead of a silent security hole.
- Every agent event is HMAC-SHA256 signed with a per-device secret issued
  at enrollment (`backend/security.py::verify_hmac`). A stolen event
  payload without the device secret can't be replayed as a different
  device, and a modified payload fails verification.
- Dashboard users authenticate via JWT (`backend/security.py`), short
  expiry, role claim embedded and re-checked server-side on every request
  (never trust a role claim from the client alone — it's re-validated
  against the DB in `auth.py::require_role`).

**At rest**
- Passwords hashed with bcrypt (via passlib), never stored in plaintext.
- PII fields (employee legal name, email) are encrypted at rest with
  AES-256-GCM (`backend/security.py::encrypt_field` /
  `decrypt_field`) rather than stored as plain columns, so a raw DB dump
  doesn't hand over the employee roster.
- Audit log is hash-chained (`AuditLog.prev_hash` /
  `AuditLog.entry_hash` in `models.py`) — each entry embeds the hash of the
  entry before it, so retroactively deleting or editing a row breaks the
  chain and is detectable. This doesn't stop someone with DB admin access
  from tampering, but it does make tampering *evident* on the next audit
  pass, which is the realistic goal.

**Application layer**
- RBAC enforced server-side for every dashboard endpoint (admin / hr /
  manager / employee), not just hidden in the UI.
- Rate limiting on the ingest endpoint (`backend/routers/ingest.py`) to
  blunt both abuse and accidental thundering-herd from a mass agent
  restart.
- Consent is enforced, not just documented: `models.py::Device.consent_ack`
  must be true or `/ingest/event` rejects the payload outright.
- Security headers middleware (CSP, X-Content-Type-Options, X-Frame-Options,
  Referrer-Policy) in `main.py`.

## What you still need to do before real deployment

- Put a real secrets manager (Vault, AWS Secrets Manager, etc.) in front of
  `.env` — plain env files are fine for dev, not for production.
- Run Postgres, not SQLite, with least-privilege DB credentials and network
  segmentation (DB not reachable from the general office network).
- Put the ingest API and dashboard behind your existing SOC monitoring —
  this system generates security-relevant signal (device tamper alerts,
  after-hours anomalies) that should flow into whatever SIEM CyberMNT
  already runs, not live in an island.
- Code-sign the agent binary once you package it (PyInstaller etc.), and
  distribute it via your MDM rather than manual install, so you have a
  clean install/uninstall audit trail.
- Get the consent notice and retention policy reviewed by someone who
  knows employment law in every jurisdiction your team works from.
- Penetration-test the ingest endpoint specifically — it's the one part of
  this system exposed to something you don't fully control (an employee's
  laptop). Treat every field in an inbound event as hostile input.

## Threat model summary

| Actor | Can they... | Mitigated by |
|---|---|---|
| Employee w/ admin rights on own laptop | Kill/uninstall the agent | Missed-heartbeat alert (detect, not prevent) |
| Employee w/ admin rights | Forge events as themselves | HMAC device secret they don't have access to at rest (store it OS-keychain-protected, not in a plaintext config in production) |
| Network attacker | Intercept/replay traffic | TLS + HMAC signing + short-lived JWTs |
| Someone with dashboard access | View data outside their role | Server-side RBAC on every endpoint |
| Someone with DB access | Read PII in bulk / silently edit history | Field-level encryption + hash-chained audit log (evident, not prevented) |
