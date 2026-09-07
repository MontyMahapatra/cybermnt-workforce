import time

from fastapi import APIRouter, HTTPException, Request, status, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import Device, ActivityEvent
from schemas import IngestEvent
from security import verify_hmac, decrypt_field, append_audit_log
from alerts import check_after_hours, check_tamper
from rate_limit import limiter

router = APIRouter(prefix="/ingest", tags=["ingest"])

# Replay guard for nonces, bounded by time rather than an ever-growing set.
# The earlier version of this stored every nonce forever, which is a slow
# memory leak in a long-running process. This keeps only what's needed to
# catch replays within NONCE_WINDOW_SECONDS, and sweeps expired entries
# lazily on each request rather than needing a separate background job.
#
# Single-process only -- back this with Redis (SETNX + TTL) once you run
# more than one backend replica, or a restart briefly re-opens the replay
# window.
NONCE_WINDOW_SECONDS = 10 * 60
_seen_nonces: dict[str, float] = {}


def _check_and_record_nonce(nonce: str, now: float):
    expired = [n for n, seen_at in _seen_nonces.items() if now - seen_at > NONCE_WINDOW_SECONDS]
    for n in expired:
        del _seen_nonces[n]

    if nonce in _seen_nonces:
        raise HTTPException(status.HTTP_409_CONFLICT, "Replayed event rejected")
    _seen_nonces[nonce] = now


@router.post("/event")
@limiter.limit("30/minute")
def ingest_event(request: Request, event: IngestEvent, db: Session = Depends(get_db)):
    signature = request.headers.get("X-Signature", "")
    now = time.time()

    device = db.query(Device).filter_by(employee_id=event.device_id).first()
    if not device:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown device")

    if not device.consent_ack:
        # Enforced server-side too, not just in the agent config -- a
        # modified agent binary can't bypass this by lying locally.
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Device has not completed the consent acknowledgment step",
        )

    # Reject events with a timestamp far from server time -- this is what
    # actually bounds the replay window above to something meaningful,
    # rather than trusting the client's clock indefinitely.
    if abs(now - event.timestamp) > NONCE_WINDOW_SECONDS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Event timestamp outside acceptable window")

    _check_and_record_nonce(event.nonce, now)

    device_secret = decrypt_field(device.device_secret_encrypted)
    if not signature or not verify_hmac(event.model_dump(), signature, device_secret):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid signature")

    device.last_seen = event.timestamp
    db.add(ActivityEvent(
        employee_id=event.device_id,
        event_type=event.type,
        timestamp=event.timestamp,
        is_idle=event.is_idle,
        idle_seconds=event.idle_seconds,
        app_category=event.app_category,
    ))
    db.commit()

    check_after_hours(db, event.device_id, event.timestamp)
    check_tamper(db, device)
    append_audit_log(db, actor=f"device:{event.device_id}", action=f"ingest:{event.type}")

    return {"status": "ok", "received_at": time.time()}
