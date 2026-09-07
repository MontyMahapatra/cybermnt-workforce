import time

from fastapi import APIRouter, HTTPException, Request, status, Depends
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from database import get_db
from models import Device, ActivityEvent
from schemas import IngestEvent
from security import verify_hmac, decrypt_field, append_audit_log
from alerts import check_after_hours, check_tamper

router = APIRouter(prefix="/ingest", tags=["ingest"])
limiter = Limiter(key_func=get_remote_address)

# Simple in-memory replay guard for nonces. In production back this with
# Redis (TTL matching your clock-skew tolerance) so it survives restarts
# and works across multiple backend instances.
_seen_nonces: set[str] = set()


@router.post("/event")
@limiter.limit("30/minute")
def ingest_event(request: Request, event: IngestEvent, db: Session = Depends(get_db)):
    signature = request.headers.get("X-Signature", "")

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

    if event.nonce in _seen_nonces:
        raise HTTPException(status.HTTP_409_CONFLICT, "Replayed event rejected")

    device_secret = decrypt_field(device.device_secret_encrypted)
    if not signature or not verify_hmac(event.model_dump(), signature, device_secret):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid signature")

    _seen_nonces.add(event.nonce)

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
