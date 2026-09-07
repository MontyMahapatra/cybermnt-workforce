"""
Alert rules. Kept deliberately simple and explainable -- an alert a manager
can't understand or trust gets ignored, which defeats the point. Wire this
into CyberMNT's existing SOC pipeline (webhook out to Slack/SIEM) rather
than treating it as a second, separate alert stream.
"""

import time
from sqlalchemy.orm import Session

from models import Device, Alert

MISSED_HEARTBEAT_THRESHOLD_SECONDS = 5 * 60  # no contact in 5 min -> alert
AFTER_HOURS_START_HOUR = 21   # 9pm
AFTER_HOURS_END_HOUR = 6      # 6am


def check_after_hours(db: Session, employee_id: str, event_timestamp: float):
    hour = time.localtime(event_timestamp).tm_hour
    if hour >= AFTER_HOURS_START_HOUR or hour < AFTER_HOURS_END_HOUR:
        _raise_alert(
            db, employee_id, "after_hours",
            f"Activity reported outside normal hours ({hour}:00 local).",
            severity="warning",
        )


def check_tamper(db: Session, device: Device):
    if device.tamper_flag:
        _raise_alert(
            db, device.employee_id, "tamper",
            "Device flagged for possible agent tampering.",
            severity="critical",
        )


def sweep_missed_heartbeats(db: Session):
    """Run this on a schedule (cron / background task), not per-request --
    this is what catches 'never opened the laptop today.'"""
    now = time.time()
    stale_devices = (
        db.query(Device)
        .filter(Device.last_seen.isnot(None))
        .filter(Device.last_seen < now - MISSED_HEARTBEAT_THRESHOLD_SECONDS)
        .all()
    )
    for device in stale_devices:
        _raise_alert(
            db, device.employee_id, "missed_heartbeat",
            f"No signal from device in over "
            f"{MISSED_HEARTBEAT_THRESHOLD_SECONDS // 60} minutes.",
            severity="warning",
        )


def _raise_alert(db: Session, employee_id: str, alert_type: str, message: str, severity: str):
    # Avoid spamming duplicate unacknowledged alerts of the same type
    existing = (
        db.query(Alert)
        .filter_by(employee_id=employee_id, alert_type=alert_type, acknowledged=False)
        .first()
    )
    if existing:
        return
    db.add(Alert(
        employee_id=employee_id, alert_type=alert_type,
        severity=severity, message=message, timestamp=time.time(),
    ))
    db.commit()
