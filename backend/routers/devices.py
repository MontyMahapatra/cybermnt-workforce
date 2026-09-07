import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from auth import require_role
from database import get_db
from models import Employee, Device, DashboardUser
from security import encrypt_field, append_audit_log

router = APIRouter(prefix="/devices", tags=["devices"])


class EnrollRequest(BaseModel):
    employee_id: str
    team: str | None = None


class EnrollResponse(BaseModel):
    employee_id: str
    device_token: str
    note: str = (
        "Copy device_token into that machine's agent config.yaml now -- "
        "it is shown once and stored only in encrypted form after this."
    )


@router.post("/enroll", response_model=EnrollResponse)
def enroll_device(
    req: EnrollRequest,
    user: DashboardUser = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Admin-only. Creates the employee record if it doesn't exist yet and
    issues a fresh device secret. consent_ack starts False on purpose --
    enrolling a device is not the same thing as the employee having seen
    the monitoring notice, and those two steps should never be collapsed
    into one call."""
    employee = db.query(Employee).filter_by(employee_id=req.employee_id).first()
    if not employee:
        employee = Employee(employee_id=req.employee_id, team=req.team)
        db.add(employee)

    existing_device = db.query(Device).filter_by(employee_id=req.employee_id).first()
    if existing_device:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "A device is already enrolled for this employee_id. Revoke it "
            "first if you need to re-issue a secret.",
        )

    device_secret = secrets.token_hex(32)
    db.add(Device(
        employee_id=req.employee_id,
        device_secret_encrypted=encrypt_field(device_secret),
        consent_ack=False,
        platform=None,
    ))
    db.commit()

    append_audit_log(db, actor=user.username, action="enroll_device", target=req.employee_id)

    return EnrollResponse(employee_id=req.employee_id, device_token=device_secret)


@router.post("/{employee_id}/acknowledge-consent")
def acknowledge_consent(
    employee_id: str,
    user: DashboardUser = Depends(require_role("admin", "hr")),
    db: Session = Depends(get_db),
):
    """Marks that the employee has actually seen and acknowledged the
    monitoring notice. Kept as its own endpoint/audit event, separate from
    enrollment, so 'device exists' and 'consent given' can never be
    conflated when someone reviews the audit log later."""
    device = db.query(Device).filter_by(employee_id=employee_id).first()
    if not device:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No device enrolled for this employee_id")

    device.consent_ack = True
    db.commit()
    append_audit_log(db, actor=user.username, action="acknowledge_consent", target=employee_id)

    return {"employee_id": employee_id, "consent_ack": True}


@router.post("/{employee_id}/revoke")
def revoke_device(
    employee_id: str,
    user: DashboardUser = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Deletes the device row outright rather than just flipping a flag --
    an offboarded employee's old device secret shouldn't be recoverable
    from the database at all."""
    device = db.query(Device).filter_by(employee_id=employee_id).first()
    if not device:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No device enrolled for this employee_id")

    db.delete(device)
    db.commit()
    append_audit_log(db, actor=user.username, action="revoke_device", target=employee_id)

    return {"employee_id": employee_id, "revoked": True}
