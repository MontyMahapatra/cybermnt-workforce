import time

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from auth import require_role, get_current_user
from database import get_db
from models import Device, Employee, ActivityEvent, Alert, DashboardUser
from schemas import EmployeeStatus, AlertOut
from security import append_audit_log

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

ONLINE_WINDOW_SECONDS = 3 * 60  # no signal in 3 min -> shown offline


def _visible_employee_ids(user: DashboardUser, db: Session) -> list[str] | None:
    """None means 'no team scoping needed' (admin/hr see everyone).
    A manager only ever gets employee_ids on their own team, enforced
    here -- not left to the frontend to filter."""
    if user.role.value in ("admin", "hr"):
        return None
    if user.role.value == "manager":
        rows = db.query(Employee).filter_by(team=user.manages_team).all()
        return [r.employee_id for r in rows]
    return []  # plain "employee" role: no team-wide dashboard access


@router.get("/team/status", response_model=list[EmployeeStatus])
def team_status(
    user: DashboardUser = Depends(require_role("admin", "hr", "manager")),
    db: Session = Depends(get_db),
):
    visible = _visible_employee_ids(user, db)
    query = db.query(Device)
    if visible is not None:
        query = query.filter(Device.employee_id.in_(visible))
    devices = query.all()

    now = time.time()
    results = []
    for d in devices:
        latest_activity = (
            db.query(ActivityEvent)
            .filter_by(employee_id=d.employee_id, event_type="activity")
            .order_by(ActivityEvent.timestamp.desc())
            .first()
        )
        active_alerts = (
            db.query(Alert)
            .filter_by(employee_id=d.employee_id, acknowledged=False)
            .count()
        )
        results.append(EmployeeStatus(
            employee_id=d.employee_id,
            online=bool(d.last_seen and (now - d.last_seen) < ONLINE_WINDOW_SECONDS),
            is_idle=latest_activity.is_idle if latest_activity else None,
            last_seen=d.last_seen,
            active_alerts=active_alerts,
        ))

    append_audit_log(db, actor=user.username, action="view_team_status")
    return results


@router.get("/alerts", response_model=list[AlertOut])
def list_alerts(
    user: DashboardUser = Depends(require_role("admin", "hr", "manager")),
    db: Session = Depends(get_db),
):
    visible = _visible_employee_ids(user, db)
    query = db.query(Alert).filter_by(acknowledged=False)
    if visible is not None:
        query = query.filter(Alert.employee_id.in_(visible))
    alerts = query.order_by(Alert.timestamp.desc()).limit(200).all()

    append_audit_log(db, actor=user.username, action="view_alerts")
    return alerts


@router.get("/employee/{employee_id}/timeline")
def employee_timeline(
    employee_id: str,
    user: DashboardUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    visible = _visible_employee_ids(user, db)
    if visible is not None and employee_id not in visible:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not authorized for this employee")
    if visible == [] and user.role.value == "employee":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Employees cannot view dashboard timelines")

    events = (
        db.query(ActivityEvent)
        .filter_by(employee_id=employee_id)
        .order_by(ActivityEvent.timestamp.desc())
        .limit(500)
        .all()
    )

    # Viewing an individual's detailed timeline is exactly the kind of
    # access that should be logged with *who* looked at *whom*, not just
    # that "the dashboard" was used.
    append_audit_log(db, actor=user.username, action="view_employee_timeline", target=employee_id)

    return [
        {
            "timestamp": e.timestamp,
            "event_type": e.event_type,
            "is_idle": e.is_idle,
            "app_category": e.app_category,
        }
        for e in events
    ]
