import enum
import time

from sqlalchemy import (
    Column, Integer, String, Float, Boolean, ForeignKey, Enum, Text
)
from sqlalchemy.orm import relationship

from database import Base


class Role(str, enum.Enum):
    admin = "admin"
    hr = "hr"
    manager = "manager"
    employee = "employee"


class DashboardUser(Base):
    """A person who can log into the dashboard (manager, HR, admin).
    Separate from Employee -- not every employee needs dashboard access,
    and this keeps auth credentials out of the employee/roster table."""
    __tablename__ = "dashboard_users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(Enum(Role), nullable=False, default=Role.employee)
    manages_team = Column(String, nullable=True)  # team name; scopes manager views to Employee.team


class Employee(Base):
    __tablename__ = "employees"

    id = Column(Integer, primary_key=True)
    employee_id = Column(String, unique=True, nullable=False, index=True)

    # Encrypted at rest -- see backend/security.py encrypt_field/decrypt_field.
    # Stored as ciphertext strings, never plaintext PII columns.
    encrypted_name = Column(Text, nullable=True)
    encrypted_email = Column(Text, nullable=True)

    manager_id = Column(String, nullable=True)
    team = Column(String, nullable=True)


class Device(Base):
    """One row per enrolled agent install. The device secret used for HMAC
    verification lives here, hashed -- we verify by re-deriving, we never
    need to read the raw secret back out."""
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)
    employee_id = Column(String, ForeignKey("employees.employee_id"), nullable=False)

    # Stored encrypted (Fernet, see security.py encrypt_field/decrypt_field),
    # NOT hashed -- HMAC verification needs the raw secret back, so a
    # one-way hash (right choice for passwords) won't work here. Encryption
    # at rest still means a raw DB dump doesn't hand over usable secrets;
    # only someone with FIELD_ENCRYPTION_KEY can recover them.
    device_secret_encrypted = Column(String, nullable=False)
    consent_ack = Column(Boolean, default=False, nullable=False)
    platform = Column(String, nullable=True)  # windows / macos / linux
    last_seen = Column(Float, nullable=True)
    tamper_flag = Column(Boolean, default=False)


class ActivityEvent(Base):
    __tablename__ = "activity_events"

    id = Column(Integer, primary_key=True)
    employee_id = Column(String, ForeignKey("employees.employee_id"), index=True)
    event_type = Column(String, nullable=False)  # activity | heartbeat
    timestamp = Column(Float, nullable=False, index=True)
    is_idle = Column(Boolean, nullable=True)
    idle_seconds = Column(Float, nullable=True)
    app_category = Column(String, nullable=True)  # productive / neutral / other


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    employee_id = Column(String, index=True)
    alert_type = Column(String, nullable=False)  # missed_heartbeat | tamper | after_hours
    severity = Column(String, nullable=False, default="info")  # info | warning | critical
    message = Column(String, nullable=False)
    timestamp = Column(Float, nullable=False, default=time.time)
    acknowledged = Column(Boolean, default=False)


class AuditLog(Base):
    """Hash-chained audit trail. Every write to sensitive data appends a
    row here whose entry_hash covers its own content + the previous row's
    hash, so deleting/editing a row breaks the chain from that point
    forward -- detectable on the next audit, even though it can't be
    physically prevented by someone with raw DB access."""
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True)
    timestamp = Column(Float, nullable=False, default=time.time)
    actor = Column(String, nullable=False)      # username or "system"
    action = Column(String, nullable=False)     # e.g. "view_employee_timeline"
    target = Column(String, nullable=True)      # e.g. employee_id affected
    prev_hash = Column(String, nullable=True)
    entry_hash = Column(String, nullable=False)
