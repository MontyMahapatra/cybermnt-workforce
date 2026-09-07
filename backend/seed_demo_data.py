"""
One-time setup for local evaluation only. Creates:
  - an admin dashboard user (username: admin / password printed below)
  - one demo employee with an enrolled, consented device

Run with the backend's virtualenv active, after the server has been
started at least once (so tables exist):

    python seed_demo_data.py
"""

import secrets

from dotenv import load_dotenv
load_dotenv()

from database import Base, engine, SessionLocal
from models import DashboardUser, Employee, Device, Role
from security import hash_password, encrypt_field

Base.metadata.create_all(bind=engine)
db = SessionLocal()

if not db.query(DashboardUser).filter_by(username="admin").first():
    admin_password = secrets.token_urlsafe(12)
    db.add(DashboardUser(
        username="admin",
        password_hash=hash_password(admin_password),
        role=Role.admin,
    ))
    print(f"Created admin user -> username: admin  password: {admin_password}")
else:
    print("Admin user already exists, skipping.")
    admin_password = None

if not db.query(Employee).filter_by(employee_id="emp_0001").first():
    db.add(Employee(
        employee_id="emp_0001",
        encrypted_name=encrypt_field("Demo Employee"),
        encrypted_email=encrypt_field("demo@cybermnt.example"),
        team="soc",
    ))

if not db.query(Device).filter_by(employee_id="emp_0001").first():
    device_secret = secrets.token_hex(32)
    db.add(Device(
        employee_id="emp_0001",
        device_secret_encrypted=encrypt_field(device_secret),
        consent_ack=True,   # demo only -- in real use this flips true only
                             # after the employee has actually acknowledged it
        platform="demo",
    ))
    print(f"Created demo device -> employee_id: emp_0001  device_token: {device_secret}")
    print("Put that device_token into agent/config.yaml to test the agent against this backend.")
else:
    print("Demo device already exists, skipping.")

db.commit()
db.close()
