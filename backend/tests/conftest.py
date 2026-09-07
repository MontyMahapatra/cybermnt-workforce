import os
import secrets
import sys
import tempfile

import pytest
from cryptography.fernet import Fernet

# Env vars must exist before any app module is imported, since several
# modules (security.py, database.py) read them at import time.
#
# Using a temp FILE-based SQLite DB rather than ':memory:' deliberately --
# FastAPI's TestClient can run sync route handlers in a worker thread, and
# SQLite's ':memory:' database is scoped per-connection, so a different
# thread getting a different connection would silently see an empty DB.
# A temp file sidesteps that class of flaky-test bug entirely.
_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp_db.name}"
os.environ["JWT_SECRET"] = secrets.token_hex(32)
os.environ["JWT_ALGORITHM"] = "HS256"
os.environ["JWT_EXPIRY_MINUTES"] = "30"
os.environ["FIELD_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["CORS_ORIGINS"] = "http://localhost:5500"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from database import Base, engine, SessionLocal  # noqa: E402
from models import Employee, Device, DashboardUser, Role  # noqa: E402
from security import encrypt_field, hash_password  # noqa: E402
from rate_limit import limiter as app_limiter  # noqa: E402


@pytest.fixture(autouse=True)
def clean_tables():
    """Reset DB tables and rate-limiter counters before every test.
    Tests share one process, so without resetting the limiter, the
    5/minute login limit (correctly) trips partway through the suite and
    fails unrelated later tests -- that's a test-isolation issue, not a
    sign the limiter is wrong."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    app_limiter.reset()
    yield


@pytest.fixture()
def client():
    return TestClient(main.app)


@pytest.fixture()
def db():
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture()
def seeded(db):
    """Two teams (soc, pentest), a consented device on each, an admin,
    and a manager scoped only to the soc team -- enough surface area to
    exercise RBAC/tenant-style isolation."""
    device_secret_soc = secrets.token_hex(32)
    device_secret_pentest = secrets.token_hex(32)
    admin_password = "admin-pass-123"
    manager_password = "manager-pass-123"

    db.add(Employee(employee_id="emp_soc_1", team="soc"))
    db.add(Employee(employee_id="emp_pentest_1", team="pentest"))
    db.add(Device(employee_id="emp_soc_1", device_secret_encrypted=encrypt_field(device_secret_soc),
                   consent_ack=True))
    db.add(Device(employee_id="emp_pentest_1", device_secret_encrypted=encrypt_field(device_secret_pentest),
                   consent_ack=False))  # deliberately NOT consented, for the consent-gate test
    db.add(DashboardUser(username="admin", password_hash=hash_password(admin_password), role=Role.admin))
    db.add(DashboardUser(username="soc_manager", password_hash=hash_password(manager_password),
                          role=Role.manager, manages_team="soc"))
    db.commit()

    return {
        "device_secret_soc": device_secret_soc,
        "device_secret_pentest": device_secret_pentest,
        "admin_password": admin_password,
        "manager_password": manager_password,
    }


def login(client, username, password):
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]
