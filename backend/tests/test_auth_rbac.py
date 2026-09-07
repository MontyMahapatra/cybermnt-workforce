from tests.conftest import login


def test_login_success(client, seeded):
    token = login(client, "admin", seeded["admin_password"])
    assert token


def test_login_wrong_password_rejected(client, seeded):
    resp = client.post("/auth/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_login_unknown_user_gets_same_error_as_wrong_password(client, seeded):
    """Same status/shape whether the account exists or not -- don't let a
    different error message be used to enumerate valid usernames."""
    resp_unknown = client.post("/auth/login", json={"username": "nobody", "password": "x"})
    resp_wrong_pw = client.post("/auth/login", json={"username": "admin", "password": "x"})
    assert resp_unknown.status_code == resp_wrong_pw.status_code == 401
    assert resp_unknown.json() == resp_wrong_pw.json()


def test_dashboard_requires_auth(client, seeded):
    resp = client.get("/dashboard/team/status")
    assert resp.status_code == 401


def test_admin_sees_all_teams(client, seeded):
    token = login(client, "admin", seeded["admin_password"])
    resp = client.get("/dashboard/team/status", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    ids = {r["employee_id"] for r in resp.json()}
    assert ids == {"emp_soc_1", "emp_pentest_1"}


def test_manager_scoped_to_own_team_only(client, seeded):
    """The core isolation test: a manager scoped to 'soc' must never see
    'pentest' data, whether via the list endpoint or a direct lookup by ID."""
    token = login(client, "soc_manager", seeded["manager_password"])

    resp = client.get("/dashboard/team/status", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    ids = {r["employee_id"] for r in resp.json()}
    assert ids == {"emp_soc_1"}
    assert "emp_pentest_1" not in ids

    forbidden = client.get(
        "/dashboard/employee/emp_pentest_1/timeline",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert forbidden.status_code == 403

    allowed = client.get(
        "/dashboard/employee/emp_soc_1/timeline",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert allowed.status_code == 200


def test_role_cannot_be_escalated_by_reusing_an_old_token_shape(client, seeded):
    """A manager token must never pass an admin-only check."""
    token = login(client, "soc_manager", seeded["manager_password"])
    resp = client.post(
        "/devices/enroll",
        json={"employee_id": "emp_new", "team": "soc"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


def test_admin_can_enroll_and_acknowledge_consent(client, seeded):
    token = login(client, "admin", seeded["admin_password"])
    resp = client.post(
        "/devices/enroll",
        json={"employee_id": "emp_new_hire", "team": "soc"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert "device_token" in resp.json()

    ack = client.post(
        "/devices/emp_new_hire/acknowledge-consent",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert ack.status_code == 200
    assert ack.json()["consent_ack"] is True


def test_audit_chain_stays_valid_after_normal_activity(client, seeded, db):
    from security import verify_audit_chain

    login(client, "admin", seeded["admin_password"])
    assert verify_audit_chain(db) is True
