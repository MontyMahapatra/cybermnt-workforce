"""
These are NOT a substitute for a real penetration test. They cover the
obvious malformed/adversarial inputs I could think of. A human attacker
will find things this doesn't.
"""

import hashlib
import hmac
import json
import time
import uuid


def _sign(event: dict, secret: str) -> str:
    body = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_missing_signature_header_rejected(client, seeded):
    event = {
        "type": "heartbeat", "timestamp": time.time(),
        "device_id": "emp_soc_1", "nonce": str(uuid.uuid4()),
    }
    resp = client.post("/ingest/event", json=event)  # no X-Signature at all
    assert resp.status_code == 401


def test_wrong_event_type_rejected_by_schema(client, seeded):
    event = {
        "type": "not_a_real_type", "timestamp": time.time(),
        "device_id": "emp_soc_1", "nonce": str(uuid.uuid4()),
    }
    sig = _sign(event, seeded["device_secret_soc"])
    resp = client.post("/ingest/event", json=event, headers={"X-Signature": sig})
    assert resp.status_code == 422  # Pydantic pattern validation on `type`


def test_wrong_app_category_rejected_by_schema(client, seeded):
    event = {
        "type": "activity", "timestamp": time.time(),
        "device_id": "emp_soc_1", "nonce": str(uuid.uuid4()),
        "app_category": "'; DROP TABLE activity_events; --",
    }
    sig = _sign(event, seeded["device_secret_soc"])
    resp = client.post("/ingest/event", json=event, headers={"X-Signature": sig})
    assert resp.status_code == 422


def test_oversized_device_id_rejected_by_schema(client, seeded):
    """device_id is capped at the schema level -- a pen-tester's giant
    string never reaches the DB query at all, it's a clean 422."""
    event = {
        "type": "heartbeat", "timestamp": time.time(),
        "device_id": "x" * 200_000, "nonce": str(uuid.uuid4()),
    }
    sig = _sign(event, "irrelevant")
    resp = client.post("/ingest/event", json=event, headers={"X-Signature": sig})
    assert resp.status_code == 422


def test_non_numeric_timestamp_rejected_by_schema(client, seeded):
    event = {
        "type": "heartbeat", "timestamp": "not-a-number",
        "device_id": "emp_soc_1", "nonce": str(uuid.uuid4()),
    }
    resp = client.post("/ingest/event", json=event, headers={"X-Signature": "irrelevant"})
    assert resp.status_code == 422


def test_missing_required_fields_rejected_by_schema(client, seeded):
    resp = client.post("/ingest/event", json={"type": "heartbeat"}, headers={"X-Signature": "x"})
    assert resp.status_code == 422


def test_extremely_long_signature_header_does_not_crash(client, seeded):
    event = {
        "type": "heartbeat", "timestamp": time.time(),
        "device_id": "emp_soc_1", "nonce": str(uuid.uuid4()),
    }
    resp = client.post("/ingest/event", json=event, headers={"X-Signature": "a" * 100_000})
    assert resp.status_code == 401


def test_malformed_json_body_rejected_cleanly(client, seeded):
    resp = client.post(
        "/ingest/event",
        content=b"{not valid json",
        headers={"X-Signature": "x", "Content-Type": "application/json"},
    )
    assert resp.status_code == 422
