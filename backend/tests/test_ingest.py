import hashlib
import hmac
import json
import time
import uuid


def _sign(event: dict, secret: str) -> str:
    body = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _event(device_id: str, event_type: str = "heartbeat") -> dict:
    return {
        "type": event_type,
        "timestamp": time.time(),
        "device_id": device_id,
        "nonce": str(uuid.uuid4()),
        "idle_seconds": None,
        "is_idle": None,
        "app_category": None,
    }


def test_valid_signed_event_accepted(client, seeded):
    event = _event("emp_soc_1")
    sig = _sign(event, seeded["device_secret_soc"])
    resp = client.post("/ingest/event", json=event, headers={"X-Signature": sig})
    assert resp.status_code == 200


def test_forged_signature_rejected(client, seeded):
    event = _event("emp_soc_1")
    resp = client.post("/ingest/event", json=event, headers={"X-Signature": "0" * 64})
    assert resp.status_code == 401


def test_wrong_device_secret_rejected(client, seeded):
    """Signing with the OTHER device's secret must not validate --
    catches any accidental cross-device secret reuse."""
    event = _event("emp_soc_1")
    sig = _sign(event, seeded["device_secret_pentest"])
    resp = client.post("/ingest/event", json=event, headers={"X-Signature": sig})
    assert resp.status_code == 401


def test_replayed_event_rejected(client, seeded):
    event = _event("emp_soc_1")
    sig = _sign(event, seeded["device_secret_soc"])
    first = client.post("/ingest/event", json=event, headers={"X-Signature": sig})
    assert first.status_code == 200
    replay = client.post("/ingest/event", json=event, headers={"X-Signature": sig})
    assert replay.status_code == 409


def test_unconsented_device_rejected_even_with_valid_signature(client, seeded):
    """This is the consent-gate test: emp_pentest_1's device exists but
    consent_ack is False. A technically-perfect signature must still be
    refused -- consent is enforced server-side, not just trusted from the
    agent's local config."""
    event = _event("emp_pentest_1")
    sig = _sign(event, seeded["device_secret_pentest"])
    resp = client.post("/ingest/event", json=event, headers={"X-Signature": sig})
    assert resp.status_code == 403


def test_unknown_device_rejected(client, seeded):
    event = _event("emp_does_not_exist")
    sig = _sign(event, "irrelevant-secret")
    resp = client.post("/ingest/event", json=event, headers={"X-Signature": sig})
    assert resp.status_code == 404


def test_stale_timestamp_rejected(client, seeded):
    event = _event("emp_soc_1")
    event["timestamp"] = time.time() - 3600  # 1 hour old, outside the window
    sig = _sign(event, seeded["device_secret_soc"])
    resp = client.post("/ingest/event", json=event, headers={"X-Signature": sig})
    assert resp.status_code == 400
