"""
CyberMNT monitoring agent.

Runs on an employee's Windows/macOS/Linux machine. Reports session state,
idle/active status, and app-category activity to the backend on a fixed
interval. Deliberately does NOT capture keystrokes, screenshots, window
titles, URLs, or file contents -- see README.md for why that's a boundary,
not a gap.

The agent will not send a single event until consent_acknowledged is true
in config.yaml. This is enforced here, not just documented, so it can't be
silently switched on without the employee having seen the notice.
"""

import hashlib
import hmac
import json
import logging
import queue
import sys
import time
import uuid
from pathlib import Path

import requests
import yaml

from platform_utils import get_idle_seconds, get_active_window_info

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("cybermnt-agent")

CONFIG_PATH = Path(__file__).parent / "config.yaml"
OFFLINE_QUEUE_PATH = Path(__file__).parent / ".offline_queue.jsonl"


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        log.error(
            "config.yaml not found. Copy config.example.yaml to config.yaml "
            "and fill in your server_url, device_token, and employee_id."
        )
        sys.exit(1)

    with open(CONFIG_PATH) as f:
        cfg = yaml.safe_load(f)

    if not cfg.get("consent_acknowledged"):
        log.error(
            "consent_acknowledged is false in config.yaml. This agent will "
            "not run until the employee has been shown the monitoring "
            "notice and this is explicitly set to true. This is not a "
            "bug -- it's the compliance gate."
        )
        sys.exit(1)

    required = ["server_url", "employee_id", "device_token"]
    missing = [k for k in required if not cfg.get(k)]
    if missing:
        log.error("Missing required config keys: %s", missing)
        sys.exit(1)

    return cfg


def sign_payload(payload: dict, device_token: str) -> str:
    """HMAC-SHA256 over the canonical JSON body, so the backend can verify
    both authenticity (only someone with the device secret could produce
    this) and integrity (any tampering invalidates the signature)."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(device_token.encode(), body, hashlib.sha256).hexdigest()


def send_event(cfg: dict, event: dict) -> bool:
    event["device_id"] = cfg["employee_id"]
    event["nonce"] = str(uuid.uuid4())  # prevents naive replay of an old event
    signature = sign_payload(event, cfg["device_token"])

    try:
        resp = requests.post(
            f"{cfg['server_url']}/ingest/event",
            json=event,
            headers={"X-Signature": signature},
            timeout=10,
            verify=cfg.get("verify_tls", True),
        )
        if resp.status_code == 200:
            return True
        log.warning("Backend rejected event: %s %s", resp.status_code, resp.text[:200])
        return False
    except requests.RequestException as e:
        log.warning("Network error sending event, will queue offline: %s", e)
        return False


def queue_offline(event: dict):
    with open(OFFLINE_QUEUE_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")


def flush_offline_queue(cfg: dict):
    if not OFFLINE_QUEUE_PATH.exists():
        return
    remaining = []
    with open(OFFLINE_QUEUE_PATH) as f:
        lines = f.readlines()
    for line in lines:
        event = json.loads(line)
        if not send_event(cfg, event):
            remaining.append(line)
    if remaining:
        with open(OFFLINE_QUEUE_PATH, "w") as f:
            f.writelines(remaining)
    else:
        OFFLINE_QUEUE_PATH.unlink(missing_ok=True)


def build_activity_event(cfg: dict) -> dict:
    idle_seconds = get_idle_seconds()
    window_info = get_active_window_info()
    is_idle = idle_seconds is not None and idle_seconds >= cfg["idle_threshold_seconds"]

    return {
        "type": "activity",
        "timestamp": time.time(),
        "idle_seconds": idle_seconds,
        "is_idle": is_idle,
        "app_category": window_info["title_category"],  # never the raw title
    }


def build_heartbeat_event(cfg: dict) -> dict:
    return {"type": "heartbeat", "timestamp": time.time()}


def main():
    cfg = load_config()
    log.info(
        "Agent starting for employee_id=%s, server=%s",
        cfg["employee_id"],
        cfg["server_url"],
    )

    last_heartbeat = 0.0
    poll_interval = cfg.get("activity_poll_interval_seconds", 15)
    heartbeat_interval = cfg.get("heartbeat_interval_seconds", 60)

    while True:
        now = time.time()

        flush_offline_queue(cfg)

        activity_event = build_activity_event(cfg)
        if not send_event(cfg, activity_event):
            queue_offline(activity_event)

        if now - last_heartbeat >= heartbeat_interval:
            heartbeat_event = build_heartbeat_event(cfg)
            if not send_event(cfg, heartbeat_event):
                queue_offline(heartbeat_event)
            last_heartbeat = now

        time.sleep(poll_interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Agent stopped.")
