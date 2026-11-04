"""
NetWatcher - background SNMP poller.

Every N seconds (configurable, stored in the settings table) a background
thread polls each device that has SNMP enabled and stores the latest result
in snmp_snapshots. The web UI never talks SNMP itself: it just re-reads these
cached snapshots, so pages load instantly and a slow/unreachable device can
never block the dashboard.

Traffic rates (bits/s per interface) are derived by comparing the interface
octet counters with those from the previous poll, so they appear from the
second poll onwards.
"""
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import snmp
from database import db_cursor

DEFAULT_INTERVAL_S = 60
MIN_INTERVAL_S = 15
MAX_INTERVAL_S = 3600
SETTING_KEY = "snmp_poll_interval"

_stop = threading.Event()
_wake = threading.Event()
_poll_lock = threading.Lock()
_thread = None


# --------------------------------------------------------------- Settings --
def get_interval() -> int:
    with db_cursor() as cur:
        cur.execute("SELECT value FROM settings WHERE key = ?", (SETTING_KEY,))
        row = cur.fetchone()
    try:
        value = int(row["value"]) if row else DEFAULT_INTERVAL_S
    except ValueError:
        value = DEFAULT_INTERVAL_S
    return max(MIN_INTERVAL_S, min(MAX_INTERVAL_S, value))


def set_interval(seconds: int) -> int:
    if not MIN_INTERVAL_S <= seconds <= MAX_INTERVAL_S:
        raise ValueError(f"interval must be between {MIN_INTERVAL_S} and {MAX_INTERVAL_S} seconds")
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (SETTING_KEY, str(seconds)),
        )
    _wake.set()  # re-evaluate the wait with the new interval
    return seconds


# ------------------------------------------------------------- Snapshots --
def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_snapshot(device_id: int):
    """Returns {"ok", "error", "last_attempt", "data"} or None if never polled."""
    with db_cursor() as cur:
        cur.execute("SELECT * FROM snmp_snapshots WHERE device_id = ?", (device_id,))
        row = cur.fetchone()
    if not row:
        return None
    return {
        "ok": bool(row["ok"]),
        "error": row["error"] or "",
        "last_attempt": row["collected_at"],
        "data": json.loads(row["data"]) if row["data"] else None,
    }


def _save_success(device_id: int, data: dict):
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO snmp_snapshots (device_id, collected_at, ok, error, data) "
            "VALUES (?, ?, 1, '', ?) "
            "ON CONFLICT(device_id) DO UPDATE SET collected_at = excluded.collected_at, "
            "ok = 1, error = '', data = excluded.data",
            (device_id, _now_iso(), json.dumps(data)),
        )


def _save_failure(device_id: int, error: str):
    # Keep the last good data so the UI can still show it (marked as stale).
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO snmp_snapshots (device_id, collected_at, ok, error, data) "
            "VALUES (?, ?, 0, ?, '') "
            "ON CONFLICT(device_id) DO UPDATE SET collected_at = excluded.collected_at, "
            "ok = 0, error = excluded.error",
            (device_id, _now_iso(), error),
        )


# ------------------------------------------------------------------ Rates --
def _delta(new, old):
    if new is None or old is None:
        return None
    if new >= old:
        return new - old
    # counter wrapped: assume 32-bit unless the old value already exceeded 32 bits
    return new + (2 ** 32 if old < 2 ** 32 else 2 ** 64) - old


def _apply_rates(data: dict, previous: dict):
    """Adds in_bps/out_bps to each interface, plus a traffic total."""
    elapsed = data["collected_epoch"] - previous.get("collected_epoch", 0)
    new_up = data["system"].get("uptime_seconds")
    old_up = previous.get("system", {}).get("uptime_seconds")
    rebooted = new_up is not None and old_up is not None and new_up < old_up
    usable = elapsed >= 1 and not rebooted

    old_by_index = {i["index"]: i for i in previous.get("interfaces", [])}
    total_in = total_out = 0
    have_rate = False
    for iface in data["interfaces"]:
        iface["in_bps"] = iface["out_bps"] = None
        old = old_by_index.get(iface["index"])
        if not usable or not old:
            continue
        d_in = _delta(iface["in_octets"], old.get("in_octets"))
        d_out = _delta(iface["out_octets"], old.get("out_octets"))
        if d_in is not None:
            iface["in_bps"] = round(d_in * 8 / elapsed)
        if d_out is not None:
            iface["out_bps"] = round(d_out * 8 / elapsed)
        if iface["oper_status"] == "up" and iface["type"] != "loopback":
            if iface["in_bps"] is not None:
                total_in += iface["in_bps"]
                have_rate = True
            if iface["out_bps"] is not None:
                total_out += iface["out_bps"]
    data["traffic"] = {"in_bps": total_in, "out_bps": total_out} if have_rate else None


# ---------------------------------------------------------------- Polling --
def poll_device(device: dict):
    try:
        data = snmp.query_host(
            device["ip"], device["snmp_community"] or "public",
            device["snmp_version"], device["snmp_port"], timeout_s=2.0,
        )
        data["collected_epoch"] = time.time()
        data["collected_at"] = _now_iso()
        previous = load_snapshot(device["id"])
        if previous and previous["data"]:
            _apply_rates(data, previous["data"])
        else:
            data["traffic"] = None
            for iface in data["interfaces"]:
                iface["in_bps"] = iface["out_bps"] = None
        _save_success(device["id"], data)
    except snmp.SnmpError as exc:
        _save_failure(device["id"], str(exc))
    except Exception as exc:  # one broken device must never stop the others
        _save_failure(device["id"], f"unexpected error: {exc}")


def poll_all() -> int:
    """Polls every SNMP-enabled device (in parallel). Returns how many were polled."""
    with _poll_lock:
        with db_cursor() as cur:
            cur.execute(
                "SELECT id, name, ip, snmp_community, snmp_version, snmp_port "
                "FROM devices WHERE snmp_enabled = 1"
            )
            devices = [dict(row) for row in cur.fetchall()]
        if not devices:
            return 0
        with ThreadPoolExecutor(max_workers=min(8, len(devices))) as pool:
            list(pool.map(poll_device, devices))
        return len(devices)


def _loop():
    while not _stop.is_set():
        try:
            poll_all()
        except Exception:
            pass
        _wake.wait(get_interval())
        _wake.clear()


def trigger_poll():
    """Ask the background thread to poll right now (non-blocking)."""
    _wake.set()


def start():
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, daemon=True, name="snmp-poller")
    _thread.start()


def stop():
    _stop.set()
    _wake.set()
