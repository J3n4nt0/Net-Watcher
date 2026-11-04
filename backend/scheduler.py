"""
NetWatcher - Auto-sweep scheduler.

Runs a ping sweep of every registered device on a fixed interval, in a
background thread, so the dashboard reflects live status without the user
manually clicking "Sweep". Pure stdlib threading — no extra dependency,
no external scheduler process to manage.
"""
import threading
import time

import nettools
from database import db_cursor

DEFAULT_INTERVAL_S = 60

_stop_event = threading.Event()
_thread = None


def _sweep_once():
    with db_cursor() as cur:
        cur.execute("SELECT ip FROM devices")
        ips = [row["ip"] for row in cur.fetchall()]

    if not ips:
        return

    result = nettools.sweep(ips)
    with db_cursor() as cur:
        for detail in result["details"]:
            cur.execute(
                "INSERT INTO ping_history (ip, alive, latency_ms) VALUES (?, ?, ?)",
                (detail["ip"], int(detail["alive"]), detail["latency_ms"]),
            )


def _loop(interval_s: int):
    while not _stop_event.is_set():
        try:
            _sweep_once()
        except Exception:
            pass  # a single bad sweep should never kill the background loop
        _stop_event.wait(interval_s)


def start(interval_s: int = DEFAULT_INTERVAL_S):
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop_event.clear()
    _thread = threading.Thread(target=_loop, args=(interval_s,), daemon=True)
    _thread.start()


def stop():
    _stop_event.set()
