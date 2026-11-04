"""
NetWatcher - Network Sysadmin Toolkit
Backend API: authentication, device inventory, live monitoring, network
diagnostic tools, and config backup/versioning for network gear.

Run:
    pip install fastapi uvicorn paramiko --break-system-packages
    python backend.py
Then open index.html in a browser (or serve the frontend/ folder statically).
"""
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import auth
import backup
import commands
import nettools
import scheduler
from database import init_db, db_cursor

app = FastAPI(title="NetWatcher API", version="2.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()


def _seed_default_admin():
    """Creates a default admin/admin account on first run only, so the app
    is usable out of the box. Change this password immediately."""
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) as c FROM users")
        if cur.fetchone()["c"] == 0:
            pw_hash, salt = auth.hash_password("admin")
            cur.execute(
                "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
                ("admin", pw_hash, salt, "admin"),
            )


_seed_default_admin()
scheduler.start(interval_s=60)  # auto-pings every registered device every 60s


# ---------------------------------------------------------------- Schemas --
class Login(BaseModel):
    username: str
    password: str


class CreateUser(BaseModel):
    username: str
    password: str
    role: str = "guest"


class UpdateUserRole(BaseModel):
    role: str


class DeviceIn(BaseModel):
    name: str
    ip: str
    device_type: str = "generic"
    vendor: str = "generic"
    ssh_port: int = 22
    tags: str = ""
    notes: str = ""


class BackupRequest(BaseModel):
    device_id: int
    username: str
    password: str


class RunCommandsRequest(BaseModel):
    device_id: int
    username: str
    password: str
    commands: list[str]
    enter_config_mode: bool = False


# --------------------------------------------------------------------- Meta
@app.get("/")
def home():
    return {"status": "NetWatcher API running", "code": 200}


# --------------------------------------------------------------------- Auth
@app.post("/login")
def login(request: Login):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE username = ?", (request.username,))
        user = cur.fetchone()

    if not user or not auth.verify_password(request.password, user["password_hash"], user["salt"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = auth.create_session(user["username"], user["role"])
    auth.log_action(user["username"], "login")
    return {"token": token, "username": user["username"], "role": user["role"]}


@app.post("/logout")
def logout(session=Depends(auth.require_user)):
    with db_cursor() as cur:
        cur.execute("DELETE FROM sessions WHERE token = ?", (session["token"],))
    return {"ok": True}


@app.get("/me")
def me(session=Depends(auth.require_user)):
    return {"username": session["username"], "role": session["role"]}


@app.post("/users")
def create_user(request: CreateUser, session=Depends(auth.require_user)):
    auth.require_admin(session)
    if request.role not in ("admin", "guest"):
        raise HTTPException(status_code=400, detail="role must be 'admin' or 'guest'")
    if len(request.password) < 4:
        raise HTTPException(status_code=400, detail="password must be at least 4 characters")
    pw_hash, salt = auth.hash_password(request.password)
    try:
        with db_cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
                (request.username, pw_hash, salt, request.role),
            )
    except Exception:
        raise HTTPException(status_code=409, detail="username already exists")
    auth.log_action(session["username"], "create_user", request.username)
    return {"ok": True, "username": request.username}


@app.get("/users")
def list_users(session=Depends(auth.require_user)):
    auth.require_admin(session)
    with db_cursor() as cur:
        cur.execute("SELECT id, username, role, created_at FROM users ORDER BY username")
        return [dict(r) for r in cur.fetchall()]


@app.put("/users/{user_id}/role")
def update_user_role(user_id: int, request: UpdateUserRole, session=Depends(auth.require_user)):
    auth.require_admin(session)
    if request.role not in ("admin", "guest"):
        raise HTTPException(status_code=400, detail="role must be 'admin' or 'guest'")

    with db_cursor() as cur:
        cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        target = cur.fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="user not found")
        if target["username"] == session["username"] and request.role != "admin":
            raise HTTPException(status_code=400, detail="you cannot demote your own account")
        cur.execute("UPDATE users SET role = ? WHERE id = ?", (request.role, user_id))

    auth.log_action(session["username"], "update_user_role", f"{target['username']} -> {request.role}")
    return {"ok": True}


@app.delete("/users/{user_id}")
def delete_user(user_id: int, session=Depends(auth.require_user)):
    auth.require_admin(session)
    with db_cursor() as cur:
        cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        target = cur.fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="user not found")
        if target["username"] == session["username"]:
            raise HTTPException(status_code=400, detail="you cannot delete your own account")
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        cur.execute("DELETE FROM sessions WHERE username = ?", (target["username"],))

    auth.log_action(session["username"], "delete_user", target["username"])
    return {"ok": True}


# ---------------------------------------------------------------- Monitoring
@app.get("/hosts")
def host_alive(subnet: str = None, ips: str = None, session=Depends(auth.require_user)):
    """
    Ping sweep. Examples:
    /hosts                                 -> scans default list
    /hosts?ips=127.0.0.1,8.8.8.8            -> scans specific ips
    /hosts?subnet=192.168.1.0/24            -> scans whole subnet
    """
    target_ips = nettools.resolve_targets(subnet, ips)
    result = nettools.sweep(target_ips)

    with db_cursor() as cur:
        for detail in result["details"]:
            cur.execute(
                "INSERT INTO ping_history (ip, alive, latency_ms) VALUES (?, ?, ?)",
                (detail["ip"], int(detail["alive"]), detail["latency_ms"]),
            )
    return result


@app.get("/ping-history")
def ping_history(ip: str, hours: int = 24, session=Depends(auth.require_user)):
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    with db_cursor() as cur:
        cur.execute(
            "SELECT alive, latency_ms, checked_at FROM ping_history "
            "WHERE ip = ? AND checked_at >= ? ORDER BY checked_at ASC",
            (ip, since),
        )
        rows = [dict(r) for r in cur.fetchall()]

    total = len(rows)
    up = sum(1 for r in rows if r["alive"])
    uptime_pct = round((up / total) * 100, 2) if total else None
    return {"ip": ip, "uptime_pct": uptime_pct, "samples": total, "history": rows}


@app.get("/monitor/summary")
def monitor_summary(session=Depends(auth.require_user)):
    """Dashboard summary: latest status of every known device."""
    with db_cursor() as cur:
        cur.execute("SELECT id, name, ip, device_type, vendor FROM devices")
        devices = [dict(r) for r in cur.fetchall()]

    summary = []
    for d in devices:
        with db_cursor() as cur:
            cur.execute(
                "SELECT alive, latency_ms, checked_at FROM ping_history "
                "WHERE ip = ? ORDER BY checked_at DESC LIMIT 1",
                (d["ip"],),
            )
            last = cur.fetchone()
        summary.append({
            **d,
            "last_status": "UP" if last and last["alive"] else ("DOWN" if last else "UNKNOWN"),
            "last_latency_ms": last["latency_ms"] if last else None,
            "last_checked": last["checked_at"] if last else None,
        })
    return {"devices": summary}


# ------------------------------------------------------------------ Devices
@app.get("/devices")
def list_devices(session=Depends(auth.require_user)):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM devices ORDER BY name")
        return [dict(r) for r in cur.fetchall()]


@app.post("/devices")
def add_device(device: DeviceIn, session=Depends(auth.require_user)):
    try:
        with db_cursor() as cur:
            cur.execute(
                "INSERT INTO devices (name, ip, device_type, vendor, ssh_port, tags, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (device.name, device.ip, device.device_type, device.vendor,
                 device.ssh_port, device.tags, device.notes),
            )
            new_id = cur.lastrowid
    except Exception:
        raise HTTPException(status_code=409, detail="a device with this IP already exists")
    auth.log_action(session["username"], "add_device", f"{device.name} ({device.ip})")
    return {"ok": True, "id": new_id}


@app.put("/devices/{device_id}")
def update_device(device_id: int, device: DeviceIn, session=Depends(auth.require_user)):
    with db_cursor() as cur:
        cur.execute(
            "UPDATE devices SET name=?, ip=?, device_type=?, vendor=?, ssh_port=?, tags=?, notes=? "
            "WHERE id=?",
            (device.name, device.ip, device.device_type, device.vendor,
             device.ssh_port, device.tags, device.notes, device_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="device not found")
    return {"ok": True}


@app.delete("/devices/{device_id}")
def delete_device(device_id: int, session=Depends(auth.require_user)):
    auth.require_admin(session)
    with db_cursor() as cur:
        cur.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="device not found")
    auth.log_action(session["username"], "delete_device", str(device_id))
    return {"ok": True}


# -------------------------------------------------------------- Diagnostics
@app.get("/tools/port-scan")
def port_scan(host: str, ports: str = None, session=Depends(auth.require_user)):
    port_list = [int(p.strip()) for p in ports.split(",")] if ports else None
    return nettools.port_scan(host, port_list)


@app.get("/tools/dns")
def dns_lookup(host: str, session=Depends(auth.require_user)):
    return nettools.dns_lookup(host)


@app.get("/tools/traceroute")
def traceroute(host: str, session=Depends(auth.require_user)):
    return nettools.traceroute(host)


@app.get("/tools/subnet")
def subnet_calc(cidr: str, session=Depends(auth.require_user)):
    try:
        return nettools.subnet_info(cidr)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ------------------------------------------------------------------ Backups
@app.post("/backups/run")
def run_backup(request: BackupRequest, session=Depends(auth.require_user)):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM devices WHERE id = ?", (request.device_id,))
        device = cur.fetchone()
    if not device:
        raise HTTPException(status_code=404, detail="device not found")

    result = backup.fetch_config_via_ssh(
        host=device["ip"], username=request.username, password=request.password,
        port=device["ssh_port"], vendor=device["vendor"],
    )
    if not result["ok"]:
        raise HTTPException(status_code=502, detail=f"SSH/config fetch failed: {result['error']}")

    save_result = backup.save_backup(request.device_id, result["config_text"])
    auth.log_action(session["username"], "config_backup", device["name"])
    return save_result


@app.get("/backups/{device_id}")
def get_backups(device_id: int, session=Depends(auth.require_user)):
    return backup.list_backups(device_id)


@app.get("/backups/text/{backup_id}")
def get_backup_text(backup_id: int, session=Depends(auth.require_user)):
    result = backup.get_backup(backup_id)
    if not result:
        raise HTTPException(status_code=404, detail="backup not found")
    return result


@app.get("/backups/diff")
def diff_backups(a: int = Query(...), b: int = Query(...), session=Depends(auth.require_user)):
    result = backup.diff_backups(a, b)
    if not result["ok"]:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# --------------------------------------------------------- Device commands
@app.post("/devices/{device_id}/exec")
def exec_device_commands(device_id: int, request: RunCommandsRequest, session=Depends(auth.require_user)):
    """
    Runs one or more CLI/config lines on a device over SSH. Admin-only,
    and every attempt (success or failure) is written to the audit log
    with the exact command text, so this is traceable after the fact.
    """
    auth.require_admin(session)

    if device_id != request.device_id:
        raise HTTPException(status_code=400, detail="device_id in path and body must match")

    with db_cursor() as cur:
        cur.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
        device = cur.fetchone()
    if not device:
        raise HTTPException(status_code=404, detail="device not found")

    result = commands.run_commands(
        host=device["ip"], username=request.username, password=request.password,
        commands=request.commands, port=device["ssh_port"], vendor=device["vendor"],
        enter_config_mode=request.enter_config_mode,
    )

    command_summary = " | ".join(request.commands)
    auth.log_action(
        session["username"],
        "device_exec" if result["ok"] else "device_exec_failed",
        f"{device['name']} ({device['ip']}): {command_summary}",
    )

    if not result["ok"]:
        raise HTTPException(status_code=502, detail=result["error"])
    return result


# --------------------------------------------------------------- Audit log
@app.get("/audit-log")
def audit_log(limit: int = 100, session=Depends(auth.require_user)):
    auth.require_admin(session)
    with db_cursor() as cur:
        cur.execute("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
