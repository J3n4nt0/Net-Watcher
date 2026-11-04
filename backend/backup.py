"""
NetWatch - Device config backup.
Pulls the running config over SSH (paramiko) and stores it versioned in
SQLite, hashed so we can detect drift between backups without diffing
full text every time.
"""
import difflib
import hashlib

from database import db_cursor

try:
    import paramiko
    HAVE_PARAMIKO = True
except ImportError:
    HAVE_PARAMIKO = False

# Command used to dump config, per vendor/platform. Extend as needed.
CONFIG_COMMANDS = {
    "cisco_ios": "show running-config",
    "cisco_nxos": "show running-config",
    "juniper": "show configuration | display set",
    "mikrotik": "/export",
    "linux": "cat /etc/network/interfaces 2>/dev/null; ip addr show",
    "generic": "show running-config",
}


def fetch_config_via_ssh(host: str, username: str, password: str,
                          port: int = 22, vendor: str = "generic",
                          timeout_s: int = 10) -> dict:
    """Connects over SSH and runs the vendor's config-dump command.
    Credentials are used in-memory only and never persisted."""
    if not HAVE_PARAMIKO:
        return {
            "ok": False,
            "error": "paramiko not installed on the backend. Run: pip install paramiko --break-system-packages",
        }

    command = CONFIG_COMMANDS.get(vendor, CONFIG_COMMANDS["generic"])
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host, port=port, username=username, password=password,
            timeout=timeout_s, look_for_keys=False, allow_agent=False,
        )
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout_s)
        output = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        client.close()
        if not output and err:
            return {"ok": False, "error": err.strip()}
        return {"ok": True, "config_text": output}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        try:
            client.close()
        except Exception:
            pass


def save_backup(device_id: int, config_text: str) -> dict:
    config_hash = hashlib.sha256(config_text.encode()).hexdigest()

    with db_cursor() as cur:
        cur.execute(
            "SELECT config_hash FROM config_backups WHERE device_id = ? ORDER BY taken_at DESC LIMIT 1",
            (device_id,),
        )
        last = cur.fetchone()

    if last and last["config_hash"] == config_hash:
        return {"saved": False, "reason": "unchanged since last backup", "config_hash": config_hash}

    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO config_backups (device_id, config_text, config_hash) VALUES (?, ?, ?)",
            (device_id, config_text, config_hash),
        )
        new_id = cur.lastrowid

    return {"saved": True, "backup_id": new_id, "config_hash": config_hash, "changed": last is not None}


def list_backups(device_id: int) -> list[dict]:
    with db_cursor() as cur:
        cur.execute(
            "SELECT id, config_hash, taken_at, LENGTH(config_text) as size_bytes "
            "FROM config_backups WHERE device_id = ? ORDER BY taken_at DESC",
            (device_id,),
        )
        return [dict(row) for row in cur.fetchall()]


def get_backup(backup_id: int) -> dict | None:
    with db_cursor() as cur:
        cur.execute("SELECT * FROM config_backups WHERE id = ?", (backup_id,))
        row = cur.fetchone()
    return dict(row) if row else None


def diff_backups(backup_id_a: int, backup_id_b: int) -> dict:
    a = get_backup(backup_id_a)
    b = get_backup(backup_id_b)
    if not a or not b:
        return {"ok": False, "error": "one or both backup IDs not found"}

    diff = difflib.unified_diff(
        a["config_text"].splitlines(keepends=True),
        b["config_text"].splitlines(keepends=True),
        fromfile=f"backup_{backup_id_a} ({a['taken_at']})",
        tofile=f"backup_{backup_id_b} ({b['taken_at']})",
    )
    return {"ok": True, "diff": "".join(diff)}
