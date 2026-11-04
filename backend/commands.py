"""
NetWatch - Device command execution ("push config" / run CLI on a device).

Sends one or more CLI lines to a network device over SSH, into the
DEVICE's own command interpreter (Cisco IOS exec/config mode, Junos CLI,
RouterOS console, a shell on a Linux host, etc). This module never touches
the NetWatch backend's own operating system — there is no subprocess,
os.system, or eval() of any kind here, only paramiko's exec_command /
invoke_shell talking to the remote device.

Guardrails are enforced by the caller (backend.py):
  - only admins may reach this
  - every call is written to audit_log with the exact command text
  - credentials are used in-memory for one connection and never stored
This module itself stays a thin, dumb transport layer on purpose.
"""
import time

try:
    import paramiko
    HAVE_PARAMIKO = True
except ImportError:
    HAVE_PARAMIKO = False

# A short list of substrings that block a command outright. This is not a
# security boundary (there is no reliable blocklist for arbitrary CLI
# syntax across vendors) — it exists purely to stop obvious foot-guns like
# wiping a device's own config or rebooting it as a side effect of what
# looks like a routine change.
DANGEROUS_SUBSTRINGS = [
    "write erase", "erase startup-config", "erase nvram",
    "format ", "reload", "reboot", "delete flash",
    "no ip address", "shutdown\n", "factory-reset", "factory reset",
]


def _looks_dangerous(command: str) -> str | None:
    lowered = command.lower()
    for needle in DANGEROUS_SUBSTRINGS:
        if needle in lowered:
            return needle
    return None


def run_commands(host: str, username: str, password: str, commands: list[str],
                  port: int = 22, timeout_s: int = 10, enter_config_mode: bool = False,
                  vendor: str = "generic") -> dict:
    """
    Runs a list of CLI lines against a device over one SSH session and
    returns the combined output per command. Uses an interactive shell
    (invoke_shell) rather than one-shot exec_command per line, since most
    network OSes expect a persistent CLI session (e.g. to stay in
    'configure terminal' mode across lines).
    """
    if not HAVE_PARAMIKO:
        return {"ok": False, "error": "paramiko not installed on the backend. Run: pip install paramiko --break-system-packages"}

    if not commands:
        return {"ok": False, "error": "no commands provided"}

    blocked = [(c, _looks_dangerous(c)) for c in commands]
    blocked = [(c, reason) for c, reason in blocked if reason]
    if blocked:
        lines = "; ".join(f"'{c}' (matches '{reason}')" for c, reason in blocked)
        return {
            "ok": False,
            "error": f"Refused: command(s) look destructive and were blocked: {lines}. "
                     f"If this is intentional, run it directly on the device console instead of through NetWatch.",
        }

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    transcript = []
    try:
        client.connect(
            hostname=host, port=port, username=username, password=password,
            timeout=timeout_s, look_for_keys=False, allow_agent=False,
        )

        shell = client.invoke_shell()
        time.sleep(1)
        if shell.recv_ready():
            shell.recv(65535)  # discard the login banner/prompt

        if enter_config_mode and vendor in ("cisco_ios", "cisco_nxos", "generic"):
            commands = ["configure terminal", *commands, "end"]

        for cmd in commands:
            shell.send(cmd + "\n")
            time.sleep(1.2)
            output = ""
            while shell.recv_ready():
                output += shell.recv(65535).decode(errors="replace")
                time.sleep(0.2)
            transcript.append({"command": cmd, "output": output.strip()})

        client.close()
        return {"ok": True, "transcript": transcript}

    except Exception as e:
        return {"ok": False, "error": str(e), "transcript": transcript}
    finally:
        try:
            client.close()
        except Exception:
            pass
