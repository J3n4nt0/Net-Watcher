"""
NetWatcher - SNMP v1/v2c client (stdlib only).

Hand-rolled BER encoding so there is no dependency on pysnmp or the net-snmp
command line tools. Supports GET, GETNEXT and GETBULK (v2c), which is all a
read-only inventory query needs. SNMPv3 is NOT supported.

query_host() collects, in one call:
  - system group (name, description, vendor, uptime, contact, location)
  - interface table (status, speed, MAC, traffic counters, errors)
  - IP addresses configured on the host
  - host-resources MIB (CPU load, RAM/disk usage) when the agent exposes it

This module is read-only: it never sends SET requests.
"""
import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor

# ----------------------------------------------------------------- Errors --


class SnmpError(Exception):
    pass


class SnmpTimeout(SnmpError):
    pass


# ------------------------------------------------------------- BER / tags --
INTEGER, OCTET_STRING, NULL, OID, SEQUENCE = 0x02, 0x04, 0x05, 0x06, 0x30
IPADDRESS, COUNTER32, GAUGE32, TIMETICKS, OPAQUE, COUNTER64 = 0x40, 0x41, 0x42, 0x43, 0x44, 0x46
NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW = 0x80, 0x81, 0x82
GET, GETNEXT, RESPONSE, GETBULK = 0xA0, 0xA1, 0xA2, 0xA5

MISSING = object()  # sentinel for noSuchObject / noSuchInstance / endOfMibView

ERROR_NAMES = {1: "tooBig", 2: "noSuchName", 3: "badValue", 4: "readOnly",
               5: "genErr", 16: "authorizationError"}


def parse_oid(text: str) -> tuple:
    return tuple(int(part) for part in text.strip(".").split("."))


def oid_to_str(oid: tuple) -> str:
    return ".".join(str(n) for n in oid)


def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(payload)) + payload


def _enc_int(value: int) -> bytes:
    length = 1
    while True:
        try:
            raw = value.to_bytes(length, "big", signed=True)
            break
        except OverflowError:
            length += 1
    return _tlv(INTEGER, raw)


def _enc_oid(oid: tuple) -> bytes:
    if len(oid) < 2:
        raise SnmpError("OID too short")
    body = bytearray([oid[0] * 40 + oid[1]])
    for sub in oid[2:]:
        chunk = [sub & 0x7F]
        sub >>= 7
        while sub:
            chunk.append(0x80 | (sub & 0x7F))
            sub >>= 7
        body.extend(reversed(chunk))
    return _tlv(OID, bytes(body))


def _read_tlv(data: bytes, pos: int):
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    end = pos + length
    if end > len(data):
        raise SnmpError("truncated SNMP packet")
    return tag, data[pos:end], end


def _dec_oid(raw: bytes) -> tuple:
    subs, value = [], 0
    for byte in raw:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            subs.append(value)
            value = 0
    first = subs[0]
    if first < 40:
        head = (0, first)
    elif first < 80:
        head = (1, first - 40)
    else:
        head = (2, first - 80)
    return head + tuple(subs[1:])


def _dec_value(tag: int, raw: bytes):
    if tag == INTEGER:
        return int.from_bytes(raw, "big", signed=True) if raw else 0
    if tag in (COUNTER32, GAUGE32, TIMETICKS, COUNTER64):
        return int.from_bytes(raw, "big")
    if tag == IPADDRESS:
        return ".".join(str(b) for b in raw)
    if tag == OID:
        return _dec_oid(raw)
    if tag == NULL:
        return None
    if tag in (NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW):
        return MISSING
    return bytes(raw)  # OCTET STRING, Opaque, anything unknown


def build_message(version: int, community: str, pdu_tag: int, request_id: int,
                  oids, field_a: int = 0, field_b: int = 0) -> bytes:
    """field_a/field_b are error-status/error-index, or non-repeaters/
    max-repetitions for GETBULK."""
    varbinds = b"".join(_tlv(SEQUENCE, _enc_oid(o) + _tlv(NULL, b"")) for o in oids)
    pdu = _tlv(pdu_tag, _enc_int(request_id) + _enc_int(field_a) + _enc_int(field_b)
               + _tlv(SEQUENCE, varbinds))
    return _tlv(SEQUENCE, _enc_int(version) + _tlv(OCTET_STRING, community.encode()) + pdu)


def parse_message(data: bytes):
    """Returns (version, community, pdu_tag, request_id, field_a, field_b, varbinds)."""
    try:
        tag, msg, _ = _read_tlv(data, 0)
        if tag != SEQUENCE:
            raise SnmpError("not an SNMP message")
        _, ver, pos = _read_tlv(msg, 0)
        _, comm, pos = _read_tlv(msg, pos)
        pdu_tag, pdu, _ = _read_tlv(msg, pos)
        _, rid, p = _read_tlv(pdu, 0)
        _, fa, p = _read_tlv(pdu, p)
        _, fb, p = _read_tlv(pdu, p)
        _, vbl, _ = _read_tlv(pdu, p)
        varbinds, q = [], 0
        while q < len(vbl):
            _, vb, q = _read_tlv(vbl, q)
            otag, ob, r = _read_tlv(vb, 0)
            vtag, vv, _ = _read_tlv(vb, r)
            if otag != OID:
                raise SnmpError("malformed varbind")
            varbinds.append((_dec_oid(ob), _dec_value(vtag, vv)))
    except (IndexError, ValueError) as exc:
        raise SnmpError("malformed SNMP packet") from exc
    signed = lambda b: int.from_bytes(b, "big", signed=True)
    return signed(ver), comm, pdu_tag, signed(rid), signed(fa), signed(fb), varbinds


# ----------------------------------------------------------------- Client --
class SnmpClient:
    def __init__(self, host: str, community: str = "public", version: str = "2c",
                 port: int = 161, timeout_s: float = 2.0, retries: int = 1):
        self.host = host
        self.community = community
        self.version = 0 if version == "1" else 1
        self.port = port
        self.timeout_s = timeout_s
        self.retries = retries

    def _request(self, pdu_tag: int, oids, field_a: int = 0, field_b: int = 0):
        try:
            family, _, _, _, addr = socket.getaddrinfo(
                self.host, self.port, type=socket.SOCK_DGRAM)[0]
        except socket.gaierror as exc:
            raise SnmpError(f"cannot resolve host '{self.host}'") from exc

        request_id = random.randint(1, 0x7FFFFFFF)
        packet = build_message(self.version, self.community, pdu_tag, request_id,
                               oids, field_a, field_b)
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                for _ in range(self.retries + 1):
                    sock.sendto(packet, addr)
                    deadline = time.monotonic() + self.timeout_s
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            break
                        sock.settimeout(remaining)
                        try:
                            data, _ = sock.recvfrom(65535)
                        except socket.timeout:
                            break
                        try:
                            parsed = parse_message(data)
                        except SnmpError:
                            continue
                        if parsed[2] != RESPONSE or parsed[3] != request_id:
                            continue
                        return parsed  # (.., error_status=parsed[4], error_index=parsed[5], varbinds=parsed[6])
        except OSError as exc:
            raise SnmpError(f"network error: {exc}") from exc

        raise SnmpTimeout(
            f"No SNMP response from {self.host}:{self.port}. Check that SNMP is enabled, "
            f"the community string and version are right, and UDP {self.port} is reachable."
        )

    def get(self, oids) -> dict:
        """GET several OIDs; returns {oid: value} for the ones that exist."""
        oids = list(oids)
        parsed = self._request(GET, oids)
        status, varbinds = parsed[4], parsed[6]
        if status == 0:
            return {oid: val for oid, val in varbinds if val is not MISSING}
        if status == 2:  # SNMPv1 noSuchName: one bad OID fails the whole request
            if len(oids) == 1:
                return {}
            result = {}
            for oid in oids:
                result.update(self.get([oid]))
            return result
        raise SnmpError(f"agent returned {ERROR_NAMES.get(status, f'error {status}')}")

    def walk(self, base: tuple, max_rows: int = 2000) -> list:
        """Walk a subtree; returns [(oid, value)] in order."""
        rows, current, last = [], base, base
        while len(rows) < max_rows:
            if self.version == 1:
                parsed = self._request(GETBULK, [current], 0, 25)
            else:
                parsed = self._request(GETNEXT, [current])
            status, varbinds = parsed[4], parsed[6]
            if status == 2:  # v1 end of MIB
                break
            if status != 0:
                raise SnmpError(f"agent returned {ERROR_NAMES.get(status, f'error {status}')}")
            advanced = False
            for oid, val in varbinds:
                if val is MISSING or oid[:len(base)] != base or oid <= last:
                    return rows
                rows.append((oid, val))
                last = oid
                advanced = True
            if not advanced:
                break
            current = last
        return rows


# --------------------------------------------------------------- Formatting
def _text(value) -> str:
    if value is None or value is MISSING:
        return ""
    if isinstance(value, bytes):
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError:
            text = value.decode("latin-1")
        return "".join(ch for ch in text if ch.isprintable() or ch in "\n\t").strip()
    if isinstance(value, tuple):
        return oid_to_str(value)
    return str(value)


def _mac(value) -> str:
    if isinstance(value, bytes) and len(value) == 6:
        return ":".join(f"{b:02x}" for b in value)
    return ""


def _int(value):
    return value if isinstance(value, int) else None


def human_uptime(seconds) -> str:
    if seconds is None:
        return ""
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if days or hours:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


ENTERPRISES = {
    9: "Cisco", 11: "HP", 171: "D-Link", 311: "Microsoft", 674: "Dell", 890: "Zyxel",
    1588: "Brocade", 1916: "Extreme Networks", 2011: "Huawei", 2636: "Juniper",
    4526: "Netgear", 6486: "Alcatel-Lucent", 6527: "Nokia", 6574: "Synology",
    8072: "Net-SNMP (Linux/Unix agent)", 10002: "Ubiquiti", 11863: "TP-Link",
    12356: "Fortinet", 14823: "Aruba", 14988: "MikroTik", 25053: "Ruckus",
    25461: "Palo Alto", 25506: "H3C", 30065: "Arista", 41112: "Ubiquiti",
}


def _vendor(object_id: tuple) -> str:
    prefix = (1, 3, 6, 1, 4, 1)
    if len(object_id) > len(prefix) and object_id[:len(prefix)] == prefix:
        number = object_id[len(prefix)]
        return ENTERPRISES.get(number, f"Enterprise #{number}")
    return ""


IF_STATUS = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant",
             6: "notPresent", 7: "lowerLayerDown"}
IF_TYPES = {1: "other", 6: "ethernet", 23: "ppp", 24: "loopback", 53: "virtual",
            71: "wifi", 131: "tunnel", 135: "vlan", 161: "lag"}
STORAGE_TYPES = {1: "other", 2: "ram", 3: "virtual memory", 4: "disk", 5: "removable disk",
                 6: "floppy", 7: "optical disk", 8: "ram disk", 9: "flash", 10: "network disk"}
STORAGE_TYPE_PREFIX = parse_oid("1.3.6.1.2.1.25.2.1")

# ------------------------------------------------------------------- OIDs --
SYSTEM_OIDS = {
    "description": parse_oid("1.3.6.1.2.1.1.1.0"),
    "object_id": parse_oid("1.3.6.1.2.1.1.2.0"),
    "uptime": parse_oid("1.3.6.1.2.1.1.3.0"),
    "contact": parse_oid("1.3.6.1.2.1.1.4.0"),
    "name": parse_oid("1.3.6.1.2.1.1.5.0"),
    "location": parse_oid("1.3.6.1.2.1.1.6.0"),
    "services": parse_oid("1.3.6.1.2.1.1.7.0"),
}
_IF = "1.3.6.1.2.1.2.2.1."
_IFX = "1.3.6.1.2.1.31.1.1.1."
_IP = "1.3.6.1.2.1.4.20.1."
_HR_STORAGE = "1.3.6.1.2.1.25.2.3.1."
TABLES = {
    "if": {
        "descr": _IF + "2", "type": _IF + "3", "speed": _IF + "5", "mac": _IF + "6",
        "admin": _IF + "7", "oper": _IF + "8", "in_octets": _IF + "10",
        "in_errors": _IF + "14", "out_octets": _IF + "16", "out_errors": _IF + "20",
        "name": _IFX + "1", "hc_in": _IFX + "6", "hc_out": _IFX + "10",
        "high_speed": _IFX + "15", "alias": _IFX + "18",
    },
    "ip": {"addr": _IP + "1", "ifindex": _IP + "2", "mask": _IP + "3"},
    "hr": {
        "cpu": "1.3.6.1.2.1.25.3.3.1.2",
        "st_type": _HR_STORAGE + "2", "st_descr": _HR_STORAGE + "3",
        "st_units": _HR_STORAGE + "4", "st_size": _HR_STORAGE + "5",
        "st_used": _HR_STORAGE + "6",
    },
}


# -------------------------------------------------------------- Collector --
def _build_system(got: dict) -> dict:
    def val(key):
        return got.get(SYSTEM_OIDS[key])

    object_id = val("object_id") if isinstance(val("object_id"), tuple) else ()
    ticks = _int(val("uptime"))
    uptime_s = ticks // 100 if ticks is not None else None
    services = _int(val("services"))
    layers = [n for n in range(1, 8) if services and services & (1 << (n - 1))]
    return {
        "name": _text(val("name")),
        "description": _text(val("description")),
        "object_id": oid_to_str(object_id),
        "vendor": _vendor(object_id),
        "uptime_seconds": uptime_s,
        "uptime_human": human_uptime(uptime_s),
        "contact": _text(val("contact")),
        "location": _text(val("location")),
        "layers": layers,
    }


def _build_interfaces(cols: dict) -> list:
    descr = cols.get("descr", {})
    interfaces = []
    for suffix in sorted(descr):
        def col(name):
            return cols.get(name, {}).get(suffix)

        high = _int(col("high_speed"))
        speed_bps = high * 1_000_000 if high else _int(col("speed"))
        hc_in, hc_out = _int(col("hc_in")), _int(col("hc_out"))
        admin, oper = _int(col("admin")), _int(col("oper"))
        iftype = _int(col("type"))
        interfaces.append({
            "index": suffix[0],
            "name": _text(col("name")) or _text(descr[suffix]),
            "descr": _text(descr[suffix]),
            "alias": _text(col("alias")),
            "type": IF_TYPES.get(iftype, str(iftype) if iftype is not None else ""),
            "speed_bps": speed_bps,
            "mac": _mac(col("mac")),
            "admin_status": IF_STATUS.get(admin, str(admin)) if admin is not None else None,
            "oper_status": IF_STATUS.get(oper, str(oper)) if oper is not None else None,
            "in_octets": hc_in if hc_in is not None else _int(col("in_octets")),
            "out_octets": hc_out if hc_out is not None else _int(col("out_octets")),
            "in_errors": _int(col("in_errors")),
            "out_errors": _int(col("out_errors")),
        })
    return interfaces


def _build_addresses(cols: dict) -> list:
    addresses = []
    for suffix, addr in sorted(cols.get("addr", {}).items()):
        addresses.append({
            "ip": _text(addr) or ".".join(str(n) for n in suffix),
            "netmask": _text(cols.get("mask", {}).get(suffix)),
            "if_index": _int(cols.get("ifindex", {}).get(suffix)),
        })
    return addresses


def _build_host_resources(cols: dict) -> dict:
    cpu = [v for _, v in sorted(cols.get("cpu", {}).items()) if isinstance(v, int)]
    storage = []
    for suffix in sorted(cols.get("st_descr", {})):
        units = _int(cols.get("st_units", {}).get(suffix)) or 0
        size = _int(cols.get("st_size", {}).get(suffix)) or 0
        used = _int(cols.get("st_used", {}).get(suffix)) or 0
        if size <= 0:
            continue
        type_oid = cols.get("st_type", {}).get(suffix)
        kind = "other"
        if isinstance(type_oid, tuple) and type_oid[:len(STORAGE_TYPE_PREFIX)] == STORAGE_TYPE_PREFIX:
            kind = STORAGE_TYPES.get(type_oid[-1], "other")
        storage.append({
            "descr": _text(cols["st_descr"][suffix]),
            "type": kind,
            "size_bytes": size * units,
            "used_bytes": used * units,
            "used_pct": round(used / size * 100, 1),
        })
    return {
        "cpu_loads": cpu,
        "cpu_avg": round(sum(cpu) / len(cpu), 1) if cpu else None,
        "storage": storage,
    }


def query_host(host: str, community: str = "public", version: str = "2c",
               port: int = 161, timeout_s: float = 2.0) -> dict:
    client = SnmpClient(host, community, version, port, timeout_s)
    started = time.monotonic()

    got = client.get(SYSTEM_OIDS.values())  # raises SnmpTimeout if the host is silent
    if not got:
        raise SnmpError("Host answered but returned no system data - the community "
                        "string may not have read access to the system MIB.")

    # Walk every table column in parallel; a missing table just comes back empty.
    def safe_walk(base_text):
        base = parse_oid(base_text)
        try:
            return {oid[len(base):]: val for oid, val in client.walk(base)}
        except SnmpError:
            return {}

    jobs = {(group, name): base for group, cols in TABLES.items() for name, base in cols.items()}
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {key: pool.submit(safe_walk, base) for key, base in jobs.items()}
        columns = {group: {} for group in TABLES}
        for (group, name), future in futures.items():
            columns[group][name] = future.result()

    interfaces = _build_interfaces(columns["if"])
    up = sum(1 for i in interfaces if i["oper_status"] == "up")
    return {
        "ok": True,
        "host": host,
        "port": port,
        "version": version,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
        "system": _build_system(got),
        "interfaces": interfaces,
        "interface_summary": {"total": len(interfaces), "up": up, "down": len(interfaces) - up},
        "addresses": _build_addresses(columns["ip"]),
        "host_resources": _build_host_resources(columns["hr"]),
    }
