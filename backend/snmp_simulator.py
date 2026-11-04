"""
NetWatcher - SNMP agent simulator (development/testing aid, read-only).

Pretends to be a small 4-port switch/server so you can try the SNMP pages
without real hardware:

    python snmp_simulator.py                 # listens on 127.0.0.1:1161
    python snmp_simulator.py --bind 0.0.0.0  # reachable from other machines

Then add a device with IP 127.0.0.1, enable SNMP, port 1161, community
"public" (version 1 or 2c). Traffic counters increase over time, so the
live-rate columns in the UI show non-zero values.
"""
import argparse
import bisect
import socket
import time

import snmp

START = time.monotonic()


def T(text):
    return snmp.parse_oid(text)


def build_mib():
    """Returns {oid: (kind, value)}. Counters are refreshed per request."""
    mib = {}

    def put(oid, kind, value):
        mib[T(oid)] = (kind, value)

    put("1.3.6.1.2.1.1.1.0", "str", "NetWatcher Simulated Switch SW-48\nFirmware 1.2.3 (simulator)")
    put("1.3.6.1.2.1.1.2.0", "oid", T("1.3.6.1.4.1.9.1.1208"))
    put("1.3.6.1.2.1.1.4.0", "str", "noc@example.net")
    put("1.3.6.1.2.1.1.5.0", "str", "sim-switch-01")
    put("1.3.6.1.2.1.1.6.0", "str", "Server room, rack 3")
    put("1.3.6.1.2.1.1.7.0", "int", 78)  # layers 2, 3, 4, 7

    ports = [
        # index, name, alias, oper status, speed Mbps
        (1, "Gi0/1", "Uplink <core> & backup", 1, 1000),
        (2, "Gi0/2", "Access point", 1, 1000),
        (3, "Gi0/3", "", 2, 1000),
        (4, "Fa0/4", "Printer", 1, 100),
    ]
    for idx, name, alias, oper, mbps in ports:
        put(f"1.3.6.1.2.1.2.2.1.1.{idx}", "int", idx)
        put(f"1.3.6.1.2.1.2.2.1.2.{idx}", "str", f"GigabitEthernet0/{idx}")
        put(f"1.3.6.1.2.1.2.2.1.3.{idx}", "int", 6)
        put(f"1.3.6.1.2.1.2.2.1.5.{idx}", "gauge", mbps * 1_000_000)
        put(f"1.3.6.1.2.1.2.2.1.6.{idx}", "bytes", bytes([0x00, 0x1A, 0x2B, 0x3C, 0x4D, idx]))
        put(f"1.3.6.1.2.1.2.2.1.7.{idx}", "int", 1)
        put(f"1.3.6.1.2.1.2.2.1.8.{idx}", "int", oper)
        put(f"1.3.6.1.2.1.2.2.1.10.{idx}", "counter", 0)
        put(f"1.3.6.1.2.1.2.2.1.14.{idx}", "counter", idx - 1)
        put(f"1.3.6.1.2.1.2.2.1.16.{idx}", "counter", 0)
        put(f"1.3.6.1.2.1.2.2.1.20.{idx}", "counter", 0)
        put(f"1.3.6.1.2.1.31.1.1.1.1.{idx}", "str", name)
        put(f"1.3.6.1.2.1.31.1.1.1.6.{idx}", "counter64", 0)
        put(f"1.3.6.1.2.1.31.1.1.1.10.{idx}", "counter64", 0)
        put(f"1.3.6.1.2.1.31.1.1.1.15.{idx}", "gauge", mbps)
        put(f"1.3.6.1.2.1.31.1.1.1.18.{idx}", "str", alias)

    for ip, mask, ifindex in (("192.168.1.2", "255.255.255.0", 1), ("10.0.0.2", "255.255.255.252", 2)):
        put(f"1.3.6.1.2.1.4.20.1.1.{ip}", "ip", ip)
        put(f"1.3.6.1.2.1.4.20.1.2.{ip}", "int", ifindex)
        put(f"1.3.6.1.2.1.4.20.1.3.{ip}", "ip", mask)

    put("1.3.6.1.2.1.25.3.3.1.2.1", "int", 12)
    put("1.3.6.1.2.1.25.3.3.1.2.2", "int", 30)
    storage = [
        (1, "1.3.6.1.2.1.25.2.1.2", "Physical memory", 4096, 1_000_000, 640_000),
        (2, "1.3.6.1.2.1.25.2.1.4", "/", 4096, 25_000_000, 9_500_000),
        (3, "1.3.6.1.2.1.25.2.1.3", "Swap space", 4096, 250_000, 8_000),
    ]
    for idx, type_oid, descr, units, size, used in storage:
        put(f"1.3.6.1.2.1.25.2.3.1.1.{idx}", "int", idx)
        put(f"1.3.6.1.2.1.25.2.3.1.2.{idx}", "oid", T(type_oid))
        put(f"1.3.6.1.2.1.25.2.3.1.3.{idx}", "str", descr)
        put(f"1.3.6.1.2.1.25.2.3.1.4.{idx}", "int", units)
        put(f"1.3.6.1.2.1.25.2.3.1.5.{idx}", "int", size)
        put(f"1.3.6.1.2.1.25.2.3.1.6.{idx}", "int", used)
    return mib


def live_value(oid, kind, value):
    """Make uptime and traffic counters move so rates are visible."""
    elapsed = time.monotonic() - START
    if oid == T("1.3.6.1.2.1.1.3.0"):
        return "ticks", int((elapsed + 5 * 86400 + 3 * 3600) * 100)
    base = "1.3.6.1.2.1.2.2.1."
    for col, per_sec in ((10, 125_000), (16, 40_000)):  # ~1 Mbit/s in, ~0.3 Mbit/s out
        prefix = T(base + str(col))
        if oid[:len(prefix)] == prefix:
            if oid[-1] == 3:  # port 3 is down
                return kind, value
            return kind, int(elapsed * per_sec * oid[-1]) % (2 ** 32)
    for col, per_sec in ((6, 125_000), (10, 40_000)):
        prefix = T("1.3.6.1.2.1.31.1.1.1." + str(col))
        if oid[:len(prefix)] == prefix and oid[-1] != 3:
            return kind, int(elapsed * per_sec * oid[-1])
    return kind, value


def enc_value(kind, value):
    if kind == "int":
        return snmp._enc_int(value)
    if kind == "str":
        return snmp._tlv(snmp.OCTET_STRING, value.encode())
    if kind == "bytes":
        return snmp._tlv(snmp.OCTET_STRING, value)
    if kind == "oid":
        return snmp._enc_oid(value)
    if kind == "ip":
        return snmp._tlv(snmp.IPADDRESS, bytes(int(x) for x in value.split(".")))
    if kind == "missing":
        return bytes([value, 0])
    if kind == "null":
        return snmp._tlv(snmp.NULL, b"")
    tag = {"counter": snmp.COUNTER32, "gauge": snmp.GAUGE32,
           "ticks": snmp.TIMETICKS, "counter64": snmp.COUNTER64}[kind]
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return snmp._tlv(tag, raw)


def handle(data, mib, keys, community):
    version, comm, pdu_tag, request_id, field_a, field_b, varbinds = snmp.parse_message(data)
    if comm != community.encode():
        return None  # real agents stay silent on a bad community
    v1 = version == 0
    oids = [oid for oid, _ in varbinds]
    out, status, index = [], 0, 0

    def next_key(oid):
        pos = bisect.bisect_right(keys, oid)
        return keys[pos] if pos < len(keys) else None

    if pdu_tag == snmp.GET:
        for i, oid in enumerate(oids, 1):
            if oid in mib:
                out.append((oid, mib[oid]))
            elif v1:
                status, index = 2, i
                out.append((oid, ("null", None)))
            else:
                out.append((oid, ("missing", snmp.NO_SUCH_OBJECT)))
    elif pdu_tag == snmp.GETNEXT:
        for i, oid in enumerate(oids, 1):
            nxt = next_key(oid)
            if nxt:
                out.append((nxt, mib[nxt]))
            elif v1:
                status, index = 2, i
                out.append((oid, ("null", None)))
            else:
                out.append((oid, ("missing", snmp.END_OF_MIB_VIEW)))
    elif pdu_tag == snmp.GETBULK:
        current = oids[0]
        for _ in range(min(field_b, 50)):
            nxt = next_key(current)
            if not nxt:
                out.append((current, ("missing", snmp.END_OF_MIB_VIEW)))
                break
            out.append((nxt, mib[nxt]))
            current = nxt
    else:
        return None

    varbind_bytes = b""
    for oid, (kind, value) in out:
        if kind not in ("missing", "null"):
            kind, value = live_value(oid, kind, value)
        varbind_bytes += snmp._tlv(snmp.SEQUENCE, snmp._enc_oid(oid) + enc_value(kind, value))
    pdu = snmp._tlv(snmp.RESPONSE, snmp._enc_int(request_id) + snmp._enc_int(status)
                    + snmp._enc_int(index) + snmp._tlv(snmp.SEQUENCE, varbind_bytes))
    return snmp._tlv(snmp.SEQUENCE, snmp._enc_int(version)
                     + snmp._tlv(snmp.OCTET_STRING, comm) + pdu)


def serve(bind, port, community):
    mib = build_mib()
    mib[T("1.3.6.1.2.1.1.3.0")] = ("ticks", 0)
    keys = sorted(mib)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((bind, port))
        print(f"SNMP simulator listening on {bind}:{port}/udp, community '{community}' (v1 + v2c)")
        while True:
            data, addr = sock.recvfrom(65535)
            try:
                reply = handle(data, mib, keys, community)
            except Exception as exc:  # never die on a malformed packet
                print("bad packet from", addr, exc)
                continue
            if reply:
                sock.sendto(reply, addr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetWatcher SNMP agent simulator")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1161)
    parser.add_argument("--community", default="public")
    args = parser.parse_args()
    serve(args.bind, args.port, args.community)
