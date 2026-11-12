"""Мінімальний SNMP v2c клієнт (GET / GETBULK-walk) на stdlib — без pysnmp/net-snmp.

Потрібен netdiag-боту: на mdlwr01 немає ні net-snmp, ні pysnmp, а нам вистачає
двох операцій тільки на читання. BER-кодування — рівно те, що потрібно для
v2c GetRequest/GetBulkRequest і розбору Response.
"""
from __future__ import annotations

import os
import socket
import struct

# ---------------------------------------------------------------- BER encode

def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _len(len(val)) + val


def _int(v: int) -> bytes:
    n = max(1, (v.bit_length() + 8) // 8)
    return _tlv(0x02, v.to_bytes(n, "big", signed=True))


def _oid_enc(oid: str) -> bytes:
    p = [int(x) for x in oid.strip(".").split(".")]
    out = bytearray([p[0] * 40 + p[1]])
    for x in p[2:]:
        chunk = [x & 0x7F]
        x >>= 7
        while x:
            chunk.append(0x80 | (x & 0x7F))
            x >>= 7
        out += bytes(reversed(chunk))
    return _tlv(0x06, bytes(out))


def _msg(community: str, pdu_tag: int, req_id: int, a: int, b: int, oids: list[str]) -> bytes:
    vbs = b"".join(_tlv(0x30, _oid_enc(o) + b"\x05\x00") for o in oids)
    pdu = _tlv(pdu_tag, _int(req_id) + _int(a) + _int(b) + _tlv(0x30, vbs))
    return _tlv(0x30, _int(1) + _tlv(0x04, community.encode()) + pdu)

# ---------------------------------------------------------------- BER decode

def _rd(buf: bytes, i: int):
    tag = buf[i]
    ln = buf[i + 1]
    i += 2
    if ln & 0x80:
        k = ln & 0x7F
        ln = int.from_bytes(buf[i:i + k], "big")
        i += k
    return tag, buf[i:i + ln], i + ln


def _oid_dec(b: bytes) -> str:
    p = [b[0] // 40, b[0] % 40]
    x = 0
    for c in b[1:]:
        x = (x << 7) | (c & 0x7F)
        if not c & 0x80:
            p.append(x)
            x = 0
    return ".".join(map(str, p))


class EndOfMib:
    pass


END = EndOfMib()


def _val(tag: int, v: bytes):
    if tag in (0x02,):
        return int.from_bytes(v, "big", signed=True) if v else 0
    if tag in (0x41, 0x42, 0x43, 0x46):  # Counter32, Gauge32, TimeTicks, Counter64
        return int.from_bytes(v, "big") if v else 0
    if tag == 0x04:
        return v  # OCTET STRING — bytes; caller decides (MAC vs text)
    if tag == 0x06:
        return _oid_dec(v)
    if tag == 0x40:
        return ".".join(map(str, v))  # IpAddress
    if tag == 0x05:
        return None
    if tag in (0x80, 0x81, 0x82):  # noSuchObject / noSuchInstance / endOfMibView
        return END
    return v


def _parse(resp: bytes):
    _, msg, _ = _rd(resp, 0)
    i = 0
    _, _, i = _rd(msg, i)  # version
    _, _, i = _rd(msg, i)  # community
    _, pdu, _ = _rd(msg, i)
    j = 0
    _, rid, j = _rd(pdu, j)
    _, err, j = _rd(pdu, j)
    _, _, j = _rd(pdu, j)
    _, vbl, _ = _rd(pdu, j)
    out = []
    k = 0
    while k < len(vbl):
        _, vb, k = _rd(vbl, k)
        _, o, m = _rd(vb, 0)
        t, v, _ = _rd(vb, m)
        out.append((_oid_dec(o), _val(t, v)))
    return int.from_bytes(rid, "big", signed=True), int.from_bytes(err, "big"), out

# ---------------------------------------------------------------- API


class SnmpError(Exception):
    pass


class Session:
    def __init__(self, host: str, community: str, timeout: float = 2.0, retries: int = 1, port: int = 161):
        self.addr = (host, port)
        self.community = community
        self.timeout = timeout
        self.retries = retries

    def _rpc(self, tag: int, a: int, b: int, oids: list[str]):
        rid = struct.unpack(">i", os.urandom(4))[0] & 0x7FFFFFFF
        pkt = _msg(self.community, tag, rid, a, b, oids)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(self.timeout)
            for _ in range(self.retries + 1):
                s.sendto(pkt, self.addr)
                try:
                    while True:
                        data, _ = s.recvfrom(65535)
                        got, err, vbs = _parse(data)
                        if got == rid:
                            if err:
                                raise SnmpError(f"{self.addr[0]}: error-status {err}")
                            return vbs
                except socket.timeout:
                    continue
        raise SnmpError(f"{self.addr[0]}: timeout")

    def get(self, *oids: str) -> dict:
        return {o: v for o, v in self._rpc(0xA0, 0, 0, list(oids)) if v is not END}

    def walk(self, root: str, max_rep: int = 40, limit: int = 20000) -> list:
        """GETBULK-обхід піддерева root; повертає [(oid, value)]."""
        root = root.strip(".")
        pref = root + "."
        cur, out = root, []
        while len(out) < limit:
            try:
                vbs = self._rpc(0xA5, 0, max_rep, [cur])
            except SnmpError:
                # частина свічів (Huawei VRP на LLDP) не встигає зібрати велику пачку — зменшуємо
                if max_rep <= 5:
                    raise
                max_rep = max(5, max_rep // 4)
                continue
            if not vbs:
                break
            for o, v in vbs:
                if v is END or not o.startswith(pref):
                    return out
                out.append((o, v))
                cur = o
        return out


def mac_str(b) -> str:
    if isinstance(b, (bytes, bytearray)) and len(b) == 6:
        return ":".join(f"{x:02x}" for x in b)
    return ""


def text(b) -> str:
    if isinstance(b, (bytes, bytearray)):
        return b.decode("utf-8", "replace").strip("\x00 ")
    return "" if b is None else str(b)
