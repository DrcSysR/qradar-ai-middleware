"""Вендор за MAC (OUI) для netdiag: база Wireshark `manuf` (MA-L / MA-M / MA-S з масками).

Файл `cache/manuf.gz` у каталозі мідлвару; оновлюється раз на `netdiag_oui_refresh_days` (типово 30) з
`netdiag_oui_url`. Не вдалось завантажити — працюємо зі старою копією; немає жодної — вендор просто невідомий.
Локально адміністровані MAC (біт 0x02 першого октету) вендора не мають: це віртуальні адаптери, Docker або
рандомізовані MAC телефонів/ноутбуків.
"""
from __future__ import annotations

import gzip
import logging
import os
import re
import threading
import time

import httpx

import netdiag

log = logging.getLogger("netdiag_oui")

DEFAULTS = {
    "netdiag_oui_url": "https://www.wireshark.org/download/automated/data/manuf.gz",
    "netdiag_oui_refresh_days": 30,
}
PATH = os.path.join(netdiag.CACHE_DIR, "manuf.gz")

_lock = threading.Lock()
_db: dict[int, dict[int, str]] | None = None     # маска (біти) → {префікс як int → назва}
_loaded_mtime = 0.0

# що за пристрій за вендором — для ознак «некерований свіч/міст» на порту
KIND = [
    (re.compile(r"(?i)tp-?link|d-?link|tenda|mercusys|netgear|zyxel|mikrotik|routerboard|totolink|keenetic|zyx|edimax|"
                r"asustek|xiaomi.*(router)|linksys|belkin|ubiquiti|cudy|wavlink|ruijie|reyee"), "router"),
    (re.compile(r"(?i)vmware|microsoft.*(hyper|corp)|oracle.*virtualbox|virtualbox|qemu|xensource|parallels|nutanix|proxmox"), "vm"),
    (re.compile(r"(?i)yealink|grandstream|panasonic|polycom|snom|fanvil|avaya|mitel|htek|gigaset"), "phone"),
    (re.compile(r"(?i)kyocera|canon|epson|brother|ricoh|konica|xerox|lexmark|sharp|zebra|toshiba tec|oki"), "printer"),
]
# QEMU/KVM, VirtualBox, Hyper-V, VMware — відомі префікси (на випадок, коли в базі назва узагальнена)
VM_PREFIX = ("52:54:00", "08:00:27", "00:15:5d", "00:50:56", "00:0c:29", "00:05:69", "00:1c:14")


def opt(cfg: dict, key: str):
    v = cfg.get(key)
    return DEFAULTS.get(key) if v in (None, "") else v


def _parse(raw: bytes) -> dict[int, dict[int, str]]:
    db: dict[int, dict[int, str]] = {}
    for line in raw.decode("utf-8", "replace").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        pref, _, mask = parts[0].partition("/")
        hexs = re.sub(r"[^0-9A-Fa-f]", "", pref)
        if len(hexs) < 6:
            continue
        bits = int(mask) if mask.isdigit() else len(hexs) * 4
        val = int(hexs.ljust(12, "0")[:12], 16) >> (48 - bits)
        name = (parts[2] if len(parts) > 2 and parts[2].strip() else parts[1]).strip()
        db.setdefault(bits, {})[val] = name[:60].rstrip(".")
    return db


def _refresh(cfg: dict) -> None:
    try:
        r = httpx.get(opt(cfg, "netdiag_oui_url"), timeout=30, follow_redirects=True, headers={"User-Agent": "netdiag-oui/1.0"})
        r.raise_for_status()
        raw = r.content
        if raw[:2] == b"\x1f\x8b":
            gzip.decompress(raw)                      # перевірка цілісності до запису
        else:
            raw = gzip.compress(raw)
        tmp = PATH + ".tmp"
        os.makedirs(os.path.dirname(PATH), exist_ok=True)
        with open(tmp, "wb") as fh:
            fh.write(raw)
        os.replace(tmp, PATH)
        log.info(f"OUI: базу оновлено ({len(raw) // 1024} КБ)")
    except Exception as e:
        log.warning(f"OUI: оновлення не вдалось ({type(e).__name__}) — працюю зі старою копією")


def _ensure(cfg: dict) -> dict[int, dict[int, str]]:
    global _db, _loaded_mtime
    with _lock:
        age = time.time() - os.path.getmtime(PATH) if os.path.exists(PATH) else None
        if age is None or age > float(opt(cfg, "netdiag_oui_refresh_days")) * 86400:
            _refresh(cfg)
        if os.path.exists(PATH) and (_db is None or os.path.getmtime(PATH) != _loaded_mtime):
            try:
                with gzip.open(PATH, "rb") as fh:
                    _db = _parse(fh.read())
                _loaded_mtime = os.path.getmtime(PATH)
            except Exception as e:
                log.warning(f"OUI: база не читається ({type(e).__name__})")
        return _db or {}


def vendor(cfg: dict, mac: str) -> dict:
    """{"vendor": str, "local": bool, "kind": router|vm|phone|printer|""}"""
    mac = (mac or "").lower()
    hexs = re.sub(r"[^0-9a-f]", "", mac)
    if len(hexs) != 12:
        return {"vendor": "", "local": False, "kind": ""}
    local = bool(int(hexs[:2], 16) & 2)
    out = {"vendor": "", "local": local, "kind": ""}
    if mac.startswith(VM_PREFIX):
        out["kind"] = "vm"
    if local:
        if hexs.startswith("0242"):
            out.update(vendor="Docker (локальний MAC)", kind="vm")
        elif hexs.startswith("525400"):
            out.update(vendor="QEMU/KVM (віртуальна машина)", kind="vm")
        else:
            out["vendor"] = "локальний/рандомізований MAC"
        return out
    db = _ensure(cfg)
    val = int(hexs, 16)
    for bits in sorted(db, reverse=True):          # спершу найдовші префікси (MA-S /36, MA-M /28), потім /24
        name = db[bits].get(val >> (48 - bits))
        if name:
            out["vendor"] = name
            break
    if not out["kind"]:
        for rx, kind in KIND:
            if out["vendor"] and rx.search(out["vendor"]):
                out["kind"] = kind
                break
    return out
