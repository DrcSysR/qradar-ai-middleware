"""Колектор знімків для netdiag: раз на `netdiag_poll_seconds` (60 с) знімає з WLC 3504 таблицю
клієнтів (точка, RSSI/SNR, стан політик, uptime…) і радіо точок (канал, завантаження, клієнти),
а з ядра MLNX01/02 — ARP. Пише в `netdiag.db`, чистить старше `netdiag_keep_minutes` (30).

Навіщо: WLC сам історії клієнта не зберігає, а для діагностики Wi-Fi потрібні останні
10–15 хвилин (роумінги, просідання сигналу, перепідключення). Один повний знімок —
~1–3 с SNMP (≈740 клієнтів, 114 точок, ~5000 ARP).

Процес-цикл (systemd `netdiag-collector.service`, Restart=always), без lock-файлу: unit один.
`--once` — один знімок і вихід (перевірка руками).
"""
from __future__ import annotations

import logging
import os
import signal
import sys
import time
from logging.handlers import RotatingFileHandler

import netdiag

LOG_FILE = os.path.join(netdiag.BASE_DIR, "netdiag_collector.log")
_stop = False


def _sig(*_):
    global _stop
    _stop = True


def cycle() -> None:
    cfg = netdiag.load_config()
    now = int(time.time())
    con = netdiag.db(cfg)
    try:
        t = time.monotonic()
        try:
            w = netdiag.collect_wlc(cfg, con, now)
        except Exception as e:
            w = -1
            logging.error(f"WLC: {e}")
        try:
            a = netdiag.collect_arp(cfg, con, now)
        except Exception as e:
            a = -1
            logging.error(f"ARP: {e}")
        netdiag.prune(cfg, con, now)
        con.execute("INSERT OR REPLACE INTO collector(k, v) VALUES('last', ?)", (f"{now} wifi={w} arp={a}",))
        con.commit()
        logging.info(f"знімок: wifi={w} arp={a} за {time.monotonic() - t:.1f} с")
    finally:
        con.close()


def main() -> int:
    handler = RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=2, encoding="utf-8") \
        if os.access(netdiag.BASE_DIR, os.W_OK) else logging.StreamHandler()
    logging.basicConfig(level=logging.INFO, handlers=[handler], format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    if "--once" in sys.argv:
        cycle()
        return 0
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)
    cfg = netdiag.load_config()
    if not cfg.get("netdiag_wlc_community"):
        logging.warning("netdiag_wlc_community порожній — Wi-Fi знімки не збираються, лише ARP")
    while not _stop:
        started = time.monotonic()
        try:
            cycle()
        except Exception as e:  # цикл не має падати від одного збою (БД заблокована, мережа)
            logging.exception(f"цикл: {e}")
        period = float(netdiag.load_config().get("netdiag_poll_seconds") or 60)
        while not _stop and time.monotonic() - started < period:
            time.sleep(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
