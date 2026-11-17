#!/usr/bin/env python3
"""
notify.py: alert on NOTEWORTHY findings while the scan keeps running.

Fires only on findings worth stopping for (not every low-confidence lead), sends
to whatever channel you configure, logs to ALERTS.md, and rings the terminal
bell. Best-effort: a failed send never interrupts the scan.

Configure ONE (or more) via environment variables:
  NOTIFY_DISCORD_WEBHOOK   a Discord channel webhook URL (easiest — phone push)
  NOTIFY_TELEGRAM_TOKEN + NOTIFY_TELEGRAM_CHAT   a Telegram bot token + chat id
  NOTIFY_WEBHOOK           any generic JSON webhook ({"text": ...})
If none set, it still writes ALERTS.md and rings the bell.
"""
import os
from pathlib import Path

import requests


def is_noteworthy(f):
    """Worth pinging you for? High-signal only."""
    t = f.get("type")
    sev = f.get("severity")
    if t == "subdomain-takeover" and sev in ("high", "medium"):
        return True
    if t == "secret" and sev == "high":
        return True
    if t == "source-map-exposed":
        return True
    if t in ("crlf", "open-redirect") and f.get("confirmed"):
        return True
    if t == "xss-reflected" and sev == "high":  # likely-exploitable
        return True
    if sev in ("high", "critical") and f.get("confirmed"):
        return True
    return False


def _format(f):
    return (f"[crlf-hunter] {f.get('type')} | sev={f.get('severity','-')} | "
            f"confirmed={f.get('confirmed')}\n{f.get('url','')}\n"
            f"{str(f.get('evidence',''))[:300]}")


def send(text):
    ok = False
    dw = os.environ.get("NOTIFY_DISCORD_WEBHOOK")
    if dw:
        try:
            requests.post(dw, json={"content": text[:1900]}, timeout=10); ok = True
        except requests.RequestException:
            pass
    tok, chat = os.environ.get("NOTIFY_TELEGRAM_TOKEN"), os.environ.get("NOTIFY_TELEGRAM_CHAT")
    if tok and chat:
        try:
            requests.post(f"https://api.telegram.org/bot{tok}/sendMessage",
                          json={"chat_id": chat, "text": text[:4000]}, timeout=10); ok = True
        except requests.RequestException:
            pass
    gw = os.environ.get("NOTIFY_WEBHOOK")
    if gw:
        try:
            requests.post(gw, json={"text": text[:1900]}, timeout=10); ok = True
        except requests.RequestException:
            pass
    try:
        with open("ALERTS.md", "a") as fh:
            fh.write(text + "\n\n---\n")
    except OSError:
        pass
    # terminal bell + visible line, always
    print("\a[ALERT] " + text.splitlines()[0], flush=True)
    return ok


def notify_findings(findings):
    """Call after each module. Returns how many alerts were sent."""
    n = 0
    for f in findings:
        if is_noteworthy(f):
            send(_format(f))
            n += 1
    return n
