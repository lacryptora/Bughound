#!/usr/bin/env python3
"""banner.py: the Bughound startup banner. Colors degrade gracefully (NO_COLOR
or a non-TTY prints plain)."""
import os
import sys

_C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "cyan": "\033[36m", "mag": "\033[35m", "yel": "\033[33m",
    "grn": "\033[32m", "gry": "\033[90m",
}


def _use_color():
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def c(key, text):
    if not _use_color():
        return text
    return f"{_C.get(key,'')}{text}{_C['reset']}"


ART = r"""
     __   _   _  ___  _  _  ___  _   _ _  _ ___
    | _ ) | | | |/ __|| || |/ _ \| | | | \| |   \
    | _ \ | |_| | (_ || __ | (_) | |_| | .` | |) |
    |___/  \___/ \___||_||_|\___/ \___/|_|\_|___/
           ___
        o /   \        sniffs out bugs so you don't have to
      __|\ o o |       recon, multi-vuln scanning, low-noise triage
     /  \_\___/_
"""


def show(modules=None, target=None, version="1.0"):
    paint = _use_color()
    if paint:
        lines = ART.splitlines()
        out = []
        for ln in lines:
            if "BUGHOUND" in ln or any(ch in ln for ch in "_|/\\") and "o" not in ln:
                out.append(c("cyan", ln))
            else:
                out.append(c("yel", ln))
        print("\n".join(out))
    else:
        print(ART)
    sub = f"  {c('bold','Bughound')} {c('gry','v'+version)}  ::  bug bounty hunting framework"
    print(sub)
    if target:
        print(f"  {c('grn','target')} : {target}")
    if modules:
        print(f"  {c('mag','modules')}: {', '.join(modules)}")
    print(c("gry", "  authorized testing only, reproduce every finding by hand\n"))
