#!/usr/bin/env python3
"""
run.py -- entry point for the DC34 badge toolkit.

Plug the badge in, run this. It finds the device, waits for it, checks it is answering,
runs the attack, and says what should be on the screen. Nothing to do in between.

    python run.py                     pin content on screen (demonstrates F-1)
    python run.py list
    python run.py check
    python run.py attack <name>
    python run.py clear
"""

import argparse
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, os.path.join(SRC, "transport"))

ATTACKS = {
    "freeze": ("freeze_display.py",
               "Pin chosen content on the screen, defeating the firmware's 3s rotation",
               "Demonstrates F-1's impact. Upload is the vendor API; persistence is not."),
    "dos": ("f9_demo.py",
            "Freeze the console, buttons and display until power is removed",
            "F-1. Unauthenticated full-device denial of service."),
    "ui": ("attack_ui_inject.py",
           "Drive the badge's menus from USB",
           "Not a finding -- designed console input reaching every listener. Kept as "
           "the mechanism demo behind F-1."),
    "rate": ("f9_rate.py",
             "Find the throughput at which F-1 fires on this unit",
             "Measurement, not an attack."),
    "bisect": ("f9_bisect.py",
               "Show that line length alone does not trigger F-1",
               "Measurement. Refutes the obvious hypothesis."),
    "fuzz": ("console_fuzz.py",
             "240 malformed inputs at the image/bio chunk parsers",
             "Diagnostic. The bounds checks hold."),
}

def find_badge_port(timeout: float):
    from badge_console import find_badge
    deadline = time.time() + timeout
    dotted = False
    while time.time() < deadline:
        port = find_badge()
        if port:
            if dotted:
                print()
            return port
        if not dotted:
            print("  waiting for the badge (USB 1D50:6198)", end="", flush=True)
            dotted = True
        else:
            print(".", end="", flush=True)
        time.sleep(1.0)
    if dotted:
        print()
    return None


def check_device(port: str):
    from badge_console import BadgeConsole, DeviceNotListening, which_stage
    try:
        with BadgeConsole(port, allow={"echo", "ver"}) as c:
            banner = c.drain(1.5)
            stage = which_stage(banner)
            if stage == "unknown":
                try:
                    banner += c.send("echo")
                    stage = which_stage(banner)
                except DeviceNotListening:
                    return stage, False
            return stage, bool(banner.strip())
    except Exception:
        return "unknown", False


def run_child(subdir, script, extra):
    path = os.path.join(SRC, subdir, script)
    if not os.path.exists(path):
        print(f"missing: {path}")
        return 1
    return subprocess.call([sys.executable, path] + list(extra),
                           cwd=os.path.dirname(path))


def with_device(a, subdir, script, extra, allow_frozen=False):
    print("[1/2] finding badge")
    port = find_badge_port(a.wait)
    if not port:
        print("\nNot found. Use a data cable; if a VM is running it may have taken the device.")
        return 1
    print(f"      {port}")
    stage, responsive = check_device(port)
    if not responsive and not allow_frozen:
        print("      enumerated but not answering -- frozen from an earlier run (F-1).")
        print("      Unplug USB for 3 s, plug it back in, re-run.")
        return 2
    print(f"[2/2] {script}\n")
    return run_child(subdir, script, ["--port", port] + list(extra))


def cmd_list():
    print("attacks     python run.py attack <name>")
    for k, (_f, desc, note) in ATTACKS.items():
        print(f"  {k:8} {desc}")
        print(f"  {'':8}   {note}")
    print("\nutility     python run.py clear               (restore the stock screen)")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--wait", type=float, default=45.0)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("list")
    sub.add_parser("check")
    sub.add_parser("clear")
    p = sub.add_parser("attack")
    p.add_argument("name", nargs="?", default="freeze", choices=sorted(ATTACKS))
    p.add_argument("extra", nargs=argparse.REMAINDER)
    a = ap.parse_args()

    if a.cmd == "list":
        return cmd_list()

    if a.cmd == "check":
        port = find_badge_port(a.wait)
        if not port:
            print("not found")
            return 1
        stage, responsive = check_device(port)
        print(f"{port}  stage={stage}  responsive={responsive}")
        if not responsive:
            print("Frozen. Unplug USB for 3 s and plug it back in.")
            return 2
        return 0

    if a.cmd == "clear":
        return with_device(a, "utils", "clear_screen.py", [])

    name = a.name if a.cmd == "attack" else "freeze"
    extra = a.extra if a.cmd == "attack" else []
    script, desc, note = ATTACKS[name]

    print("=" * 70)
    print(f"  {desc}")
    print(f"  {note}")
    print("=" * 70 + "\n")

    return with_device(a, "attacks", script, extra)


if __name__ == "__main__":
    sys.exit(main())
