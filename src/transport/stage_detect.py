#!/usr/bin/env python3
"""
stage_detect.py -- find the badge's serial port and identify which firmware stage
is answering, without sending anything that can change state.

Why this exists: the badge presents a CDC serial console in two completely different
firmware stages, and they have different command sets.

  Xous stage   -- normal boot. Verbs: echo, ver, test, image, bio
                  (dc34-console/src/cmds.rs:125-132)
  boot1 stage  -- bootloader REPL. ~30 verbs including `peek`
                  (bao1x-boot/boot1/src/repl.rs)

`peek`, the arbitrary-read primitive this project cares about, only exists in boot1.

HOW TO REACH boot1
------------------
boot1 skips the boot and drops into its REPL if a key is held at power-on.

  bao1x-boot/boot1/src/main.rs:133
      let mut current_key = if let Some(key) = crate::platform::get_key(&board_type, &iox) {
          if key != KeyPress::Invalid { Some(key) }   // "skip boot if a key is pressed"

For the baosec board type -- which the DC34 core module is -- get_key scans a 2x3
keyboard matrix (libs/bao1x-hal/src/board/baosec.rs:330), so *any* of the badge's
buttons will do. There is no dedicated "PROG" button on this board; that name comes
from the dabao variant, which instead samples a single boot pin, PC13
(bao1x-boot/boot1/src/platform/bao1x/bao1x.rs:39-40).

  Procedure: hold any badge button down, power-cycle (unplug/replug USB or pull a
  battery), keep holding until the banner appears, then release.

  Success looks like:   ~~Boot1 up! (<semver>: <release>)~~
                        Configured board type: ...

SAFETY
------
Read-only. This tool sends at most `echo` and `help`. It never writes.

USAGE
-----
    python stage_detect.py                 # auto-detect port, identify stage
    python stage_detect.py --port COM5
    python stage_detect.py --watch          # poll until boot1 appears
"""

import argparse
import sys
import time

from badge_console import (BadgeConsole, DeviceNotListening, PortBusy,
                           find_badge, list_ports, which_stage)


def show_ports() -> None:
    print("serial ports:")
    for dev, desc, hwid in list_ports():
        mark = "  <-- badge (1D50:6198)" if ("1D50" in hwid.upper() and "6198" in hwid.upper()) else ""
        print(f"  {dev:8} {desc}  [{hwid}]{mark}")


def probe(port: str, verbose: bool = True) -> str:
    """Identify the firmware stage.

    Tries passive identification first -- just listening. The badge streams log output
    continuously, and those logs are stage-specific, so most of the time we can tell
    which firmware is running without writing anything at all.

    That matters: if the vault UI is on a screen that does not service console input
    (the QR/GeneScan screen), writing blocks. Listening always works. Only fall back to
    sending `echo` when the device happens to be silent.
    """
    with BadgeConsole(port, allow={"echo", "help"}) as c:
        banner = c.drain(2.0)
        stage = which_stage(banner)
        source = "passive (log stream)"

        listening = True
        if stage == "unknown":
            # Device is quiet or unrecognised -- nudge it. `echo` is inert in both stages.
            try:
                banner = banner + c.send("echo")
                stage = which_stage(banner)
                source = "active (echo)"
            except DeviceNotListening:
                listening = False
                source = "passive only -- device refused input"

        if verbose:
            print(f"\n--- output from {port}  [{source}] ---")
            print(banner.rstrip() or "(silence)")
            print("--- end ---\n")
        return stage, listening, bool(banner.strip())


def report(stage: str, listening: bool = True, talking: bool = True) -> int:
    if stage == "unknown" and not listening:
        print("STAGE: could not identify -- the badge is not accepting console input.")
        print()
        if talking:
            print("  It is streaming logs, so USB and the cable are fine. The vault UI")
            print("  is on a screen that does not service the console -- the QR /")
            print("  GeneScan screen does this.")
        else:
            print("  It is also silent, which usually means the screen has gone to")
            print("  sleep under power management.")
        print()
        print("  Fix: press a badge button to wake it / leave that screen, then re-run.")
        print("  No unplugging and no power cycle is needed.")
        print()
        print("  If it still refuses after waking:")
        print("      python diag_serial.py --port <PORT>")
        return 4
    return _report_stage(stage)


def _report_stage(stage: str) -> int:
    if stage == "boot1":
        print("STAGE: boot1 bootloader REPL")
        print()
        print("  `peek` is available here. Next step:")
        print("      python peek_probe.py --port <PORT>")
        return 0
    if stage == "xous":
        print("STAGE: Xous application console")
        print()
        print("  Verbs here: echo, ver, test, image, bio")
        print("  There is NO peek/poke at this stage -- no CSR or raw memory access.")
        print()
        print("  To reach boot1: hold ANY badge button, power-cycle, keep holding")
        print("  until you see '~~Boot1 up!~~', then release.")
        return 2
    print("STAGE: unknown -- the device answered, but not with a recognised banner.")
    print()
    print("  Try pressing a button to wake the badge, or power-cycle and re-run.")
    return 3


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--port", help="serial port; auto-detected if omitted")
    ap.add_argument("--list-ports", action="store_true")
    ap.add_argument("--watch", action="store_true",
                    help="poll until boot1 appears (for catching the boot window)")
    a = ap.parse_args()

    if a.list_ports:
        show_ports()
        return 0

    port = a.port or find_badge()
    if not port:
        print("No badge found (looking for USB VID 1D50, PID 6198).")
        print()
        show_ports()
        print()
        print("If nothing above looks like the badge:")
        print("  - wake it with a button press, then replug")
        print("  - use a DATA usb cable, not charge-only")
        print("  - check battery / core module seating")
        return 1

    print(f"using port: {port}")

    if not a.watch:
        try:
            return report(*probe(port))
        except PortBusy as e:
            print(f"\n{e}")
            return 1

    print("watching for boot1 -- hold a button and power-cycle now. Ctrl-C to stop.")
    try:
        while True:
            try:
                if probe(port, verbose=False)[0] == "boot1":
                    print()
                    return report("boot1")
            except Exception:
                pass  # port disappears across a replug; that is expected
            time.sleep(1.0)
            port = a.port or find_badge() or port
    except KeyboardInterrupt:
        print("\nstopped.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
