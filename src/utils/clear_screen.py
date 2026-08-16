#!/usr/bin/env python3
"""
clear_screen.py -- remove a user bitmap from the badge's OLED and restore the stock UI.

Uses the badge's documented `image clear` console command
(dc34-console/src/cmds/image.rs:90), which deletes the PDDB image key and pokes the vault
to reload. Not an exploit; the counterpart to uploading one.

Retries, because characters sent to the console are injected into a bounded queue and
dropped silently when it overflows (bao1x-hal-service/src/servers/keyboard.rs:504).

USAGE
    python clear_screen.py --port COM5
"""

import argparse
import sys
import time


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default="COM5")
    ap.add_argument("--retries", type=int, default=5)
    a = ap.parse_args()

    import serial
    try:
        ser = serial.Serial(a.port, 115200, timeout=0.3, write_timeout=5.0)
    except Exception as e:
        print(f"cannot open {a.port}: {e}")
        return 1
    time.sleep(0.5)

    for attempt in range(1, a.retries + 1):
        # Flush the input line first: button presses land in the same buffer as serial
        # characters and would otherwise corrupt the verb.
        ser.reset_input_buffer()
        ser.write(b"\r\n")
        ser.flush()
        time.sleep(0.4)
        ser.reset_input_buffer()

        ser.write(b"image clear\r\n")
        ser.flush()
        time.sleep(1.5)
        out = ser.read(16384).decode("utf8", "replace")

        if "CLEAR" in out:
            ser.close()
            print(f"cleared (attempt {attempt})")
            print("The badge should be back to its stock screen.")
            return 0
        print(f"  attempt {attempt}: {out.strip()[-90:]!r}")
        time.sleep(0.6)

    ser.close()
    print("\nNever acknowledged. Either the console is frozen (finding F-1 -- power-cycle")
    print("and retry), or the badge had no user bitmap set in the first place.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
