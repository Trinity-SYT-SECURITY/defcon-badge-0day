#!/usr/bin/env python3
"""
f9_bisect.py -- how long a console line does it take to wedge the badge? (finding F-1)

Walks UPWARD from short to long. The first length that kills the console ends the run, so
a single battery pull yields one failure bracket plus every passing point below it.

Uses `echo`, the most inert verb in the console (dc34-console/src/cmds/echo.rs) -- it only
echoes its argument. Anything that breaks is therefore about the *length of the line*,
not about what the command does with the data.

A bare newline is sent before every command. Physical button presses are injected into
the same input line as serial characters (usb-bao1x/src/main.rs:605 replays CDC bytes as
keystrokes), so any buttons pressed since the last command are still sitting in the line
buffer and would otherwise corrupt the verb.

Recovery between runs: pull an AA battery. Unplugging USB is not enough -- the badge is
battery powered.
"""

import sys
import time

import serial

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM5"
# Which verb carries the payload. `echo` isolates pure line length; `image` and `bio`
# additionally run a base64 decode over the argument, which is where the original
# console-kill was observed.
VERB = sys.argv[2] if len(sys.argv) > 2 else "echo"
LENGTHS = [64, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096]


def clear_line(s):
    """Flush whatever is sitting in the badge's input line buffer."""
    s.reset_input_buffer()
    s.write(b"\r\n")
    s.flush()
    time.sleep(0.4)
    s.reset_input_buffer()


def probe(s):
    """Send `ver` and return the reply, or '' if the console is dead."""
    try:
        clear_line(s)
        s.write(b"ver\r\n")
        s.flush()
    except Exception:
        return ""
    time.sleep(0.9)
    try:
        return s.read(8192).decode("utf8", "replace")
    except Exception:
        return ""


def alive(reply: str) -> bool:
    """Any coherent reply means the console is still running.

    Deliberately loose. Physical button presses land in the same input line as serial
    characters, so the verb can arrive corrupted (e.g. `→ver`) and the console answers
    with its command list instead of the version. That is still a live console -- the
    thing being tested is whether it answers at all, not what it answers.
    """
    low = reply.lower()
    return any(m in low for m in ("xous", "[console]", "commands:"))


def main() -> int:
    try:
        s = serial.Serial(PORT, 115200, timeout=0.3, write_timeout=3.0)
    except Exception as e:
        print(f"cannot open {PORT}: {e}")
        return 1
    time.sleep(0.4)

    base = probe(s)
    print(f"baseline `ver`: {base.strip()[:90]!r}")
    if not alive(base):
        print("badge not responding at baseline -- pull a battery and retry.")
        s.close()
        return 1
    print()

    last_ok = 0
    verdict = None
    for n in LENGTHS:
        payload = VERB.encode() + b" " + b"A" * n + b"\r\n"
        print(f"  {n:>5} chars ... ", end="", flush=True)
        try:
            clear_line(s)
            s.write(payload)
            s.flush()
        except Exception as e:
            print(f"WRITE FAILED ({type(e).__name__}) -- USB OUT wedged at this length")
            verdict = (last_ok, n, "write path")
            break
        time.sleep(1.3)
        if alive(probe(s)):
            print("console alive")
            last_ok = n
        else:
            print("NO REPLY -- console dead")
            verdict = (last_ok, n, "console")
            break

    s.close()
    print()
    if verdict:
        ok, bad, where = verdict
        print(f"  THRESHOLD: {ok} chars OK  ->  {bad} chars wedges it ({where})")
        print()
        print("  Now check the PHYSICAL buttons on the badge.")
        print("  This is the question the finding turns on:")
        print("    * buttons still change the screen  -> only the console died")
        print("    * buttons do nothing, screen frozen -> the keyboard/UI chain died too,")
        print("      i.e. one line over USB takes out the whole device until reboot")
        print()
        print("  Then pull an AA battery to recover.")
    else:
        print(f"  all lengths up to {LENGTHS[-1]} survived -- console still alive")
    return 0


if __name__ == "__main__":
    sys.exit(main())
