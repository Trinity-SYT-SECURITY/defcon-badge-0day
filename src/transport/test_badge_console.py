"""Self-check for badge_console. No hardware required.

Run:  python test_badge_console.py

Covers the two things that actually bit us:
  1. send() must terminate on a device that never stops talking. The Xous console
     streams log output continuously; a purely quiet-based read loop spins forever
     and holds the COM port, which makes every other tool fail with "Access is denied".
  2. the command allowlist / denylist must reject before anything is transmitted.
"""

import sys
import time

from badge_console import DENYLIST, BadgeConsole, UnsafeCommand


class FakePort:
    """Minimal stand-in for serial.Serial."""

    def __init__(self, payload=b""):
        self.payload = payload
        self.written = []

    def read(self, _n):
        time.sleep(0.01)
        return self.payload

    def write(self, b):
        self.written.append(b)

    def reset_input_buffer(self):
        pass


def console(allow, port):
    c = BadgeConsole.__new__(BadgeConsole)
    c.allow = frozenset(allow)
    c._ser = port
    return c


def check(name, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{'  ' + detail if detail else ''}")
    return ok


def main():
    results = []
    print("send() termination")

    # A device that never goes quiet must still return, bounded by hard_cap.
    c = console({"peek"}, FakePort(b"INFO:spam\n"))
    t0 = time.time()
    out = c.send("peek 40065000 8", settle=0.05, hard_cap=2.0)
    el = time.time() - t0
    results.append(check("chatty device terminates", el < 3.0,
                         f"({el:.2f}s, {len(out)} bytes)"))

    # A quiet device must exit early rather than burning the whole cap.
    c = console({"peek"}, FakePort(b""))
    t0 = time.time()
    c.send("peek 1000 4", settle=0.05, quiet_for=0.3, hard_cap=6.0)
    el = time.time() - t0
    results.append(check("quiet device exits early", el < 1.5, f"({el:.2f}s)"))

    print("\ncommand gating")

    c = console({"peek"}, FakePort())
    for verb in ["self_destruct", "publock", "lockdown", "uf2 AABB", "uf2_flush",
                 "idmode", "altboot", "boardtype", "require-pq", "baosec-init",
                 "ate", "paranoid", "skipping", "usb_speed"]:
        blocked = False
        try:
            c.check(verb)
        except UnsafeCommand:
            blocked = True
        results.append(check(f"blocks {verb.split()[0]}", blocked))

    # Not on the denylist, but not in this tool's allowlist either.
    blocked = False
    try:
        c.check("bio clear")
    except UnsafeCommand:
        blocked = True
    results.append(check("blocks out-of-allowlist verb (bio)", blocked))

    results.append(check("allows declared verb", c.check("peek 40065000 8") ==
                         "peek 40065000 8"))

    # A tool must not be able to declare a denied verb in the first place.
    rejected = False
    try:
        BadgeConsole("COM_NONEXISTENT", allow={"peek", "self_destruct"})
    except UnsafeCommand:
        rejected = True
    results.append(check("rejects allowlist containing a denied verb", rejected))

    results.append(check("nothing was transmitted during gating tests",
                         c._ser.written == []))

    print(f"\n{sum(results)}/{len(results)} passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
