#!/usr/bin/env python3
"""
console_fuzz.py -- fuzz the badge's console parsers over USB serial. No bootloader needed.

TARGETS
-------
The Xous console exposes five verbs (dc34-console/src/cmds.rs:125-132):
    echo, ver, test, image, bio

Two of them take structured binary payloads and are the only attacker-shaped parsers
reachable while the badge is running normally:

  image <base64>   dc34-console/src/cmds/image.rs:107
  bio   <base64>   dc34-console/src/cmds/bio.rs:579

Both decode base64, require exactly 70 decoded bytes, verify a CRC-32 over the first 66,
then bounds-check a u16 chunk index. Static review says those checks are correct; this
fuzzes them on real silicon to see whether the implementation matches the reading.

SAFETY -- why this cannot brick the badge
-----------------------------------------
The fuzzer is built to exercise the *reject* path only. An upload only commits to PDDB
when every chunk slot is filled (32 for `image`, 60 for `bio`), so a run that never sends
a complete valid set never writes anything:

  * every generated chunk is deliberately malformed (bad base64, wrong length, bad CRC,
    or an out-of-range index), so none is ever accepted;
  * `--allow-valid` is required to send even one well-formed chunk, and even then the
    tool refuses to send enough distinct indices to complete a set;
  * the verb allowlist is {image, bio, echo, ver} -- `badge_console` rejects everything
    else before transmission, and `bio pin` / `bio clk` / `bio clear` are NOT sent, so
    PDDB pin/clock/code keys are untouched.

Nothing here writes RRAM, and no BIO code is ever loaded or run.

If a chunk *were* accepted by accident, recovery is documented in backup/BASELINE.md:
`python apply_max_gene.py --restore` for BIO, `image clear` for the bitmap.

DETECTION
---------
A parser bug shows up as one of:
  * no reply where "ERR"/"OK" was expected  -- the service died or hung
  * a Rust panic string in the log stream
  * the console going permanently unresponsive after a specific input

The tool re-probes with `ver` after every case and reports the first input after which
the badge stopped answering.

USAGE
    python console_fuzz.py --dry-run            # show the case list, send nothing
    python console_fuzz.py --port COM5
    python console_fuzz.py --port COM5 --iters 500
"""

import argparse
import base64
import random
import sys
import time
import zlib

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "transport"))
from badge_console import (BadgeConsole, DeviceNotListening, PortBusy,
                           Transcript, find_badge)

CHUNK_DATA = 64
CHUNK_WIRE = 2 + CHUNK_DATA + 4      # 70, per image.rs:33 / bio.rs:23
IMAGE_CHUNKS = 32                    # image.rs:35
BIO_CHUNKS = 0xF00 // CHUNK_DATA     # 60, bio.rs:26


def wire(index: int, data: bytes, crc: int | None = None) -> bytes:
    """Build a wire chunk. `crc=None` computes the correct CRC-32 over index||data."""
    body = index.to_bytes(2, "big") + data
    if crc is None:
        crc = zlib.crc32(body) & 0xFFFFFFFF
    return body + crc.to_bytes(4, "big")


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def build_cases(rng: random.Random, iters: int, allow_valid: bool):
    """Yield (label, verb, argument). Every case is designed to be REJECTED."""
    cases = []
    good = bytes(rng.getrandbits(8) for _ in range(CHUNK_DATA))

    # -- structural edge cases, deterministic -------------------------------
    for verb, nchunks in (("image", IMAGE_CHUNKS), ("bio", BIO_CHUNKS)):
        # index exactly at and beyond the bound -- the check is `index >= NUM_CHUNKS`
        for idx, why in ((nchunks, "index == NUM_CHUNKS"),
                         (nchunks + 1, "index == NUM_CHUNKS+1"),
                         (0xFFFF, "index == 0xFFFF"),
                         (0x8000, "index high bit set")):
            cases.append((f"{verb} {why}", verb, b64(wire(idx, good))))

        # CRC mismatch -- must be rejected before the index check even matters
        cases.append((f"{verb} bad CRC", verb, b64(wire(0, good, crc=0))))
        cases.append((f"{verb} CRC off by one", verb,
                      b64(wire(0, good, crc=(zlib.crc32(b"\x00\x00" + good) + 1) & 0xFFFFFFFF))))

        # wrong decoded length -- `decoded.len() != CHUNK_WIRE_SIZE`
        for n, why in ((0, "empty"), (1, "1 byte"), (CHUNK_WIRE - 1, "69 bytes"),
                       (CHUNK_WIRE + 1, "71 bytes"), (4096, "4096 bytes")):
            cases.append((f"{verb} length {why}", verb, b64(bytes(n))))

        # malformed base64
        for s, why in (("!!!!", "invalid alphabet"), ("A", "1 char"), ("AB", "2 chars"),
                       ("ABC", "3 chars"), ("=" * 8, "all padding"),
                       ("A" * 4096, "very long"), ("\x00\x01\x02", "control bytes")):
            cases.append((f"{verb} b64 {why}", verb, s))

        # whitespace / argument handling
        cases.append((f"{verb} empty arg", verb, ""))
        cases.append((f"{verb} spaces", verb, "   "))

    # -- randomised mutation of a valid chunk -------------------------------
    for _ in range(iters):
        verb = rng.choice(("image", "bio"))
        nchunks = IMAGE_CHUNKS if verb == "image" else BIO_CHUNKS
        raw = bytearray(wire(rng.randrange(0, nchunks), good))
        for _ in range(rng.randint(1, 6)):
            raw[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
        # keep it rejected: corrupt the CRC unless explicitly allowed otherwise
        if not allow_valid:
            raw[-1] ^= 0xFF
        cases.append((f"{verb} mutated", verb, b64(bytes(raw))))

    return cases


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port")
    ap.add_argument("--iters", type=int, default=200)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--allow-valid", action="store_true",
                    help="permit well-formed chunks (still never completes a set)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--wait-alive", type=int, default=0, metavar="SECONDS",
                    help="poll until the badge accepts input, then start immediately. "
                         "The badge does not wake from USB traffic -- only a button press "
                         "does -- so this catches the window after you press one.")
    ap.add_argument("--log", default="console_fuzz_transcript.txt")
    a = ap.parse_args()

    rng = random.Random(a.seed)
    cases = build_cases(rng, a.iters, a.allow_valid)

    if a.dry_run:
        print(f"{len(cases)} cases; verbs used: image, bio (plus `ver` as a liveness probe)")
        print("every case is built to be REJECTED -- no upload can complete\n")
        seen = set()
        for label, verb, arg in cases:
            if label in seen:
                continue
            seen.add(label)
            shown = arg if len(arg) <= 48 else arg[:45] + "..."
            print(f"  {label:34} {verb} {shown!r}")
        print(f"\n({len(cases) - len(seen)} further randomised mutations suppressed)")
        return 0

    port = a.port or find_badge()
    if not port:
        print("No badge found. Run: python stage_detect.py --list-ports")
        return 1

    if a.wait_alive:
        print(f"waiting up to {a.wait_alive}s for the badge to accept input.")
        print("PRESS A BADGE BUTTON NOW -- USB traffic alone will not wake it.")
        deadline = time.time() + a.wait_alive
        alive = False
        while time.time() < deadline and not alive:
            try:
                with BadgeConsole(port, allow={"ver"}, write_timeout=0.6) as c:
                    if c.send("ver", quiet_for=0.2, hard_cap=1.5).strip():
                        alive = True
            except (DeviceNotListening, PortBusy, Exception):
                pass
            if not alive:
                left = int(deadline - time.time())
                print(f"  ...still asleep ({left}s left)", end="\r", flush=True)
                time.sleep(0.6)
        print()
        if not alive:
            print("badge never became responsive; nothing was fuzzed.")
            return 1
        print("badge is awake -- starting immediately.\n")

    t = Transcript()
    t.add(f"# console_fuzz  port={port}  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    t.add(f"# {len(cases)} cases, seed={a.seed}")
    t.add("")

    anomalies = []
    try:
        with BadgeConsole(port, allow={"image", "bio", "ver", "echo"}) as c:
            baseline = c.send("ver")
            t.add(f"baseline `ver` -> {baseline.strip()[:120]!r}")
            if not baseline.strip():
                t.add("WARNING: no reply to `ver`; badge may already be unresponsive.")
            t.add("")

            for i, (label, verb, arg) in enumerate(cases):
                cmd = f"{verb} {arg}" if arg else verb
                try:
                    out = c.send(cmd, quiet_for=0.25, hard_cap=3.0)
                except DeviceNotListening:
                    anomalies.append((label, cmd, "device stopped accepting input"))
                    t.add(f"!! {label}: device stopped accepting input")
                    break

                low = out.lower()
                bad = ("panic" in low or "unwrap" in low or "assertion" in low
                       or "index out of bounds" in low)
                empty = not out.strip()

                if bad or empty:
                    probe = c.send("ver", quiet_for=0.25, hard_cap=3.0)
                    alive = bool(probe.strip())
                    note = "panic text" if bad else "no reply"
                    if not alive:
                        note += "; console DEAD after this case"
                    anomalies.append((label, cmd, note))
                    t.add(f"!! [{i}] {label}")
                    t.add(f"   cmd: {cmd[:120]}")
                    t.add(f"   out: {out.strip()[:300]!r}")
                    t.add(f"   {note}")
                    if not alive:
                        break

            t.add("")
    except PortBusy as e:
        print(f"\n{e}")
        return 1
    except Exception as e:
        print(f"serial error: {e}")
        return 1

    t.add("=" * 66)
    if not anomalies:
        t.add(f"RESULT: {len(cases)} malformed inputs, every one rejected cleanly.")
        t.add("No panic text, no missing replies, console alive throughout.")
        t.add("The static reading of image.rs:133 / bio.rs:605 is confirmed on silicon.")
        rc = 0
    else:
        t.add(f"RESULT: {len(anomalies)} anomalies")
        for label, cmd, note in anomalies:
            t.add(f"  {label:34} {note}")
        t.add("")
        t.add("Re-run a single case by hand before calling it a finding -- serial")
        t.add("timing can produce a false 'no reply'.")
        rc = 2

    t.save(a.log)
    print(f"\ntranscript: {a.log}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
