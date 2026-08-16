"""Is F-1 about command RATE rather than line length?

The bisect refuted the length hypothesis: `echo` and `image` both survive 4096-char
arguments when sent one at a time with settle delays. But the original kill happened
during rapid-fire fuzzing (240 cases, ~0.35s apart), at case 10.

This reproduces the fuzzer's timing instead of its payload.
"""
import sys, time, serial

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM5"

def probe(s):
    try:
        s.reset_input_buffer(); s.write(b"\r\n"); s.flush(); time.sleep(0.3)
        s.reset_input_buffer(); s.write(b"ver\r\n"); s.flush()
    except Exception:
        return ""
    time.sleep(0.9)
    try: return s.read(8192).decode("utf8","replace")
    except Exception: return ""

def alive(r): 
    low = r.lower()
    return any(m in low for m in ("xous","[console]","commands:"))

s = serial.Serial(PORT, 115200, timeout=0.3, write_timeout=3.0)
time.sleep(0.4)
if not alive(probe(s)):
    print("badge not responding at baseline -- pull a battery."); sys.exit(1)
print("baseline OK\n")

# Escalating burst pressure: N commands back to back with `gap` seconds between.
for gap, count, size in [(0.35, 20, 100), (0.35, 20, 1000), (0.10, 30, 1000),
                         (0.02, 40, 1000), (0.0, 60, 2000)]:
    print(f"  burst: {count} cmds, gap {gap}s, {size} chars each ... ", end="", flush=True)
    try:
        for _ in range(count):
            s.write(b"image " + b"A"*size + b"\r\n")
            if gap: time.sleep(gap)
        s.flush()
    except Exception as e:
        print(f"WRITE FAILED: {type(e).__name__} -- USB OUT wedged")
        print(f"\n  TRIGGER: burst of {count} @ gap {gap}s, {size} chars")
        break
    time.sleep(2.0)
    if alive(probe(s)):
        print("console alive")
    else:
        print("NO REPLY -- console dead")
        print(f"\n  TRIGGER: burst of {count} @ gap {gap}s, {size} chars")
        break
else:
    print("\n  survived every burst pattern tested")

s.close()
print("\nIf it died: check whether the PHYSICAL buttons still work, then pull a battery.")
