# dc34-0day

Security findings in the DEF CON 34 badge core module (Baochip-1x SoC, Xous OS), with tooling that reproduces them.

One finding: an unauthenticated USB peer can freeze the entire device — display, physical buttons and console — until power is removed. It was triggered on hardware, repeatedly, and the result is visible on the badge's own screen.

```bash
pip install -r requirements.txt
python run.py                                    # pin content on screen (the demo)
```

---

## Commands

```bash
python run.py                                    # = attack freeze
python run.py list                               # everything available
python run.py check                              # find the badge, report its state
python run.py clear                              # restore the stock screen

python run.py attack freeze                      # pin content past the firmware's rotation
python run.py attack freeze -- --art cat         # built-in pixel art
python run.py attack freeze -- --art skull
python run.py attack freeze -- --text "PWNED BY\nMEOW"
python run.py attack freeze -- --art cat --invert    # if the panel comes out reversed
python run.py attack freeze -- --art cat --delay 3   # if it froze on the DEF CON logo

python run.py attack dos                         # freeze the device, with evidence log
python run.py attack ui                          # drive the menus from USB
python run.py attack ui -- --index 0             # Screen Off
python run.py attack ui -- --index 5             # Change font
python run.py attack rate                        # find this unit's vuln threshold
python run.py attack bisect                      # show line length alone does not do it
python run.py attack fuzz                        # 240 malformed chunk-parser inputs

python src/transport/test_badge_console.py       # 20 self-tests, no hardware needed
```

Plug the badge in with a **data** cable and run. Everything else — waiting for enumeration, checking the device is answering, reporting what should be on screen — is handled. If a tool says the badge is frozen, unplug USB for three seconds and re-run.

## DEMO

https://youtu.be/WA4zOgad1fg

---

## What was found

**console throughput starves every keyboard listener.** Send console text over USB faster than the keyboard server drains its queue and the display, the physical buttons and the console all stop together. No authentication, no pairing, no button press, no prior state. Only removing power recovers the device.

Three files compose it: an unbounded loop over attacker-controlled input inside a message handler (`usb-bao1x/src/main.rs:610`), a blocking send into a bounded queue (`keyboard/src/lib.rs:106`), and a *lossy* send on the far side (`bao1x-hal-service/src/servers/keyboard.rs:492`). Backpressure only travels backwards, so the attacker's traffic gets a retry loop while the user's button press is discarded.

Full write-up, code, reasoning and the two wrong hypotheses along the way: https://no-flag.com/2026/08/16/dc34-badge-deadlock/

### The bar

Two conditions, both required. **The code is wrong** — a missing bound, an inverted constant, an unbounded loop on attacker-controlled input; behaviour that is unfortunate but working as designed does not qualify. And **the attack ran on the badge and succeeded**, reproducibly, with the effect observable on the device.

Source and RTL review turned up six further candidate defects. None were fired at the badge successfully and some were never fired at all — testing the boot1 EP0 path means writing past a buffer in firmware-update mode on the only unit available. Reading code and concluding a bug exists is not the same as demonstrating one, so they are not published here. 

---

## What is a defect here, and what is not

Worth being blunt about, because the demo mixes both on purpose.

`python run.py attack freeze` does two things. It uploads a picture using the badge's **documented `image` console command** — that is not an exploit, and `apply_image.py` in the vendor's own tooling does the same. Then it triggers, so the vault stops redrawing and the picture stays.

The firmware alternates any user bitmap with the DEF CON logo every three seconds, with no setting to stop it (`dc34-vault/src/ux.rs:783`). Putting a picture on the screen proves nothing. **Keeping it there, against code written to prevent that, is the part that needs the defect.**

`python run.py attack ui` drives the vault's menus from USB and works, but it is **not counted as a finding**. Nothing along that path is wrong: injecting console input over serial is a designed feature, and the keyboard server forwards keys to all listeners by design. The interface is more privileged than it looks — worth raising with the vendor — but no bound is missing and no signal is miswired. It is kept because it is the clearest demonstration of the mechanism behind vuln: the same path is a UI hijack at 1.5 s per keystroke and a device freeze at 0.55 s.

---

## Layout

```
run.py                     entry point
src/transport/             serial layer, command denylist, self-tests
src/attacks/               reproduction, measurement, and the visible demo
src/utils/                 clear_screen.py
```

---

## Safety

The boot1 REPL contains verbs that permanently damage the device: `self_destruct`, `publock`, `lockdown`, and the firmware writers `uf2` / `uf2_flush`. `test reset` is also destructive despite the name — it is `pddb.delete_dict(DC34_DICT)`, which deletes `k0` along with everything else.

No tool here writes a raw string to the serial port. Everything goes through `src/transport/badge_console.py`, which makes each tool declare the verbs it needs, rejects anything outside that set before transmission, and enforces a project-wide denylist underneath that no tool can opt out of. `test_badge_console.py` covers it — the last assertion checks that a blocked command transmitted zero bytes.

Other guards: the UI tool refuses menu entry 2 (*Delete*) by name; the fuzzer is built so no upload can complete, so nothing reaches PDDB; nothing sends `bootwait`, which burns a one-way counter that no backup can restore.

**Recovery is always the same.** Remove power — unplug USB with no battery fitted, or pull a cell. The badge freezing is working, not the tool misbehaving.

---

## References

Only projects actually used.

- **[bunnie/dc34-image](https://github.com/bunnie/dc34-image)** — the official image uploader. Its chunk protocol (70-byte frames: `u16` index, 64 bytes data, CRC-32) is what `src/attacks/freeze_display.py` speaks. Reading it is how the wire format was established.
- **[ACD421/dc34-badge-tools](https://github.com/ACD421/dc34-badge-tools)** — community tooling for lights and OLED. Used to establish prior art and exclude it: it showed `k0` is public, the light-exchange format is public, and BIO code execution is already productised. Its `apply_image.py` also served as the reference for per-chunk acknowledgement and retry, which is why uploads here retry rather than firing blind.
- **[nastea1/dc34-gamete](https://github.com/nastea1/dc34-gamete)** — released `k0` with the designer's permission. Cited only to explain why the light-gene protocol was dropped as an attack surface: it is not gated on a secret.
- **[betrusted-io/usb-device](https://github.com/betrusted-io/usb-device)** — the fork the running firmware builds against. Diffed against upstream to check whether the fork introduced anything into the control-transfer path; it did not, which closed the running firmware's USB stack as a target.
- **[defcon.org/34b](https://defcon.org/34b/)** — badge documentation and the published list of already-closed attack paths, used to avoid re-reporting known ground.

Sources reviewed rather than referenced as tools: `xous-core`, `dc34-vault`, `dc34-console`, `baochip-1x` — the badge's own published firmware and RTL.

---
# Disclosure
Note: This vulnerability disclosure was made public with the consent of the person primarily responsible for the project. All applicable vulnerability disclosure and reporting procedures were followed.


---

## License

MIT. See [LICENSE](LICENSE).
