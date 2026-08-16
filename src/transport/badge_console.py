"""
badge_console.py -- shared serial helper for DC34 badge research tooling.

Every tool in this project talks to the badge through this module. It exists for one
reason: the boot1 REPL sits one typo away from commands that permanently damage the
device. `self_destruct`, `publock` and `lockdown` are real verbs in
bao1x-boot/boot1/src/repl.rs. This module makes it structurally impossible for a tool
built on it to send them by accident.

Design rule: a tool declares the verbs it needs. Anything outside that set raises
before a byte reaches the wire.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

BAUD = 115200

# Verbs that must never be transmitted by any tool in this project, regardless of what
# a caller declares. This is a hard floor, checked after the per-tool allowlist.
#
# Sourced from bao1x-boot/boot1/src/repl.rs match arms:
#   self_destruct  :714  -- destroys the device
#   lockdown       :698  -- irreversible
#   publock        :909  -- locks public key slots, irreversible
#   uf2 / uf2_flush:164,431 -- writes firmware
#   idmode         :679  -- identity mode change
#   altboot        :663  -- alternate boot partition
#   boardtype      :634  -- rewrites board identity
#   require-pq     :724  -- one-way counter, irreversible
#   baosec-init    :740  -- reinitialises the device
#   ate / atecheck :1057 -- factory test entry
#   paranoid       :492  -- one-way counter
#   skipping       :514  -- clock scramble config
#   rand_collateral:870  -- rewrites collateral
#   usb_speed      :1096 -- one-way counter
DENYLIST = frozenset({
    "self_destruct", "lockdown", "publock",
    "uf2", "uf2_flush", "has-crc",
    "idmode", "altboot", "boardtype",
    "require-pq", "baosec-init",
    "ate", "atecheck",
    "paranoid", "skipping", "rand_collateral", "usb_speed",
    "qe", "ifr",
})

# Verbs that only read state. Safe to issue at any time, including before a backup
# exists, because none of them can modify the device.
READ_ONLY = frozenset({"peek", "echo", "ver", "help", "bogomips", "audit"})


class UnsafeCommand(RuntimeError):
    """Raised when a tool attempts to send a command outside its declared allowlist."""


class PortBusy(RuntimeError):
    """Raised when the COM port is already owned by another process."""


class DeviceNotListening(RuntimeError):
    """Raised when the badge accepts a connection but never drains its OUT endpoint.

    Observed cause: the vault UI is on a screen that does not service console input --
    the QR / GeneScan screen is the reliable way to reproduce it. Reads still work (the
    device keeps streaming logs), but the host's TX buffer fills and never empties.

    The serial layer defaults write_timeout to None, under which this manifests as a
    permanent hang inside ser.write(). That also keeps the COM port owned, so every later
    tool fails with "Access is denied". Hence write_timeout is mandatory here, not optional.
    """


@dataclass
class Transcript:
    """Everything sent and received, so a run is reproducible and auditable."""
    lines: list[str] = field(default_factory=list)

    def add(self, s: str = "") -> None:
        print(s)
        self.lines.append(s)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.lines) + "\n")


def list_ports() -> list[tuple[str, str, str]]:
    """Return (device, description, hwid) for every serial port."""
    from serial.tools import list_ports as lp
    return [(p.device, p.description, p.hwid) for p in lp.comports()]


def find_badge() -> str | None:
    """Return the first port whose hwid looks like the badge (VID 1D50, PID 6198)."""
    for dev, _desc, hwid in list_ports():
        h = hwid.upper()
        if "1D50" in h and "6198" in h:
            return dev
    return None


class BadgeConsole:
    """A serial console restricted to a declared set of command verbs.

    Usage:
        with BadgeConsole("COM5", allow={"peek", "echo"}) as c:
            print(c.send("peek 40065000 8"))
    """

    def __init__(self, port: str, allow: set[str], baud: int = BAUD,
                 timeout: float = 1.0, write_timeout: float = 2.0):
        bad = set(allow) & DENYLIST
        if bad:
            raise UnsafeCommand(
                f"allowlist contains permanently denied verbs: {sorted(bad)}"
            )
        self.allow = frozenset(allow)
        self.port = port
        self._baud = baud
        self._timeout = timeout
        self._write_timeout = write_timeout
        self._ser = None

    # -- lifecycle ------------------------------------------------------------
    def __enter__(self) -> "BadgeConsole":
        import serial
        try:
            # write_timeout is mandatory -- see DeviceNotListening. Without it a badge
            # sitting on the QR screen hangs ser.write() forever and holds the port.
            self._ser = serial.Serial(
                self.port, self._baud,
                timeout=self._timeout, write_timeout=self._write_timeout)
        except serial.SerialException as e:
            if "Access is denied" in str(e) or "PermissionError" in str(e):
                raise PortBusy(
                    f"{self.port} is held open by another process.\n"
                    f"  Close any serial terminal (PuTTY, Arduino monitor, screen), and\n"
                    f"  kill leftover Python holding the port:\n"
                    f"      Get-Process python | Stop-Process\n"
                    f"  Only one program can own a COM port at a time."
                ) from e
            raise
        time.sleep(0.4)
        self._ser.reset_input_buffer()
        return self

    def __exit__(self, *exc) -> None:
        if self._ser:
            self._ser.close()

    # -- safety ---------------------------------------------------------------
    def check(self, cmd: str) -> str:
        """Validate a command without sending it. Returns the command on success."""
        stripped = cmd.strip()
        if not stripped:
            raise UnsafeCommand("empty command")
        verb = stripped.split()[0]
        if verb in DENYLIST:
            raise UnsafeCommand(
                f"{verb!r} is on the project-wide denylist and will never be sent"
            )
        if verb not in self.allow:
            raise UnsafeCommand(
                f"{verb!r} is not in this tool's allowlist {sorted(self.allow)}"
            )
        return stripped

    # -- I/O ------------------------------------------------------------------
    def send(self, cmd: str, settle: float = 0.35, quiet_for: float = 0.5,
             hard_cap: float = 6.0) -> str:
        """Send one allowlisted command and collect the reply.

        Collection ends on whichever comes first: the line going quiet for `quiet_for`
        seconds, or `hard_cap` seconds total.

        The hard cap is not optional. This badge's Xous console streams log output
        continuously (RTC ticks, UI keypress echo, service logs), so a purely
        quiet-based loop never terminates on a chatty device -- and while it spins it
        holds the COM port open, which on Windows makes every other tool fail with
        "Access is denied".
        """
        import serial

        cmd = self.check(cmd)
        self._ser.reset_input_buffer()
        try:
            self._ser.write((cmd + "\r\n").encode())
        except serial.SerialTimeoutException as e:
            raise DeviceNotListening(
                "The badge is connected and streaming logs, but it is not reading\n"
                "  console input -- the write timed out.\n"
                "\n"
                "  Most likely the vault UI is on a screen that does not service the\n"
                "  console. The QR / GeneScan screen does exactly this; you can confirm\n"
                "  it by watching for 'dc34_vault::ux: Nonce encoded ... Qrcode' in the\n"
                "  log stream.\n"
                "\n"
                "  Fix: press a badge button to leave that screen and return to idle,\n"
                "  then re-run. No unplugging or power cycle is needed.\n"
                "\n"
                "  Diagnose with: python diag_serial.py --port " + self.port
            ) from e
        time.sleep(settle)

        buf = b""
        start = time.time()
        last_data = start
        while True:
            now = time.time()
            if now - start >= hard_cap:
                break
            chunk = self._ser.read(4096)
            if chunk:
                buf += chunk
                last_data = time.time()
            elif time.time() - last_data >= quiet_for:
                break
        return buf.decode("utf-8", errors="replace")

    def drain(self, seconds: float = 1.0) -> str:
        """Read whatever the device is already emitting, sending nothing."""
        buf = b""
        end = time.time() + seconds
        while time.time() < end:
            chunk = self._ser.read(4096)
            if chunk:
                buf += chunk
        return buf.decode("utf-8", errors="replace")


def which_stage(banner: str) -> str:
    """Identify which firmware stage is on the far end, from its output.

    boot1 prints '~~Boot1 up! (...)~~' at bao1x-boot/boot1/src/main.rs:108.
    The Xous console app prints log lines tagged 'dc34_console'.
    """
    b = banner.lower()
    # boot1 banner, main.rs:108
    if "boot1 up" in b or "alt-boot1 up" in b:
        return "boot1"
    # boot1 REPL error/help strings
    if "peek disallowed" in b or "bootwait" in b:
        return "boot1"
    # Xous: the console's own command list, or any Xous service log tag. The vault and
    # console services log continuously, so this usually matches passively.
    if any(s in b for s in ("dc34_console", "dc34_vault", "commands:",
                            "xous", "pddb", "bao1x_hal_service")):
        return "xous"
    return "unknown"
