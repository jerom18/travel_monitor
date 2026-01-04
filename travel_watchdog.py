#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
travel_watchdog.py  (Pi Zero 2 W)

What it does:
1) LAN connectivity: finds default gateway dynamically and pings it
2) WAN connectivity: pings google.com (change WAN_TARGET if you like)
3) Tailscale connectivity: confirms tailscale backend running + self online; then (if any peer online) tailscale-pings one
4) Speed test: every 30 mins between 08:00-20:00 (local time), tries tools in order "best"->"worst":
      a) librespeed-cli  (JSON)
      b) Ookla speedtest (speedtest -f json) if available
      c) speedtest-cli   (speedtest-cli --json) and/or (speedtest --json) if that's the python tool
      d) HTTPS download test via curl (least "accurate" but hardest to block)
   Ensures you always get a logged outcome (success or "blocked/unreachable").

5) If any of (1)-(3) fail => broadcasts BLE advert with a 4-byte payload:
      [version=1][bitmask][lan_rtt_ms or 255][wan_rtt_ms or 255]
   bitmask: bit0 LAN fail, bit1 WAN fail, bit2 TS fail
6) Optionally scans for a BLE device by name, connects, and writes a larger JSON
   payload over a configured GATT characteristic ("direct push" mode).

Run:
  sudo python3 travel_watchdog.py
Phone:
  Scan for BLE device name "TravelWatch" and inspect Manufacturer Data.
  For direct push, set TARGET_DEVICE_NAME to your phone's BLE name as shown in
  the scanning app or OS Bluetooth list. The phone app should subscribe to
  notifications or read from the characteristic identified by TARGET_CHAR_UUID.
"""

import asyncio
import importlib.util
import sys
import json
import random
import re
import shlex
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, time as dtime
from typing import Optional, Tuple, Dict, Any, List

if importlib.util.find_spec("dbus_next") is None:
    log("Missing dependency: dbus-next. Attempting install via pip.")
    install = subprocess.run(
        [sys.executable, "-m", "pip", "install", "dbus-next"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
    )
    if install.returncode != 0:
        raise SystemExit(
            "Failed to install dbus-next. "
            f"stdout: {install.stdout.strip()} stderr: {install.stderr.strip()}"
        )

from dbus_next.aio import MessageBus
from dbus_next.service import ServiceInterface, method, dbus_property, PropertyAccess
from dbus_next import Variant
from dbus_next.constants import BusType

BLUEZ_SERVICE = "org.bluez"
LE_ADVERTISING_MANAGER_IFACE = "org.bluez.LEAdvertisingManager1"
DBUS_OM_IFACE = "org.freedesktop.DBus.ObjectManager"

# ---- Config ----
PING_TIMEOUT_SEC = 2
CHECK_INTERVAL_SEC = 20  # how often to re-check 1-3 and update BLE state

WAN_TARGET = "google.com"  # or 1.1.1.1 etc.

SPEEDTEST_WINDOW_START = dtime(8, 0)
SPEEDTEST_WINDOW_END = dtime(20, 0)
SPEEDTEST_INTERVAL_SEC = 30 * 60  # 30 minutes

LOG_PATH = "/tmp/travel_watchdog.log"

# BLE advert: manufacturer data company id 0xFFFF (test/unknown). Payload is 4 bytes.
MFG_COMPANY_ID = 0xFFFF
PAYLOAD_VERSION = 1

# Direct push (GATT write) config
# Phone selection: set TARGET_DEVICE_NAME to the BLE name shown by your phone
# or BLE scanner app (some platforms expose the "Bluetooth name"/alias).
# Notifications: your phone app should subscribe to characteristic
# notifications or do explicit reads of TARGET_CHAR_UUID to receive JSON updates.
DIRECT_PUSH_ENABLED = True
TARGET_DEVICE_NAME = "TravelWatchPhone"  # BLE device name to connect to
TARGET_SERVICE_UUID = "0000ffe0-0000-1000-8000-00805f9b34fb"
TARGET_CHAR_UUID = "0000ffe1-0000-1000-8000-00805f9b34fb"
DIRECT_PUSH_SCAN_TIMEOUT_SEC = 15
DIRECT_PUSH_RETRY_SEC = 30
DIRECT_PUSH_MAX_CHUNK = 180  # bytes per GATT write (kept conservative)

# HTTPS fallback for speed-ish test (harder to block than speedtest.net)
HTTP_TEST_URL = "https://speed.hetzner.de/10MB.bin"


def log(msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} {msg}"
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def run(cmd: str, timeout: int = 10) -> Tuple[int, str, str]:
    """Run a command; return (rc, stdout, stderr)."""
    p = subprocess.run(
        shlex.split(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        text=True,
    )
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def which(cmd: str) -> bool:
    rc, _, _ = run(f"bash -lc 'command -v {shlex.quote(cmd)} >/dev/null 2>&1'", timeout=5)
    return rc == 0


def get_default_gateway() -> Optional[str]:
    # Typical: "default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.50 metric 600"
    rc, out, _ = run("ip route show default", timeout=5)
    if rc != 0 or not out:
        return None
    m = re.search(r"default via (\S+)", out)
    return m.group(1) if m else None


def ping(host: str) -> Tuple[bool, Optional[int]]:
    """Ping once; returns (ok, rtt_ms capped 0-255)."""
    try:
        rc, out, _ = run(f"ping -c 1 -W {PING_TIMEOUT_SEC} {host}", timeout=PING_TIMEOUT_SEC + 2)
    except subprocess.TimeoutExpired:
        return False, None
    if rc != 0:
        return False, None
    m = re.search(r"time=([\d\.]+)\s*ms", out)
    if not m:
        return True, None
    rtt = int(float(m.group(1)))
    return True, max(0, min(255, rtt))


def tailscale_status_json() -> Optional[Dict[str, Any]]:
    rc, out, _ = run("tailscale status --json", timeout=5)
    if rc != 0 or not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def tailscale_ok_and_peer() -> Tuple[bool, Optional[str]]:
    """
    Returns (tailscale_ok, peer_ip_to_ping).
    tailscale_ok means backend running and self online.
    peer_ip_to_ping is an online peer Tailscale IP if found.
    """
    st = tailscale_status_json()
    if not st:
        return False, None

    backend = st.get("BackendState")
    self_node = st.get("Self", {})
    self_online = bool(self_node.get("Online", False))

    if backend != "Running" or not self_online:
        return False, None

    peers = st.get("Peer", {}) or {}
    online_peer_ips: List[str] = []
    for _, peer in peers.items():
        if not peer.get("Online"):
            continue
        addrs = peer.get("TailscaleIPs") or []
        if addrs:
            online_peer_ips.append(addrs[0])

    if online_peer_ips:
        return True, random.choice(online_peer_ips)
    return True, None


def tailscale_ping(peer_ip: str) -> bool:
    rc, _, _ = run(f"tailscale ping -c 1 -timeout 2s {peer_ip}", timeout=6)
    return rc == 0


# ---------------- Speed test helpers ----------------

def parse_json_from_out_err(stdout: str, stderr: str) -> Optional[Dict[str, Any]]:
    """
    Some tools (notably librespeed-cli in some versions) can emit JSON to stderr.
    Try stdout first, then stderr.
    """
    for blob in (stdout, stderr):
        blob = (blob or "").strip()
        if not blob:
            continue
        try:
            return json.loads(blob)
        except json.JSONDecodeError:
            continue
    return None


def http_download_test(url: str = HTTP_TEST_URL, timeout: int = 25) -> Optional[Dict[str, Any]]:
    """
    Plain HTTPS download throughput estimate using curl.
    Returns dict with approx_down_mbps, or None if it fails.
    """
    if not which("curl"):
        return None

    start = time.time()
    rc, out, err = run(
        f"curl -L --max-time {timeout} -o /dev/null -s -w '%{{size_download}}' {shlex.quote(url)}",
        timeout=timeout + 5
    )
    if rc != 0 or not out:
        return None

    try:
        bytes_dl = float(out.strip())
        secs = max(0.001, time.time() - start)
        down_mbps = (bytes_dl * 8) / secs / 1_000_000
        return {"tool": "http-curl", "download_mbps": down_mbps, "upload_mbps": None, "ping_ms": None}
    except Exception:
        return None


def run_speedtest_best_effort() -> Dict[str, Any]:
    """
    Tries tools in order best -> worst and always returns a result dict with:
      - tool
      - ok (bool)
      - download_mbps / upload_mbps (floats or None)
      - ping_ms (float or None)
      - error (str, if not ok)
    """

    # 1) LibreSpeed CLI (usually easiest to run on locked-down networks)
    if which("librespeed-cli"):
        rc, out, err = run("librespeed-cli --json", timeout=120)
        j = parse_json_from_out_err(out, err)
        if rc == 0 and j:
            # librespeed-cli JSON field names vary a bit between versions; handle common ones
            # Common keys: download, upload, ping, jitter (often in Mbps)
            dl = None
            ul = None
            ping_ms = None

            # Try a few patterns:
            # - {"download": 123.45, "upload": 67.89, "ping": 12.3}
            # - {"download": {"bandwidth": ...}} etc (less common)
            if isinstance(j.get("download"), (int, float)):
                dl = float(j.get("download"))
            elif isinstance(j.get("download"), dict) and "bandwidth" in j["download"]:
                # assume bytes/sec -> Mbps
                dl = (float(j["download"]["bandwidth"]) * 8) / 1_000_000

            if isinstance(j.get("upload"), (int, float)):
                ul = float(j.get("upload"))
            elif isinstance(j.get("upload"), dict) and "bandwidth" in j["upload"]:
                ul = (float(j["upload"]["bandwidth"]) * 8) / 1_000_000

            if isinstance(j.get("ping"), (int, float)):
                ping_ms = float(j.get("ping"))
            elif isinstance(j.get("ping"), dict) and "latency" in j["ping"]:
                ping_ms = float(j["ping"]["latency"])

            # If dl/ul are present but look like bps, convert:
            # Heuristic: if value > 10_000 it's probably bps not Mbps
            if dl is not None and dl > 10_000:
                dl = dl / 1_000_000
            if ul is not None and ul > 10_000:
                ul = ul / 1_000_000

            return {"tool": "librespeed-cli", "ok": True, "download_mbps": dl, "upload_mbps": ul, "ping_ms": ping_ms}

        return {"tool": "librespeed-cli", "ok": False, "download_mbps": None, "upload_mbps": None, "ping_ms": None,
                "error": (err or out or "Failed/blocked").strip()[:240]}

    # 2) Ookla Speedtest CLI (official)
    if which("speedtest"):
        # Detect if this is Ookla by checking help for -f / --format
        rc_h, out_h, _ = run("speedtest -h", timeout=10)
        is_ookla = (rc_h == 0) and (("-f" in out_h) or ("--format" in out_h))
        if is_ookla:
            rc, out, err = run("speedtest -f json", timeout=120)
            j = parse_json_from_out_err(out, err)
            if rc == 0 and j:
                # Ookla JSON: download/upload bandwidth in bytes/sec
                dl_mbps = (float(j.get("download", {}).get("bandwidth", 0)) * 8) / 1_000_000
                ul_mbps = (float(j.get("upload", {}).get("bandwidth", 0)) * 8) / 1_000_000
                ping_ms = j.get("ping", {}).get("latency")
                ping_ms = float(ping_ms) if ping_ms is not None else None
                return {"tool": "ookla-speedtest", "ok": True, "download_mbps": dl_mbps, "upload_mbps": ul_mbps, "ping_ms": ping_ms}

            return {"tool": "ookla-speedtest", "ok": False, "download_mbps": None, "upload_mbps": None, "ping_ms": None,
                    "error": (err or out or "Failed/blocked").strip()[:240]}

    # 3) speedtest-cli (python) (either as `speedtest-cli` or `speedtest --json`)
    # 3a) speedtest-cli explicit
    if which("speedtest-cli"):
        rc, out, err = run("speedtest-cli --json", timeout=120)
        j = parse_json_from_out_err(out, err)
        if rc == 0 and j:
            dl_bps = float(j.get("download", 0))
            ul_bps = float(j.get("upload", 0))
            ping_ms = j.get("ping")
            ping_ms = float(ping_ms) if ping_ms is not None else None
            return {"tool": "speedtest-cli", "ok": True, "download_mbps": dl_bps / 1_000_000, "upload_mbps": ul_bps / 1_000_000, "ping_ms": ping_ms}

        return {"tool": "speedtest-cli", "ok": False, "download_mbps": None, "upload_mbps": None, "ping_ms": None,
                "error": (err or out or "Failed/blocked").strip()[:240]}

    # 3b) speedtest --json (if `speedtest` is the python tool rather than Ookla)
    if which("speedtest"):
        rc, out, err = run("speedtest --json", timeout=120)
        j = parse_json_from_out_err(out, err)
        if rc == 0 and j:
            dl_bps = float(j.get("download", 0))
            ul_bps = float(j.get("upload", 0))
            ping_ms = j.get("ping")
            ping_ms = float(ping_ms) if ping_ms is not None else None
            return {"tool": "speedtest(py)--json", "ok": True, "download_mbps": dl_bps / 1_000_000, "upload_mbps": ul_bps / 1_000_000, "ping_ms": ping_ms}

        return {"tool": "speedtest(py)--json", "ok": False, "download_mbps": None, "upload_mbps": None, "ping_ms": None,
                "error": (err or out or "Failed/blocked").strip()[:240]}

    # 4) Worst-case: HTTPS download estimate
    res = http_download_test()
    if res:
        return {"tool": res["tool"], "ok": True, "download_mbps": res["download_mbps"], "upload_mbps": None, "ping_ms": None}

    return {"tool": "none", "ok": False, "download_mbps": None, "upload_mbps": None, "ping_ms": None,
            "error": "No speed test method available (install librespeed-cli, speedtest, speedtest-cli and/or curl)."}


# ---------------- BLE advertising via BlueZ D-Bus ----------------

class Advertisement(ServiceInterface):
    """
    Minimal org.bluez.LEAdvertisement1 object.
    Broadcast with manufacturer data payload.
    """
    def __init__(self, index: int, payload: bytes, local_name: str = "TravelWatch"):
        super().__init__("org.bluez.LEAdvertisement1")
        self.path = f"/com/example/advertisement{index}"
        self._payload = payload
        self._local_name = local_name

    def set_payload(self, payload: bytes) -> None:
        self._payload = payload

    @dbus_property(access=PropertyAccess.READ)
    def Type(self) -> "s":
        return "broadcast"

    @dbus_property(access=PropertyAccess.READ)
    def LocalName(self) -> "s":
        return self._local_name

    @dbus_property(access=PropertyAccess.READ)
    def ManufacturerData(self) -> "a{qv}":
        # dbus-next requires "ay" value as Python bytes (NOT list[int])
        return {MFG_COMPANY_ID: Variant("ay", bytes(self._payload))}

    @dbus_property(access=PropertyAccess.READ)
    def ServiceUUIDs(self) -> "as":
        return []

    @dbus_property(access=PropertyAccess.READ)
    def Includes(self) -> "as":
        return []

    @method()
    def Release(self) -> None:
        log("BLE advertisement released by BlueZ")


async def find_adapter(bus: MessageBus) -> Optional[str]:
    managed = await get_managed_objects(bus)

    for path, ifaces in managed.items():
        if "org.bluez.Adapter1" in ifaces and LE_ADVERTISING_MANAGER_IFACE in ifaces:
            return path
    return None


async def register_advert(bus: MessageBus, adapter_path: str, advert: Advertisement) -> None:
    intro = await bus.introspect(BLUEZ_SERVICE, adapter_path)
    proxy = bus.get_proxy_object(BLUEZ_SERVICE, adapter_path, intro)
    adv_mgr = proxy.get_interface(LE_ADVERTISING_MANAGER_IFACE)
    await adv_mgr.call_register_advertisement(advert.path, {})


async def unregister_advert(bus: MessageBus, adapter_path: str, advert: Advertisement) -> None:
    intro = await bus.introspect(BLUEZ_SERVICE, adapter_path)
    proxy = bus.get_proxy_object(BLUEZ_SERVICE, adapter_path, intro)
    adv_mgr = proxy.get_interface(LE_ADVERTISING_MANAGER_IFACE)
    try:
        await adv_mgr.call_unregister_advertisement(advert.path)
    except Exception:
        pass


def build_payload(lan_fail: bool, wan_fail: bool, ts_fail: bool,
                  lan_rtt: Optional[int], wan_rtt: Optional[int]) -> bytes:
    bitmask = 0
    bitmask |= 1 if lan_fail else 0
    bitmask |= 2 if wan_fail else 0
    bitmask |= 4 if ts_fail else 0
    lan_b = lan_rtt if lan_rtt is not None else 255
    wan_b = wan_rtt if wan_rtt is not None else 255
    return bytes([PAYLOAD_VERSION, bitmask & 0xFF, lan_b & 0xFF, wan_b & 0xFF])


def in_speedtest_window(now: datetime) -> bool:
    t = now.time()
    return (t >= SPEEDTEST_WINDOW_START) and (t < SPEEDTEST_WINDOW_END)


async def get_managed_objects(bus: MessageBus) -> Dict[str, Dict[str, Dict[str, Any]]]:
    obj = await bus.introspect(BLUEZ_SERVICE, "/")
    om = bus.get_proxy_object(BLUEZ_SERVICE, "/", obj).get_interface(DBUS_OM_IFACE)
    return await om.call_get_managed_objects()


async def start_discovery(bus: MessageBus, adapter_path: str) -> None:
    intro = await bus.introspect(BLUEZ_SERVICE, adapter_path)
    proxy = bus.get_proxy_object(BLUEZ_SERVICE, adapter_path, intro)
    adapter = proxy.get_interface("org.bluez.Adapter1")
    await adapter.call_start_discovery()


async def stop_discovery(bus: MessageBus, adapter_path: str) -> None:
    intro = await bus.introspect(BLUEZ_SERVICE, adapter_path)
    proxy = bus.get_proxy_object(BLUEZ_SERVICE, adapter_path, intro)
    adapter = proxy.get_interface("org.bluez.Adapter1")
    try:
        await adapter.call_stop_discovery()
    except Exception:
        pass


async def find_device_path_by_name(
    bus: MessageBus,
    adapter_path: str,
    target_name: str,
    timeout_sec: int,
) -> Optional[str]:
    await start_discovery(bus, adapter_path)
    try:
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            managed = await get_managed_objects(bus)
            for path, ifaces in managed.items():
                dev = ifaces.get("org.bluez.Device1")
                if not dev:
                    continue
                if not path.startswith(adapter_path):
                    continue
                name = dev.get("Name") or dev.get("Alias")
                if name == target_name:
                    return path
            await asyncio.sleep(1)
        return None
    finally:
        await stop_discovery(bus, adapter_path)


async def connect_device(bus: MessageBus, device_path: str) -> bool:
    intro = await bus.introspect(BLUEZ_SERVICE, device_path)
    proxy = bus.get_proxy_object(BLUEZ_SERVICE, device_path, intro)
    device = proxy.get_interface("org.bluez.Device1")
    try:
        await device.call_connect()
        return True
    except Exception:
        return False


async def disconnect_device(bus: MessageBus, device_path: str) -> None:
    intro = await bus.introspect(BLUEZ_SERVICE, device_path)
    proxy = bus.get_proxy_object(BLUEZ_SERVICE, device_path, intro)
    device = proxy.get_interface("org.bluez.Device1")
    try:
        await device.call_disconnect()
    except Exception:
        pass


def find_characteristic_path(
    managed: Dict[str, Dict[str, Dict[str, Any]]],
    device_path: str,
    char_uuid: str,
    service_uuid: Optional[str] = None,
) -> Optional[str]:
    char_uuid = char_uuid.lower()
    service_uuid = service_uuid.lower() if service_uuid else None
    service_uuid_by_path: Dict[str, str] = {}

    for path, ifaces in managed.items():
        svc = ifaces.get("org.bluez.GattService1")
        if not svc:
            continue
        uuid = str(svc.get("UUID", "")).lower()
        service_uuid_by_path[path] = uuid

    for path, ifaces in managed.items():
        char = ifaces.get("org.bluez.GattCharacteristic1")
        if not char:
            continue
        if not path.startswith(device_path):
            continue
        uuid = str(char.get("UUID", "")).lower()
        if uuid != char_uuid:
            continue
        if service_uuid:
            service_path = char.get("Service")
            if not service_path:
                continue
            if service_uuid_by_path.get(service_path, "") != service_uuid:
                continue
        return path
    return None


def chunk_bytes(data: bytes, chunk_size: int) -> List[bytes]:
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


async def write_characteristic(bus: MessageBus, char_path: str, payload: bytes) -> bool:
    intro = await bus.introspect(BLUEZ_SERVICE, char_path)
    proxy = bus.get_proxy_object(BLUEZ_SERVICE, char_path, intro)
    char = proxy.get_interface("org.bluez.GattCharacteristic1")
    try:
        for chunk in chunk_bytes(payload, DIRECT_PUSH_MAX_CHUNK):
            await char.call_write_value(chunk, {})
        return True
    except Exception:
        return False


def build_direct_message(state: "NetState", speedtest: Optional[Dict[str, Any]]) -> bytes:
    payload: Dict[str, Any] = {
        "version": 1,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "lan": {"ok": state.lan_ok, "rtt_ms": state.lan_rtt},
        "wan": {"ok": state.wan_ok, "rtt_ms": state.wan_rtt},
        "tailscale": {"ok": state.ts_ok, "peer": state.ts_peer_used},
    }
    if speedtest:
        payload["speedtest"] = speedtest
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass
class DirectPushState:
    device_path: Optional[str] = None
    char_path: Optional[str] = None
    last_attempt: float = 0.0


async def ensure_direct_push_ready(
    bus: MessageBus,
    adapter_path: str,
    state: DirectPushState,
) -> bool:
    if state.device_path and state.char_path:
        return True
    if time.time() - state.last_attempt < DIRECT_PUSH_RETRY_SEC:
        return False
    state.last_attempt = time.time()

    device_path = await find_device_path_by_name(
        bus, adapter_path, TARGET_DEVICE_NAME, DIRECT_PUSH_SCAN_TIMEOUT_SEC
    )
    if not device_path:
        log(f"Direct push: device '{TARGET_DEVICE_NAME}' not found")
        return False
    if not await connect_device(bus, device_path):
        log(f"Direct push: failed to connect to {device_path}")
        return False
    managed = await get_managed_objects(bus)
    char_path = find_characteristic_path(
        managed, device_path, TARGET_CHAR_UUID, TARGET_SERVICE_UUID
    )
    if not char_path:
        log("Direct push: target characteristic not found after connect")
        await disconnect_device(bus, device_path)
        return False
    state.device_path = device_path
    state.char_path = char_path
    log(f"Direct push: connected to {device_path} char={char_path}")
    return True


@dataclass
class NetState:
    lan_ok: bool
    wan_ok: bool
    ts_ok: bool
    lan_rtt: Optional[int]
    wan_rtt: Optional[int]
    ts_peer_used: Optional[str]


async def main() -> None:
    log("Starting travel_watchdog")

    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    adapter_path = await find_adapter(bus)
    if not adapter_path:
        raise RuntimeError("No BLE-capable BlueZ adapter with LEAdvertisingManager1 found (is bluetooth up?).")

    # Initial advert = assume fail until first checks complete
    current_payload = build_payload(lan_fail=True, wan_fail=True, ts_fail=True, lan_rtt=None, wan_rtt=None)
    advert = Advertisement(index=0, payload=current_payload, local_name="TravelWatch")
    bus.export(advert.path, advert)

    await register_advert(bus, adapter_path, advert)
    log(f"BLE advertising registered on {adapter_path} (LocalName=TravelWatch)")

    last_speedtest = 0.0
    last_bitmask: Optional[int] = None
    last_direct_payload: Optional[bytes] = None
    last_speedtest_result: Optional[Dict[str, Any]] = None
    direct_state = DirectPushState()

    try:
        while True:
            # 1) LAN check
            gw = get_default_gateway()
            if not gw:
                lan_ok, lan_rtt = False, None
            else:
                lan_ok, lan_rtt = ping(gw)

            # 2) WAN check (simple ping)
            wan_ok, wan_rtt = ping(WAN_TARGET)

            # 3) Tailscale check
            ts_ok_basic, peer_ip = tailscale_ok_and_peer()
            ts_ok = ts_ok_basic
            if ts_ok_basic and peer_ip:
                ts_ok = tailscale_ping(peer_ip)

            state = NetState(
                lan_ok=lan_ok, wan_ok=wan_ok, ts_ok=ts_ok,
                lan_rtt=lan_rtt, wan_rtt=wan_rtt, ts_peer_used=peer_ip
            )

            lan_fail = not state.lan_ok
            wan_fail = not state.wan_ok
            ts_fail = not state.ts_ok

            payload = build_payload(lan_fail, wan_fail, ts_fail, state.lan_rtt, state.wan_rtt)
            bitmask = payload[1]

            # Update BLE advert on state change (simple and reliable)
            if bitmask != last_bitmask:
                advert.set_payload(payload)
                await unregister_advert(bus, adapter_path, advert)
                await register_advert(bus, adapter_path, advert)
                last_bitmask = bitmask

                log(
                    f"STATE changed: "
                    f"LAN={'OK' if lan_ok else 'FAIL'}({gw},{lan_rtt}ms) "
                    f"WAN={'OK' if wan_ok else 'FAIL'}({WAN_TARGET},{wan_rtt}ms) "
                    f"TS={'OK' if ts_ok else 'FAIL'}(peer={peer_ip}) "
                    f"bitmask={bitmask:03b}"
                )

            if DIRECT_PUSH_ENABLED:
                direct_payload = build_direct_message(state, last_speedtest_result)
                if direct_payload != last_direct_payload:
                    if await ensure_direct_push_ready(bus, adapter_path, direct_state):
                        if await write_characteristic(bus, direct_state.char_path, direct_payload):
                            last_direct_payload = direct_payload
                            log(f"Direct push: sent {len(direct_payload)} bytes")
                        else:
                            log("Direct push: write failed, will retry")
                            direct_state.device_path = None
                            direct_state.char_path = None

            # 4) Speedtest schedule (08:00-20:00, every 30 mins)
            now = datetime.now()
            if in_speedtest_window(now) and (time.time() - last_speedtest) >= SPEEDTEST_INTERVAL_SEC:
                res = run_speedtest_best_effort()
                last_speedtest_result = res
                if res["ok"]:
                    dl = res.get("download_mbps")
                    ul = res.get("upload_mbps")
                    ping_ms = res.get("ping_ms")
                    dl_s = f"{dl:.2f}Mbps" if isinstance(dl, (int, float)) else "n/a"
                    ul_s = f"{ul:.2f}Mbps" if isinstance(ul, (int, float)) else "n/a"
                    ping_s = f"{ping_ms:.1f}ms" if isinstance(ping_ms, (int, float)) else "n/a"
                    log(f"SPEEDTEST {res['tool']}: down={dl_s} up={ul_s} ping={ping_s}")
                else:
                    log(f"SPEEDTEST {res['tool']}: BLOCKED/FAILED ({res.get('error','unknown')})")
                last_speedtest = time.time()

            await asyncio.sleep(CHECK_INTERVAL_SEC)

    finally:
        await unregister_advert(bus, adapter_path, advert)
        log("Stopped travel_watchdog")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
