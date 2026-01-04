# travel_watchdog

`travel_watchdog.py` monitors LAN/WAN/Tailscale connectivity and advertises
status over BLE. It can also **direct-push** a richer JSON payload to a
connected phone over GATT (write to a characteristic) instead of only
broadcasting a 4-byte manufacturer-data advert.

## Requirements

- Raspberry Pi Zero 2 W (or similar) with BlueZ running.
- Python 3 with `dbus-next` installed.
- Optional: `tailscale`, `librespeed-cli`, `speedtest`, `speedtest-cli`, `curl`
  for connectivity checks and speed tests.

## Run

```bash
sudo python3 travel_watchdog.py
```

Logs are written to `/tmp/travel_watchdog.log`.

## BLE Advertising

The script advertises a BLE device name `TravelWatch` and exposes 4 bytes of
manufacturer data:

```
[version=1][bitmask][lan_rtt_ms or 255][wan_rtt_ms or 255]
```

Bitmask:
- bit0: LAN failure
- bit1: WAN failure
- bit2: Tailscale failure

## Direct Push to Phone (GATT)

Direct push is enabled with these constants in `travel_watchdog.py`:

- `DIRECT_PUSH_ENABLED`
- `TARGET_DEVICE_NAME`
- `TARGET_SERVICE_UUID`
- `TARGET_CHAR_UUID`

### Selecting the phone

Set `TARGET_DEVICE_NAME` to match the BLE name of your phone. You can find it in:

- The OS Bluetooth device list (phone "Bluetooth name")
- A BLE scanner app (e.g., LightBlue, nRF Connect)

### Notifications to expect

The script **writes** a JSON payload to the characteristic specified by
`TARGET_CHAR_UUID`. Your phone app should do one of the following:

- **Subscribe to notifications/indications** for that characteristic (preferred).
- **Poll reads** of the characteristic on an interval.

The payload looks like:

```json
{
  "version": 1,
  "timestamp": "2025-01-01T12:00:00",
  "lan": {"ok": true, "rtt_ms": 3},
  "wan": {"ok": true, "rtt_ms": 15},
  "tailscale": {"ok": true, "peer": "100.x.y.z"},
  "speedtest": {"tool": "librespeed-cli", "ok": true, "download_mbps": 120.5, "upload_mbps": 30.2, "ping_ms": 10.2}
}
```

If your phone app supports notifications, you'll receive an update whenever
the payload changes (e.g., connectivity transitions or new speed test data).

### Characteristic requirements

The characteristic must accept GATT `Write` operations. If your phone app uses a
custom BLE service, set `TARGET_SERVICE_UUID` and `TARGET_CHAR_UUID`
accordingly.

## Troubleshooting

- Ensure `bluetoothd` is running and `hciconfig` shows the adapter up.
- If the script reports "device not found", verify `TARGET_DEVICE_NAME` in your
  BLE scanner app.
- If you see connection timeouts, reduce the scan window or increase
  `DIRECT_PUSH_RETRY_SEC`.
