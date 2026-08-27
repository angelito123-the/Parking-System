# Scanner device test checklist

Use this checklist before assigning a phone or tablet to a gate. Open **Gate Operations → Scan & Process → Scanner details → Run Device Check** first. The result must say the device is ready; native QR detection and flashlight support are useful but optional.

## Device matrix

Test at least one device from each class used by guards:

| Class | Suggested coverage | Required browser |
| --- | --- | --- |
| Low-end Android | 3–4 GB RAM, older rear camera | Current Chrome |
| Standard Android | Typical guard phone | Current Chrome |
| iPhone/iPad | Any model still receiving OS updates | Current Safari |
| Desktop fallback | USB or built-in camera | Current Chrome or Edge |

## Scenarios

Run 20 scans for every relevant device and record the result in **Administration → Scanner Performance**.

1. Normal daylight at 25–40 cm.
2. Dim indoor lighting; confirm guidance suggests more light and test the flashlight when available.
3. Strong glare; tilt the QR and confirm it can recover without restarting the page.
4. QR near each camera edge, not only in the center.
5. Slight motion and a wrinkled or lightly damaged print.
6. Stop and resume the camera five times.
7. Disable the network, scan an already-synced active sticker, restore the network, and confirm **Offline Queue: 0** after synchronization.
8. Attempt the same QR twice quickly and confirm duplicate protection.
9. Confirm success and error feedback can be noticed through the visual result, sound, or vibration.

## Acceptance targets

- At least 95% successful reads for intact printed stickers in normal lighting.
- Median read time under 2 seconds in normal lighting and under 4 seconds in dim lighting.
- No duplicate gate movements after offline synchronization or repeated taps.
- Camera recovery works without reloading the whole app.
- No QR contents or camera frames appear in scanner analytics.

If a device misses the targets, run **Recalibrate Camera**, clean the lens, improve the gate lighting, and repeat. Use **Reset Learning** only when the device or camera conditions have materially changed.
