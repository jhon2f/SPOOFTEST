# HWID Spoofer — PatchGuard-safe (WORKING, VM-verified)

## What's verified working (VM, Win10 19045, test mode)

`final_spoof.exe` covers MAC + disk + SMBIOS. No SSDT patch, no code cave — so
nothing PatchGuard hashes.

- **SMBIOS** (UUID + system/baseboard/chassis serial) — direct rewrite of the
  physical SMBIOS table via the `WmipSMBiosTablePhysicalAddress` pattern +
  `MmMapIoSpaceEx`. Stable UUID generated once; serial strings mutated in place.
- **Disk serial** — IRP dispatch hook on `\Driver\disk` (swap
  `MajorFunction[IRP_MJ_DEVICE_CONTROL]`) + a completion routine (`SL_INVOKE_ON_SUCCESS`)
  that mutates the `STORAGE_DEVICE_DESCRIPTOR` serial after the disk driver fills it.
- **MAC (ARP)** — usermode registry `NetworkAddress` (keeps the original OUI, changes
  the NIC bytes); persists across reboot.

**Confirmed:** UUID `4CB25525… → 121E938E…`, disk `VMWARE-TEST-SER-1 →
VNWARE-TEST-VER-1`, MAC keeps OUI + changed NIC bytes.

## Why this is PatchGuard-safe
- PatchGuard hashes the SSDT/IDT/GDT/MSRs — it does **not** hash a driver's
  `MajorFunction` dispatch array, and the physical SMBIOS write isn't a code patch at
  all. This is the technique used by working public spoofers (soar/ReFo reference).

## Run flow (final)
1. Elevated: `sc start PhysDrv` then `final_spoof.exe` (writes MAC + maps spoofdrv).
2. Reboot (applies the MAC).
3. Run `final_spoof.exe` again (re-installs SMBIOS/disk; MAC is idempotent).
4. Launch the game in that same session.

## Remaining gate
- **Signing** — test-signed; EAC blocks test mode. Live use needs an EV cert or a
  vulnerable signed driver as the mapping primitive. (PatchGuard is no longer the
  blocker.)

## Files (host `C:\vmshare\`)
- `physdrv.c/.sys` — physical R/W + self-mapping loader
- `spoofdrv.c/.sys` — SMBIOS physical write + disk IRP dispatch hook
- `final_spoof.c/.exe` — one-shot: MAC registry + maps spoofdrv
- `hook_test.c/.exe` — maps spoofdrv, verifies UUID/disk/volume
- `build_*.bat`, `run_*.bat`, `sign*.ps1`

## Build + sign + test
Build in VM (`Win10Drv`, `drvdev` / `fwafwaf22$$`). Sign on HOST: `signtool sign
/fd sha256 /sha1 A1B32FF40F278FDC5C70B9BBCEC439F2AD590B6A physdrv.sys`. Test:
reboot → elevated `sc start PhysDrv` → `final_spoof.exe`.
