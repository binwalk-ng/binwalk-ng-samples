# Coverage gaps

These binwalk-ng signatures have no standard/common-tool generator. They are
intentionally **not** generated here (per the "common tools only" rule). Each
entry explains why and what would be needed to produce a real sample.

## Vendor/proprietary firmware

These formats are written by vendor-specific firmware packing tools that are
not part of any mainstream distribution and often leaked/undocumented:

- `tplink`, `dlink`, `dlk`, `dlch`, `seama`, `trx`, `shrs`, `palmos`,
  `android_boot_image`, `hachiko`/`mem2isa` (matter_ota is upstream-tested),
  `arcadyan`, `rdc`, `wince`, `gfd`, `iscu`...

  Generating real ones requires the vendor's packing tool (e.g. OpenWrt's
  outdated `mktplinkfw` / `trx` scripts) or firmware from a device.
  Proof-of-hierarchy samples already exist upstream in binwalk-ng's
  `tests/inputs/`.

## Operating-system/Apple/Windows-only tools

- APFS, DMG (`hdiutil`), Windows DPAPI/EFS (`CryptProtectData`), DXBC/Effect
  bytecode (`fxc`/`dxc`), VxWorks, WinCE, VMK/vmdk raw. No Linux/FLOSS
  generator exists.

## Size- or resource-limited

- `btrfs` — `mkfs.btrfs` refuses to create any image under ~72MB (per-device
  minimum), which is too large for a sample repo. Include when the repo
  accepts a 72MB+ file.
- `nvgfx` / Linux kernel images (`bzImage`, `vmlinux`, `zImage`) — building a
  kernel with the right config and arch produces one, but that is a heavy
  build; `mkimage` already covers the standard u-boot boot wrapper (uImage).

## "Hash-constant" tables (sha256/md5/crc32/aes)

These signatures match ASCII-encoded initial value tables that occur inside
real crypto implementations. A tool-pure way to produce them is compiling (with
`gcc`) a program whose source embeds the public constant tables from
(FIPS-197, RFC-1321, RFC-3174, RFC-1952). This is legitimate (the tables are
public algorithm constants, not binwalk's code) but the samples are large and
low value, so they're deferred.

## Formats needing existing real-world files

- Motorola S-record with the standard 'HDR'-style S0 record
  (`S00600004844521B`): no common tool writes that exact S0 header;
  `objcopy -O srec` writes a path-based S0 header, which is why this repo
  registers the `srec_generic` signature instead.

## Not included but already covered upstream

Formats with an existing tested sample in `tests/inputs/`: `cramfs`,
`romfs`, qcow2, RAR (no FLOSS creator), 7-Zip (covered above), Arj, lzfse,
Android sparse, mixtures etc. The generator here re-covers the subset with
standard tools; the hand-made ones remain in binwalk-ng.