# Coverage gaps

These binwalk-ng signatures have no standard/common-tool generator. They are
intentionally **not** generated here (per the "common tools only" rule). Each
entry explains why and what would be needed to produce a real sample.
Formats that ship as committed fixtures instead live in `samples/`,
alongside the generated files.

## Vendor/proprietary firmware

These formats are written by vendor-specific firmware packing tools that are
not part of any mainstream distribution and often leaked/undocumented:

- `arcadyan`, `csman` (incl. its decompression bomb), `eva`
  (single/dual/secondary), `matter_ota`, `program_store` — **covered via
  committed fixtures** in `samples/` (vendor tool output from upstream's
  test corpus).
- `tplink`, `dlink`, `dlk`, `dlch`, `seama`, `trx`, `shrs`, `palmos`,
  `android_boot_image`, `hachiko`/`mem2isa`, `rdc`, `wince`, `gfd`,
  `iscu`... — no fixture at all: generating real ones requires the vendor's
  packing tool (e.g. OpenWrt's outdated `mktplinkfw` / `trx` scripts) or
  firmware from a device.

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
(FIPS-197, RFC-1321, RFC-3174, RFC-1952). This stays within the constraints
(the tables are public algorithm constants, not binwalk's code), but the
samples would be large and of limited value, so the format is deferred.

## Formats needing existing real-world files

None remain. The standard 'HDR'-style S0 record (`S00600004844521B`) is
covered by `srec_cat -header HDR` (the path-based S0 header that
`objcopy -O srec` writes alone cannot produce it). Caveat: the `srecord` package is not on every host
(e.g. Arch does not ship it), so the sample appears only when `srec_cat`
is on `$PATH` — Ubuntu 26.04 ships it in universe, so the Docker image
always produces it; elsewhere build it from source
(https://sourceforge.net/projects/srecord) to activate it.

## Not included but covered upstream

Remaining upstream-only fixtures not re-created here: Android sparse, and
historical mixture files. (`png_malformed` is covered here as the generated
`png.malformed.png`, and the RAR3 pair, the RAR3 DOS SFX, squashfs_v2,
the S6-count s-record, the multi-format BMP and the firmware/fs formats are
covered as committed fixtures in `samples/`.)