# binwalk-ng-samples

Verifiable test samples for [binwalk-ng](https://github.com/reFirmLabs/binwalk-ng),
generated with **only standard, independent tooling** — never by reading
binwalk(-ng)'s source or replicating its parser logic.

Every sample is produced by a real, general-purpose generator (`gzip`, `tar`,
`mkfs.*`, `openssl`, `gcc`, `dtc`, `sgdisk`, ...), so samples are genuine tool
output rather than crafted bytes that happen to satisfy a parser. Formats no
standard tool can write (vendor firmware packing, RAR3, romfs, YAFFS2, ...)
ship as committed fixtures in `samples/` instead.

## Layout

```
Dockerfile                     builds the full generator environment (ubuntu:26.04)
.gitattributes                 protects binary samples from CRLF/merge corruption
scripts/
  generate_samples.py          produce everything in samples/ (common tools only)
  data/extraction_reference.txt  the shared payload text (vendored, see "Data")
samples/                       all payload files: generated samples (rewritten
                               every run) and committed fixtures for formats
                               with no generator (see GAPS.md)
```

## Reproducible generation

Two ways, both deterministic:

```sh
# on this host (needs the tools installed; faketime wrapper or LD_PRELOAD):
faketime -f '2025-04-30 15:32:03' python3 scripts/generate_samples.py  # writes ./samples

# or in Docker (nothing needs to be installed on the host; libfaketime +
# the pinned clock are built into the image):
docker build -t binwalk-ng-samples .
docker run --rm -v "$PWD/samples:/artifacts" binwalk-ng-samples
```

The Dockerfile pins `ubuntu:26.04` and installs every tool the generator
uses, so any machine with Docker produces the same artifacts. The build
itself also runs the generator, so the samples are available in the image
under `/artifacts` (retrievable with `docker cp`).

Generation is byte-reproducible: two runs produce identical samples, byte
for byte, whether run on this host or in Docker. The wall clock is pinned to
a fixed date, `2025-04-30 15:32:03` (`faketime -f '2025-04-30 15:32:03'`,
and `libfaketime` is baked into the Dockerfile), so every timestamp a format
can store — zip/lzop headers, filesystem superblock times, uImage/pcap/GPT
headers, X.509 validity dates, GnuPG signature timestamps — is constant.
Everything else is pinned per format: a fixed OpenSSL salt (`-S`), a fixed
LUKS uuid/pbkdf iterations (with the RNG-written digest, salts and key
material zeroed afterwards), fixed ext4/gpt/ntfs UUIDs, vendored RSA + GPG
seed keys instead of per-run generation, an ext4 hash seed, `--mtime=@0`
ustar and `-mkfs-time 0` squashfs, `-n` gzip, cpio inode pinning, a fixed
UBI image sequence (`ubinize -Q`), a pinned MBR disk id, a repinned PDF
`/ID`, the sox INFO chunk stripped, the OpenSSL `Salted__` header restored
when the installed OpenSSL omits it with `-S`, and a fixed-seed PRNG for
incompressible streams instead of `/dev/urandom`.

## Verification

binwalk-ng's own test suite can consume `samples/` directly (each file is a
self-contained payload; run `binwalk -y <sig> -- <file>` and expect the
signature at offset 0). The generator prints the expected signature for every
sample it emits, so failures are visible at generation time.

The committed fixtures (formats with no generator, see GAPS.md) are
verified the same way: `binwalk -y <sig> -- samples/<fixture>` for
detection; their contents are fixed by commit.

## Data

The only "content" involved is:

| seed | content | used for |
|------|---------|----------|
| `scripts/data/extraction_reference.txt` | this repo's fixed payload text, vendored alongside the generator so generation never depends on an external checkout | the single file inside every archive & filesystem, and the input of every compression stream |
| `main.c` | one-line `int main(...) { return 0; }` | compiled by gcc / mingw / objcopy into ELF, PE and S-record samples |
| `msg.txt` | `signed message` | signed by `openssl` / `gpg` |
| `lzfse.txt` | 1000 spaces + `Testing, 1, 2, 3...` repeated 100× | input of the `lzfse` stream (1000-space prefix, then repeated lines) |
| `scripts/data/rsa_key.pem` | ephemeral 2048-bit RSA key, generated once | `pem.private_key.pem` (byte-copy), the `pem.certificate.pem` signer, `pem.public_key.pem` |
| `scripts/data/gpg.key` | ephemeral GPG keypair, generated once under the pinned clock | `gpg.signed.gpg` (signature pinned via `--faked-system-time`; the key's creation date is the pinned date, keeping gpg's signing clock within the key's validity period) |
| seeded bytes | fixed-seed SHA-256 counter stream | zstd / lzop inputs (need incompressible data) |

## Flow coverage

Beyond one file per format, the generator emits samples that exercise
binwalk's more complex logic:

- **Compound streams** — concatenated gzip members (`gzip.multimember.gz`),
  two JPEGs (`jpeg.duo.jpg`) and two BMPs (`bmp.duo.bmp`) back-to-back.
- **Non-zero offsets** — `gzip.embedded.gz.bin` pads a gzip stream so its
  signature appears at `0x1000` and *not* at offset 0.
- **Trailing garbage** — gzip/lz4/zstd samples (`*.trailing.*`) have data
  appended after the stream; extraction must stop at the parsed end.
- **Nested containers** — `tarball.tar.gz` (tar inside gzip), `zip.archive.zip`
  (contains a gzip member), u-boot with a gzip-compressed kernel
  (`uimage.arm.gzip.ub`), and filesystems whose trees contain `docs/` plus a
  nested `payload.gz`.
- **Truncated inputs** — `tarball.truncated.tar` and `zip.truncated.zip`
  (tail cut) are still extractable/detected. `png.malformed.png` is the
  inverse: cut inside the first IDAT chunk, so the chunk walk must reject
  it (no signature, no extraction — a negative test). `samples/` also
  carries the second negative fixture, `csman_decompression_bomb.bin` (valid
  CSMAN whose zlib entry decompresses ~120KiB -> ~120MiB; the parser's
  size limit must abort it with no signature).
- **Non-zero offset + concatenation** — `arj.embedded.bin` pads 13 seeded
  bytes in front of two back-to-back ARJ archives (signatures at `0xD` and
  `0xD + len(arj1)`), mirroring the junk-prefix layout typical of firmware
  images.
- **Tree / metadata** — the tar includes a directory tree (plain `docs/` plus a
  sticky-bit `subdir/`), an executable `run.sh`, a symlink and pinned
  `mtime=0` metadata so extraction/output is byte-reproducible.

## Design constraints

- **No binwalk code is used to generate samples.** Generation is the job of
  the standard tool the generator invokes.
- Samples are fresh output of that tool, produced at generation time, never
  hand-authored blobs.
- `.gitattributes` marks everything under `samples/` as
  `-text -diff -merge` so CRLF conversion and merge heuristics can never
  corrupt the binaries.
- Formats with no standard generator (vendor/proprietary firmware headers,
  Apple/Windows-only tools, etc.) are documented in `GAPS.md` with the reason.

### Coverage

Formats currently generated: gzip, bzip2, xz, lzma, lz4, zstd, lzfse, lzop,
zlib, compress'd, tar (+gzip-nested, truncated), cpio, zip (+truncated), 7-Zip,
arj (+offset/concatenated), RAR5 (plain + solid), cab, deb, GIF, PNG
(+malformed), JPEG (+duo), BMP (+duo), SVG, ELF, Motorola S-record (generic +
standard 'HDR' S0), PE/COFF, ext4, FAT, NTFS, cramfs, JFFS2, UBIFS, squashfs,
ISO-9660, UBI, GPT (EFI), MBR, qcow2, RIFF/WAV, PDF, OpenSSL salted, PEM
(cert/private/public), PKCS#1 DER DigestInfo, LUKS, GnuPG signed, FDT device
tree (dtb), u-boot uImage (+gzip body), pcapng.

Formats covered as committed fixtures in `samples/` (no 26.04 tool can write
them): arcadyan, csman (+decompression-bomb negative), eva (single/dual/
secondary), matter_ota, Broadcom ProgramStore (+dual), RAR3 (plain + solid),
romfs, YAFFS2.

## Generator notes

The generator prints one line per sample with the exact command behind it,
e.g. `zstd --zstd=wlog=14 (2+ blocks)` notes the option needed to satisfy
binwalk's two-block rule, or `dd + mkfs.ext4` notes the blank disk followed
by the formatter. Determinism notes appear on the same line where a tool
option pins a value (e.g. `ubinize -Q pinned` for the fixed UBI image
sequence, `mkfs.cramfs (pinned tree)` for the pinned block timestamps).

All tools the generator uses are installed in the Docker image.
