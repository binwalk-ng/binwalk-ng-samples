# binwalk-ng-samples

Verifiable test samples for [binwalk-ng](https://github.com/reFirmLabs/binwalk-ng),
generated with **only standard, independent tooling** — never by reading
binwalk(-ng)'s source or replicating its parser logic.

Every sample is produced by a real, general-purpose generator (`gzip`, `tar`,
`mkfs.*`, `openssl`, `gcc`, `dtc`, `sgdisk`, ...). This keeps the samples
honest: they are what the tools actually emit, not crafted magic bytes that
happen to satisfy a parser.

## Layout

```
Dockerfile                     builds the full generator environment (ubuntu:26.04)
.gitattributes                 protects binary samples from CRLF/merge corruption
scripts/
  generate_samples.py          produce everything in samples/ (common tools only)
  data/extraction_reference.txt  the shared payload text (vendored, see "Data")
samples/                       the generated payload fixtures, nothing else
```

## Reproducible generation

Two ways, both deterministic:

```sh
# on this host (needs the tools installed):
python3 scripts/generate_samples.py            # writes ./samples

# or in Docker (nothing needs to be installed on the host):
docker build -t binwalk-ng-samples .
docker run --rm -v "$PWD/samples:/artifacts" binwalk-ng-samples
```

The Dockerfile pins `ubuntu:26.04` and installs every tool the generator
uses, so any machine with Docker produces the same artifacts. The build
itself also runs the generator, so the resulting image carries the samples
under `/artifacts` (handy for `docker cp`).

Reproducibility caveat: formats whose containers store wall-clock metadata
(zip timestamps, lzop headers, GnuPG signature timestamps, X.509 validity
dates) differ byte-for-byte between builds. Their *content* is identical.
The rest are fully pinned: tar uses `--sort=name --mtime=@0` (byte-identical
ustar, including a symlink entry), gzip uses `-n` (no stored timestamp), and
streams that need incompressible input (zstd, lzop) use the fixed-seed
deterministic PRNG rather than `/dev/urandom`.

## Verification

binwalk-ng's own test suite can consume `samples/` directly (each file is a
self-contained payload; run `binwalk -y <sig> -- <file>` and expect the
signature at offset 0). The generator prints the expected signature for every
sample it emits, so failures are visible at generation time.

## Data

The only "content" involved is:

| seed | content | used for |
|------|---------|----------|
| `scripts/data/extraction_reference.txt` | copied verbatim from binwalk-ng's `tests/inputs/extraction_reference.txt` (the reference text its own extraction tests compare against) | the single file inside every archive & filesystem, and the input of every compression stream |
| `main.c` | one-line `int main(...) { return 0; }` | compiled by gcc / mingw / objcopy into ELF, PE and S-record samples |
| `msg.txt` | `signed message` | signed by `openssl` / `gpg` |
| seeded bytes | fixed-seed SHA-256 counter stream | zstd / lzop inputs (need incompressible data) |

Every sample is produced now by the standard tool named on the generator's
output line (e.g. `gzip -9n`), with the payload listed above.

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
  (tail cut) are still extractable/detected.
- **Tree / metadata** — the tar includes a directory, a symlink and pinned
  `mtime=0` metadata so extraction/output is byte-reproducible.

## Design constraints

- **No binwalk code is used to generate samples.** Generation is the job of
  the standard tool the generator invokes.
- Samples are real output of that tool, produced now (not authored blobs).
- `.gitattributes` marks everything under `samples/` as `-text -diff -merge`
  so CRLF conversion and merge heuristics can never corrupt the binaries.
- Formats with no standard generator (vendor/proprietary firmware headers,
  Apple/Windows-only tools, etc.) are documented in `GAPS.md` with the reason.

### Coverage

Formats currently generated: gzip, bzip2, xz, lzma, lz4, zstd, lzop, zlib,
compress'd, tar (+gzip-nested, truncated), cpio, zip (+truncated), 7-Zip, cab,
deb, GIF, PNG, JPEG (+duo), BMP (+duo), SVG, ELF, Motorola S-record (generic),
PE/COFF, ext4, FAT, NTFS, JFFS2, UBIFS, squashfs, ISO-9660, GPT (EFI), OpenSSL
salted, PEM (cert/private/public), PKCS#1 DER DigestInfo, LUKS, GnuPG signed,
FDT device tree (dtb), u-boot uImage (+gzip body), pcapng.

## Generator notes

The generator prints one line per sample with the exact command behind it,
e.g. `zstd --zstd=wlog=14 (2+ blocks)` notes the option needed to satisfy
binwalk's two-block rule, or `dd + mkfs.ext4` notes the blank disk followed
by the formatter.