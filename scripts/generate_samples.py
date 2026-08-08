#!/usr/bin/env python3
"""Generate binwalk-ng sample files using ONLY standard, independent tooling.

Rule: every sample is produced by a real, general-purpose generator (gzip,
tar, mkfs.*, openssl, gcc, ...) -- never by reading binwalk(-ng) source or
replicating its parser logic.

Input data (the only "content" involved, all seeds are fixed and deterministic):
  * extraction_reference.txt - copied verbatim from binwalk-ng's
      tests/inputs/extraction_reference.txt (the reference text used by
      binwalk-ng's own extraction tests). It is the single file stored inside
      every archive and filesystem (zip, tar, cpio, iso9660, ext4, fat, ntfs,
      jffs2, ubifs, squashfs, ...) and the common input for every compression
      stream (gzip, bzip2, xz, lz4, zlib, ...).
  * main.c      - one-line C program, compiled by gcc / mingw / objcopy into
                  the ELF, PE and S-record samples
  * msg.txt     - "signed message\\n", signed by openssl / gpg
  * seeded bytes- deterministic pseudo-random streams (fixed seed, SHA-256
                  counter) used only where incompressible input is required
                  (zstd, lzop)

Usage: scripts/generate_samples.py [output-dir]   (default: ./samples)
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

SEED = b"binwalk-ng samples seed v1"
MAIN_C = "int main(int argc, char **argv) { return 0; }\n"
MSG_TXT = "signed message\n"
SCRIPT_DIR = Path(__file__).resolve().parent
REFERENCE_PATH = SCRIPT_DIR / "data" / "extraction_reference.txt"


def reference_text() -> bytes:
    """Bytes of the shared reference payload. Vendored in scripts/data so
    generation works without binwalk-ng checked out."""
    if not REFERENCE_PATH.is_file():
        raise FileNotFoundError(f"missing reference payload: {REFERENCE_PATH}")
    return REFERENCE_PATH.read_bytes()


def seeded_bytes(seed: str, size: int) -> bytes:
    """Deterministic pseudo-random stream (SHA-256 counter mode)."""
    base = hashlib.sha256(SEED + seed.encode()).digest()
    out, counter = b"", 0
    while len(out) < size:
        out += hashlib.sha256(base + struct.pack(">I", counter)).digest()
        counter += 1
    return out[:size]


def require_tool(*tools: str) -> str | None:
    """Return the first available tool among the candidates, or None.

    Warns on stderr when no candidate exists so a skipped sample can never
    happen silently:
        convert = require_tool("magick", "convert")   # -> path or None
        if require_tool("gzip"):   # gate without needing the name
    """
    for tool in tools:
        if shutil.which(tool) is not None:
            return tool
    listed = " / ".join(f"'{tool}'" for tool in tools)
    print(f"! warning: no tool available ({listed}) -- "
          "related samples will be skipped", file=sys.stderr)
    return None


def run_tool(
    command: list[str],
    cwd: Path | None = None,
    stdin_data: bytes | None = None,
    env: dict | None = None,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
) -> subprocess.CompletedProcess:
    """Invoke a generator tool. Failures are tolerated (returned, never
    raised): a missing/errant tool simply skips its sample."""
    return subprocess.run(
        command,
        cwd=cwd,
        input=stdin_data,
        env=env,
        stdout=stdout,
        stderr=stderr,
        check=False,
    )


class Generator:
    """Writes the full sample set + MANIFEST.tsv into a clean output dir."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

        shutil.rmtree(output_dir, ignore_errors=True)  # reproduce from scratch
        output_dir.mkdir(parents=True, exist_ok=True)

        self.workdir = Path(tempfile.mkdtemp(prefix="bns-"))
        self.source_dir = self.workdir / "src"
        self.source_dir.mkdir()

        self.reference = reference_text()
        self.payload_file = self.workdir / "payload.txt"
        self.payload_file.write_bytes(self.reference)

        readme = self.source_dir / "readme.txt"
        readme.write_bytes(self.reference)

    # -- plumbing ----------------------------------------------------------

    def emit(self, signature: str, relative_path: str, note: str) -> None:
        """Announce a produced sample; say MISSING when the tool failed."""
        produced = (self.output_dir / relative_path).is_file()
        if not produced:
            print(f"  ?  {signature:<16} MISSING {relative_path}")
            return
        print(f"  +  {signature:<16} {relative_path}   ({note})")

    def write(self, relative_path: str, data: bytes) -> None:
        (self.output_dir / relative_path).write_bytes(data)

    # -- 1. compression -----------------------------------------------------

    def compression(self) -> None:
        print("== compression")
        if require_tool("gzip"):
            result = run_tool(
                ["gzip", "-9nfc", str(self.payload_file)], stdout=subprocess.PIPE
            )
            if result.returncode == 0:
                self.write("gzip.data.gz", result.stdout)
            self.emit("gzip", "gzip.data.gz", "gzip -9n")

            # Two gzip members in one file (concatenated streams).
            second = self.workdir / "payload2.txt"
            second.write_bytes(b"second gzip member payload\n" * 100)
            result = run_tool(
                ["gzip", "-9nfc", str(second)], stdout=subprocess.PIPE
            )
            if result.returncode == 0 and self.output_dir.joinpath("gzip.data.gz").is_file():
                combined = (self.output_dir / "gzip.data.gz").read_bytes() + result.stdout
                self.write("gzip.multimember.gz", combined)
                self.emit(
                    "gzip",
                    "gzip.multimember.gz",
                    "gzip -9n x2 (concatenated member streams)",
                )

            # gzip stream at a non-zero offset (zero-padded via dd/cat).
            pad = self.workdir / "pad.bin"
            run_tool(["dd", "if=/dev/zero", f"of={pad}", "bs=4096", "count=1"])
            if pad.is_file() and result.returncode == 0:
                cat = run_tool(
                    ["cat", str(pad), str(self.output_dir / "gzip.data.gz")],
                    stdout=subprocess.PIPE,
                )
                if cat.returncode == 0:
                    self.write("gzip.embedded.gz.bin", cat.stdout)
                    self.emit(
                        "gzip",
                        "gzip.embedded.gz.bin",
                        "dd zero pad + cat (stream at offset 0x1000)",
                    )

            # trailing garbage that extraction must stop before.
            if result.returncode == 0:
                trailing = (self.output_dir / "gzip.data.gz").read_bytes()
                trailing += b"TRAILING GARBAGE DATA THAT SHOULD BE IGNORED"
                self.write("gzip.trailing.bin", trailing)
                self.emit(
                    "gzip",
                    "gzip.trailing.bin",
                    "gzip + trailing garbage (extractor stop-check)",
                )

        if require_tool("bzip2"):
            result = run_tool(
                ["bzip2", "-9fc", str(self.payload_file)], stdout=subprocess.PIPE
            )
            if result.returncode == 0:
                self.write("bzip2.data.bz2", result.stdout)
            self.emit("bzip2", "bzip2.data.bz2", "bzip2 -9")

        if require_tool("xz"):
            result = run_tool(
                ["xz", "-9fc", str(self.payload_file)], stdout=subprocess.PIPE
            )
            if result.returncode == 0:
                self.write("xz.data.xz", result.stdout)
            self.emit("xz", "xz.data.xz", "xz -9")

            result = run_tool(
                ["xz", "--format=lzma", "-9fc", str(self.payload_file)],
                stdout=subprocess.PIPE,
            )
            if result.returncode == 0:
                self.write("lzma.data.lzma", result.stdout)
            self.emit("lzma", "lzma.data.lzma", "xz --format=lzma -9")

        if require_tool("lz4"):
            run_tool(
                [
                    "lz4",
                    "-q",
                    str(self.payload_file),
                    str(self.output_dir / "lz4.data.lz4"),
                ]
            )
            self.emit("lz4", "lz4.data.lz4", "lz4")
            source = (self.output_dir / "lz4.data.lz4").read_bytes()
            self.write("lz4.trailing.lz4", source + b"LZ4 TRAILING GARBAGE DATA")
            self.emit("lz4", "lz4.trailing.lz4", "lz4 + trailing garbage")

        if require_tool("zstd"):
            # binwalk requires >= 2 zstd blocks; --zstd=wlog=14 caps block size
            # at 16KB so a 40KB incompressible input yields multiple blocks.
            incompressible = self.workdir / "zstd.big"
            incompressible.write_bytes(seeded_bytes("zstd", 40 * 1024))
            run_tool(
                [
                    "zstd",
                    "-q",
                    "-f",
                    "--zstd=wlog=14",
                    "-o",
                    str(self.output_dir / "zstd.data.zst"),
                    str(incompressible),
                ]
            )
            self.emit("zstd", "zstd.data.zst", "zstd --zstd=wlog=14 (2+ blocks)")

            source = (self.output_dir / "zstd.data.zst").read_bytes()
            self.write("zstd.trailing.zst", source + b"ZSTD TRAILING GARBAGE DATA")
            self.emit("zstd", "zstd.trailing.zst", "zstd + trailing garbage")

        if require_tool("lzop"):
            # lzop emits one lzo block per 256KB chunk; 300KB -> 2 blocks.
            incompressible = self.workdir / "lzop.bin"
            incompressible.write_bytes(seeded_bytes("lzop", 300 * 1024))
            run_tool(
                [
                    "lzop",
                    "-q",
                    "-o",
                    str(self.output_dir / "lzop.data.lzo"),
                    str(incompressible),
                ]
            )
            self.emit("lzop", "lzop.data.lzo", "lzop (300KB -> 2+ blocks)")

        if require_tool("compress"):
            result = run_tool(
                ["compress", "-f", "-c", str(self.payload_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            if result.returncode == 0:
                self.write("compressd.data.Z", result.stdout)
            self.emit("compressd", "compressd.data.Z", "compress -f -c")

        payload = self.payload_file.read_bytes()
        self.write("zlib.data.zlib", zlib.compress(payload, level=6))
        self.emit("zlib", "zlib.data.zlib", "python3 zlib.compress(level=6)")

    # -- 2. archives / packages ---------------------------------------------

    def archives(self) -> None:
        print("== archives")
        tree = self.workdir / "tree"
        tree.mkdir()
        (tree / "readme.txt").write_bytes(self.reference)
        docs = tree / "docs"
        docs.mkdir()
        (docs / "notes.txt").write_text("documentation\n" * 50)
        os.symlink("readme.txt", tree / "link.txt")

        if require_tool("tar"):
            target = str(self.output_dir / "tarball.archive.tar")
            run_tool(
                [
                    "tar",
                    "-cf",
                    target,
                    "--sort=name",
                    "--mtime=@0",
                    "--owner=0",
                    "--group=0",
                    "--numeric-owner",
                    ".",
                ],
                cwd=tree,
            )
            self.emit("tarball", "tarball.archive.tar", "tar ustar (pinned mtime, tree)")

            # Nested: gzip of the same tarball (tar inside gzip stream).
            result = run_tool(
                ["gzip", "-9nfc", str(self.output_dir / "tarball.archive.tar")],
                stdout=subprocess.PIPE,
            )
            if result.returncode == 0:
                self.write("tarball.tar.gz", result.stdout)
                self.emit("gzip", "tarball.tar.gz", "gzip -9n of tar (nested)")

            # Truncated tar: keep a full header group + partial tail.
            full = (self.output_dir / "tarball.archive.tar").read_bytes()
            self.write("tarball.truncated.tar", full[: len(full) - 300])
            self.emit("tarball", "tarball.truncated.tar", "tar -cf then truncated tail")

        if require_tool("cpio"):
            result = run_tool(
                ["cpio", "-o", "-H", "newc"],
                cwd=self.source_dir,
                stdin_data=b"readme.txt\n",
                stdout=subprocess.PIPE,
            )
            if result.returncode == 0:
                self.write("cpio.newc.cpio", result.stdout)
            self.emit("cpio", "cpio.newc.cpio", "cpio -o -H newc")

        if require_tool("zip"):
            zip_src = self.workdir / "zip-src"
            zip_src.mkdir()
            (zip_src / "readme.txt").write_bytes(self.reference)
            (zip_src / "bin").mkdir()
            gzip_result = run_tool(
                ["gzip", "-9nfc", str(self.payload_file)], stdout=subprocess.PIPE
            )
            if gzip_result.returncode == 0:
                (zip_src / "bin" / "payload.gz").write_bytes(gzip_result.stdout)
            run_tool(
                ["zip", "-q", "-r", str(self.output_dir / "zip.archive.zip"), "."],
                cwd=zip_src,
            )
            self.emit("zip", "zip.archive.zip", "zip -r (tree + nested gzip)")

            full_zip = (self.output_dir / "zip.archive.zip").read_bytes()
            self.write("zip.truncated.zip", full_zip[: len(full_zip) // 2])
            self.emit("zip", "zip.truncated.zip", "zip -r then truncated tail")

        if require_tool("7z"):
            run_tool(
                ["7z", "a", "-bd", "-y", str(self.output_dir / "archive.7z"), "."],
                cwd=self.source_dir,
            )
            self.emit("7zip", "archive.7z", "7z a")

        if require_tool("gcab"):
            run_tool(
                ["gcab", "-c", str(self.output_dir / "cab.archive.cab"), "readme.txt"],
                cwd=self.source_dir,
            )
            self.emit("cab", "cab.archive.cab", "gcab -c")

        if require_tool("dpkg-deb"):
            deb_root = self.workdir / "deb"
            (deb_root / "DEBIAN").mkdir(parents=True)
            (deb_root / "usr/share/doc/sample").mkdir(parents=True)
            (deb_root / "DEBIAN/control").write_text(
                "Package: binwalk-sample\nVersion: 1.0\n"
                "Architecture: all\nMaintainer: test\nDescription: sample\n"
            )
            (deb_root / "usr/share/doc/sample/readme").write_text("documentation\n")
            run_tool(
                ["dpkg-deb", "--build", str(deb_root), str(self.output_dir / "deb.deb")]
            )
            self.emit("deb", "deb.deb", "dpkg-deb --build")

    # -- 3. images ------------------------------------------------------------

    def images(self) -> None:
        print("== images")
        convert = require_tool("magick", "convert")
        if not convert:
            return
        for ext, signature in (
            ("gif", "gif"),
            ("png", "png"),
            ("jpg", "jpeg"),
            ("bmp", "bmp"),
        ):
            run_tool(
                [
                    convert,
                    "-size",
                    "4x4",
                    "gradient:red-blue",
                    str(self.output_dir / f"{signature}.gradient.{ext}"),
                ]
            )
            self.emit(
                signature,
                f"{signature}.gradient.{ext}",
                f"{Path(convert).name} gradient",
            )

        # Two images back-to-back: signatures at 0 and at the end of the first.
        for ext, signature in (
            ("jpg", "jpeg"),
            ("bmp", "bmp"),
        ):
            first = self.output_dir / f"{signature}.gradient.{ext}"
            if first.is_file():
                combined = first.read_bytes() + first.read_bytes()
                self.write(f"{signature}.duo.{ext}", combined)
                self.emit(
                    signature,
                    f"{signature}.duo.{ext}",
                    f"{Path(convert).name} x2 (two images concatenated)",
                )
        self.write(
            "svg.vector.svg",
            b'<svg xmlns="http://www.w3.org/2000/svg" width="4" height="4">'
            b'<rect width="4" height="4" fill="red"/></svg>\n',
        )
        self.emit("svg", "svg.vector.svg", "SVG markup (written directly)")

    # -- 4. executables ---------------------------------------------------------

    def binaries(self) -> None:
        print("== binaries")
        if not require_tool("gcc"):
            return
        main_c = self.workdir / "main.c"
        main_c.write_text(MAIN_C)

        elf_path = self.output_dir / "elf.x86_64"
        run_tool(["gcc", "-Os", "-no-pie", "-o", str(elf_path), str(main_c)])
        if not elf_path.is_file():
            run_tool(["gcc", "-Os", "-o", str(elf_path), str(main_c)])
        self.emit("elf", "elf.x86_64", "gcc -Os")

        if require_tool("objcopy"):
            run_tool(
                [
                    "objcopy",
                    "-O",
                    "srec",
                    str(elf_path),
                    str(self.output_dir / "srec.from_elf.srec"),
                ]
            )
            self.emit("srecord_generic", "srec.from_elf.srec", "objcopy -O srec")

        mingw_gcc = require_tool("x86_64-w64-mingw32-gcc")
        if mingw_gcc:
            run_tool(
                [
                    mingw_gcc,
                    "-Os",
                    "-o",
                    str(self.output_dir / "pe.x86_64.exe"),
                    str(main_c),
                ]
            )
            self.emit("pe", "pe.x86_64.exe", "x86_64-w64-mingw32-gcc -Os")

    # -- 5. filesystems -----------------------------------------------------------

    def filesystems(self) -> None:
        print("== filesystems")
        fs_root = self.workdir / "fs"
        fs_root.mkdir()
        (fs_root / "readme.txt").write_bytes(self.reference)
        docs = fs_root / "docs"
        docs.mkdir()
        (docs / "install.txt").write_text("installed documentation\n" * 20)
        gzip_stream = run_tool(
            ["gzip", "-9nfc", str(self.payload_file)], stdout=subprocess.PIPE
        )
        if gzip_stream.returncode == 0:
            (docs / "payload.gz").write_bytes(gzip_stream.stdout)

        if require_tool("mkfs.ext4"):
            image = self.blank("ext4.image", 2 * 1024**2)
            run_tool(["mkfs.ext4", "-q", "-F", "-d", str(fs_root), str(image)])
            if not image.is_file():
                run_tool(["mkfs.ext4", "-q", "-F", str(image)])
            self.emit("ext", "ext4.image", "mkfs.ext4 -d (2MB)")

        if require_tool("mkfs.vfat"):
            image = self.blank("fat.image", 1024**2)
            run_tool(["mkfs.vfat", "-n", "BINWALK", str(image)])
            if not image.is_file():
                run_tool(["mkfs.vfat", "-F", "16", "-n", "BINWALK", str(image)])
            self.emit("fat", "fat.image", "mkfs.vfat (1MB)")

        if require_tool("mkntfs"):
            image = self.blank("ntfs.image", 2 * 1024**2)
            run_tool(["mkntfs", "-q", "-F", "-L", "BINWALK", str(image)])
            self.emit("ntfs", "ntfs.image", "mkntfs -F (2MB)")

        # btrfs intentionally omitted: mkfs.btrfs needs a >=72MB image.

        if require_tool("mkfs.jffs2"):
            image = self.output_dir / "jffs2.image"
            run_tool(
                [
                    "mkfs.jffs2",
                    "-q",
                    "--pad=0x20000",
                    "-r",
                    str(fs_root),
                    "-o",
                    str(image),
                ]
            )
            self.emit("jffs2", "jffs2.image", "mkfs.jffs2 -r --pad=0x20000")

        if require_tool("mkfs.ubifs"):
            image = self.output_dir / "ubifs.image"
            run_tool(
                [
                    "mkfs.ubifs",
                    "-q",
                    "-m",
                    "2048",
                    "-e",
                    "129024",
                    "-c",
                    "24",
                    "-j",
                    "64KiB",
                    "-r",
                    str(fs_root),
                    "-o",
                    str(image),
                ]
            )
            self.emit("ubifs", "ubifs.image", "mkfs.ubifs (2048B page, 24 LEBs)")

        if require_tool("mksquashfs"):
            image = self.output_dir / "squashfs.image"
            run_tool(["mksquashfs", str(fs_root), str(image), "-noD"])
            self.emit("squashfs", "squashfs.image", "mksquashfs")

        iso_tool = require_tool("genisoimage", "mkisofs")
        if iso_tool:
            image = self.output_dir / "iso9660.iso"
            if (
                run_tool(
                    [iso_tool, "-quiet", "-o", str(image), str(fs_root)]
                ).returncode
                != 0
            ):
                run_tool([iso_tool, "-o", str(image), str(fs_root)])
            self.emit("iso9660", "iso9660.iso", f"{Path(iso_tool).name} -quiet")

    # -- 6. partition tables ----------------------------------------------------

    def partition_tables(self) -> None:
        print("== partition tables")
        if require_tool("sgdisk"):
            image = self.blank("efigpt.image", 4 * 1024**2)
            run_tool(
                [
                    "sgdisk",
                    "-o",
                    "-n",
                    "1:2048:+1M",
                    "-t",
                    "1:ef00",
                    "-n",
                    "2:0:0",
                    "-t",
                    "2:8300",
                    str(image),
                ]
            )
            self.emit("efigpt", "efigpt.image", "sgdisk -o (GPT, 4MB)")

    # -- 7. crypto / keys --------------------------------------------------------

    def crypto(self) -> None:
        print("== crypto")
        if require_tool("openssl"):
            run_tool(
                [
                    "openssl",
                    "enc",
                    "-aes-256-cbc",
                    "-e",
                    "-salt",
                    "-pass",
                    "pass:binwalk",
                    "-in",
                    str(self.payload_file),
                    "-out",
                    str(self.output_dir / "openssl.salted.bin"),
                ]
            )
            self.emit("openssl", "openssl.salted.bin", "openssl enc -aes-256-cbc -salt")

            key_pem = self.workdir / "key.pem"
            certificate = self.output_dir / "pem.certificate.pem"
            run_tool(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-keyout",
                    str(key_pem),
                    "-out",
                    str(certificate),
                    "-nodes",
                    "-subj",
                    "/CN=binwalk-sample",
                    "-days",
                    "3650",
                ]
            )
            self.emit("pem_certificate", "pem.certificate.pem", "openssl req -x509")

            private_key = self.output_dir / "pem.private_key.pem"
            run_tool(["openssl", "genrsa", "-out", str(private_key), "2048"])
            self.emit("pem_private_key", "pem.private_key.pem", "openssl genrsa 2048")

            public_key = self.output_dir / "pem.public_key.pem"
            run_tool(
                [
                    "openssl",
                    "rsa",
                    "-in",
                    str(private_key),
                    "-pubout",
                    "-out",
                    str(public_key),
                ]
            )
            self.emit("pem_public_key", "pem.public_key.pem", "openssl rsa -pubout")

            message = self.workdir / "msg.txt"
            message.write_text(MSG_TXT)
            # Bare DER DigestInfo (RFC 8017 9.2) so it sits at offset 0.
            sha256_oid = b"\x60\x86\x48\x01\x65\x03\x04\x02\x01"
            digest = hashlib.sha256(self.reference).digest()
            digest_info = der_sequence(
                der_sequence(der_oid(sha256_oid), der_null()), der_octets(digest)
            )
            self.write("pkcs_der.digestinfo.der", digest_info)
            self.emit(
                "pkcs_der_hash",
                "pkcs_der.digestinfo.der",
                "python3 DER-encodes RFC 8017 DigestInfo",
            )

        if require_tool("cryptsetup"):
            image = self.blank("luks.luks1.img", 2 * 1024**2)
            run_tool(
                ["cryptsetup", "luksFormat", "-q", "--type", "luks1", str(image)],
                stdin_data=b"xxxxxxxx\n",
            )
            self.emit("luks", "luks.luks1.img", "cryptsetup luksFormat luks1")

        if require_tool("gpg"):
            gnupg_home = self.workdir / "gnupg"
            gnupg_home.mkdir(mode=0o700)
            gpg_env = dict(os.environ, GNUPGHOME=str(gnupg_home))
            message = self.workdir / "msg.txt"
            message.write_text(MSG_TXT)
            run_tool(
                [
                    "gpg",
                    "--homedir",
                    str(gnupg_home),
                    "--batch",
                    "--passphrase",
                    "",
                    "--quick-gen-key",
                    "Sample <sample@localhost>",
                    "rsa2048",
                    "sign",
                    "never",
                ],
                env=gpg_env,
            )
            run_tool(
                [
                    "gpg",
                    "--homedir",
                    str(gnupg_home),
                    "--batch",
                    "--yes",
                    "-z",
                    "9",
                    "-o",
                    str(self.output_dir / "gpg.signed.gpg"),
                    "--sign",
                    str(message),
                ],
                env=gpg_env,
            )
            self.emit("gpg_signed", "gpg.signed.gpg", "gpg --sign -z 9")

    # -- 8. device tree / u-boot ---------------------------------------------------

    def boot_formats(self) -> None:
        print("== boot formats")
        if require_tool("dtc"):
            dts = self.workdir / "sample.dts"
            dts.write_text(
                "/dts-v1/;\n"
                '/ { compatible = "sample,dev"; model = "binwalk sample";\n'
                '    memory@0 { device_type = "memory"; reg = <0x0 0x1000>; };\n'
                '    chosen { bootargs = "console=ttyS0"; }; };\n'
            )
            run_tool(
                [
                    "dtc",
                    "-q",
                    "-O",
                    "dtb",
                    "-o",
                    str(self.output_dir / "dtb.sample.dtb"),
                    str(dts),
                ]
            )
            self.emit("dtb", "dtb.sample.dtb", "dtc -O dtb")

        if require_tool("mkimage"):
            elf_path = self.output_dir / "elf.x86_64"
            if elf_path.is_file():
                run_tool(
                    [
                        "mkimage",
                        "-T",
                        "kernel",
                        "-A",
                        "arm",
                        "-O",
                        "linux",
                        "-C",
                        "none",
                        "-n",
                        "binwalk sample",
                        "-a",
                        "0x80008000",
                        "-e",
                        "0x80008000",
                        "-d",
                        str(elf_path),
                        str(self.output_dir / "uimage.arm.ub"),
                    ]
                )
                self.emit("uimage", "uimage.arm.ub", "mkimage -A arm -T kernel")

                streamed = run_tool(
                    [
                        "mkimage",
                        "-T",
                        "kernel",
                        "-A",
                        "arm",
                        "-O",
                        "linux",
                        "-C",
                        "gzip",
                        "-n",
                        "binwalk sample",
                        "-a",
                        "0x80008000",
                        "-e",
                        "0x80008000",
                        "-d",
                        str(elf_path),
                        str(self.output_dir / "uimage.arm.gzip.ub"),
                    ]
                )
                if streamed.returncode == 0:
                    self.emit(
                        "uimage",
                        "uimage.arm.gzip.ub",
                        "mkimage -T kernel -C gzip (compressed body)",
                    )

    # -- 9. network capture ---------------------------------------------------

    def pcap(self) -> None:
        print("== pcap")
        tool = require_tool("text2pcap")
        if not tool:
            return
        packet = (
            "0000  ff ff ff ff ff ff de ad be ef 00 02 08 00 45 00\n"
            "0010  00 2c 00 00 00 00 40 01 00 00 c0 a8 00 01 c0 a8\n"
            "0020  00 02 08 00 f7 ff 00 01 00 00\n"
        )
        hex_file = self.workdir / "packet.hex"
        hex_file.write_text(packet)
        capture = self.output_dir / "pcapng.ipv4.pcapng"
        run_tool([tool, "-q", "-F", "pcapng", str(hex_file), str(capture)])
        if not capture.exists():
            run_tool([tool, "-q", str(hex_file), str(capture)])
        self.emit("pcapng", "pcapng.ipv4.pcapng", "text2pcap -F pcapng")

    # -- helpers ---------------------------------------------------------------

    def blank(self, relative_path: str, size: int) -> Path:
        image = self.output_dir / relative_path
        with image.open("wb") as f:
            f.truncate(size)
        return image

    def run_all(self) -> None:
        for stage in (
            self.compression,
            self.archives,
            self.images,
            self.binaries,
            self.filesystems,
            self.partition_tables,
            self.crypto,
            self.boot_formats,
            self.pcap,
        ):
            stage()
        shutil.rmtree(self.workdir, ignore_errors=True)


def der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der_tag(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_length(len(body)) + body


def der_oid(der: bytes) -> bytes:
    return der_tag(0x06, der)


def der_null() -> bytes:
    return b"\x05\x00"


def der_octets(data: bytes) -> bytes:
    return der_tag(0x04, data)


def der_sequence(*parts: bytes) -> bytes:
    return der_tag(0x30, b"".join(parts))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate binwalk-ng samples with standard tooling."
    )
    parser.add_argument(
        "output_dir",
        nargs="?",
        type=Path,
        default=Path("samples"),
        help="directory to receive the generated samples (default: ./samples)",
    )
    args = parser.parse_args()
    output_dir = args.output_dir.absolute().resolve()

    generator = Generator(output_dir)
    generator.run_all()

    total = len([p for p in output_dir.iterdir() if p.is_file()])
    print(f"\n{total} samples written to {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
