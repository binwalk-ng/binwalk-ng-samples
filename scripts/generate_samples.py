#!/usr/bin/env python3
"""Generate binwalk-ng sample files using ONLY standard, independent tooling.

Rule: every sample is produced by a real, general-purpose generator (gzip,
tar, mkfs.*, openssl, gcc, ...) — never by reading binwalk(-ng) source or
replicating its parser logic.

Input data (the only "content" involved, all seeds are fixed and deterministic):
  * extraction_reference.txt - this repo's fixed payload text, vendored under
      scripts/data so generation never depends on an external checkout. It is
      the single file stored inside every archive and filesystem (zip, tar,
      cpio, iso9660, ext4, fat, ntfs, jffs2, ubifs, squashfs, ...) and the
      common input for every compression stream (gzip, bzip2, xz, lz4, zlib, ...).
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
import re
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
RSA_KEY_PATH = SCRIPT_DIR / "data" / "rsa_key.pem"
GPG_KEY_PATH = SCRIPT_DIR / "data" / "gpg.key"
FIXED_UUID = "11111111-2222-3333-4444-555555555555"
FIXED_SALT = "deadbeef00001234"
FIXED_TIME = 1746027123  # 2025-04-30 15:32:03 UTC (the pinned wall clock)


def pin_mtime(path: Path) -> None:
    """Pin a file's mtime to the fixed wall clock (2025-04-30 15:32:03 UTC)."""
    os.utime(path, (FIXED_TIME, FIXED_TIME))


def pin_tree(root: Path) -> None:
    """Pin mtimes of an input tree (dirs and files): some archive/filesystem
    tools read stat() results that the faketime wrapper does not intercept."""
    for path in sorted(root.rglob("*")):
        pin_mtime(path)
    pin_mtime(root)


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
    print(
        f"! warning: no tool available ({listed}) -- related samples will be skipped",
        file=sys.stderr,
    )
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
    """Writes the full sample set into the output dir."""

    # Committed fixtures for formats with no standard generator (see GAPS.md).
    # They live alongside the generated files and must survive regeneration.
    FIXTURES = frozenset(
        {
            "arcadyan.bin",
            "bmp.multiformat.bmp",
            "csman.bin",
            "csman_decompression_bomb.bin",
            "eva_dual_kernel.bin",
            "eva_secondary_only.bin",
            "eva_single_kernel.bin",
            "matter_ota.bin",
            "program_store.bin",
            "program_store.dual.bin",
            "rar3.dos_sfx.exe",
            "rar3.rar",
            "rar3.solid.rar",
            "romfs.image",
            "squashfs_v2.bin",
            "srec_s6.hex",
            "yaffs2.image",
        }
    )

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

        for p in output_dir.glob("*"):
            if p.is_file() and p.name not in Generator.FIXTURES:
                p.unlink()  # rewrite generated samples from scratch
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
            result = run_tool(["gzip", "-9nfc", str(second)], stdout=subprocess.PIPE)
            if (
                result.returncode == 0
                and self.output_dir.joinpath("gzip.data.gz").is_file()
            ):
                combined = (
                    self.output_dir / "gzip.data.gz"
                ).read_bytes() + result.stdout
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

        if require_tool("lzfse"):
            # Input pattern: 1000 leading spaces then repeated lines
            # (deterministic, and the compressibility profile matters).
            lzfse_input = b" " * 1000 + b"Testing, 1, 2, 3...\n" * 100
            result = run_tool(
                ["lzfse", "-encode"],
                stdin_data=lzfse_input,
                stdout=subprocess.PIPE,
            )
            if result.returncode == 0:
                self.write("lzfse.data.lzfse", result.stdout)
            self.emit(
                "lzfse", "lzfse.data.lzfse", "lzfse -encode (space+repeat pattern)"
            )

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
        pin_tree(self.source_dir)
        tree = self.workdir / "tree"
        tree.mkdir()
        (tree / "readme.txt").write_bytes(self.reference)
        docs = tree / "docs"
        docs.mkdir()
        (docs / "notes.txt").write_text("documentation\n" * 50)
        os.symlink("readme.txt", tree / "link.txt")
        run_sh = tree / "run.sh"
        run_sh.write_text("#!/bin/sh\necho hi\n")
        run_sh.chmod(0o755)
        subdir = tree / "subdir"
        subdir.mkdir()
        subdir.chmod(0o1755)
        (subdir / "payload.bin").write_bytes(b"\xab" * 256)

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
            self.emit(
                "tarball",
                "tarball.archive.tar",
                "tar ustar (pinned mtime, exec + sticky-dir tree)",
            )

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
                # newc embeds the source inode number; pin it (8 hex chars).
                cpio_data = bytearray(result.stdout)
                cpio_data[6:14] = b"00000001"
                self.write("cpio.newc.cpio", bytes(cpio_data))
            self.emit("cpio", "cpio.newc.cpio", "cpio -o -H newc (inode pinned)")

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
            pin_tree(zip_src)
            # No -r: InfoZIP stamps directory entries with its own clock,
            # which is not reproducible. An explicit file list yields no
            # directory entries.
            run_tool(
                [
                    "zip",
                    "-q",
                    str(self.output_dir / "zip.archive.zip"),
                    "readme.txt",
                    "bin/payload.gz",
                ],
                cwd=zip_src,
            )
            self.emit("zip", "zip.archive.zip", "zip -r (tree + nested gzip)")

            full_zip = (self.output_dir / "zip.archive.zip").read_bytes()
            self.write("zip.truncated.zip", full_zip[: len(full_zip) // 2])
            self.emit("zip", "zip.truncated.zip", "zip -r then truncated tail")

        arj = require_tool("arj")
        if arj:
            # Fixed relative names: arj embeds the archive name in the
            # header, so absolute paths would vary per run.
            run_tool(
                [arj, "a", str(self.output_dir / "arj.archive.arj"), "readme.txt"],
                cwd=self.source_dir,
            )
            self.emit("arj", "arj.archive.arj", "arj a")

            # Non-zero offset + concatenation: 13 seeded pad bytes, then two
            # archives back-to-back (signatures at 0xD and 0xD + len(arj1)).
            first = self.output_dir / "arj.archive.arj"
            if first.is_file():
                blob = seeded_bytes("arj", 13) + first.read_bytes() * 2
                self.write("arj.embedded.bin", blob)
                self.emit(
                    "arj",
                    "arj.embedded.bin",
                    "13-byte seeded pad + arj x2 (offsets 0xD, 0xD+len)",
                )

        rar = require_tool("rar")
        if rar:
            # -ep1 keeps only the file name in the archive (no paths);
            # timestamps come from the pinned clock.
            run_tool(
                [
                    rar,
                    "a",
                    "-ep1",
                    "-idq",
                    str(self.output_dir / "rar5.rar"),
                    "readme.txt",
                ],
                cwd=self.source_dir,
            )
            self.emit("rar", "rar5.rar", "rar a -ep1 (RAR5)")

            run_tool(
                [
                    rar,
                    "a",
                    "-ep1",
                    "-idq",
                    "-s",
                    str(self.output_dir / "rar5.solid.rar"),
                    "readme.txt",
                ],
                cwd=self.source_dir,
            )
            self.emit("rar", "rar5.solid.rar", "rar a -ep1 -s (RAR5 solid)")

        sevenzip = require_tool("7z")
        if sevenzip:
            run_tool(
                [sevenzip, "a", "-bd", "-y", str(self.output_dir / "archive.7z"), "."],
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

        # Negative test: magic and every chunk up to the first IDAT stay
        # intact, but the IDAT's declared length now overruns the file, so a
        # parser that walks declared chunk lengths must reject it (no
        # signature, no extraction). Deterministic cut: header + chunks +
        # half the IDAT.
        png = self.output_dir / "png.gradient.png"
        if png.is_file():
            png_data = png.read_bytes()
            off = 8
            while off + 8 <= len(png_data):
                length = struct.unpack(">I", png_data[off : off + 4])[0]
                if png_data[off + 4 : off + 8] == b"IDAT":
                    self.write("png.malformed.png", png_data[: off + 8 + length // 2])
                    self.emit(
                        "png",
                        "png.malformed.png",
                        "PNG cut mid-IDAT (no signature expected -- negative test)",
                    )
                    break
                off += 12 + length

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
            if elf_path.is_file():
                shutil.copy2(elf_path, self.workdir / "elf.x86_64")
                # Run with fixed relative names: objcopy embeds argv[1] in
                # the S0 comment record, so absolute paths would vary per run.
                run_tool(
                    ["objcopy", "-O", "srec", "elf.x86_64", "srec.from_elf.srec"],
                    cwd=self.workdir,
                )
                shutil.copy2(
                    self.workdir / "srec.from_elf.srec",
                    self.output_dir / "srec.from_elf.srec",
                )
            self.emit("srecord_generic", "srec.from_elf.srec", "objcopy -O srec")

        srec_cat = require_tool("srec_cat")
        if srec_cat and (self.output_dir / "srec.from_elf.srec").is_file():
            # srec_cat prefixes a standard 'HDR' S0 record
            # (S00600004844521B) that objcopy does not write.
            run_tool(
                [
                    srec_cat,
                    str(self.output_dir / "srec.from_elf.srec"),
                    "-header",
                    "HDR",
                    "-o",
                    str(self.output_dir / "srec.hdr.srec"),
                ]
            )
            self.emit(
                "srecord",
                "srec.hdr.srec",
                "srec_cat -header HDR (S0 = S00600004844521B)",
            )

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
        pin_tree(fs_root)

        if require_tool("mkfs.ext4"):
            image = self.blank("ext4.image", 2 * 1024**2)
            run_tool(
                [
                    "mkfs.ext4",
                    "-q",
                    "-F",
                    "-U",
                    FIXED_UUID,
                    "-E",
                    f"hash_seed={FIXED_UUID}",
                    "-d",
                    str(fs_root),
                    str(image),
                ]
            )
            if not image.is_file():
                run_tool(
                    [
                        "mkfs.ext4",
                        "-q",
                        "-F",
                        "-U",
                        FIXED_UUID,
                        "-E",
                        f"hash_seed={FIXED_UUID}",
                        str(image),
                    ]
                )
            self.emit("ext", "ext4.image", "mkfs.ext4 -d -U fixed (2MB)")

        if require_tool("mkfs.vfat"):
            image = self.blank("fat.image", 1024**2)
            run_tool(["mkfs.vfat", "-n", "BINWALK", "-i", "12345678", str(image)])
            if not image.is_file():
                run_tool(
                    [
                        "mkfs.vfat",
                        "-F",
                        "16",
                        "-n",
                        "BINWALK",
                        "-i",
                        "12345678",
                        str(image),
                    ]
                )
            if image.is_file() and shutil.which("mmd") and shutil.which("mcopy"):
                # mkfs.vfat only formats; populate offline with mtools
                # (no mount needed). Source mtimes are pinned via pin_tree,
                # directory timestamps come from the faketime-pinned clock.
                # Names are 8.3-safe so no LFN entries are written.
                run_tool(["mmd", "-i", str(image), "::/docs"])
                run_tool(
                    ["mcopy", "-i", str(image), str(fs_root / "readme.txt"), "::/"]
                )
                run_tool(
                    [
                        "mcopy",
                        "-i",
                        str(image),
                        str(fs_root / "docs" / "install.txt"),
                        "::/docs/",
                    ]
                )
                payload_gz = fs_root / "docs" / "payload.gz"
                if payload_gz.is_file():
                    run_tool(["mcopy", "-i", str(image), str(payload_gz), "::/docs/"])
            elif image.is_file():
                print(
                    "! warning: no tool available ('mmd' / 'mcopy') "
                    "-- fat.image will be empty",
                    file=sys.stderr,
                )
            self.emit("fat", "fat.image", "mkfs.vfat -i fixed + mtools (1MB)")

        if require_tool("mkntfs"):
            image = self.blank("ntfs.image", 2 * 1024**2)
            run_tool(["mkntfs", "-q", "-F", "-L", "BINWALK", str(image)])
            if image.is_file() and shutil.which("ntfscp"):
                # mkntfs only formats; populate offline with ntfscp (part of
                # ntfs-3g, no mount needed). ntfs-3g ships no offline mkdir,
                # so docs/ is flattened into root (install.txt, payload.gz).
                # Timestamps come from the faketime-pinned clock.
                run_tool(
                    ["ntfscp", str(image), str(fs_root / "readme.txt"), "readme.txt"]
                )
                run_tool(
                    [
                        "ntfscp",
                        str(image),
                        str(fs_root / "docs" / "install.txt"),
                        "install.txt",
                    ]
                )
                payload_gz = fs_root / "docs" / "payload.gz"
                if payload_gz.is_file():
                    run_tool(["ntfscp", str(image), str(payload_gz), "payload.gz"])
            elif image.is_file():
                print(
                    "! warning: no tool available ('ntfscp') "
                    "-- ntfs.image will be empty",
                    file=sys.stderr,
                )
            if image.is_file():
                # Zero the random NTFS volume serial (boot sector bytes 0x48..0x50).
                # Done after ntfscp so final bytes stay deterministic.
                data = bytearray(image.read_bytes())
                data[0x48:0x50] = b"\x00" * 8
                image.write_bytes(bytes(data))
            self.emit("ntfs", "ntfs.image", "mkntfs -F + ntfscp (2MB, serial zeroed)")

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
            if image.is_file():
                # mkfs.ubifs leaves 16 uninitialized bytes in the superblock
                # (0x6C..0x7C, heap garbage from a partially-filled node);
                # zero them, then recompute the node CRC (mtd-utils crc32:
                # zlib polynomial, zero init, no final complement).
                data = bytearray(image.read_bytes())
                data[0x6C : 0x6C + 16] = b"\x00" * 16
                node_len = struct.unpack("<I", data[16:20])[0]
                crc = zlib.crc32(bytes(data[8:node_len])) ^ 0xFFFFFFFF
                data[4:8] = struct.pack("<I", crc & 0xFFFFFFFF)
                image.write_bytes(bytes(data))
            self.emit("ubifs", "ubifs.image", "mkfs.ubifs (2048B page, 24 LEBs)")

        if require_tool("mksquashfs"):
            image = self.output_dir / "squashfs.image"
            # -mkfs-time is the modern name (4.6+); older builds only know
            # -fixed-time, so fall back when the current tool rejects it.
            result = run_tool(
                ["mksquashfs", str(fs_root), str(image), "-noD", "-mkfs-time", "0"]
            )
            if result.returncode != 0:
                run_tool(
                    [
                        "mksquashfs",
                        str(fs_root),
                        str(image),
                        "-noD",
                        "-fixed-time",
                        "0",
                    ]
                )
            self.emit("squashfs", "squashfs.image", "mksquashfs -mkfs-time 0")

        if require_tool("mkfs.cramfs"):
            image = self.output_dir / "cramfs.image"
            run_tool(["mkfs.cramfs", str(fs_root), str(image)])
            self.emit("cramfs", "cramfs.image", "mkfs.cramfs (pinned tree)")

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

    # -- 6. containers ------------------------------------------------------------

    def containers(self) -> None:
        print("== containers")

        # UBI: wraps the ubifs.image sample into a UBI image on 128KiB PEBs.
        # ubinize picks a random 32-bit image sequence number by default;
        # -Q pins it, making the output byte-identical between runs.
        if require_tool("ubinize"):
            ubifs = self.output_dir / "ubifs.image"
            if ubifs.is_file():
                cfg = self.workdir / "ubinize.cfg"
                cfg.write_text(
                    "[ubifs]\n"
                    "mode=ubi\n"
                    f"image={ubifs}\n"
                    "vol_id=0\n"
                    "vol_type=dynamic\n"
                    "vol_name=rootfs\n"
                )
                run_tool(
                    [
                        "ubinize",
                        "-Q",
                        "0x11111111",
                        "-m",
                        "2048",
                        "-p",
                        "128KiB",
                        "-s",
                        "2048",
                        "-o",
                        str(self.output_dir / "ubi.image"),
                        str(cfg),
                    ]
                )
            self.emit(
                "ubi",
                "ubi.image",
                "ubinize -Q pinned (wraps ubifs.image, 128KiB PEBs)",
            )

        if require_tool("qemu-img"):
            run_tool(
                [
                    "qemu-img",
                    "create",
                    "-q",
                    "-f",
                    "qcow2",
                    str(self.output_dir / "qcow2.image"),
                    "4M",
                ]
            )
            self.emit(
                "qcow",
                "qcow2.image",
                "qemu-img create -f qcow2 (4MB virtual disk)",
            )

        if require_tool("sox"):
            image = self.output_dir / "riff.sine.wav"
            run_tool(
                [
                    "sox",
                    "-n",
                    "-r",
                    "8000",
                    "-c",
                    "1",
                    "-b",
                    "16",
                    str(image),
                    "synth",
                    "0.5",
                    "sine",
                    "440",
                ]
            )
            if image.is_file():
                # Some sox builds stamp a LIST INFO chunk with the sox version
                # and creation date; drop it so the sample is byte-identical
                # regardless of the sox build that produced it.
                self.strip_riff_list(image)
            self.emit(
                "riff", "riff.sine.wav", "sox synth sine 440 (LIST chunk stripped)"
            )

        if require_tool("gs"):
            ps = self.workdir / "sample.ps"
            ps.write_text(
                "%!PS\n/Helvetica findfont 24 scalefont setfont\n"
                "72 720 moveto (Hello binwalk sample) show\nshowpage\n"
            )
            image = self.output_dir / "pdf.sample.pdf"
            run_tool(["gs", "-q", "-sDEVICE=pdfwrite", "-o", str(image), str(ps)])
            if image.is_file():
                # gs stamps a per-run random /ID into the trailer; repin it to
                # a constant (same length, so xref offsets stay valid).
                fixed = b"B10B10B10B10B10B10B10B10B10B10B1"
                patched = re.sub(
                    rb"/ID \[<[0-9A-Fa-f]{32}><[0-9A-Fa-f]{32}>\]",
                    b"/ID [<" + fixed + b"><" + fixed + b">]",
                    image.read_bytes(),
                )
                if patched != image.read_bytes():
                    image.write_bytes(patched)
            self.emit(
                "pdf",
                "pdf.sample.pdf",
                "gs pdfwrite (pinned clock, /ID repinned)",
            )

    def strip_riff_list(self, image: Path) -> None:
        """Remove a 'LIST INFO' chunk from a RIFF/WAVE file, if present, and
        fix the enclosing RIFF chunk size accordingly."""
        data = bytearray(image.read_bytes())
        i = data.find(b"LIST")
        if i < 0 or i + 8 > len(data):
            return
        size = struct.unpack("<I", data[i + 4 : i + 8])[0]
        total = 8 + size + (size & 1)
        if i + total > len(data):
            return
        del data[i : i + total]
        data[4:8] = struct.pack("<I", struct.unpack("<I", data[4:8])[0] - total)
        image.write_bytes(bytes(data))

    # -- 7. partition tables ----------------------------------------------------

    def partition_tables(self) -> None:
        print("== partition tables")
        if require_tool("sgdisk"):
            image = self.blank("efigpt.image", 4 * 1024**2)
            run_tool(
                [
                    "sgdisk",
                    "-o",
                    "-U",
                    FIXED_UUID,
                    "-n",
                    "1:2048:+1M",
                    "-t",
                    "1:ef00",
                    "-u",
                    "1:11111111-2222-3333-4444-555555555551",
                    "-n",
                    "2:0:0",
                    "-t",
                    "2:8300",
                    "-u",
                    "2:11111111-2222-3333-4444-555555555552",
                    str(image),
                ]
            )
            self.emit("efigpt", "efigpt.image", "sgdisk -o (GPT, 4MB)")

        if require_tool("sfdisk"):
            image = self.blank("mbr.image", 8 * 1024**2)
            run_tool(["sfdisk", str(image)], stdin_data=b"type=83\n")
            if image.is_file():
                # sfdisk stamps a random disk id (boot sector bytes 0x1B8..);
                # pin it to a constant so two runs are byte-identical.
                data = bytearray(image.read_bytes())
                data[0x1B8:0x1BC] = struct.pack("<I", 0x12345678)
                image.write_bytes(bytes(data))
            self.emit("mbr", "mbr.image", "sfdisk (8MB, disk id pinned)")

    # -- 8. crypto / keys --------------------------------------------------------

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
                    "-S",
                    FIXED_SALT,
                    "-pass",
                    "pass:binwalk",
                    "-in",
                    str(self.payload_file),
                    "-out",
                    str(self.output_dir / "openssl.salted.bin"),
                ]
            )
            salted = self.output_dir / "openssl.salted.bin"
            if salted.is_file() and not salted.read_bytes().startswith(b"Salted__"):
                # Newer openssl no longer writes the "Salted__" magic when the
                # salt is supplied with -S (only when it generates its own);
                # restore the standard header -- the ciphertext is still keyed
                # to exactly this salt, so the file remains valid.
                salted.write_bytes(
                    b"Salted__" + bytes.fromhex(FIXED_SALT) + salted.read_bytes()
                )
            self.emit(
                "openssl",
                "openssl.salted.bin",
                f"openssl enc -aes-256-cbc -S {FIXED_SALT} (fixed salt)",
            )

            # The RSA keypair is vendored seed data (see README "Data"), so the
            # three PEM samples are byte-deterministic: no key generation, no
            # random factors anywhere.
            private_key = self.output_dir / "pem.private_key.pem"
            private_key.write_bytes(RSA_KEY_PATH.read_bytes())
            self.emit(
                "pem_private_key",
                "pem.private_key.pem",
                "vendored seed key (genrsa once)",
            )

            certificate = self.output_dir / "pem.certificate.pem"
            csr = self.workdir / "sample.csr"
            run_tool(
                [
                    "openssl",
                    "req",
                    "-new",
                    "-key",
                    str(RSA_KEY_PATH),
                    "-out",
                    str(csr),
                    "-subj",
                    "/CN=binwalk-sample",
                ]
            )
            run_tool(
                [
                    "openssl",
                    "x509",
                    "-req",
                    "-in",
                    str(csr),
                    "-signkey",
                    str(RSA_KEY_PATH),
                    "-set_serial",
                    "1",
                    "-days",
                    "3650",
                    "-out",
                    str(certificate),
                ]
            )
            self.emit(
                "pem_certificate",
                "pem.certificate.pem",
                "openssl req + x509 -req -set_serial 1 (pinned clock)",
            )

            public_key = self.output_dir / "pem.public_key.pem"
            run_tool(
                [
                    "openssl",
                    "rsa",
                    "-in",
                    str(RSA_KEY_PATH),
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
                [
                    "cryptsetup",
                    "luksFormat",
                    "-q",
                    "--type",
                    "luks1",
                    "--uuid",
                    FIXED_UUID,
                    "--pbkdf-force-iterations",
                    "10000",
                    str(image),
                ],
                stdin_data=b"xxxxxxxx\n",
            )
            if image.is_file():
                self.zero_luks_randomness(image)
            self.emit(
                "luks",
                "luks.luks1.img",
                "cryptsetup luksFormat luks1 (fixed uuid/iterations)",
            )

        if require_tool("gpg"):
            gnupg_home = self.workdir / "gnupg"
            gnupg_home.mkdir(mode=0o700)
            gpg_env = dict(os.environ, GNUPGHOME=str(gnupg_home))
            message = self.workdir / "msg.txt"
            message.write_text(MSG_TXT)
            # The signing key is vendored seed data (see README "Data"),
            # so the signature is byte-deterministic; --faked-system-time pins
            # the signature timestamp to the same fixed date as the faketime
            # wall clock (2025-04-30).
            run_tool(
                [
                    "gpg",
                    "--homedir",
                    str(gnupg_home),
                    "--batch",
                    "--import",
                    str(GPG_KEY_PATH),
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
                    "--faked-system-time",
                    "20250430T153203",
                    "-z",
                    "9",
                    "-o",
                    str(self.output_dir / "gpg.signed.gpg"),
                    "--sign",
                    str(message),
                ],
                env=gpg_env,
            )
            self.emit(
                "gpg_signed",
                "gpg.signed.gpg",
                "gpg --sign -z 9 (vendored key, faked time)",
            )

    def zero_luks_randomness(self, image: Path) -> None:
        """Zero the random fields cryptsetup leaves in a LUKS1 header.

        The master-key digest, the active keyslot's salt and its encrypted
        key material (plus the wiped padding beyond) come from the system
        RNG; everything else is pinned (uuid, pbkdf iterations). LUKS1 is
        big-endian, so active slots are detected via ">I". Zeroing these
        regions makes the sample byte-deterministic."""
        data = bytearray(image.read_bytes())
        data[0x70 : 0x70 + 20] = b"\x00" * 20  # mkDigest
        data[0x84 : 0x84 + 32] = b"\x00" * 32  # mkDigestSalt
        for slot in range(8):
            base = 0xD0 + slot * 0x30
            # Zero every slot's salt: inactive slots are already zero.
            data[base + 8 : base + 8 + 32] = b"\x00" * 32
        data[0x1000:] = b"\x00" * (len(data) - 0x1000)  # key slots + padding
        image.write_bytes(bytes(data))

    # -- 9. device tree / u-boot ---------------------------------------------------

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

    # -- 10. network capture ---------------------------------------------------

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
        if capture.exists():
            # text2pcap embeds the input path in a file-comment option; the
            # 8-char mkdtemp suffix varies per run, so pin it to a fixed one.
            raw = capture.read_bytes()
            raw = raw.replace(str(hex_file).encode(), b"/tmp/bns-00000000/packet.hex")
            capture.write_bytes(raw)
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
            self.containers,
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
