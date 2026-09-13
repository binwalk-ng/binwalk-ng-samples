FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    FAKETIME='2025-04-30 15:32:03'

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
        build-essential binutils python3 \
        zip unzip cpio tar gzip bzip2 xz-utils lz4 zstd lzfse lzop ncompress \
        7zip gcab genisoimage dosfstools mtools ntfs-3g mtd-utils squashfs-tools \
        gdisk u-boot-tools imagemagick wireshark-common \
        gcc-mingw-w64-x86-64 device-tree-compiler \
        cryptsetup gnupg openssl libfaketime srecord \
        qemu-utils sox ghostscript arj rar \
        util-linux-extra fdisk \
    && rm -rf /var/lib/apt/lists/*

# Preload libfaketime so every tool in the image sees the pinned clock.
RUN lib="$(find /usr/lib -name 'libfaketime.so*' | head -n1)" \
    && test -n "$lib" && echo "$lib" > /etc/ld.so.preload

WORKDIR /opt/ng-samples
COPY scripts/ /opt/ng-samples/scripts/
# Seed committed fixtures: Generator preserves FIXTURES but never creates
# them, so builds starting from an empty /artifacts would omit fixture-only
# samples (srec_s6.hex, RAR3, ...). `cp -an` seeds only missing files, so a
# mounted checkout keeps its own copies.
COPY samples/ /opt/ng-samples/samples-seed/

RUN mkdir -p /artifacts \
    && cp -an /opt/ng-samples/samples-seed/. /artifacts/ \
    && python3 scripts/generate_samples.py /artifacts

CMD ["sh", "-c", "cp -an /opt/ng-samples/samples-seed/. /artifacts/ 2>/dev/null || true; exec python3 scripts/generate_samples.py /artifacts"]