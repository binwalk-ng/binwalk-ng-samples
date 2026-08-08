# Build environment for the binwalk-ng sample generator.
#
# Everything the generator could ever need is installed here, so the build is
# reproducible: identical images produce identical samples, no matter what is
# (or is not) installed on the host.
#
# Build:        docker build -t binwalk-ng-samples .
# Generate on host:
#               docker run --rm -v "$PWD/samples:/artifacts" binwalk-ng-samples
# Inspect samples inside the image (also produced at build time):
#               docker run --rm binwalk-ng-samples ls -la /artifacts
#               docker cp "$(docker create binwalk-ng-samples)":/artifacts ./samples

FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Tools used by scripts/generate_samples.py (see its header for exactly which
# tool produces which format). --no-install-recommends keeps the image lean.
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
        build-essential binutils python3 \
        zip unzip cpio tar gzip bzip2 xz-utils lz4 zstd lzop ncompress \
        gcab genisoimage dosfstools ntfs-3g mtd-utils squashfs-tools \
        gdisk u-boot-tools imagemagick wireshark-common \
        gcc-mingw-w64-x86-64 device-tree-compiler \
        cryptsetup gnupg openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ng-samples
COPY scripts/ /opt/ng-samples/scripts/

# Generate the samples once, at build time, so the resulting image contains
# the full artifact set under /artifacts.
RUN python3 scripts/generate_samples.py /artifacts

# Re-running the container regenerates into a bind mount (or /artifacts).
CMD ["python3", "scripts/generate_samples.py", "/artifacts"]
