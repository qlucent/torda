# rpm-based target (Rocky/RHEL, rpm -> RHEL/Rocky OSV feed). Its reason to exist
# is the release-aware OSV test (spec §7.3): a Debian-only-fixed CVE must NOT be
# flagged here and vice-versa. Same privileged-run contract as the ubuntu target.
FROM rockylinux:9
ARG TORDA_REF=main

RUN dnf -y install git curl ca-certificates gcc gcc-c++ make clang \
      llvm llvm-devel elfutils-libelf-devel pkgconf-pkg-config nmap-ncat \
    && dnf clean all

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
# bpf-linker is version-locked to an LLVM major (its `llvm-sys` req) — an unpinned
# install now pulls 0.11.1 (LLVM 21+) and fails to link. Pin it to match this
# image's LLVM. Rocky 9 (RHEL 9.5+) ships LLVM 19, so 0.9.13 (llvm-sys ^191) is the
# match; if the base image's `llvm-devel` major changes, bump the pin to the
# corresponding bpf-linker (0.9.13→19, 0.9.14→20, 0.10.x/0.11.x→21+). NOTE: the
# ubuntu target was live-verified 2026-09-19; this rocky pin is by the same rule
# but should be confirmed on a `bench-rocky` run.
RUN rustup toolchain install nightly --component rust-src \
    && cargo install bpf-linker --version 0.9.13

RUN git clone --depth 1 --branch "${TORDA_REF}" https://github.com/qlucent/torda.git /src/torda \
    && cd /src/torda \
    && cargo build -p torda --features linux-ebpf \
    && cargo build -p torda-bench \
    && install -m 0755 target/debug/torda /usr/local/bin/torda \
    && install -m 0755 target/debug/torda-bench /usr/local/bin/torda-bench

RUN mkdir -p /etc/torda-bench && touch /etc/torda-bench/ISOLATED

WORKDIR /src/torda/bench
CMD ["bash"]
