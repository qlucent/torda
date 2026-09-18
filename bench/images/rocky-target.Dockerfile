# rpm-based target (Rocky/RHEL, rpm -> RHEL/Rocky OSV feed). Its reason to exist
# is the release-aware OSV test (spec §7.3): a Debian-only-fixed CVE must NOT be
# flagged here and vice-versa. Same privileged-run contract as the ubuntu target.
FROM rockylinux:9
ARG TORDA_REF=main

RUN dnf -y install git curl ca-certificates gcc gcc-c++ make clang llvm \
      elfutils-libelf-devel pkgconf-pkg-config nmap-ncat \
    && dnf clean all

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup toolchain install nightly --component rust-src \
    && (cargo install bpf-linker || true)

RUN git clone --depth 1 --branch "${TORDA_REF}" https://github.com/qlucent/torda.git /src/torda \
    && cd /src/torda \
    && cargo build -p torda --features linux-ebpf \
    && cargo build -p torda-bench \
    && install -m 0755 target/debug/torda /usr/local/bin/torda \
    && install -m 0755 target/debug/torda-bench /usr/local/bin/torda-bench

RUN mkdir -p /etc/torda-bench && touch /etc/torda-bench/ISOLATED

WORKDIR /src/torda/bench
CMD ["bash"]
