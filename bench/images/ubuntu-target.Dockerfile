# Linux eBPF target (Debian/Ubuntu, dpkg -> Debian/Ubuntu OSV feed).
#
# Clones torda@TORDA_REF (which now includes bench/), builds the agent with
# --features linux-ebpf AND the torda-bench harness, and drops the ISOLATION
# sentinel. eBPF loads against the HOST kernel, so run PRIVILEGED with BTF, e.g.:
#
#   docker run --rm --privileged --pid=host \
#     -v /sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro \
#     -v "$PWD/results:/src/torda/bench/results" torda-bench-ubuntu \
#     bash bench/scripts/bench_entry.sh
#
# (Validated on a real Linux host / GCP VM — the eBPF verifier + capture path
# cannot run on the Windows authoring box; see README "Validation".)
FROM ubuntu:22.04
ARG TORDA_REF=main
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      git curl ca-certificates build-essential clang llvm pkg-config libelf-dev \
      make netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

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

# ISOLATION sentinel (spec §0): atomics refuse to run without it — present ONLY
# inside a disposable target, never on the control host.
RUN mkdir -p /etc/torda-bench && touch /etc/torda-bench/ISOLATED

WORKDIR /src/torda/bench
CMD ["bash"]
