//! Build script for `torda-substrate`.
//!
//! ## Default / Windows / feature-off build: NO-OP
//! On the default cross-platform build this script does nothing: it compiles no
//! eBPF, spawns no `cargo`, pulls in no aya/bpf toolchain, and writes nothing.
//! The gate below returns before any of that. So the host build stays clean and
//! aya never enters the dependency tree.
//!
//! ## `--features linux-ebpf` on a Linux target: compile the BPF object
//! Only when BOTH `CARGO_FEATURE_LINUX_EBPF` is set AND `CARGO_CFG_TARGET_OS ==
//! "linux"` does this script build the kernel-side `crates/substrate-ebpf` crate
//! (which is EXCLUDED from the workspace) to a `bpfel-unknown-none` object via
//! `cargo +nightly build`, then copy it to `$OUT_DIR/substrate-ebpf.o`. The
//! userspace `EbpfBus` loader (Task 2) embeds that object with `include_bytes!`
//! (see `src/ebpf.rs`).
//!
//! The nested build is driven by manifest path so it works even though the ebpf
//! crate is excluded from the workspace; the ebpf crate's own `.cargo/config.toml`
//! selects the BPF target + bpf-linker. clang is NOT required.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Feature + platform gate. On the default Windows build neither var lines up,
    // so this returns immediately: a true no-op.
    let feature_on = env::var_os("CARGO_FEATURE_LINUX_EBPF").is_some();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if !(feature_on && target_os == "linux") {
        return;
    }
    build_ebpf_object();
}

/// Compile `crates/substrate-ebpf` to a BPF object and stage it in `OUT_DIR`.
/// Only ever called on a Linux `--features linux-ebpf` build.
fn build_ebpf_object() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let crates_dir = manifest_dir.parent().expect("crates dir");
    let ebpf_dir = crates_dir.join("substrate-ebpf");
    let common_dir = crates_dir.join("substrate-ebpf-common");

    // Rebuild the object when the kernel program or the shared wire struct change.
    println!("cargo:rerun-if-changed={}", ebpf_dir.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_dir.join("Cargo.toml").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_dir.join(".cargo/config.toml").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        common_dir.join("src").display()
    );

    // Keep the nested target dir under OUT_DIR so it never clobbers the Windows
    // (or host) target tree, and is cleaned with the build output.
    let target_dir = out_dir.join("substrate-ebpf-target");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir)
        .args(["+nightly", "build", "--release"])
        .env("CARGO_TARGET_DIR", &target_dir);

    // The parent cargo invocation exports env that would corrupt a nested BPF
    // build: its RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS override the ebpf crate's
    // `--cfg bpf_target_arch`, and its RUSTC wrappers/toolchain pin point at host
    // tooling. Strip them so the ebpf crate's own `.cargo/config.toml` (target,
    // build-std, cfg) fully controls the compile.
    for key in [
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTUP_TOOLCHAIN",
        "CARGO_MAKEFLAGS",
    ] {
        cmd.env_remove(key);
    }

    let status = cmd
        .status()
        .expect("failed to spawn `cargo +nightly build` for substrate-ebpf");
    assert!(
        status.success(),
        "substrate-ebpf BPF build failed (need nightly + bpf-linker on PATH)"
    );

    // The `[[bin]]` is named `torda-substrate-ebpf`; stage its object at a stable
    // path for the loader's `include_bytes!`.
    let obj = target_dir
        .join("bpfel-unknown-none")
        .join("release")
        .join("torda-substrate-ebpf");
    let dst = out_dir.join("substrate-ebpf.o");
    std::fs::copy(&obj, &dst)
        .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", obj.display(), dst.display()));
}
