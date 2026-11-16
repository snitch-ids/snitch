//! Provides the BPF object for the `ebpf` feature as `SNITCH_BPF_OBJECT`.
//!
//! - `SNITCH_BPF_OBJ=<path>`: use a prebuilt object (Yocto: meta-snitch's
//!   cargo-bpf class builds it with the target's Rust and LLVM).
//! - otherwise: build `snitch-ebpf` here with
//!   `cargo +nightly build -Z build-std=core --target bpfel-unknown-none`.
//!   Needs the nightly toolchain with `rust-src`, and `bpf-linker` on PATH:
//!
//!   rustup toolchain install nightly --component rust-src
//!   cargo install bpf-linker
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=SNITCH_BPF_OBJ");
    if env::var_os("CARGO_FEATURE_EBPF").is_none()
        || env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
    {
        return;
    }

    if let Some(obj) = env::var_os("SNITCH_BPF_OBJ") {
        let obj = PathBuf::from(obj);
        if !obj.is_file() {
            panic!("SNITCH_BPF_OBJ={} is not a file", obj.display());
        }
        println!("cargo:rerun-if-changed={}", obj.display());
        println!("cargo:rustc-env=SNITCH_BPF_OBJECT={}", obj.display());
        return;
    }

    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let manifest = root.join("snitch-ebpf/Cargo.toml");
    for p in [
        "snitch-ebpf/src",
        "snitch-ebpf/Cargo.toml",
        "snitch-ebpf/Cargo.lock",
        "snitch-ebpf-common/src",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(p).display());
    }
    let target_dir = PathBuf::from(env::var("OUT_DIR").unwrap()).join("ebpf");

    let mut cmd = Command::new("cargo");
    cmd.args(["+nightly", "build", "--release", "-Z", "build-std=core"])
        .args(["--target", "bpfel-unknown-none"])
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--target-dir")
        .arg(&target_dir);
    if env::var("PROFILE").as_deref() == Ok("release") {
        cmd.arg("--locked");
    }
    // Settings meant for the host build must not leak into the BPF build.
    for var in [
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "CARGO_TARGET_DIR",
        "RUSTUP_TOOLCHAIN",
    ] {
        cmd.env_remove(var);
    }
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("running cargo +nightly for snitch-ebpf: {e}"));
    if !status.success() {
        panic!(
            "building snitch-ebpf failed ({status}). Needs nightly with rust-src and \
             bpf-linker (see build.rs), or set SNITCH_BPF_OBJ to a prebuilt object."
        );
    }
    let obj = target_dir.join("bpfel-unknown-none/release/snitch-ebpf");
    assert!(Path::new(&obj).is_file(), "{} missing", obj.display());
    println!("cargo:rustc-env=SNITCH_BPF_OBJECT={}", obj.display());
}
