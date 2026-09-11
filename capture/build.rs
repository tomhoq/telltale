//! Windows only: points the linker at the Npcap SDK's `Packet.lib`, and
//! delay-loads `Packet.dll` in this crate's own test binaries.
//!
//! Delay-loading is what lets a missing Npcap be reported instead of killing
//! the process before `main` — see `src/npcap.rs`. `rustc-link-arg` applies
//! only to this package's binaries and tests, so the CLI's build script repeats
//! it for `telltale-pf`; the link search path, by contrast, reaches dependents.

use std::env;
use std::path::PathBuf;

const SDK_URL: &str = "https://npcap.com/#download";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=NPCAP_SDK");
    println!("cargo:rerun-if-env-changed=LIB");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    link_npcap_sdk();

    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg=/DELAYLOAD:Packet.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-arg=delayimp.lib");
    }
}

fn link_npcap_sdk() {
    // The SDK ships x86 libraries at the root of `Lib` and the rest in a
    // per-architecture subdirectory.
    let arch_dir = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x64",
        Ok("aarch64") => "ARM64",
        _ => "",
    };

    if let Some(sdk) = env::var_os("NPCAP_SDK") {
        let dir = PathBuf::from(sdk).join("Lib").join(arch_dir);
        if !dir.join("Packet.lib").is_file() {
            panic!(
                "NPCAP_SDK is set, but there is no Packet.lib in `{}`. Point it at the \
                 extracted Npcap SDK (the directory containing `Lib` and `Include`); \
                 the SDK is on {SDK_URL}",
                dir.display()
            );
        }
        println!("cargo:rustc-link-search=native={}", dir.display());
        return;
    }

    // Not an error: the library may also come from `LIB` or from `-L` in
    // rustflags, which a build script cannot see. Warn so the linker's own
    // "cannot open Packet.lib" has an explanation next to it.
    let on_lib_path = env::var_os("LIB")
        .map(|lib| env::split_paths(&lib).any(|dir| dir.join("Packet.lib").is_file()))
        .unwrap_or(false);
    if !on_lib_path {
        println!(
            "cargo:warning=Packet.lib not found: set NPCAP_SDK to the extracted Npcap SDK \
             (download it from {SDK_URL}) if linking fails"
        );
    }
}
