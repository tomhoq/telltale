//! Delay-loads Npcap's `Packet.dll` on Windows, so a machine without Npcap
//! gets told to install it instead of a process that dies before `main` with
//! STATUS_DLL_NOT_FOUND. The DLL is loaded by `pf_capture::npcap`; the
//! capture crate's build script explains the rest.

use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg=/DELAYLOAD:Packet.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-arg=delayimp.lib");
    } else {
        // GNU ld has no delay-load; the binary will need Npcap's directory on
        // PATH to start at all, live capture or not.
        println!(
            "cargo:warning=Packet.dll cannot be delay-loaded on this toolchain; \
             telltale-pf will only start with Npcap's directory on PATH"
        );
    }
}
