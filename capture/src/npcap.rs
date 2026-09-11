//! Npcap detection for live capture on Windows.
//!
//! pnet's Windows backend calls into Npcap's `Packet.dll`. Npcap installs it in
//! `System32\Npcap`, which is not on the DLL search path, so an ordinary
//! load-time import kills the process with `STATUS_DLL_NOT_FOUND` before `main`
//! runs — there is never a chance to tell the user what is missing. The
//! binaries therefore link `Packet.dll` with `/DELAYLOAD` (see the build
//! scripts), and [`ensure_available`] loads it by full path before the first
//! pnet datalink call. Once a module named `Packet.dll` is in the process, the
//! delay-load helper binds to it instead of searching.
//!
//! Nothing here installs anything. A missing Npcap is reported with a pointer
//! to the official installer, the same as Wireshark and Nmap do.

use std::ffi::{OsStr, OsString};
use std::io;
use std::iter;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::OnceLock;

use pf_core::{Error, Result};
use windows_sys::Win32::System::LibraryLoader::{
    LoadLibraryExW, LOAD_LIBRARY_FLAGS, LOAD_LIBRARY_SEARCH_SYSTEM32,
    LOAD_WITH_ALTERED_SEARCH_PATH,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

/// Where to send people who do not have Npcap. The official page, never a
/// mirror: it is a kernel driver.
pub const DOWNLOAD_URL: &str = "https://npcap.com/#download";

/// Load Npcap's `Packet.dll`, or explain how to get it.
///
/// Must run before any `pnet::datalink` call on Windows — including
/// `datalink::interfaces()` — because with the DLL delay-loaded, a pnet call
/// that finds no `Packet.dll` raises a structured exception rather than
/// returning an error. Cheap after the first call.
pub fn ensure_available() -> Result<()> {
    static LOADED: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    LOADED.get_or_init(load).clone().map_err(Error::Capture)
}

fn load() -> std::result::Result<(), String> {
    let npcap_dir = system_directory().map(|system| system.join("Npcap"));

    // Npcap's own directory first. Loading by full path with an altered search
    // path lets Packet.dll find anything it depends on next to itself.
    if let Some(dir) = &npcap_dir {
        let path = dir.join("Packet.dll");
        if path.is_file() {
            let _ = load_library(&dir.join("wpcap.dll"), LOAD_WITH_ALTERED_SEARCH_PATH);
            return load_library(&path, LOAD_WITH_ALTERED_SEARCH_PATH).map_err(|source| {
                format!(
                    "Npcap looks installed but `{}` failed to load: {source}. \
                     Reinstall Npcap from {DOWNLOAD_URL}",
                    path.display()
                )
            });
        }
    }

    // Npcap in WinPcap-compatible mode puts Packet.dll straight into System32.
    // Deliberately System32 only, not the default search order: that includes
    // the current directory, and a planted Packet.dll in a tool people run
    // elevated is exactly what not to load.
    let _ = load_library(Path::new("wpcap.dll"), LOAD_LIBRARY_SEARCH_SYSTEM32);
    if load_library(Path::new("Packet.dll"), LOAD_LIBRARY_SEARCH_SYSTEM32).is_ok() {
        return Ok(());
    }

    Err(format!(
        "Npcap is not installed, and live capture on Windows needs it. \
         Install it from {DOWNLOAD_URL} (the same capture driver Wireshark and \
         Nmap use), then run this again. Replaying capture files works without it."
    ))
}

/// The module is deliberately never freed: pnet's delay-loaded imports are
/// bound to it for the life of the process.
fn load_library(path: &Path, flags: LOAD_LIBRARY_FLAGS) -> io::Result<()> {
    let wide = to_wide(path.as_os_str());
    // SAFETY: `wide` is NUL-terminated and outlives the call; a null file
    // handle is what the API requires.
    let module = unsafe { LoadLibraryExW(wide.as_ptr(), ptr::null_mut(), flags) };
    if module.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn system_directory() -> Option<PathBuf> {
    let mut buf = vec![0u16; 260];
    loop {
        // SAFETY: the buffer is valid for `buf.len()` u16s.
        let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
        match len {
            0 => return None,
            // Too small: `len` is the size needed, including the NUL.
            _ if len > buf.len() => buf.resize(len, 0),
            _ => return Some(PathBuf::from(OsString::from_wide(&buf[..len]))),
        }
    }
}

fn to_wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(iter::once(0)).collect()
}
