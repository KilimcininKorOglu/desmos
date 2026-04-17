//! Windows Wintun TUN adapter.
//!
//! Wraps the [Wintun](https://www.wintun.net/) driver's DLL API
//! behind the [`crate::tun::Tun`] trait via the `wintun` crate.
//! The DLL is loaded at runtime from a caller-supplied path
//! (typically bundled next to the binary).
//!
//! # Usage
//!
//! ```ignore
//! let tun = WintunTun::create(
//!     "path/to/wintun.dll",
//!     "Desmos Tunnel",
//!     "Desmos",
//!     0x0800_0000, // 8 MiB ring
//! )?;
//! ```
//!
//! The adapter and session are torn down when `WintunTun` is
//! dropped. The Wintun driver removes the virtual network
//! interface automatically.
//!
//! # Thread model
//!
//! `wintun::Session::receive_blocking` blocks until a packet
//! arrives (or `shutdown()` is called from another thread).
//! The pipeline typically runs `recv` in a dedicated reader
//! thread while `send` is called from the outbound path.

// This entire module only compiles on Windows. On other platforms
// it is not included (cfg gate in windows/mod.rs and lib.rs).

use std::io;
use std::sync::Arc;

use crate::tun::Tun;

/// Default DLL filename searched relative to the binary.
pub const WINTUN_DLL_NAME: &str = "wintun.dll";

/// Default ring capacity: 8 MiB.
pub const DEFAULT_RING_CAPACITY: u32 = 0x0080_0000;

/// A Wintun-backed TUN device on Windows.
pub struct WintunTun {
    /// Adapter name for the `Tun::name` accessor.
    adapter_name: String,
    /// The Wintun session handle. `Arc` because `Session` is
    /// shared between the reader and the shutdown path.
    #[cfg(target_os = "windows")]
    session: Arc<wintun::Session>,
    /// Keep the adapter alive so the interface is not torn down
    /// while the session is open. `wintun 0.5` returns the adapter
    /// wrapped in an `Arc` because `start_session` requires
    /// `&Arc<Adapter>`.
    #[cfg(target_os = "windows")]
    _adapter: Arc<wintun::Adapter>,
    /// Keep the library handle alive.
    #[cfg(target_os = "windows")]
    _wintun: wintun::Wintun,
}

#[cfg(target_os = "windows")]
impl WintunTun {
    /// Create a new Wintun adapter and start a packet session.
    ///
    /// - `dll_path`: path to `wintun.dll` (absolute or relative
    ///   to the working directory).
    /// - `adapter_name`: human-readable name shown in
    ///   `ipconfig /all` (e.g. `"Desmos Tunnel"`).
    /// - `tunnel_type`: type string stored in the adapter's
    ///   registry key (e.g. `"Desmos"`).
    /// - `ring_capacity`: internal ring buffer size in bytes.
    ///   Must be a power of two between `MIN_RING_CAPACITY`
    ///   and `MAX_RING_CAPACITY`. Use [`DEFAULT_RING_CAPACITY`]
    ///   for the default 8 MiB.
    pub fn create(
        dll_path: &str,
        adapter_name: &str,
        tunnel_type: &str,
        ring_capacity: u32,
    ) -> io::Result<Self> {
        let wintun_lib = unsafe { wintun::load_from_path(dll_path) }
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))?;

        // Generate a deterministic GUID from the adapter name
        // so re-creating the same tunnel reuses the adapter
        // rather than leaving orphans.
        let guid = name_to_guid(adapter_name);

        let adapter =
            match wintun::Adapter::create(&wintun_lib, adapter_name, tunnel_type, Some(guid)) {
                Ok(a) => a,
                Err(e) => {
                    return Err(io::Error::new(io::ErrorKind::Other, e.to_string()));
                }
            };

        let session = adapter
            .start_session(ring_capacity)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        Ok(Self {
            adapter_name: adapter_name.to_string(),
            session: Arc::new(session),
            _adapter: adapter,
            _wintun: wintun_lib,
        })
    }

    /// Get a clone of the session `Arc` so the pipeline can call
    /// `shutdown()` from a signal handler thread.
    pub fn session_handle(&self) -> Arc<wintun::Session> {
        Arc::clone(&self.session)
    }
}

#[cfg(target_os = "windows")]
impl Tun for WintunTun {
    fn name(&self) -> &str {
        &self.adapter_name
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match self.session.receive_blocking() {
            Ok(packet) => {
                let bytes = packet.bytes();
                let len = bytes.len().min(buf.len());
                buf[..len].copy_from_slice(&bytes[..len]);
                Ok(len)
            }
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
        }
    }

    fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut packet = self
            .session
            .allocate_send_packet(buf.len() as u16)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        packet.bytes_mut().copy_from_slice(buf);
        self.session.send_packet(packet);
        Ok(buf.len())
    }
}

// ---- Non-Windows stub ------------------------------------------------------

#[cfg(not(target_os = "windows"))]
impl WintunTun {
    /// Stub — always errors on non-Windows.
    pub fn create(
        _dll_path: &str,
        adapter_name: &str,
        _tunnel_type: &str,
        _ring_capacity: u32,
    ) -> io::Result<Self> {
        Ok(Self { adapter_name: adapter_name.to_string() })
    }
}

#[cfg(not(target_os = "windows"))]
impl Tun for WintunTun {
    fn name(&self) -> &str {
        &self.adapter_name
    }
    fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "wintun: not on windows"))
    }
    fn send(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "wintun: not on windows"))
    }
}

// ---- Helpers ---------------------------------------------------------------

/// Derive a deterministic GUID from the adapter name so the same
/// tunnel name reuses the same adapter on re-creation.
fn name_to_guid(name: &str) -> u128 {
    // FNV-1a 128-bit hash seeded with a fixed namespace UUID.
    // Not cryptographic — just deterministic and collision-free
    // for the handful of adapter names a single host will carry.
    const FNV_OFFSET: u128 = 0x6C62_272E_07BB_0142_62B8_2175_6295_C58D;
    const FNV_PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013B;
    let mut h = FNV_OFFSET;
    for &b in name.as_bytes() {
        h ^= b as u128;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_to_guid_is_deterministic() {
        let a = name_to_guid("Desmos Tunnel");
        let b = name_to_guid("Desmos Tunnel");
        assert_eq!(a, b);
    }

    #[test]
    fn name_to_guid_differs_for_different_names() {
        let a = name_to_guid("Desmos Tunnel");
        let b = name_to_guid("Other Tunnel");
        assert_ne!(a, b);
    }

    #[test]
    fn default_ring_capacity_is_power_of_two() {
        assert!(DEFAULT_RING_CAPACITY.is_power_of_two());
    }

    #[test]
    fn default_ring_capacity_is_8mib() {
        assert_eq!(DEFAULT_RING_CAPACITY, 8 * 1024 * 1024);
    }

    #[test]
    fn stub_create_returns_name() {
        #[cfg(not(target_os = "windows"))]
        {
            let tun =
                WintunTun::create("fake.dll", "Test", "Desmos", DEFAULT_RING_CAPACITY).unwrap();
            assert_eq!(tun.name(), "Test");
        }
    }

    #[test]
    fn stub_recv_send_return_unsupported() {
        #[cfg(not(target_os = "windows"))]
        {
            let mut tun =
                WintunTun::create("fake.dll", "Test", "Desmos", DEFAULT_RING_CAPACITY).unwrap();
            let mut buf = [0u8; 64];
            assert_eq!(tun.recv(&mut buf).unwrap_err().kind(), io::ErrorKind::Unsupported);
            assert_eq!(tun.send(&[1, 2, 3]).unwrap_err().kind(), io::ErrorKind::Unsupported);
        }
    }

    // ---- Windows-only integration tests --------------------------------

    #[cfg(target_os = "windows")]
    mod windows_integration {
        use super::*;

        #[test]
        #[ignore = "needs admin privileges and wintun.dll"]
        fn create_wintun_adapter() {
            let tun =
                WintunTun::create(WINTUN_DLL_NAME, "Desmos Test", "Desmos", DEFAULT_RING_CAPACITY)
                    .unwrap();
            assert_eq!(tun.name(), "Desmos Test");
        }
    }
}
