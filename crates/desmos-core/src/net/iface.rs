//! Per-interface discovery.
//!
//! `list()` walks every host network interface and returns a
//! `NetworkInterface` per adapter: kernel name, 6-byte MAC, any IPv4
//! and IPv6 addresses the kernel has assigned, plus a coarse
//! `IfaceFlags` bitfield.
//!
//! # Implementation notes
//!
//! On Linux we combine two data sources:
//!
//! - `/sys/class/net/<name>/{address,operstate,flags}` for MAC,
//!   operstate, and raw flags. `/sys` is a plain filesystem: no FFI,
//!   no ioctls, no privileges.
//! - A hand-declared `getifaddrs`/`freeifaddrs` FFI for the per-
//!   interface IPv4 / IPv6 address list. POSIX, present on every
//!   glibc and musl build, and we only touch four fields of
//!   `struct ifaddrs` so layout mismatches cannot hurt us.
//!
//! On other Unix targets `getifaddrs` still works but MAC discovery
//! needs `AF_LINK` (BSD) or Netlink (Linux) — out of scope for Task
//! 20. We return zeroed MAC on non-Linux Unix and document the
//! shortfall until the cross-platform phase fills it in.
//!
//! On Windows `list()` returns [`IfaceError::NotImplemented`]; the
//! eventual implementation will use `GetAdaptersAddresses` in Phase 6.

use std::ffi::CStr;
use std::fmt;
#[cfg(target_os = "linux")]
use std::fs;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

#[derive(Debug)]
pub enum IfaceError {
    Io { context: &'static str, source: std::io::Error },
    NotImplemented(&'static str),
}

impl fmt::Display for IfaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { context, source } => write!(f, "net: {context}: {source}"),
            Self::NotImplemented(what) => {
                write!(f, "net: not implemented on this platform: {what}")
            }
        }
    }
}

impl std::error::Error for IfaceError {}

/// Coarse link flags. We lift the bits that actually matter to the
/// bonding engine (`IFF_UP`, `IFF_RUNNING`, `IFF_LOOPBACK`, `IFF_POINTOPOINT`)
/// and lower them into a tiny custom bitfield so callers do not need to
/// know the kernel constant values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IfaceFlags {
    pub up: bool,
    pub running: bool,
    pub loopback: bool,
    pub point_to_point: bool,
    pub broadcast: bool,
    pub multicast: bool,
}

impl IfaceFlags {
    /// Decode a Linux `/sys/class/net/<name>/flags` hex value. The file
    /// contains the raw `net_device::flags` bitmap.
    pub fn from_linux_bits(bits: u32) -> Self {
        const IFF_UP: u32 = 1 << 0;
        const IFF_BROADCAST: u32 = 1 << 1;
        const IFF_LOOPBACK: u32 = 1 << 3;
        const IFF_POINTOPOINT: u32 = 1 << 4;
        const IFF_RUNNING: u32 = 1 << 6;
        const IFF_MULTICAST: u32 = 1 << 12;
        Self {
            up: bits & IFF_UP != 0,
            running: bits & IFF_RUNNING != 0,
            loopback: bits & IFF_LOOPBACK != 0,
            point_to_point: bits & IFF_POINTOPOINT != 0,
            broadcast: bits & IFF_BROADCAST != 0,
            multicast: bits & IFF_MULTICAST != 0,
        }
    }
}

/// A single host interface with enough information for the bonding
/// engine and the `desmos interfaces` CLI table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInterface {
    pub name: String,
    /// 6-byte hardware address. Zeroed on non-Linux Unix and on
    /// virtual interfaces that do not expose one (loopback, tun).
    pub mac: [u8; 6],
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
    pub flags: IfaceFlags,
    pub operstate: String,
}

impl NetworkInterface {
    /// Is this interface a candidate for bonding? Must be up, running,
    /// and not the loopback adapter.
    pub fn is_bondable(&self) -> bool {
        self.flags.up && self.flags.running && !self.flags.loopback
    }

    /// Render the MAC address as six colon-separated lowercase hex
    /// bytes. Matches the `ip link` / `/sys/class/net/.../address`
    /// canonical form.
    pub fn mac_string(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]
        )
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// List every network interface on the host.
pub fn list() -> Result<Vec<NetworkInterface>, IfaceError> {
    #[cfg(target_os = "linux")]
    {
        linux_list()
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        other_unix_list()
    }
    #[cfg(target_os = "windows")]
    {
        windows_list()
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        Err(IfaceError::NotImplemented("list() on this platform"))
    }
}

// ---------------------------------------------------------------------------
// Windows: GetAdaptersAddresses
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn windows_list() -> Result<Vec<NetworkInterface>, IfaceError> {
    use std::mem;
    use std::ptr;

    const AF_UNSPEC: u32 = 0;
    const GAA_FLAG_INCLUDE_PREFIX: u32 = 0x0010;
    const ERROR_SUCCESS: u32 = 0;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;

    #[repr(C)]
    struct IpAdapterAddresses {
        _alignment: u64,
        next: *mut IpAdapterAddresses,
        adapter_name: *mut u8,
        first_unicast: *mut IpAdapterUnicastAddress,
        _pad1: [*mut u8; 3],
        dns_suffix: *mut u16,
        description: *mut u16,
        friendly_name: *mut u16,
        physical_address: [u8; 8],
        physical_address_length: u32,
        flags: u32,
        mtu: u32,
        if_type: u32,
        oper_status: u32,
        // ... more fields we don't need
    }

    #[repr(C)]
    struct IpAdapterUnicastAddress {
        _alignment: u64,
        next: *mut IpAdapterUnicastAddress,
        address: SocketAddress,
        // ... more fields
    }

    #[repr(C)]
    struct SocketAddress {
        sockaddr: *mut Sockaddr,
        sockaddr_length: i32,
    }

    #[repr(C)]
    struct Sockaddr {
        sa_family: u16,
        sa_data: [u8; 14],
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetAdaptersAddresses(
            family: u32,
            flags: u32,
            reserved: *mut u8,
            adapter_addresses: *mut u8,
            size_pointer: *mut u32,
        ) -> u32;
    }

    let mut buf_size: u32 = 0;
    let rc = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut buf_size,
        )
    };
    if rc != ERROR_BUFFER_OVERFLOW && rc != ERROR_SUCCESS {
        return Err(IfaceError::Io {
            context: "GetAdaptersAddresses size query",
            source: std::io::Error::from_raw_os_error(rc as i32),
        });
    }

    let mut buf = vec![0u8; buf_size as usize];
    let rc = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX,
            ptr::null_mut(),
            buf.as_mut_ptr(),
            &mut buf_size,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(IfaceError::Io {
            context: "GetAdaptersAddresses",
            source: std::io::Error::from_raw_os_error(rc as i32),
        });
    }

    let mut result = Vec::new();
    let mut adapter = buf.as_ptr() as *const IpAdapterAddresses;

    while !adapter.is_null() {
        let a = unsafe { &*adapter };

        let name = unsafe {
            if a.friendly_name.is_null() {
                String::from("unknown")
            } else {
                let mut len = 0;
                let mut p = a.friendly_name;
                while *p != 0 {
                    len += 1;
                    p = p.add(1);
                }
                String::from_utf16_lossy(std::slice::from_raw_parts(a.friendly_name, len))
            }
        };

        let mut mac = [0u8; 6];
        let mac_len = (a.physical_address_length as usize).min(6);
        mac[..mac_len].copy_from_slice(&a.physical_address[..mac_len]);

        let oper = match a.oper_status {
            1 => "up",
            2 => "down",
            3 => "testing",
            _ => "unknown",
        };

        let flags = IfaceFlags {
            up: a.oper_status == 1,
            running: a.oper_status == 1,
            loopback: a.if_type == 24,
            point_to_point: a.if_type == 23,
            broadcast: a.if_type == 6,
            multicast: true,
        };

        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        let mut unicast = a.first_unicast;
        while !unicast.is_null() {
            let u = unsafe { &*unicast };
            if !u.address.sockaddr.is_null() {
                let sa = unsafe { &*u.address.sockaddr };
                if sa.sa_family == 2 {
                    let bytes: [u8; 4] =
                        [sa.sa_data[2], sa.sa_data[3], sa.sa_data[4], sa.sa_data[5]];
                    ipv4.push(Ipv4Addr::from(bytes));
                } else if sa.sa_family == 23 {
                    let sa6 = sa.sa_data.as_ptr() as *const u8;
                    let mut addr_bytes = [0u8; 16];
                    unsafe {
                        std::ptr::copy_nonoverlapping(sa6.add(6), addr_bytes.as_mut_ptr(), 16);
                    }
                    ipv6.push(Ipv6Addr::from(addr_bytes));
                }
            }
            unicast = u.next;
        }

        result.push(NetworkInterface { name, mac, ipv4, ipv6, flags, operstate: oper.to_string() });

        adapter = a.next;
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Linux path: /sys enumeration + getifaddrs for IPs
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn linux_list() -> Result<Vec<NetworkInterface>, IfaceError> {
    // Step 1: enumerate via /sys/class/net.
    let entries = fs::read_dir("/sys/class/net")
        .map_err(|e| IfaceError::Io { context: "open /sys/class/net", source: e })?;
    let mut out: Vec<NetworkInterface> = Vec::new();
    for entry in entries {
        let entry = entry
            .map_err(|e| IfaceError::Io { context: "read /sys/class/net entry", source: e })?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.is_empty() {
            continue;
        }
        let mac = read_sys_mac(&name).unwrap_or([0u8; 6]);
        let operstate = read_sys_operstate(&name).unwrap_or_else(|| "unknown".to_string());
        let flag_bits = read_sys_flags(&name).unwrap_or(0);
        let flags = IfaceFlags::from_linux_bits(flag_bits);
        out.push(NetworkInterface {
            name,
            mac,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            flags,
            operstate,
        });
    }

    // Step 2: populate IP addresses via getifaddrs.
    let mut addresses = getifaddrs_addresses()?;
    for iface in &mut out {
        if let Some((v4, v6)) = addresses.remove(&iface.name) {
            iface.ipv4 = v4;
            iface.ipv6 = v6;
        }
    }

    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

#[cfg(target_os = "linux")]
fn read_sys_mac(name: &str) -> Option<[u8; 6]> {
    let path = format!("/sys/class/net/{name}/address");
    let raw = fs::read_to_string(path).ok()?;
    parse_mac(raw.trim())
}

#[cfg(target_os = "linux")]
fn read_sys_operstate(name: &str) -> Option<String> {
    let path = format!("/sys/class/net/{name}/operstate");
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

#[cfg(target_os = "linux")]
fn read_sys_flags(name: &str) -> Option<u32> {
    let path = format!("/sys/class/net/{name}/flags");
    let raw = fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();
    let stripped = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    u32::from_str_radix(stripped, 16).ok()
}

/// Parse `"aa:bb:cc:dd:ee:ff"` into `[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]`.
/// Returns `None` on any parse error or on the all-zero string that
/// `/sys` prints for interfaces with no hardware address.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        if p.len() != 2 {
            return None;
        }
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// getifaddrs: hand-declared FFI and address extraction
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod ffi {
    use std::os::raw::c_char;
    use std::os::raw::c_int;
    use std::os::raw::c_uint;

    #[repr(C)]
    pub struct Ifaddrs {
        pub ifa_next: *mut Ifaddrs,
        pub ifa_name: *const c_char,
        pub ifa_flags: c_uint,
        pub ifa_addr: *mut Sockaddr,
        // Real struct has four more fields after this; we never
        // read them and never construct an `Ifaddrs` by value, so
        // truncating is safe as long as we treat the pointer as
        // opaque beyond these four.
    }

    /// Bare header every `sockaddr_*` starts with. `sa_family` is
    /// the discriminator: 2 = AF_INET, 10 = AF_INET6 on Linux,
    /// 30 = AF_INET6 on BSD/macOS. We only look at IPv4 and IPv6,
    /// so the BSD difference is handled by a `#[cfg]` branch.
    #[repr(C)]
    pub struct Sockaddr {
        pub sa_family: u16,
        pub sa_data: [u8; 14],
    }

    #[repr(C)]
    pub struct SockaddrIn {
        pub sin_family: u16,
        pub sin_port: u16,
        pub sin_addr: [u8; 4],
        pub sin_zero: [u8; 8],
    }

    #[repr(C)]
    pub struct SockaddrIn6 {
        pub sin6_family: u16,
        pub sin6_port: u16,
        pub sin6_flowinfo: u32,
        pub sin6_addr: [u8; 16],
        pub sin6_scope_id: u32,
    }

    extern "C" {
        pub fn getifaddrs(ifap: *mut *mut Ifaddrs) -> c_int;
        pub fn freeifaddrs(ifa: *mut Ifaddrs);
    }

    pub const AF_INET: u16 = 2;
    #[cfg(target_os = "linux")]
    pub const AF_INET6: u16 = 10;
    #[cfg(not(target_os = "linux"))]
    pub const AF_INET6: u16 = 30;
}

/// Read `sockaddr.sa_family` in a way that works on both glibc-shape
/// `sockaddr` (2-byte `sa_family_t` at offset 0) and BSD-shape
/// `sockaddr` (1-byte `sa_len` at offset 0, 1-byte `sa_family` at
/// offset 1). macOS, FreeBSD, and the other BSDs all use the BSD
/// layout; Linux and anything glibc-based uses the 2-byte layout.
#[cfg(unix)]
fn read_sa_family(addr: *const ffi::Sockaddr) -> u16 {
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "ios",
    ))]
    unsafe {
        *(addr as *const u8).add(1) as u16
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "ios",
    )))]
    unsafe {
        (*addr).sa_family
    }
}

/// Intermediate map produced by `getifaddrs_addresses`: interface
/// name → `(v4, v6)` address lists.
#[cfg(unix)]
type AddressMap = std::collections::HashMap<String, (Vec<Ipv4Addr>, Vec<Ipv6Addr>)>;

#[cfg(unix)]
fn getifaddrs_addresses() -> Result<AddressMap, IfaceError> {
    use std::collections::HashMap;
    let mut head: *mut ffi::Ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` allocates a linked list and writes the head
    // pointer via `head`. On success returns 0. On failure returns -1
    // and `head` is untouched.
    let rc = unsafe { ffi::getifaddrs(&mut head) };
    if rc != 0 {
        return Err(IfaceError::Io {
            context: "getifaddrs",
            source: std::io::Error::last_os_error(),
        });
    }
    if head.is_null() {
        return Ok(HashMap::new());
    }

    let mut out: HashMap<String, (Vec<Ipv4Addr>, Vec<Ipv6Addr>)> = HashMap::new();

    // SAFETY: we walk the linked list the syscall returned. Each node
    // is allocated and owned by libc; `freeifaddrs` at the end
    // releases the entire list. We never mutate through the
    // pointer. Bounds and lifetime are guaranteed by the POSIX spec.
    let mut cur = head;
    while !cur.is_null() {
        unsafe {
            let node = &*cur;
            if node.ifa_name.is_null() {
                cur = node.ifa_next;
                continue;
            }
            let name = CStr::from_ptr(node.ifa_name).to_string_lossy().into_owned();
            if !node.ifa_addr.is_null() {
                let family = read_sa_family(node.ifa_addr);
                let entry = out.entry(name).or_insert_with(|| (Vec::new(), Vec::new()));
                if family == ffi::AF_INET {
                    let sa = &*(node.ifa_addr as *const ffi::SockaddrIn);
                    entry.0.push(Ipv4Addr::from(sa.sin_addr));
                } else if family == ffi::AF_INET6 {
                    let sa = &*(node.ifa_addr as *const ffi::SockaddrIn6);
                    entry.1.push(Ipv6Addr::from(sa.sin6_addr));
                }
            }
            cur = node.ifa_next;
        }
    }

    // SAFETY: freeifaddrs takes ownership of the list head returned by
    // getifaddrs and releases every node in the chain.
    unsafe { ffi::freeifaddrs(head) };
    Ok(out)
}

// ---------------------------------------------------------------------------
// Non-Linux Unix fallback: getifaddrs only, no MAC.
// ---------------------------------------------------------------------------

#[cfg(all(unix, not(target_os = "linux")))]
fn other_unix_list() -> Result<Vec<NetworkInterface>, IfaceError> {
    let addresses = getifaddrs_addresses()?;
    let mut out: Vec<NetworkInterface> = addresses
        .into_iter()
        .map(|(name, (ipv4, ipv6))| NetworkInterface {
            name,
            mac: [0u8; 6],
            ipv4,
            ipv6,
            // Flags and operstate are Linux `/sys`-only; left empty on BSD.
            flags: IfaceFlags::default(),
            operstate: "unknown".to_string(),
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mac_round_trips_lowercase_canonical() {
        let bytes = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(bytes, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn parse_mac_rejects_bad_shapes() {
        assert!(parse_mac("").is_none());
        assert!(parse_mac("aa:bb:cc").is_none());
        assert!(parse_mac("aa-bb-cc-dd-ee-ff").is_none());
        assert!(parse_mac("gg:hh:ii:jj:kk:ll").is_none());
        assert!(parse_mac("aa:bb:cc:dd:ee:ff:00").is_none());
    }

    #[test]
    fn iface_flags_decode_expected_bits() {
        // IFF_UP | IFF_RUNNING | IFF_LOOPBACK = 1 | 64 | 8 = 0x49
        let f = IfaceFlags::from_linux_bits(0x49);
        assert!(f.up);
        assert!(f.running);
        assert!(f.loopback);
        assert!(!f.point_to_point);
    }

    #[test]
    fn iface_flags_all_unset_is_all_false() {
        let f = IfaceFlags::from_linux_bits(0);
        assert_eq!(f, IfaceFlags::default());
    }

    #[test]
    fn mac_string_is_lowercase_six_bytes() {
        let iface = NetworkInterface {
            name: "eth0".to_string(),
            mac: [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e],
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            flags: IfaceFlags::default(),
            operstate: "up".to_string(),
        };
        assert_eq!(iface.mac_string(), "00:1a:2b:3c:4d:5e");
    }

    #[test]
    fn is_bondable_requires_up_running_and_not_loopback() {
        let base = NetworkInterface {
            name: "x".to_string(),
            mac: [0u8; 6],
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            flags: IfaceFlags::default(),
            operstate: "up".to_string(),
        };
        let mut up_running =
            NetworkInterface { flags: IfaceFlags::from_linux_bits(0x41), ..base.clone() };
        assert!(up_running.is_bondable());

        // Same but with IFF_LOOPBACK set (bit 3, 0x08).
        up_running.flags = IfaceFlags::from_linux_bits(0x49);
        assert!(!up_running.is_bondable());

        // Up without running.
        let up_only = NetworkInterface { flags: IfaceFlags::from_linux_bits(0x01), ..base.clone() };
        assert!(!up_only.is_bondable());
    }

    /// On any Unix dev host, `list()` should at least return the
    /// loopback interface. We cannot assert specific IPs because
    /// those depend on host config, but `lo` must be present and
    /// marked as a loopback.
    #[cfg(unix)]
    #[test]
    fn list_contains_loopback_on_unix() {
        let ifaces = list().unwrap();
        let lo = ifaces
            .iter()
            .find(|i| i.name == "lo" || i.name == "lo0")
            .expect("no loopback interface in list()");
        #[cfg(target_os = "linux")]
        {
            assert!(lo.flags.loopback, "loopback must have IFF_LOOPBACK");
        }
        // Loopback always has at least one IPv4 (127.0.0.1).
        assert!(lo.ipv4.iter().any(|a| a.is_loopback()), "loopback must expose 127.0.0.1",);
    }

    #[cfg(unix)]
    #[test]
    fn list_is_sorted_by_name() {
        let ifaces = list().unwrap();
        let mut sorted = ifaces.clone();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(ifaces, sorted);
    }
}
