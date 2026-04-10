//! Linux-only TUN device tests. All are `#[ignore]` because creating a
//! TUN requires `CAP_NET_ADMIN` which no normal CI runner grants by
//! default. Run manually with:
//!
//! ```bash
//! sudo -E cargo test --test tun_linux -- --ignored
//! ```

#![cfg(target_os = "linux")]

use std::path::Path;

use desmos_rt::LinuxTun;
use desmos_rt::Tun;

fn sysfs_exists(name: &str) -> bool {
    Path::new(&format!("/sys/class/net/{name}")).exists()
}

#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn create_and_drop_removes_interface() {
    let tun = LinuxTun::create("desmos_test0").expect("create");
    assert_eq!(tun.name(), "desmos_test0");
    assert!(
        sysfs_exists("desmos_test0"),
        "interface did not appear in /sys/class/net after create"
    );
    drop(tun);
    assert!(
        !sysfs_exists("desmos_test0"),
        "interface still present after drop — kernel should auto-remove non-persist TUN"
    );
}

#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn send_on_down_interface_errors() {
    // Without bringing the interface up, a write should fail. This verifies
    // the send() plumbing surfaces kernel errors without corrupting the fd.
    let mut tun = LinuxTun::create("desmos_test1").expect("create");
    let pkt = [0u8; 20]; // minimal IPv4 header-sized buffer
    let err = tun.send(&pkt).unwrap_err();
    // Typical errno here is ENETDOWN or EIO; both surface as raw_os_error.
    assert!(err.raw_os_error().is_some(), "expected an OS error, got {err}");
}
