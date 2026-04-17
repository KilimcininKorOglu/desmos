//! Linux privilege drop: uid/gid + `PR_SET_NO_NEW_PRIVS` + seccomp BPF.
//!
//! After switching to the unprivileged user the module installs a
//! seccomp BPF filter that blocks syscalls the daemon should never
//! need post-init:
//!
//! - `open` / `openat` — prevents opening new TUN devices or files
//! - `socket` — prevents binding new sockets
//! - `execve` / `execveat` — prevents spawning child processes
//!
//! The filter is architecture-aware (x86_64 vs aarch64 have different
//! syscall numbers) and uses a blocklist approach: everything not
//! explicitly blocked is allowed. This avoids breaking normal
//! runtime operations (read, write, mmap, futex, etc.).

use std::io;

use super::posix_drop_ids;

// ---- prctl / seccomp constants ----------------------------------------------

/// `PR_SET_NO_NEW_PRIVS` — prevents regaining privileges via execve
/// of a setuid binary.
const PR_SET_NO_NEW_PRIVS: i32 = 38;

/// `PR_SET_SECCOMP` — install seccomp mode.
const PR_SET_SECCOMP: i32 = 22;

/// `SECCOMP_MODE_FILTER` — BPF program filter mode.
const SECCOMP_MODE_FILTER: u64 = 2;

// ---- Seccomp BPF instruction encoding --------------------------------------

/// BPF instruction (sock_filter).  8 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// BPF program descriptor (sock_fprog).
#[repr(C)]
struct BpfProg {
    len: u16,
    filter: *const BpfInsn,
}

// BPF opcodes (subset needed for seccomp).
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_RET: u16 = 0x06;
const BPF_K: u16 = 0x00;

/// `SECCOMP_RET_ERRNO | EPERM` — return EPERM to the caller.
const SECCOMP_RET_ERRNO_EPERM: u32 = 0x0005_0001;

/// `SECCOMP_RET_ALLOW` — allow the syscall.
const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;

/// `AUDIT_ARCH_X86_64`.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// `AUDIT_ARCH_AARCH64`.
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

// seccomp_data offsets.
/// Offset of `nr` (syscall number) in `struct seccomp_data`.
const SECCOMP_DATA_NR: u32 = 0;
/// Offset of `arch` in `struct seccomp_data`.
const SECCOMP_DATA_ARCH: u32 = 4;

// ---- Syscall numbers --------------------------------------------------------

// x86_64
#[cfg(target_arch = "x86_64")]
const SYS_OPEN_X86: u32 = 2;
#[cfg(target_arch = "x86_64")]
const SYS_SOCKET_X86: u32 = 41;
#[cfg(target_arch = "x86_64")]
const SYS_EXECVE_X86: u32 = 59;
#[cfg(target_arch = "x86_64")]
const SYS_OPENAT_X86: u32 = 257;
#[cfg(target_arch = "x86_64")]
const SYS_EXECVEAT_X86: u32 = 322;

// aarch64 — openat is the primary open syscall (no legacy open).
#[cfg(target_arch = "aarch64")]
const SYS_OPENAT_ARM64: u32 = 56;
#[cfg(target_arch = "aarch64")]
const SYS_EXECVE_ARM64: u32 = 221;
#[cfg(target_arch = "aarch64")]
const SYS_SOCKET_ARM64: u32 = 198;
#[cfg(target_arch = "aarch64")]
const SYS_EXECVEAT_ARM64: u32 = 281;

// ---- FFI --------------------------------------------------------------------

extern "C" {
    fn prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i32;
}

// ---- Public entry point -----------------------------------------------------

/// Drop uid/gid, set NO_NEW_PRIVS, install seccomp BPF filter.
pub(crate) fn drop_and_sandbox(uid: u32, gid: u32) -> io::Result<()> {
    // Step 1: drop uid/gid.
    posix_drop_ids(uid, gid)?;

    // Step 2: prevent privilege escalation via setuid binaries.
    if unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // Step 3: install seccomp BPF blocklist.
    install_seccomp_filter()?;

    Ok(())
}

// ---- BPF filter construction ------------------------------------------------

/// Build and install the seccomp BPF blocklist filter.
fn install_seccomp_filter() -> io::Result<()> {
    let filter = build_filter();
    let prog = BpfProg { len: filter.len() as u16, filter: filter.as_ptr() };

    let ret =
        unsafe { prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog as *const BpfProg as u64, 0, 0) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Construct the BPF instruction array.
///
/// Filter logic:
/// 1. Load architecture → if not ours, ALLOW (safe default).
/// 2. Load syscall number.
/// 3. If blocked → ERRNO(EPERM).
/// 4. Otherwise → ALLOW.
fn build_filter() -> Vec<BpfInsn> {
    // Determine blocked syscalls based on compile-time target arch.
    #[cfg(target_arch = "x86_64")]
    let (arch, blocked) = (
        AUDIT_ARCH_X86_64,
        &[SYS_OPEN_X86, SYS_OPENAT_X86, SYS_SOCKET_X86, SYS_EXECVE_X86, SYS_EXECVEAT_X86][..],
    );

    #[cfg(target_arch = "aarch64")]
    let (arch, blocked) = (
        AUDIT_ARCH_AARCH64,
        &[SYS_OPENAT_ARM64, SYS_SOCKET_ARM64, SYS_EXECVE_ARM64, SYS_EXECVEAT_ARM64][..],
    );

    // Fallback for other architectures: empty blocklist (allow all).
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let (arch, blocked): (u32, &[u32]) = (0, &[]);

    let num_blocked = blocked.len();

    let mut insns = Vec::with_capacity(4 + num_blocked + 1);

    // [0] Load architecture.
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH));

    // [1] If arch != ours → skip to ALLOW (jump over everything).
    // jt=0 (fall through to next), jf = 2 + num_blocked (skip to allow).
    let skip_to_allow = (1 + num_blocked) as u8;
    insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, arch, 0, skip_to_allow));

    // [2] Load syscall number.
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR));

    // [3..3+N-1] Check each blocked syscall.
    for (i, &nr) in blocked.iter().enumerate() {
        let remaining = num_blocked - i - 1;
        // If match → jump to DENY (at offset remaining + 1 from here).
        // If no match → fall through to next check (or ALLOW).
        insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, (remaining + 1) as u8, 0));
    }

    // [3+N] ALLOW — default action.
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // [3+N+1] DENY — return EPERM.
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO_EPERM));

    insns
}

// ---- BPF helpers ------------------------------------------------------------

const fn bpf_stmt(code: u16, k: u32) -> BpfInsn {
    BpfInsn { code, jt: 0, jf: 0, k }
}

const fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> BpfInsn {
    BpfInsn { code, jt, jf, k }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpf_insn_size() {
        assert_eq!(std::mem::size_of::<BpfInsn>(), 8);
    }

    #[test]
    fn bpf_prog_layout() {
        // sock_fprog: u16 len + padding + pointer.
        assert_eq!(
            std::mem::size_of::<BpfProg>(),
            std::mem::size_of::<u16>() + 6 + std::mem::size_of::<usize>(),
        );
    }

    #[test]
    fn filter_has_correct_length() {
        let filter = build_filter();
        // header (3 insns) + blocked syscalls + allow + deny.
        #[cfg(target_arch = "x86_64")]
        assert_eq!(filter.len(), 3 + 5 + 2); // 10

        #[cfg(target_arch = "aarch64")]
        assert_eq!(filter.len(), 3 + 4 + 2); // 9
    }

    #[test]
    fn filter_starts_with_arch_check() {
        let filter = build_filter();
        // First instruction: load arch.
        assert_eq!(filter[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(filter[0].k, SECCOMP_DATA_ARCH);
    }

    #[test]
    fn filter_ends_with_allow_deny() {
        let filter = build_filter();
        let n = filter.len();
        // Second to last: ALLOW.
        assert_eq!(filter[n - 2].code, BPF_RET | BPF_K);
        assert_eq!(filter[n - 2].k, SECCOMP_RET_ALLOW);
        // Last: DENY.
        assert_eq!(filter[n - 1].code, BPF_RET | BPF_K);
        assert_eq!(filter[n - 1].k, SECCOMP_RET_ERRNO_EPERM);
    }

    #[test]
    fn blocked_syscalls_present_in_filter() {
        let filter = build_filter();
        let syscall_checks: Vec<u32> = filter
            .iter()
            .filter(|i| i.code == BPF_JMP | BPF_JEQ | BPF_K && i.k != 0)
            .skip(1) // skip arch check
            .map(|i| i.k)
            .collect();

        #[cfg(target_arch = "x86_64")]
        {
            assert!(syscall_checks.contains(&SYS_OPEN_X86));
            assert!(syscall_checks.contains(&SYS_OPENAT_X86));
            assert!(syscall_checks.contains(&SYS_SOCKET_X86));
            assert!(syscall_checks.contains(&SYS_EXECVE_X86));
            assert!(syscall_checks.contains(&SYS_EXECVEAT_X86));
        }

        #[cfg(target_arch = "aarch64")]
        {
            assert!(syscall_checks.contains(&SYS_OPENAT_ARM64));
            assert!(syscall_checks.contains(&SYS_SOCKET_ARM64));
            assert!(syscall_checks.contains(&SYS_EXECVE_ARM64));
            assert!(syscall_checks.contains(&SYS_EXECVEAT_ARM64));
        }
    }

    #[test]
    #[ignore = "needs root on Linux"]
    #[cfg(target_os = "linux")]
    fn drop_and_sandbox_blocks_open() {
        // This test must run as root. After dropping, open() should
        // return EPERM.
        drop_and_sandbox(65534, 65534).unwrap();
        let result = std::fs::File::open("/dev/null");
        assert!(result.is_err());
    }
}
