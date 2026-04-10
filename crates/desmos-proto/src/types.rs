//! Newtype wrappers for primitive protocol values.
//!
//! These exist to stop us from accidentally passing a sequence number where
//! a session id is expected. Every wrapper is `Copy` and zero-overhead.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct SessionId(pub u16);

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sid:{:#06x}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct InterfaceId(pub u8);

impl fmt::Display for InterfaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "if:{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Seq(pub u32);

impl Seq {
    pub fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

impl fmt::Display for Seq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Microsecond timestamp, stored as a 32-bit value that wraps every 71 minutes.
/// This is intentional: wire bandwidth per packet matters more than absolute
/// wall-clock time, and the link-health state machine only compares deltas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct TimestampUs(pub u32);

impl fmt::Display for TimestampUs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}us", self.0)
    }
}
