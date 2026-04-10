//! 8-bit flag bitfield carried in byte 1 of the DWP header.
//!
//! We hand-roll a bitflags-style wrapper instead of pulling in the
//! `bitflags` crate, staying within the 5-crate runtime budget.
//! Unknown bits are preserved on round-trip so future protocol revisions
//! can add flags without breaking older peers.

use core::fmt;
use core::ops::BitOr;
use core::ops::BitOrAssign;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags(u8);

impl Flags {
    pub const EMPTY: Self = Self(0);
    pub const FIN: Self = Self(1 << 0);
    pub const ACK: Self = Self(1 << 1);
    pub const FRAG: Self = Self(1 << 2);
    pub const REDUNDANT: Self = Self(1 << 3);
    pub const PRIORITY: Self = Self(1 << 4);

    /// Mask of every flag defined in this protocol version. Used only by
    /// diagnostics — decode preserves unknown bits verbatim so the peer can
    /// handle them.
    pub const KNOWN: Self =
        Self(Self::FIN.0 | Self::ACK.0 | Self::FRAG.0 | Self::REDUNDANT.0 | Self::PRIORITY.0);

    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }

    pub fn has_unknown_bits(self) -> bool {
        (self.0 & !Self::KNOWN.0) != 0
    }
}

impl BitOr for Flags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for Flags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut write_flag = |name: &str| -> fmt::Result {
            if !first {
                f.write_str("|")?;
            }
            first = false;
            f.write_str(name)
        };
        if self.contains(Self::FIN) {
            write_flag("FIN")?;
        }
        if self.contains(Self::ACK) {
            write_flag("ACK")?;
        }
        if self.contains(Self::FRAG) {
            write_flag("FRAG")?;
        }
        if self.contains(Self::REDUNDANT) {
            write_flag("REDUNDANT")?;
        }
        if self.contains(Self::PRIORITY) {
            write_flag("PRIORITY")?;
        }
        if first {
            f.write_str("-")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_flags_contain_nothing() {
        assert!(!Flags::EMPTY.contains(Flags::FIN));
        assert_eq!(Flags::EMPTY.bits(), 0);
    }

    #[test]
    fn bitor_combines() {
        let f = Flags::ACK | Flags::FIN;
        assert!(f.contains(Flags::ACK));
        assert!(f.contains(Flags::FIN));
        assert!(!f.contains(Flags::FRAG));
    }

    #[test]
    fn insert_and_remove_round_trip() {
        let mut f = Flags::EMPTY;
        f.insert(Flags::PRIORITY);
        assert!(f.contains(Flags::PRIORITY));
        f.remove(Flags::PRIORITY);
        assert!(!f.contains(Flags::PRIORITY));
    }

    #[test]
    fn unknown_bits_preserved_across_from_bits() {
        let f = Flags::from_bits(0b1110_0001);
        assert!(f.contains(Flags::FIN));
        assert!(f.has_unknown_bits());
        assert_eq!(f.bits(), 0b1110_0001);
    }

    #[test]
    fn display_renders_known_flags() {
        assert_eq!(Flags::EMPTY.to_string(), "-");
        assert_eq!((Flags::FIN | Flags::ACK).to_string(), "FIN|ACK");
    }
}
