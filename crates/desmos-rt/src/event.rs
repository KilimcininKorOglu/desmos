//! Platform-agnostic event types used by the reactor.
//!
//! `Token` is an opaque 64-bit identifier returned verbatim by the
//! reactor when a source becomes ready. Callers typically encode a
//! category (see [`Tag`]) in the high bits and an index in the low
//! bits so the dispatch layer can demultiplex events by source type.

/// Opaque event identifier. Reactor returns exactly what the caller
/// supplied at registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Token(pub u64);

/// Category hint for a [`Token`]. Not consulted by the reactor itself;
/// provided so the dispatch layer can pack it into the top byte of a
/// token at registration time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Tag {
    Udp = 0,
    Tun = 1,
    Timer = 2,
    Signal = 3,
    Other = 255,
}

impl Tag {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Readiness mask: which kinds of I/O a source reports ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Interest(u8);

impl Interest {
    pub const EMPTY: Self = Self(0);
    pub const READABLE: Self = Self(1 << 0);
    pub const WRITABLE: Self = Self(1 << 1);

    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub fn is_readable(self) -> bool {
        self.contains(Self::READABLE)
    }

    pub fn is_writable(self) -> bool {
        self.contains(Self::WRITABLE)
    }

    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for Interest {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for Interest {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// A single readiness notification delivered by the reactor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    pub token: Token,
    pub readiness: Interest,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interest_bits_and_bitor() {
        let rw = Interest::READABLE | Interest::WRITABLE;
        assert!(rw.is_readable());
        assert!(rw.is_writable());
        assert!(rw.contains(Interest::READABLE));
        assert_eq!(rw.bits(), 0b11);
    }

    #[test]
    fn empty_interest_has_nothing() {
        let i = Interest::EMPTY;
        assert!(!i.is_readable());
        assert!(!i.is_writable());
    }

    #[test]
    fn tag_values_are_stable() {
        assert_eq!(Tag::Udp.as_u8(), 0);
        assert_eq!(Tag::Tun.as_u8(), 1);
        assert_eq!(Tag::Timer.as_u8(), 2);
        assert_eq!(Tag::Signal.as_u8(), 3);
        assert_eq!(Tag::Other.as_u8(), 255);
    }
}
