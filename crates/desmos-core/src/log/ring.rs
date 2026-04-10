//! Bounded ring buffer holding recent log entries for Web UI tailing.

use std::collections::VecDeque;

use super::Entry;

pub struct LogRing {
    capacity: usize,
    buf: VecDeque<Entry>,
}

impl LogRing {
    pub fn with_capacity(capacity: usize) -> Self {
        Self { capacity, buf: VecDeque::with_capacity(capacity) }
    }

    pub fn push(&mut self, entry: Entry) {
        if self.buf.len() == self.capacity {
            self.buf.pop_front();
        }
        self.buf.push_back(entry);
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn snapshot(&self) -> Vec<Entry> {
        self.buf.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::Entry;
    use crate::log::Level;

    fn make(i: usize) -> Entry {
        Entry { level: Level::Info, target: "t", msg: "m", fields: vec![("seq", i.to_string())] }
    }

    #[test]
    fn wraps_at_capacity_and_evicts_oldest() {
        let mut r = LogRing::with_capacity(3);
        for i in 0..5 {
            r.push(make(i));
        }
        assert_eq!(r.len(), 3);
        let snap = r.snapshot();
        assert_eq!(snap[0].fields[0].1, "2");
        assert_eq!(snap[1].fields[0].1, "3");
        assert_eq!(snap[2].fields[0].1, "4");
    }

    #[test]
    fn empty_ring_snapshots_empty_vec() {
        let r = LogRing::with_capacity(10);
        assert!(r.is_empty());
        assert_eq!(r.snapshot().len(), 0);
        assert_eq!(r.capacity(), 10);
    }
}
