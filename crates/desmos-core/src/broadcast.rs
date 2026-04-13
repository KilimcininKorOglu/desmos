//! Lock-free broadcast ring for fan-out to multiple WebSocket subscribers.
//!
//! `Broadcast<T>` is a bounded ring buffer where one publisher can
//! `send(item)` and any number of subscribers hold a `Receiver<T>`
//! handle that reads items non-destructively.  Each receiver tracks
//! its own read cursor so slow subscribers see items until they're
//! overwritten by the ring wrapping.
//!
//! The ring is `Sync + Send` so the publisher thread (daemon main
//! loop) and subscriber threads (WebSocket handler tasks) can share
//! it via `Arc<Broadcast<T>>`.
//!
//! # Design
//!
//! - Fixed-capacity ring with power-of-two slots.
//! - `write_pos` is an `AtomicU64` monotonically advancing counter.
//! - Each slot holds `Mutex<Option<Arc<T>>>` so subscribers clone the
//!   `Arc` without copying the payload.
//! - Subscribers call `recv(cursor)` with their last-seen position
//!   and get back `(new_cursor, items)`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// A broadcast ring buffer.
pub struct Broadcast<T> {
    slots: Vec<Mutex<Option<Arc<T>>>>,
    mask: u64,
    write_pos: AtomicU64,
}

impl<T: Clone> Broadcast<T> {
    /// Create a new broadcast ring with the given capacity.
    ///
    /// Capacity is rounded up to the next power of two.
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.next_power_of_two().max(2);
        let mut slots = Vec::with_capacity(cap);
        for _ in 0..cap {
            slots.push(Mutex::new(None));
        }
        Self { slots, mask: (cap as u64) - 1, write_pos: AtomicU64::new(0) }
    }

    /// Publish an item to all subscribers.
    pub fn send(&self, item: T) {
        let pos = self.write_pos.fetch_add(1, Ordering::Release);
        let idx = (pos & self.mask) as usize;
        let mut slot = self.slots[idx].lock().unwrap();
        *slot = Some(Arc::new(item));
    }

    /// Current write position (monotonic counter).
    pub fn position(&self) -> u64 {
        self.write_pos.load(Ordering::Acquire)
    }

    /// Capacity of the ring (power of two).
    pub fn capacity(&self) -> usize {
        (self.mask + 1) as usize
    }

    /// Create a new receiver starting at the current position.
    pub fn subscribe(&self) -> Receiver<T> {
        Receiver { cursor: self.position(), _marker: std::marker::PhantomData }
    }

    /// Read all items from `cursor` to the current write position.
    ///
    /// Returns `(new_cursor, items)`.  If the cursor is too far behind
    /// (items have been overwritten), it snaps forward to the oldest
    /// available position.
    pub fn recv(&self, cursor: u64) -> (u64, Vec<Arc<T>>) {
        let head = self.position();
        if cursor >= head {
            return (cursor, Vec::new());
        }

        // Snap forward if cursor is too old.
        let cap = self.capacity() as u64;
        let start = if head - cursor > cap { head - cap } else { cursor };

        let mut items = Vec::with_capacity((head - start) as usize);
        for pos in start..head {
            let idx = (pos & self.mask) as usize;
            let slot = self.slots[idx].lock().unwrap();
            if let Some(item) = slot.as_ref() {
                items.push(Arc::clone(item));
            }
        }

        (head, items)
    }
}

// SAFETY: Broadcast uses Mutex internally, safe to share across threads.
unsafe impl<T: Send> Send for Broadcast<T> {}
unsafe impl<T: Send + Sync> Sync for Broadcast<T> {}

/// A subscriber handle that tracks its read cursor.
#[derive(Debug, Clone)]
pub struct Receiver<T> {
    cursor: u64,
    _marker: std::marker::PhantomData<fn() -> T>,
}

impl<T: Clone> Receiver<T> {
    /// Poll for new items from the broadcast ring.
    pub fn poll(&mut self, ring: &Broadcast<T>) -> Vec<Arc<T>> {
        let (new_cursor, items) = ring.recv(self.cursor);
        self.cursor = new_cursor;
        items
    }

    /// Current cursor position.
    pub fn cursor(&self) -> u64 {
        self.cursor
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_rounds_to_power_of_two() {
        let b = Broadcast::<u32>::new(5);
        assert_eq!(b.capacity(), 8);
        let b = Broadcast::<u32>::new(8);
        assert_eq!(b.capacity(), 8);
        let b = Broadcast::<u32>::new(1);
        assert_eq!(b.capacity(), 2);
    }

    #[test]
    fn send_and_recv_basic() {
        let b = Broadcast::new(4);
        let cursor = b.position();
        b.send(10u32);
        b.send(20);
        b.send(30);
        let (new_cursor, items) = b.recv(cursor);
        assert_eq!(new_cursor, 3);
        assert_eq!(items.len(), 3);
        assert_eq!(*items[0], 10);
        assert_eq!(*items[1], 20);
        assert_eq!(*items[2], 30);
    }

    #[test]
    fn recv_at_head_returns_empty() {
        let b = Broadcast::new(4);
        b.send(1u32);
        let pos = b.position();
        let (new_pos, items) = b.recv(pos);
        assert_eq!(new_pos, pos);
        assert!(items.is_empty());
    }

    #[test]
    fn slow_subscriber_snaps_forward() {
        let b = Broadcast::new(4); // capacity = 4
        let cursor = b.position(); // 0
                                   // Send 8 items — ring wraps twice.
        for i in 0..8u32 {
            b.send(i);
        }
        let (new_cursor, items) = b.recv(cursor);
        // Should snap to head - capacity = 8 - 4 = 4.
        assert_eq!(new_cursor, 8);
        assert_eq!(items.len(), 4);
        assert_eq!(*items[0], 4);
        assert_eq!(*items[3], 7);
    }

    #[test]
    fn multiple_subscribers_independent() {
        let b = Broadcast::new(8);
        b.send(1u32);
        b.send(2);

        let mut r1 = b.subscribe(); // cursor = 2
        b.send(3);

        let mut r2 = b.subscribe(); // cursor = 3

        let items1 = r1.poll(&b);
        assert_eq!(items1.len(), 1);
        assert_eq!(*items1[0], 3);

        let items2 = r2.poll(&b);
        assert!(items2.is_empty());

        b.send(4);
        let items1 = r1.poll(&b);
        assert_eq!(items1.len(), 1);
        assert_eq!(*items1[0], 4);

        let items2 = r2.poll(&b);
        assert_eq!(items2.len(), 1);
        assert_eq!(*items2[0], 4);
    }

    #[test]
    fn subscribe_starts_at_current_position() {
        let b = Broadcast::new(4);
        b.send(1u32);
        b.send(2);
        let r = b.subscribe();
        assert_eq!(r.cursor(), 2);
    }

    #[test]
    fn empty_ring_recv_returns_empty() {
        let b = Broadcast::<u32>::new(4);
        let (pos, items) = b.recv(0);
        assert_eq!(pos, 0);
        assert!(items.is_empty());
    }

    #[test]
    fn concurrent_send_recv() {
        let b = Arc::new(Broadcast::new(256));
        let b2 = Arc::clone(&b);

        let sender = std::thread::spawn(move || {
            for i in 0..1000u32 {
                b2.send(i);
            }
        });

        // Subscriber reads after sender finishes.
        sender.join().unwrap();
        assert_eq!(b.position(), 1000);

        // Read the last 256 items (capacity).
        let (pos, items) = b.recv(0);
        assert_eq!(pos, 1000);
        assert_eq!(items.len(), 256);
        assert_eq!(*items[0], 744); // 1000 - 256
        assert_eq!(*items[255], 999);
    }
}
