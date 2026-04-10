//! Single-producer / single-consumer lock-free ring buffer.
//!
//! Used as the primary conduit between packet pipeline stages
//! (`IMPLEMENTATION.md §2.6`). The ring is bounded, power-of-two-sized,
//! and uses monotonic 64-bit counters: the item count is simply
//! `tail - head`. Full = `count == capacity`, empty = `count == 0`.
//!
//! # Concurrency
//!
//! - Exactly **one** producer owns [`Producer`]; exactly **one** consumer
//!   owns [`Consumer`]. Both are created via [`SpscRing::new_split`].
//! - The producer has exclusive write access to the slot at `tail & mask`
//!   until it publishes via a `Release` store to `tail`.
//! - The consumer has exclusive write access to the slot at `head & mask`
//!   until it publishes via a `Release` store to `head`.
//! - `head` and `tail` live in their own 64-byte cache lines so the two
//!   threads never cause false sharing on the same line.
//!
//! # Safety audit
//!
//! Every `unsafe` block is prefixed with a SAFETY comment describing the
//! exact invariant it relies on. This crate is the only one in the
//! workspace with `unsafe` code; review concentration lives here.

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// 64-byte aligned wrapper so independent atomics do not share a cache line.
#[repr(align(64))]
struct CachePadded<T>(T);

pub struct SpscRing<T> {
    buffer: Box<[UnsafeCell<MaybeUninit<T>>]>,
    mask: usize,
    head: CachePadded<AtomicUsize>,
    tail: CachePadded<AtomicUsize>,
}

// SAFETY: access to the internal buffer is partitioned so that at any time
// the producer is the sole writer of slot `tail & mask` and the consumer is
// the sole reader of slot `head & mask`. All hand-offs go through atomic
// Release/Acquire on `head` and `tail`, so no data race occurs as long as
// only the single owning `Producer` / `Consumer` pair touches the ring.
unsafe impl<T: Send> Send for SpscRing<T> {}
unsafe impl<T: Send> Sync for SpscRing<T> {}

impl<T> SpscRing<T> {
    /// Allocate a ring with `capacity` slots. `capacity` must be a non-zero
    /// power of two so the index wrap becomes a bitmask.
    ///
    /// # Panics
    /// Panics if `capacity` is zero or not a power of two.
    pub fn new_split(capacity: usize) -> (Producer<T>, Consumer<T>) {
        assert!(capacity > 0, "SpscRing capacity must be non-zero");
        assert!(
            capacity.is_power_of_two(),
            "SpscRing capacity must be a power of two (got {capacity})"
        );
        let mut slots: Vec<UnsafeCell<MaybeUninit<T>>> = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(UnsafeCell::new(MaybeUninit::uninit()));
        }
        let ring = Arc::new(Self {
            buffer: slots.into_boxed_slice(),
            mask: capacity - 1,
            head: CachePadded(AtomicUsize::new(0)),
            tail: CachePadded(AtomicUsize::new(0)),
        });
        (Producer { ring: Arc::clone(&ring) }, Consumer { ring })
    }

    pub fn capacity(&self) -> usize {
        self.mask + 1
    }
}

impl<T> Drop for SpscRing<T> {
    fn drop(&mut self) {
        // By the time this Drop runs, both Arc handles (Producer and
        // Consumer) are gone, so we have exclusive access. Walk [head, tail)
        // and drop every initialised slot.
        let head = self.head.0.load(Ordering::Relaxed);
        let tail = self.tail.0.load(Ordering::Relaxed);
        let mut cur = head;
        while cur != tail {
            // SAFETY: slot was initialised by a `try_push` whose Release
            // store was observed by the consumer, and has not yet been
            // consumed (otherwise head would be past it). No other thread
            // can touch the slot because both Producer and Consumer are
            // dropped.
            unsafe {
                (*self.buffer[cur & self.mask].get()).assume_init_drop();
            }
            cur = cur.wrapping_add(1);
        }
    }
}

/// Sending side of an [`SpscRing`]. Must stay on a single producer thread.
pub struct Producer<T> {
    ring: Arc<SpscRing<T>>,
}

/// Receiving side of an [`SpscRing`]. Must stay on a single consumer thread.
pub struct Consumer<T> {
    ring: Arc<SpscRing<T>>,
}

impl<T> Producer<T> {
    /// Attempt to push `value`. Returns `Err(value)` if the ring is full.
    pub fn try_push(&self, value: T) -> Result<(), T> {
        // We are the sole writer of `tail` so a Relaxed load is fine.
        let tail = self.ring.tail.0.load(Ordering::Relaxed);
        // Acquire matches the consumer's Release store on `head`.
        let head = self.ring.head.0.load(Ordering::Acquire);
        if tail.wrapping_sub(head) == self.ring.capacity() {
            return Err(value);
        }
        let idx = tail & self.ring.mask;
        // SAFETY: slot `idx` is owned by the producer until we publish via
        // the Release store to `tail` below. Only our thread writes here.
        unsafe {
            (*self.ring.buffer[idx].get()).write(value);
        }
        // Release so the consumer's Acquire load on `tail` observes the
        // slot write above.
        self.ring.tail.0.store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    pub fn capacity(&self) -> usize {
        self.ring.capacity()
    }

    /// Approximate current length, usable only for metrics. The consumer may
    /// advance `head` between the two loads, so the returned value is a
    /// lower bound on the true queue length at any later point.
    pub fn len(&self) -> usize {
        let tail = self.ring.tail.0.load(Ordering::Relaxed);
        let head = self.ring.head.0.load(Ordering::Relaxed);
        tail.wrapping_sub(head)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> Consumer<T> {
    /// Attempt to pop one item. Returns `None` if the ring is empty.
    pub fn try_pop(&self) -> Option<T> {
        // Sole writer of `head`, Relaxed is fine.
        let head = self.ring.head.0.load(Ordering::Relaxed);
        // Acquire matches the producer's Release store on `tail` that
        // published the slot at `head & mask`.
        let tail = self.ring.tail.0.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let idx = head & self.ring.mask;
        // SAFETY: the slot at `idx` was initialised by a `try_push` that
        // has Released on `tail`, which we Acquired above. The slot is
        // ours until we publish via the Release store on `head` below;
        // the producer cannot overwrite it yet because the ring is not
        // full until we advance `head`.
        let value = unsafe { (*self.ring.buffer[idx].get()).assume_init_read() };
        self.ring.head.0.store(head.wrapping_add(1), Ordering::Release);
        Some(value)
    }

    pub fn capacity(&self) -> usize {
        self.ring.capacity()
    }

    /// See [`Producer::len`] — same caveat.
    pub fn len(&self) -> usize {
        let tail = self.ring.tail.0.load(Ordering::Relaxed);
        let head = self.ring.head.0.load(Ordering::Relaxed);
        tail.wrapping_sub(head)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_pop_single_item() {
        let (p, c) = SpscRing::new_split(4);
        assert!(c.try_pop().is_none());
        p.try_push(42u32).unwrap();
        assert_eq!(c.try_pop(), Some(42));
        assert!(c.try_pop().is_none());
    }

    #[test]
    fn full_ring_rejects_push() {
        let (p, c) = SpscRing::new_split(2);
        p.try_push(1u32).unwrap();
        p.try_push(2u32).unwrap();
        assert_eq!(p.try_push(3u32), Err(3));
        assert_eq!(c.try_pop(), Some(1));
        p.try_push(3u32).unwrap();
        assert_eq!(c.try_pop(), Some(2));
        assert_eq!(c.try_pop(), Some(3));
    }

    #[test]
    fn capacity_is_power_of_two() {
        let (p, _c) = SpscRing::<u8>::new_split(16);
        assert_eq!(p.capacity(), 16);
    }

    #[test]
    #[should_panic(expected = "power of two")]
    fn non_power_of_two_capacity_panics() {
        let _ = SpscRing::<u8>::new_split(3);
    }

    #[test]
    #[should_panic(expected = "non-zero")]
    fn zero_capacity_panics() {
        let _ = SpscRing::<u8>::new_split(0);
    }

    #[test]
    fn drop_runs_for_unconsumed_items() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::atomic::Ordering;
        use std::sync::Arc;

        struct CountOnDrop(Arc<AtomicUsize>);
        impl Drop for CountOnDrop {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let counter = Arc::new(AtomicUsize::new(0));
        {
            let (p, _c) = SpscRing::new_split(4);
            for _ in 0..3 {
                assert!(p.try_push(CountOnDrop(Arc::clone(&counter))).is_ok());
            }
            // producer and consumer drop here, which drops the Arc<SpscRing>
        }
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn fifo_order_preserved_single_thread() {
        let (p, c) = SpscRing::new_split(8);
        for i in 0..8u32 {
            p.try_push(i).unwrap();
        }
        for i in 0..8u32 {
            assert_eq!(c.try_pop(), Some(i));
        }
    }

    #[test]
    fn len_reports_count() {
        let (p, c) = SpscRing::new_split(4);
        assert_eq!(p.len(), 0);
        p.try_push(1u32).unwrap();
        p.try_push(2u32).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(c.len(), 2);
        c.try_pop().unwrap();
        assert_eq!(c.len(), 1);
    }
}
