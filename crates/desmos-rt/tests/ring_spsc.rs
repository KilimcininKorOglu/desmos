//! Two-thread stress test for `SpscRing`. Pushes 1 000 000 sequential
//! u32 values on the producer thread and verifies they come back in
//! FIFO order on the consumer thread.
//!
//! Acceptance for Task 9:
//! - 1M items through the ring with order preserved
//! - consumer observes exactly the produced sequence with no gaps / dupes

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;

use desmos_rt::SpscRing;

const N: u32 = 1_000_000;

#[test]
fn stress_one_million_items_preserves_order() {
    let (producer, consumer) = SpscRing::<u32>::new_split(1024);

    let sent = Arc::new(AtomicUsize::new(0));
    let sent_pr = Arc::clone(&sent);

    let producer_thread = thread::spawn(move || {
        for i in 0..N {
            loop {
                if producer.try_push(i).is_ok() {
                    sent_pr.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                std::hint::spin_loop();
            }
        }
    });

    let consumer_thread = thread::spawn(move || {
        let mut expected = 0u32;
        while expected < N {
            match consumer.try_pop() {
                Some(v) => {
                    assert_eq!(v, expected, "out-of-order item at index {expected}");
                    expected += 1;
                }
                None => std::hint::spin_loop(),
            }
        }
    });

    producer_thread.join().expect("producer panicked");
    consumer_thread.join().expect("consumer panicked");
    assert_eq!(sent.load(Ordering::Relaxed), N as usize);
}

#[test]
fn stress_small_capacity_forces_backpressure() {
    // Capacity 2 → producer will be blocked in try_push frequently, exercising
    // the full/empty transition paths under contention.
    let (producer, consumer) = SpscRing::<u32>::new_split(2);

    let producer_thread = thread::spawn(move || {
        for i in 0..100_000u32 {
            loop {
                if producer.try_push(i).is_ok() {
                    break;
                }
                std::hint::spin_loop();
            }
        }
    });

    let consumer_thread = thread::spawn(move || {
        let mut expected = 0u32;
        while expected < 100_000 {
            if let Some(v) = consumer.try_pop() {
                assert_eq!(v, expected);
                expected += 1;
            } else {
                std::hint::spin_loop();
            }
        }
    });

    producer_thread.join().unwrap();
    consumer_thread.join().unwrap();
}
