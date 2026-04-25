//! Broadcast sink: publishes every log entry to a `Broadcast<Entry>`
//! ring so WebSocket subscribers can tail the log stream.

use std::sync::Arc;

use super::sink::Sink;
use super::Entry;
use crate::broadcast::Broadcast;

pub struct BroadcastSink {
    bus: Arc<Broadcast<Entry>>,
}

impl BroadcastSink {
    pub fn new(bus: Arc<Broadcast<Entry>>) -> Self {
        Self { bus }
    }
}

impl Sink for BroadcastSink {
    fn write(&mut self, entry: &Entry) {
        self.bus.send(entry.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::Level;

    #[test]
    fn entries_appear_in_broadcast() {
        let bus = Arc::new(Broadcast::new(16));
        let mut sink = BroadcastSink::new(Arc::clone(&bus));

        let entry = Entry {
            level: Level::Info,
            target: "test",
            msg: "hello",
            fields: vec![("key", "value".to_string())],
        };
        sink.write(&entry);

        let (cursor, items) = bus.recv(0);
        assert_eq!(cursor, 1);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].msg, "hello");
    }

    #[test]
    fn multiple_entries_accumulate() {
        let bus = Arc::new(Broadcast::new(16));
        let mut sink = BroadcastSink::new(Arc::clone(&bus));

        for i in 0..5 {
            let entry = Entry {
                level: Level::Debug,
                target: "test",
                msg: "tick",
                fields: vec![("i", format!("{i}"))],
            };
            sink.write(&entry);
        }

        let (cursor, items) = bus.recv(0);
        assert_eq!(cursor, 5);
        assert_eq!(items.len(), 5);
    }
}
