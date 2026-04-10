//! Log sink trait and built-in stderr implementation.

use std::io;
use std::io::BufWriter;
use std::io::Write;

use super::Entry;

pub trait Sink: Send + Sync {
    fn write(&mut self, entry: &Entry);
}

pub struct StderrSink {
    inner: BufWriter<io::Stderr>,
}

impl StderrSink {
    pub fn new() -> Self {
        Self { inner: BufWriter::new(io::stderr()) }
    }
}

impl Default for StderrSink {
    fn default() -> Self {
        Self::new()
    }
}

impl Sink for StderrSink {
    fn write(&mut self, entry: &Entry) {
        let _ = writeln!(self.inner, "{entry}");
        let _ = self.inner.flush();
    }
}

#[cfg(test)]
pub struct CapturingSink {
    pub entries: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

#[cfg(test)]
impl CapturingSink {
    pub fn new() -> Self {
        Self { entries: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())) }
    }
}

#[cfg(test)]
impl Default for CapturingSink {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl Sink for CapturingSink {
    fn write(&mut self, entry: &Entry) {
        self.entries.lock().unwrap().push(entry.to_string());
    }
}
