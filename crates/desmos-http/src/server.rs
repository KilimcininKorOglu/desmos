//! HTTP/1.1 server: TCP listener + connection loop.
//!
//! The server binds to an address, accepts connections, reads
//! requests, and dispatches them to a user-provided handler.
//! It is single-threaded and uses blocking I/O with a configurable
//! read timeout — reactor integration (epoll/kqueue) is wired in
//! a later task.
//!
//! # Connection handling
//!
//! Each accepted connection is processed inline.  The server reads
//! the full request (headers + body), calls the handler, writes the
//! response, and optionally keeps the connection alive for pipelining.
//!
//! # Limits
//!
//! - Max header section: 64 KiB
//! - Max body: 1 MiB (enforced by `request::MAX_BODY_SIZE`)
//! - Max concurrent connections: configurable (default 100)
//! - Read timeout: 30 seconds

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::errors::{HttpError, StatusCode};
use crate::request::{self, Request};
use crate::response::Response;

/// Maximum size of the header section read buffer (64 KiB).
const MAX_HEADER_BUF: usize = 64 * 1024;

/// Default read timeout for client connections.
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Read timeout for client connections.
    pub read_timeout: Duration,
    /// Maximum number of concurrent connections (advisory).
    pub max_connections: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self { read_timeout: DEFAULT_READ_TIMEOUT, max_connections: 100 }
    }
}

/// A handler function that processes an HTTP request and returns a response.
pub type Handler = fn(&Request<'_>) -> Response;

/// A minimal HTTP/1.1 server.
pub struct HttpServer {
    listener: TcpListener,
    config: ServerConfig,
    handler: Handler,
}

impl HttpServer {
    /// Bind to the given address and create the server.
    pub fn bind<A: ToSocketAddrs>(addr: A, handler: Handler) -> io::Result<Self> {
        Self::bind_with_config(addr, handler, ServerConfig::default())
    }

    /// Bind with a custom configuration.
    pub fn bind_with_config<A: ToSocketAddrs>(
        addr: A,
        handler: Handler,
        config: ServerConfig,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(false)?;
        Ok(Self { listener, config, handler })
    }

    /// Return the local address the server is bound to.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Run the server, accepting and handling connections.
    ///
    /// This method blocks indefinitely. It processes one connection
    /// at a time in the current thread. For concurrent handling,
    /// wrap in a thread pool or integrate with the reactor (Task 51+).
    pub fn run(&self) -> io::Result<()> {
        eprintln!("[http] listening on {}", self.listener.local_addr()?);

        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    if let Err(e) = self.handle_connection(stream) {
                        eprintln!("[http] connection error: {e}");
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => eprintln!("[http] accept error: {e}"),
            }
        }
        Ok(())
    }

    /// Accept a single connection and return. Used for testing.
    pub fn accept_one(&self) -> io::Result<()> {
        let (stream, _addr) = self.listener.accept()?;
        self.handle_connection(stream)
    }

    /// Handle a single TCP connection (possibly with keep-alive).
    fn handle_connection(&self, mut stream: TcpStream) -> io::Result<()> {
        stream.set_read_timeout(Some(self.config.read_timeout))?;
        stream.set_nodelay(true)?;

        loop {
            match self.read_and_respond(&mut stream) {
                Ok(keep_alive) => {
                    if !keep_alive {
                        break;
                    }
                }
                Err(HttpError::Timeout) | Err(HttpError::ConnectionClosed) => break,
                Err(e) => {
                    let resp = error_to_response(&e);
                    let _ = stream.write_all(&resp.to_bytes());
                    break;
                }
            }
        }
        Ok(())
    }

    /// Read one request, dispatch to the handler, write the response.
    /// Returns `true` if keep-alive should continue.
    fn read_and_respond(&self, stream: &mut TcpStream) -> Result<bool, HttpError> {
        // Read the header section into a buffer.
        let mut buf = vec![0u8; 4096];
        let mut filled = 0;

        loop {
            if filled >= MAX_HEADER_BUF {
                return Err(HttpError::HeaderTooLong);
            }

            match stream.read(&mut buf[filled..]) {
                Ok(0) => return Err(HttpError::ConnectionClosed),
                Ok(n) => {
                    filled += n;
                    // Check for end of headers.
                    if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    // Grow buffer if needed.
                    if filled == buf.len() {
                        buf.resize(buf.len() * 2, 0);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Err(HttpError::Timeout);
                }
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                    return Err(HttpError::Timeout);
                }
                Err(e) => return Err(HttpError::Io(e)),
            }
        }

        // We have the full header section. Need to also have the body
        // if Content-Length is present. Read more if needed.
        let header_str = std::str::from_utf8(&buf[..filled])
            .map_err(|_| HttpError::BadRequest("non-UTF-8 in headers"))?;

        // Peek at Content-Length to know how much more to read.
        if let Some(cl_start) = header_str.to_ascii_lowercase().find("content-length:") {
            let after = &header_str[cl_start + 15..];
            if let Some(end) = after.find("\r\n") {
                if let Ok(content_len) = after[..end].trim().parse::<usize>() {
                    if content_len > request::MAX_BODY_SIZE {
                        return Err(HttpError::PayloadTooLarge);
                    }
                    let header_end = header_str.find("\r\n\r\n").unwrap() + 4;
                    let total_needed = header_end + content_len;
                    while filled < total_needed {
                        if buf.len() < total_needed {
                            buf.resize(total_needed, 0);
                        }
                        match stream.read(&mut buf[filled..total_needed]) {
                            Ok(0) => return Err(HttpError::ConnectionClosed),
                            Ok(n) => filled += n,
                            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                                return Err(HttpError::Timeout);
                            }
                            Err(e) => return Err(HttpError::Io(e)),
                        }
                    }
                }
            }
        }

        let full_str = std::str::from_utf8(&buf[..filled])
            .map_err(|_| HttpError::BadRequest("non-UTF-8 in request"))?;

        let (req, _consumed) = request::parse_request(full_str)?;

        let keep_alive = req.headers.is_keep_alive() && !req.headers.is_close();

        // Dispatch to handler.
        let response = (self.handler)(&req);

        // Write response.
        stream.write_all(&response.to_bytes()).map_err(HttpError::Io)?;
        stream.flush().map_err(HttpError::Io)?;

        Ok(keep_alive)
    }
}

/// Map an `HttpError` to an appropriate error response.
fn error_to_response(err: &HttpError) -> Response {
    match err {
        HttpError::BadRequest(msg) => Response::bad_request(msg),
        HttpError::PayloadTooLarge => {
            let mut r = Response::new(StatusCode::PAYLOAD_TOO_LARGE);
            r.body_text("Payload Too Large");
            r
        }
        HttpError::UriTooLong => {
            let mut r = Response::new(StatusCode::URI_TOO_LONG);
            r.body_text("URI Too Long");
            r
        }
        HttpError::TooManyHeaders | HttpError::HeaderTooLong => {
            Response::bad_request("header limits exceeded")
        }
        _ => Response::internal_error(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::thread;

    fn hello_handler(_req: &Request<'_>) -> Response {
        let mut r = Response::ok();
        r.body_text("Hello, World!");
        r
    }

    #[test]
    fn server_serves_get_200() {
        let server = HttpServer::bind("127.0.0.1:0", hello_handler).unwrap();
        let addr = server.local_addr().unwrap();

        let handle = thread::spawn(move || {
            server.accept_one().unwrap();
        });

        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();

        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Length: 13\r\n"));
        assert!(response.ends_with("Hello, World!"));

        handle.join().unwrap();
    }

    #[test]
    fn server_handles_post_with_body() {
        fn echo_handler(req: &Request<'_>) -> Response {
            let mut r = Response::ok();
            r.body_raw("application/octet-stream", req.body.clone());
            r
        }

        let server = HttpServer::bind("127.0.0.1:0", echo_handler).unwrap();
        let addr = server.local_addr().unwrap();

        let handle = thread::spawn(move || {
            server.accept_one().unwrap();
        });

        let body = b"test body data";
        let mut stream = TcpStream::connect(addr).unwrap();
        write!(
            stream,
            "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();

        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with("test body data"));

        handle.join().unwrap();
    }

    #[test]
    fn server_returns_error_for_bad_request() {
        let server = HttpServer::bind("127.0.0.1:0", hello_handler).unwrap();
        let addr = server.local_addr().unwrap();

        let handle = thread::spawn(move || {
            server.accept_one().unwrap();
        });

        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(b"INVALID REQUEST\r\n\r\n").unwrap();

        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();

        assert!(response.contains("400 Bad Request") || response.contains("HTTP/1.1 400"));

        handle.join().unwrap();
    }

    #[test]
    fn config_defaults() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.read_timeout, Duration::from_secs(30));
        assert_eq!(cfg.max_connections, 100);
    }

    #[test]
    fn error_to_response_maps_correctly() {
        let r = error_to_response(&HttpError::PayloadTooLarge);
        assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);

        let r = error_to_response(&HttpError::BadRequest("test"));
        assert_eq!(r.status, StatusCode::BAD_REQUEST);

        let r = error_to_response(&HttpError::UriTooLong);
        assert_eq!(r.status, StatusCode::URI_TOO_LONG);
    }
}
