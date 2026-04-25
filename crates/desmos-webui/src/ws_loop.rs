//! WebSocket frame loops for stats and log streams.
//!
//! Called by the HTTP server's post-upgrade hook after a 101 response.
//! Each loop runs on the connection thread until the client disconnects
//! or the daemon shuts down.

use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;
use std::time::Instant;

use desmos_http::websocket::frame;
use desmos_http::websocket::frame::Frame;
use desmos_http::websocket::frame::Opcode;

pub fn handle_upgrade(stream: TcpStream, uri: &str) {
    if uri.contains("/ws/stats") {
        run_stats_loop(stream);
    } else if uri.contains("/ws/logs") {
        run_logs_loop(stream);
    }
}

fn is_shutdown() -> bool {
    desmos_core::daemon::try_context()
        .map(|ctx| ctx.tunnel_state() == desmos_core::daemon::TunnelState::Down)
        .unwrap_or(false)
}

fn run_stats_loop(mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let mut cursor: u64 = 0;
    let interval = Duration::from_millis(500);
    let mut last_send = Instant::now();

    loop {
        if is_shutdown() {
            break;
        }

        if last_send.elapsed() < interval {
            std::thread::sleep(Duration::from_millis(50));
            if check_client_close(&mut stream) {
                break;
            }
            continue;
        }
        last_send = Instant::now();

        let json = match desmos_core::daemon::try_context() {
            Some(ctx) => {
                let (new_cursor, items) = ctx.stats_bus.recv(cursor);
                cursor = new_cursor;
                if let Some(snap) = items.last() {
                    format!(
                        r#"{{"total_tx_bytes":{},"total_rx_bytes":{},"interfaces":[]}}"#,
                        snap.metrics.bytes_sent, snap.metrics.bytes_received
                    )
                } else {
                    r#"{"total_tx_bytes":0,"total_rx_bytes":0,"interfaces":[]}"#.to_string()
                }
            }
            None => r#"{"total_tx_bytes":0,"total_rx_bytes":0,"interfaces":[]}"#.to_string(),
        };

        if send_text_frame(&mut stream, &json).is_err() {
            break;
        }
    }

    let _ = send_close_frame(&mut stream);
}

fn run_logs_loop(mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let mut cursor: u64 = 0;

    loop {
        if is_shutdown() {
            break;
        }

        if check_client_close(&mut stream) {
            break;
        }

        if let Some(ctx) = desmos_core::daemon::try_context() {
            let (new_cursor, items) = ctx.log_bus.recv(cursor);
            cursor = new_cursor;
            for entry in &items {
                let json = format!(
                    r#"{{"level":"{}","target":"{}","message":"{}"}}"#,
                    entry.level.as_str(),
                    entry.target,
                    entry.msg
                );
                if send_text_frame(&mut stream, &json).is_err() {
                    return;
                }
            }
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    let _ = send_close_frame(&mut stream);
}

fn send_text_frame(stream: &mut TcpStream, text: &str) -> std::io::Result<()> {
    let f = Frame { fin: true, opcode: Opcode::Text, payload: text.as_bytes().to_vec() };
    let bytes = frame::encode_frame(&f);
    stream.write_all(&bytes)?;
    stream.flush()
}

fn send_close_frame(stream: &mut TcpStream) -> std::io::Result<()> {
    let f = Frame { fin: true, opcode: Opcode::Close, payload: Vec::new() };
    let bytes = frame::encode_frame(&f);
    stream.write_all(&bytes)?;
    stream.flush()
}

fn check_client_close(stream: &mut TcpStream) -> bool {
    let mut buf = [0u8; 2];
    match std::io::Read::read(stream, &mut buf) {
        Ok(0) => true,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => false,
        Err(_) => true,
        _ => false,
    }
}
