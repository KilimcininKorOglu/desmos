//! IPC client: connects to the daemon's Unix domain socket and
//! sends a JSON-line command, returning the response string.

#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::io::BufRead;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
const DEFAULT_PATH: &str = "/var/run/desmos.sock";

#[cfg(unix)]
pub fn send_command(command: &str) -> Result<String, String> {
    send_raw(DEFAULT_PATH, &format!(r#"{{"command":"{command}"}}"#))
}

#[cfg(unix)]
pub fn send_command_with_json(json_line: &str) -> Result<String, String> {
    send_raw(DEFAULT_PATH, json_line)
}

#[cfg(unix)]
pub fn send_command_to(path: &str, command: &str) -> Result<String, String> {
    send_raw(path, &format!(r#"{{"command":"{command}"}}"#))
}

#[cfg(unix)]
fn send_raw(path: &str, json_line: &str) -> Result<String, String> {
    let stream = UnixStream::connect(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound || e.kind() == io::ErrorKind::ConnectionRefused {
            "daemon not running — start with `desmos up`".to_string()
        } else {
            format!("IPC connect error: {e}")
        }
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("IPC timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("IPC timeout: {e}"))?;

    let mut writer = io::BufWriter::new(&stream);
    writeln!(writer, "{json_line}").map_err(|e| format!("IPC write: {e}"))?;
    writer.flush().map_err(|e| format!("IPC flush: {e}"))?;

    let reader = io::BufReader::new(&stream);
    let line = reader
        .lines()
        .next()
        .ok_or_else(|| "no response from daemon".to_string())?
        .map_err(|e| format!("IPC read: {e}"))?;

    Ok(line)
}

#[cfg(not(unix))]
pub fn send_command(_command: &str) -> Result<String, String> {
    Err("IPC not supported on this platform".to_string())
}

#[cfg(not(unix))]
pub fn send_command_with_json(_json_line: &str) -> Result<String, String> {
    Err("IPC not supported on this platform".to_string())
}
