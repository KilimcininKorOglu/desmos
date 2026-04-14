//! Build script for the Desmos Web UI.
//!
//! When the `embed-frontend` feature is enabled:
//! 1. Runs `npm ci && npm run build` in `web/` (only if `web/dist/`
//!    is missing or `web/src/` is newer).
//! 2. Scans `web/dist/` for all files.
//! 3. Generates `embedded_files.rs` in `OUT_DIR` with `include_bytes!`
//!    entries for every file, plus a lookup function.
//!
//! When `embed-frontend` is disabled, generates an empty file list
//! so the crate compiles without Node.js.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let web_dir = PathBuf::from(&manifest_dir).join("web");
    let dist_dir = web_dir.join("dist");

    #[cfg(feature = "embed-frontend")]
    {
        // Rerun if any source file changes.
        println!("cargo:rerun-if-changed=web/src/");
        println!("cargo:rerun-if-changed=web/package.json");
        println!("cargo:rerun-if-changed=web/vite.config.ts");
        println!("cargo:rerun-if-changed=web/tsconfig.json");
        println!("cargo:rerun-if-changed=web/index.html");

        if needs_rebuild(&web_dir, &dist_dir) {
            run_npm_build(&web_dir);
        }

        assert!(dist_dir.exists(), "web/dist/ not found after build. Check npm/vite output.");

        generate_embed_file(&dist_dir, &out_dir);
    }

    #[cfg(not(feature = "embed-frontend"))]
    {
        let _ = (&web_dir, &dist_dir);
        generate_empty_embed(&out_dir);
    }
}

/// Check if we need to rebuild the frontend.
///
/// Returns true if `dist/` doesn't exist or if any source file is
/// newer than `dist/index.html`.
#[cfg(feature = "embed-frontend")]
fn needs_rebuild(web_dir: &Path, dist_dir: &Path) -> bool {
    let index = dist_dir.join("index.html");
    if !index.exists() {
        return true;
    }

    let dist_mtime = match fs::metadata(&index).and_then(|m| m.modified()) {
        Ok(t) => t,
        Err(_) => return true,
    };

    // Check if any source file is newer.
    let src_dir = web_dir.join("src");
    if let Ok(entries) = fs::read_dir(src_dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if let Ok(mtime) = meta.modified() {
                    if mtime > dist_mtime {
                        return true;
                    }
                }
            }
        }
    }

    // Check package.json.
    if let Ok(meta) = fs::metadata(web_dir.join("package.json")) {
        if let Ok(mtime) = meta.modified() {
            if mtime > dist_mtime {
                return true;
            }
        }
    }

    false
}

/// Run `npm ci && npm run build` in the web directory.
#[cfg(feature = "embed-frontend")]
fn run_npm_build(web_dir: &Path) {
    eprintln!("desmos-webui build.rs: running npm ci ...");

    let npm = if cfg!(windows) { "npm.cmd" } else { "npm" };

    let status = Command::new(npm)
        .args(["ci"])
        .current_dir(web_dir)
        .status()
        .expect("failed to run npm ci — is Node.js installed?");

    assert!(status.success(), "npm ci failed with {status}");

    eprintln!("desmos-webui build.rs: running npm run build ...");

    let status = Command::new(npm)
        .args(["run", "build"])
        .current_dir(web_dir)
        .status()
        .expect("failed to run npm run build");

    assert!(status.success(), "npm run build failed with {status}");
}

/// Scan `dist/` and generate `embedded_files.rs`.
#[cfg(feature = "embed-frontend")]
fn generate_embed_file(dist_dir: &Path, out_dir: &str) {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    collect_files(dist_dir, dist_dir, &mut files);
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let out_path = PathBuf::from(out_dir).join("embedded_files.rs");
    let mut f = fs::File::create(out_path).unwrap();

    writeln!(f, "/// Number of embedded frontend files.").unwrap();
    writeln!(f, "pub const EMBEDDED_FILE_COUNT: usize = {};", files.len()).unwrap();
    writeln!(f).unwrap();

    // Generate static byte arrays.
    for (i, (_web_path, disk_path)) in files.iter().enumerate() {
        let abs = fs::canonicalize(disk_path).unwrap();
        writeln!(f, "static FILE_{i}_DATA: &[u8] = include_bytes!(\"{}\");", abs.display())
            .unwrap();
    }

    writeln!(f).unwrap();
    writeln!(f, "/// Lookup an embedded file by its web path.").unwrap();
    writeln!(f, "///").unwrap();
    writeln!(f, "/// Returns `(content_type, bytes)` on match.").unwrap();
    writeln!(f, "pub fn lookup(path: &str) -> Option<(&'static str, &'static [u8])> {{").unwrap();
    writeln!(f, "    match path {{").unwrap();

    for (i, (web_path, disk_path)) in files.iter().enumerate() {
        let ext = disk_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let mime = mime_for_ext(ext);
        writeln!(f, "        \"/{web_path}\" => Some((\"{mime}\", FILE_{i}_DATA)),").unwrap();
    }

    // Also serve index.html for "/" path.
    if let Some((i, _)) = files.iter().enumerate().find(|(_, (p, _))| p == "index.html") {
        writeln!(f, "        \"/\" => Some((\"text/html; charset=utf-8\", FILE_{i}_DATA)),")
            .unwrap();
    }

    writeln!(f, "        _ => None,").unwrap();
    writeln!(f, "    }}").unwrap();
    writeln!(f, "}}").unwrap();
}

/// Recursively collect all files under `root` with their web-relative paths.
#[cfg(feature = "embed-frontend")]
fn collect_files(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, out);
        } else {
            let rel = path.strip_prefix(root).unwrap();
            let web_path = rel.to_string_lossy().replace('\\', "/");
            out.push((web_path, path));
        }
    }
}

/// Map file extension to MIME type.
fn mime_for_ext(ext: &str) -> &'static str {
    match ext {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "map" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Generate an empty embed file when the frontend feature is disabled.
#[cfg(not(feature = "embed-frontend"))]
fn generate_empty_embed(out_dir: &str) {
    let out_path = PathBuf::from(out_dir).join("embedded_files.rs");
    let mut f = fs::File::create(out_path).unwrap();

    writeln!(f, "/// Number of embedded frontend files.").unwrap();
    writeln!(f, "pub const EMBEDDED_FILE_COUNT: usize = 0;").unwrap();
    writeln!(f).unwrap();
    writeln!(f, "/// Lookup an embedded file by its web path.").unwrap();
    writeln!(f, "///").unwrap();
    writeln!(f, "/// Always returns `None` when the frontend is not embedded.").unwrap();
    writeln!(f, "pub fn lookup(_path: &str) -> Option<(&'static str, &'static [u8])> {{").unwrap();
    writeln!(f, "    None").unwrap();
    writeln!(f, "}}").unwrap();
}
