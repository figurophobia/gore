//! Small HTTP helpers shared by the parts of gore that fetch things from the network
//! (GDRE Tools, Godot editors, GDExtension plugin binaries).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Where gore keeps the things it downloads (`~/.local/share/gore`).
pub fn data_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("GORE_HOME") {
        return PathBuf::from(dir);
    }
    if cfg!(windows) {
        if let Some(dir) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(dir).join("gore");
        }
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".local/share/gore")
}

/// Cache folder for downloaded archives.
pub fn cache_dir() -> PathBuf {
    data_dir().join("cache")
}

/// GET returning the body as text.
pub fn get_text(url: &str) -> Result<String> {
    let response = ureq::get(url)
        .set("User-Agent", "gore")
        .call()
        .with_context(|| format!("cannot fetch {url}"))?;
    Ok(response.into_string()?)
}

/// GET returning parsed JSON.
pub fn get_json(url: &str) -> Result<serde_json::Value> {
    let text = get_text(url)?;
    serde_json::from_str(&text).with_context(|| format!("cannot parse the JSON from {url}"))
}

/// Returns true when the URL answers a HEAD request with a success status.
pub fn exists(url: &str) -> bool {
    ureq::head(url).set("User-Agent", "gore").call().is_ok()
}

/// Downloads `url` into the cache as `name`, reusing an earlier download.
pub fn fetch_cached(url: &str, name: &str) -> Result<PathBuf> {
    let dir = cache_dir();
    std::fs::create_dir_all(&dir)?;
    let target = dir.join(name);
    if target.is_file() && std::fs::metadata(&target)?.len() > 0 {
        return Ok(target);
    }
    download(url, &target)?;
    Ok(target)
}

/// Downloads `url` to `target`, drawing a progress line on a terminal.
pub fn download(url: &str, target: &Path) -> Result<()> {
    let response = ureq::get(url)
        .set("User-Agent", "gore")
        .call()
        .with_context(|| format!("cannot download {url}"))?;
    let total: Option<u64> = response
        .header("Content-Length")
        .and_then(|v| v.parse().ok());
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let partial = target.with_extension("part");
    let mut out = std::fs::File::create(&partial)
        .with_context(|| format!("cannot create {}", partial.display()))?;
    let mut reader = response.into_reader();
    let mut buf = vec![0u8; 1 << 16];
    let mut done: u64 = 0;
    let mut last_shown = u64::MAX;
    let tty = crate::gdre::stderr_is_tty();
    loop {
        let n = reader.read(&mut buf).context("download interrupted")?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])?;
        done += n as u64;
        let mib = done >> 20;
        if tty && mib != last_shown {
            last_shown = mib;
            match total {
                Some(t) if t > 0 => eprint!(
                    "\r\x1b[2K  {name}: {} / {} MiB ({}%)",
                    mib,
                    t >> 20,
                    done * 100 / t
                ),
                _ => eprint!("\r\x1b[2K  {name}: {mib} MiB"),
            }
        }
    }
    if tty {
        eprint!("\r\x1b[2K");
    }
    out.flush()?;
    drop(out);
    if let Some(t) = total {
        if done != t {
            bail!("incomplete download of {url} ({done} of {t} bytes)");
        }
    }
    std::fs::rename(&partial, target)?;
    Ok(())
}
