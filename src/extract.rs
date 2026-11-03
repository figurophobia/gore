//! Extraction of the pack contents to disk.

use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use rayon::prelude::*;

use crate::crypto::{self, KEY_LEN};
use crate::pck::{Pck, PckEntry};

/// Result of an extraction run.
#[derive(Debug, Default, Clone)]
pub struct ExtractStats {
    pub written: usize,
    pub skipped: usize,
    pub decrypted: usize,
    pub checksum_errors: Vec<String>,
}

/// Turns a `res://` style path into a safe relative path.
pub fn safe_relative_path(raw: &str) -> Option<PathBuf> {
    let mut path = PathBuf::new();
    if let Some(rest) = raw.strip_prefix("res://") {
        for part in rest.split('/') {
            if part.is_empty() {
                continue;
            }
            path.push(part);
        }
    } else if let Some(rest) = raw.strip_prefix("user://") {
        path.push("@@user@@");
        for part in rest.split('/') {
            if part.is_empty() {
                continue;
            }
            path.push(part);
        }
    } else {
        for part in raw.split('/') {
            if part.is_empty() {
                continue;
            }
            path.push(part);
        }
    }
    // Reject anything that tries to escape the output directory.
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            _ => return None,
        }
    }
    if path.as_os_str().is_empty() {
        None
    } else {
        Some(path)
    }
}

/// Decodes a single entry's bytes: decrypting the `FileAccessEncrypted` blob when the entry
/// is encrypted, or slicing the plaintext out of the pack otherwise. Returns the bytes and
/// whether decryption happened.
fn decode_entry(
    data: &[u8],
    pck: &Pck,
    entry: &PckEntry,
    key: Option<&[u8; KEY_LEN]>,
) -> Result<(Vec<u8>, bool)> {
    let start = pck.data_offset(entry) as usize;
    if entry.encrypted() {
        let key = key.with_context(|| {
            format!("file '{}' is encrypted but no key was supplied", entry.path)
        })?;
        // For encrypted files the pack entry stores the *plaintext* size, while the data on
        // disk is the `FileAccessEncrypted` blob: header + padded ciphertext.
        let head = data
            .get(start..start + crypto::EncryptedBlob::HEADER_SIZE)
            .with_context(|| format!("the encrypted file '{}' is truncated", entry.path))?;
        let mut blob = crypto::EncryptedBlob::parse_header(head)
            .with_context(|| format!("cannot parse the encrypted file '{}'", entry.path))?;
        let need = blob.total_len();
        let raw = data
            .get(start..start + need)
            .with_context(|| format!("the encrypted file '{}' is truncated", entry.path))?;
        blob.ciphertext = raw[crypto::EncryptedBlob::HEADER_SIZE..need].to_vec();
        let plain = blob.decrypt(key).with_context(|| {
            format!(
                "cannot decrypt '{}': wrong key or corrupted data (MD5 mismatch)",
                entry.path
            )
        })?;
        Ok((plain, true))
    } else {
        let end = start
            .checked_add(entry.size as usize)
            .context("file offset overflow")?;
        let raw = data.get(start..end).with_context(|| {
            format!(
                "file '{}' lies outside the pack (offset {start}, size {})",
                entry.path, entry.size
            )
        })?;
        Ok((raw.to_vec(), false))
    }
}

/// Extracts every file of the pack into `out_dir`.
///
/// Decryption, checksum verification and writing run in parallel across entries (they are
/// independent), after the needed directories are created up front to avoid a race.
pub fn extract(
    data: &[u8],
    pck: &Pck,
    out_dir: &Path,
    key: Option<&[u8; KEY_LEN]>,
) -> Result<ExtractStats> {
    // Resolve the destination path of every writable entry; drop removed/unsafe ones.
    let mut jobs: Vec<(&PckEntry, PathBuf)> = Vec::with_capacity(pck.entries.len());
    let mut skipped = 0usize;
    for entry in &pck.entries {
        match (entry.removed(), safe_relative_path(&entry.path)) {
            (false, Some(rel)) => jobs.push((entry, out_dir.join(rel))),
            _ => skipped += 1,
        }
    }

    // Create the parent directories once, sequentially, so parallel writes never race to make
    // the same folder.
    let mut dirs: HashSet<&Path> = HashSet::new();
    for (_, abs) in &jobs {
        if let Some(parent) = abs.parent() {
            dirs.insert(parent);
        }
    }
    for dir in dirs {
        fs::create_dir_all(dir)
            .with_context(|| format!("cannot create directory {}", dir.display()))?;
    }

    // Decode, verify and write every file in parallel.
    let results: Vec<Result<(bool, Option<String>)>> = jobs
        .par_iter()
        .map(|(entry, abs)| {
            let (content, decrypted) = decode_entry(data, pck, entry, key)?;
            // Godot 3.x packs do not store a real MD5 (it is left empty), so it is only
            // checked when the pack actually provides one.
            let has_md5 = entry.md5.iter().any(|&b| b != 0);
            let checksum_error = (has_md5
                && (content.len() as u64 != entry.size || crypto::md5(&content) != entry.md5))
                .then(|| entry.path.clone());
            fs::write(abs, &content).with_context(|| format!("cannot write {}", abs.display()))?;
            Ok((decrypted, checksum_error))
        })
        .collect();

    let mut stats = ExtractStats {
        skipped,
        ..Default::default()
    };
    for r in results {
        let (decrypted, checksum_error) = r?;
        stats.written += 1;
        if decrypted {
            stats.decrypted += 1;
        }
        if let Some(path) = checksum_error {
            stats.checksum_errors.push(path);
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitises_paths() {
        assert_eq!(
            safe_relative_path("res://icon.svg").unwrap(),
            PathBuf::from("icon.svg")
        );
        assert_eq!(
            safe_relative_path("res://a/b/c.png").unwrap(),
            PathBuf::from("a/b/c.png")
        );
        assert!(safe_relative_path("res://../../etc/passwd").is_none());
    }
}
