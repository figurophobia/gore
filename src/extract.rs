//! Extraction of the pack contents to disk.

use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};

use crate::crypto::{self, KEY_LEN};
use crate::pck::Pck;

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

/// Extracts every file of the pack into `out_dir`.
pub fn extract(
    data: &[u8],
    pck: &Pck,
    out_dir: &Path,
    key: Option<&[u8; KEY_LEN]>,
) -> Result<ExtractStats> {
    let mut stats = ExtractStats::default();
    let mut written: HashSet<PathBuf> = HashSet::new();

    for entry in &pck.entries {
        if entry.removed() {
            stats.skipped += 1;
            continue;
        }
        let rel = match safe_relative_path(&entry.path) {
            Some(p) => p,
            None => {
                stats.skipped += 1;
                continue;
            }
        };
        let abs = out_dir.join(&rel);
        let start = pck.data_offset(entry) as usize;

        let content: Vec<u8> = if entry.encrypted() {
            let key = key.with_context(|| {
                format!("file '{}' is encrypted but no key was supplied", entry.path)
            })?;
            // For encrypted files the pack entry stores the *plaintext* size, while the
            // data on disk is the `FileAccessEncrypted` blob: header + padded ciphertext.
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
            stats.decrypted += 1;
            plain
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
            raw.to_vec()
        };

        // Godot 3.x packs do not store a real MD5 (it is left empty), so it is only
        // checked when the pack actually provides one.
        let has_md5 = entry.md5.iter().any(|&b| b != 0);
        if has_md5 && (content.len() as u64 != entry.size || crypto::md5(&content) != entry.md5) {
            stats.checksum_errors.push(entry.path.clone());
        }

        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create directory {}", parent.display()))?;
        }
        fs::write(&abs, &content).with_context(|| format!("cannot write {}", abs.display()))?;
        written.insert(rel);
        stats.written += 1;
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
