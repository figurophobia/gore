//! Encryption key recovery.
//!
//! The Godot exporter embeds the 256 bit PCK encryption key inside the game binary.
//! Recovering it is a matter of finding the right 32 bytes in the binary; the only hard
//! part is telling a real key from 11 million random windows.
//!
//! This module uses the pack itself as an oracle: the file table is encrypted with
//! AES-256-CFB and starts with the length of the first file path, so decrypting the
//! first blocks with a candidate key produces either a plausible path header or garbage.
//! That turns the search into a cheap, parallel filter with a definitive final check
//! (the MD5 of the decrypted table).

use std::ops::Range;

use rayon::prelude::*;

use crate::crypto::{self, KEY_LEN};

/// Strictness of the plaintext filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// The first path must look like a real path (path characters, not starting with a
    /// separator). This is what an exported pack produces.
    Strict,
    /// The first path must use path characters only.
    Loose,
    /// The first path must be printable ASCII.
    Weak,
}

/// Knows what a decrypted file table header must look like.
#[derive(Debug, Clone)]
pub struct Oracle {
    iv: [u8; crypto::IV_LEN],
    /// First blocks of the encrypted file table.
    ct: Vec<u8>,
}

impl Oracle {
    /// Builds the oracle from the encrypted file table of a pack.
    pub fn new(dir_data: &[u8]) -> Option<Oracle> {
        let (blob, _) = crypto::EncryptedBlob::parse(dir_data)?;
        Some(Oracle {
            iv: blob.iv,
            ct: blob.ciphertext,
        })
    }

    /// Decrypts the first blocks of the table with `key` and checks the structure.
    ///
    /// Returns the score of the match (higher is better) or `None` when the plaintext
    /// cannot be a file table header.
    pub fn test(&self, key: &[u8; KEY_LEN], tier: Tier) -> Option<u8> {
        if self.ct.len() < 32 {
            return None;
        }
        // First block: [u32 path_len][path bytes...]
        let ks0 = crypto::aes_encrypt_block(key, &self.iv);
        let mut pt0 = [0u8; 16];
        for i in 0..16 {
            pt0[i] = self.ct[i] ^ ks0[i];
        }
        let len = u32::from_le_bytes(pt0[0..4].try_into().ok()?);
        if !(4..=1 << 20).contains(&len) || len % 4 != 0 {
            return None;
        }
        let path_bytes = (len as usize - 4).min(12);
        for &b in &pt0[4..4 + path_bytes] {
            if !is_path_byte(b) {
                return None;
            }
        }
        match tier {
            Tier::Strict => {
                // A real path never starts with a separator or a control character.
                if !is_path_start(pt0[4]) {
                    return None;
                }
                Some(3)
            }
            Tier::Loose => Some(2),
            Tier::Weak => {
                for &b in &pt0[4..4 + path_bytes] {
                    if !(0x20..=0x7e).contains(&b) {
                        return None;
                    }
                }
                Some(1)
            }
        }
    }
}

#[inline]
fn is_path_start(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_')
}

#[inline]
fn is_path_byte(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'/' | b':' | b'-' | b' ')
}

/// A key candidate found in a binary.
#[derive(Debug, Clone)]
pub struct KeyHit {
    /// Offset inside the scanned file.
    pub offset: u64,
    pub key: [u8; KEY_LEN],
    pub score: u8,
}

/// Scans `data` for a 32 byte window that decrypts the file table into a plausible path.
///
/// `ranges` restricts the search to interesting regions of the file (data sections).
/// `step` is the distance between candidate offsets: `8` is a good first pass because
/// data blobs are usually aligned, `1` is the exhaustive pass.
pub fn scan(
    data: &[u8],
    oracle: &Oracle,
    ranges: &[Range<usize>],
    step: usize,
    tier: Tier,
) -> Option<KeyHit> {
    let step = step.max(1);
    ranges.par_iter().find_map_any(|range| {
        let start = range.start;
        let end = range.end.min(data.len());
        if end < start + KEY_LEN {
            return None;
        }
        let mut off = start;
        while off + KEY_LEN <= end {
            let mut key = [0u8; KEY_LEN];
            key.copy_from_slice(&data[off..off + KEY_LEN]);
            if let Some(score) = oracle.test(&key, tier) {
                return Some(KeyHit {
                    offset: off as u64,
                    key,
                    score,
                });
            }
            off += step;
        }
        None
    })
}

/// Same as [`scan`], but every candidate that passes the structural filter is confirmed by
/// `verify` (which must decrypt the real file table). Only a true key can pass that check,
/// so the result is guaranteed to be correct.
pub fn scan_verified(
    data: &[u8],
    oracle: &Oracle,
    ranges: &[Range<usize>],
    step: usize,
    tier: Tier,
    verify: &(impl Fn(&[u8; KEY_LEN]) -> bool + Sync),
) -> Option<KeyHit> {
    let step = step.max(1);
    ranges.par_iter().find_map_any(|range| {
        let start = range.start;
        let end = range.end.min(data.len());
        if end < start + KEY_LEN {
            return None;
        }
        let mut off = start;
        while off + KEY_LEN <= end {
            let mut key = [0u8; KEY_LEN];
            key.copy_from_slice(&data[off..off + KEY_LEN]);
            if let Some(score) = oracle.test(&key, tier) {
                if verify(&key) {
                    return Some(KeyHit {
                        offset: off as u64,
                        key,
                        score,
                    });
                }
            }
            off += step;
        }
        None
    })
}

/// Tries a list of passwords, using the two ways Godot derives a key from a password.
pub fn try_passwords(oracle: &Oracle, passwords: &[String]) -> Option<KeyHit> {
    for password in passwords {
        let mut candidates: Vec<[u8; KEY_LEN]> = Vec::new();
        // 1) md5(password) as 32 ASCII hex characters (FileAccessEncrypted::open_and_parse_password).
        candidates.push(crypto::key_from_password(password));
        // 2) The password itself, zero padded to 32 bytes.
        let mut padded = [0u8; KEY_LEN];
        let bytes = password.as_bytes();
        let n = bytes.len().min(KEY_LEN);
        padded[..n].copy_from_slice(&bytes[..n]);
        candidates.push(padded);
        // 3) A 64 character hex password used verbatim as the key.
        if let Some(key) = crypto::parse_hex_key(password) {
            candidates.push(key);
        }
        for key in candidates {
            for tier in [Tier::Strict, Tier::Loose, Tier::Weak] {
                if let Some(score) = oracle.test(&key, tier) {
                    return Some(KeyHit {
                        offset: 0,
                        key,
                        score,
                    });
                }
            }
        }
    }
    None
}

/// A small built-in word list, used when no `--wordlist` is given.
pub const DEFAULT_PASSWORDS: &[&str] = &[
    "godot",
    "godotengine",
    "godot4",
    "godot3",
    "encryption",
    "encrypt",
    "password",
    "secret",
    "test",
    "key",
    "admin",
    "123456",
    "12345678",
    "qwerty",
    "letmein",
    "abc123",
    "0000000000000000000000000000000000000000000000000000000000000000",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a synthetic encrypted file table so the oracle can be tested end to end.
    fn synthetic_table(path: &str) -> (Vec<u8>, [u8; KEY_LEN]) {
        let key = [0x42u8; KEY_LEN];
        let mut path_bytes = path.as_bytes().to_vec();
        let pad = (4 - (path_bytes.len() % 4)) % 4;
        path_bytes.extend(std::iter::repeat(0u8).take(pad));
        let mut plain = Vec::new();
        plain.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
        plain.extend_from_slice(&path_bytes);

        let iv = [0x11u8; 16];
        // Godot pads the plaintext to a multiple of 16 before encrypting it.
        let mut padded = plain.clone();
        while padded.len() % 16 != 0 {
            padded.push(0);
        }
        let ct = crypto::cfb_encrypt(&padded, &key, &iv);
        let mut blob = Vec::new();
        blob.extend_from_slice(&crypto::md5(&plain));
        blob.extend_from_slice(&(plain.len() as u64).to_le_bytes());
        blob.extend_from_slice(&iv);
        blob.extend_from_slice(&ct);
        (blob, key)
    }

    #[test]
    fn oracle_accepts_the_right_key_only() {
        let (blob, key) = synthetic_table("res://icon.svg");
        let oracle = Oracle::new(&blob).unwrap();
        assert!(oracle.test(&key, Tier::Strict).is_some());
        assert!(oracle.test(&[0u8; KEY_LEN], Tier::Weak).is_none());
    }

    #[test]
    fn finds_a_key_hidden_in_a_blob() {
        let (blob, key) = synthetic_table("res://levels/mirraxis/mirraxis.tscn");
        let oracle = Oracle::new(&blob).unwrap();
        let mut data = vec![0xAAu8; 4096];
        data[1234..1234 + KEY_LEN].copy_from_slice(&key);
        let range = 0..data.len();
        let hit = scan(
            &data,
            &oracle,
            std::slice::from_ref(&range),
            1,
            Tier::Strict,
        )
        .unwrap();
        assert_eq!(hit.offset, 1234);
        assert_eq!(hit.key, key);
    }
}
