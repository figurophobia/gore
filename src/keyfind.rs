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
    /// The first path may contain any non-control bytes, including UTF-8 (a pack whose first
    /// file has an accented or non-Latin name). This is the loosest structural filter: it
    /// leans almost entirely on the file-table length field and the final MD5 verification.
    Utf8,
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
        let path = &pt0[4..4 + path_bytes];
        // Per-byte validity depends on the tier: UTF-8 allows high bytes, the rest require
        // path characters.
        let byte_ok = |b: u8| match tier {
            Tier::Utf8 => b >= 0x20, // any printable or high byte, no control characters
            _ => is_path_byte(b),
        };
        for &b in path {
            if !byte_ok(b) {
                return None;
            }
        }
        match tier {
            Tier::Strict => {
                // A real path never starts with a separator or a control character.
                if !is_path_start(pt0[4]) {
                    return None;
                }
                Some(4)
            }
            Tier::Loose => Some(3),
            Tier::Weak => {
                for &b in path {
                    if !(0x20..=0x7e).contains(&b) {
                        return None;
                    }
                }
                Some(2)
            }
            Tier::Utf8 => Some(1),
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

/// Size of the slices the scan is cut into so every CPU core gets work.
///
/// The key search is overwhelmingly dominated by the whole-file passes, which are a single
/// `Range` covering the entire binary. Iterating that range on one thread leaves every other
/// core idle, so the range is split into chunks of this size (with a `KEY_LEN - 1` overlap so
/// a key straddling a chunk boundary is still seen) and the chunks are run in parallel.
const CHUNK: usize = 1 << 20; // 1 MiB

/// How many distinct byte values a window must have to be worth an AES probe, in the passes
/// where the cheap pre-filter is enabled. A real AES-256 key is 32 random bytes, so it has
/// close to 32 distinct values; long runs of zeros or repeated padding (most of `.rodata`)
/// are rejected before the expensive key schedule. The exhaustive final passes disable this
/// so even a degenerate key (all zeros, a repeated byte) is still found.
const MIN_DISTINCT_BYTES: usize = 12;

/// True when the 32 byte window has enough distinct values to plausibly be a random key.
#[inline]
fn passes_prefilter(win: &[u8]) -> bool {
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    for &b in win {
        if !seen[b as usize] {
            seen[b as usize] = true;
            distinct += 1;
            if distinct >= MIN_DISTINCT_BYTES {
                return true;
            }
        }
    }
    false
}

/// Cuts `ranges` into parallel-friendly chunks of at most [`CHUNK`] bytes, each overlapping
/// the next by `KEY_LEN - 1` so no candidate key is missed at a boundary.
fn chunks(ranges: &[Range<usize>], data_len: usize) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    for range in ranges {
        let start = range.start;
        let end = range.end.min(data_len);
        if end < start + KEY_LEN {
            continue;
        }
        let mut off = start;
        while off + KEY_LEN <= end {
            let chunk_end = (off + CHUNK).min(end);
            out.push(off..chunk_end);
            if chunk_end == end {
                break;
            }
            // Step back so a key spanning the cut is covered by the next chunk too.
            off = chunk_end - (KEY_LEN - 1);
        }
    }
    out
}

/// Sweeps one chunk, calling `accept` on every window that passes the structural oracle (and
/// the pre-filter, when enabled). Returns the first accepted hit.
#[inline]
fn sweep_chunk(
    data: &[u8],
    oracle: &Oracle,
    chunk: &Range<usize>,
    step: usize,
    tier: Tier,
    prefilter: bool,
    accept: &impl Fn(&[u8; KEY_LEN]) -> bool,
) -> Option<KeyHit> {
    let end = chunk.end.min(data.len());
    let mut off = chunk.start;
    while off + KEY_LEN <= end {
        let win = &data[off..off + KEY_LEN];
        if !prefilter || passes_prefilter(win) {
            let mut key = [0u8; KEY_LEN];
            key.copy_from_slice(win);
            if let Some(score) = oracle.test(&key, tier) {
                if accept(&key) {
                    return Some(KeyHit {
                        offset: off as u64,
                        key,
                        score,
                    });
                }
            }
        }
        off += step;
    }
    None
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
    let chunks = chunks(ranges, data.len());
    chunks
        .par_iter()
        .find_map_any(|chunk| sweep_chunk(data, oracle, chunk, step, tier, false, &|_| true))
}

/// Same as [`scan`], but every candidate that passes the structural filter is confirmed by
/// `verify` (which must decrypt the real file table). Only a true key can pass that check,
/// so the result is guaranteed to be correct.
///
/// `prefilter` skips low-entropy windows before the AES probe; leave it off for the final
/// exhaustive pass so a degenerate key is never missed.
pub fn scan_verified(
    data: &[u8],
    oracle: &Oracle,
    ranges: &[Range<usize>],
    step: usize,
    tier: Tier,
    prefilter: bool,
    verify: &(impl Fn(&[u8; KEY_LEN]) -> bool + Sync),
) -> Option<KeyHit> {
    let step = step.max(1);
    let chunks = chunks(ranges, data.len());
    chunks
        .par_iter()
        .find_map_any(|chunk| sweep_chunk(data, oracle, chunk, step, tier, prefilter, verify))
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
            for tier in [Tier::Strict, Tier::Loose, Tier::Weak, Tier::Utf8] {
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

    #[test]
    fn utf8_tier_accepts_a_non_ascii_first_path() {
        // A pack whose first file has an accented name: the stricter tiers reject it, the
        // UTF-8 tier does not.
        // The non-ASCII bytes fall within the first path bytes the oracle inspects.
        let (blob, key) = synthetic_table("res://áéíóú.tscn");
        let oracle = Oracle::new(&blob).unwrap();
        assert!(oracle.test(&key, Tier::Strict).is_none());
        assert!(oracle.test(&key, Tier::Weak).is_none());
        assert!(oracle.test(&key, Tier::Utf8).is_some());
    }

    #[test]
    fn finds_a_key_straddling_a_chunk_boundary() {
        // The whole-file passes are cut into CHUNK-sized slices; a key sitting across a cut
        // must still be found thanks to the overlap.
        let (blob, key) = synthetic_table("res://main.tscn");
        let oracle = Oracle::new(&blob).unwrap();
        let off = CHUNK - 16; // straddles the first/second chunk boundary
        let mut data = vec![0x00u8; CHUNK + 4096];
        data[off..off + KEY_LEN].copy_from_slice(&key);
        let range = 0..data.len();
        let hit = scan(
            &data,
            &oracle,
            std::slice::from_ref(&range),
            1,
            Tier::Strict,
        )
        .unwrap();
        assert_eq!(hit.offset as usize, off);
        assert_eq!(hit.key, key);
    }

    #[test]
    fn prefilter_rejects_low_entropy_but_keeps_real_keys() {
        assert!(!passes_prefilter(&[0u8; KEY_LEN]));
        assert!(!passes_prefilter(&[0xABu8; KEY_LEN]));
        assert!(passes_prefilter(&[
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31
        ]));
    }
}
