//! Godot's crypto primitives: AES-256-CFB and MD5, matching `core/io/file_access_encrypted.cpp`
//! and `core/crypto/crypto_core.cpp` of the Godot engine.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use md5::{Digest, Md5};

/// Size of a Godot encryption key (AES-256).
pub const KEY_LEN: usize = 32;
/// Size of the CFB initialisation vector.
pub const IV_LEN: usize = 16;

/// Computes the MD5 digest of `data`.
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut result = [0u8; 16];
    result.copy_from_slice(&out);
    result
}

/// Encrypts a single 16-byte block with AES-256 (ECB). Used as the CFB keystream generator.
#[inline]
pub fn aes_encrypt_block(key: &[u8; KEY_LEN], block: &[u8; IV_LEN]) -> [u8; IV_LEN] {
    let cipher = Aes256::new(key.into());
    let mut buf = *block;
    cipher.encrypt_block((&mut buf).into());
    buf
}

/// AES-256-CFB decryption (segment size 128 bits), as used by `CryptoCore::decrypt_cfb`.
pub fn cfb_decrypt(data: &[u8], key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;
    for chunk in data.chunks(IV_LEN) {
        let ks = aes_encrypt_block(key, &prev);
        let mut block = [0u8; IV_LEN];
        for (i, &b) in chunk.iter().enumerate() {
            block[i] = b ^ ks[i];
        }
        out.extend_from_slice(&block[..chunk.len()]);
        // The feedback is the previous *ciphertext* block.
        let mut next = [0u8; IV_LEN];
        next[..chunk.len()].copy_from_slice(chunk);
        prev = next;
    }
    out
}

/// AES-256-CFB encryption (the counterpart of [`cfb_decrypt`]).
///
/// Note that the feedback is the previous *ciphertext* block, exactly as in
/// `CryptoCore::encrypt_cfb`.
pub fn cfb_encrypt(data: &[u8], key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;
    for chunk in data.chunks(IV_LEN) {
        let ks = aes_encrypt_block(key, &prev);
        let mut block = [0u8; IV_LEN];
        for (i, &b) in chunk.iter().enumerate() {
            block[i] = b ^ ks[i];
        }
        out.extend_from_slice(&block[..chunk.len()]);
        let mut next = [0u8; IV_LEN];
        next[..chunk.len()].copy_from_slice(&block[..chunk.len()]);
        prev = next;
    }
    out
}

/// The framing used by `FileAccessEncrypted` (no magic header variant):
///
/// ```text
/// [16 bytes] MD5 of the plaintext
/// [ 8 bytes] plaintext length (u64, little endian)
/// [16 bytes] IV
/// [   n    ] AES-256-CFB ciphertext (padded to a multiple of 16)
/// ```
#[derive(Debug, Clone)]
pub struct EncryptedBlob {
    pub plaintext_md5: [u8; 16],
    pub plaintext_len: u64,
    pub iv: [u8; IV_LEN],
    pub ciphertext: Vec<u8>,
}

impl EncryptedBlob {
    /// Size of the header that precedes the ciphertext.
    pub const HEADER_SIZE: usize = 16 + 8 + 16;

    /// Parses the header of an encrypted blob.
    ///
    /// The ciphertext is not read here: its length depends on the plaintext length
    /// (it is padded to a multiple of 16) and the container may store the header
    /// separately from the payload.
    pub fn parse_header(buf: &[u8]) -> Option<EncryptedBlob> {
        if buf.len() < EncryptedBlob::HEADER_SIZE {
            return None;
        }
        let mut plaintext_md5 = [0u8; 16];
        plaintext_md5.copy_from_slice(&buf[0..16]);
        let plaintext_len = u64::from_le_bytes(buf[16..24].try_into().ok()?);
        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(&buf[24..40]);
        Some(EncryptedBlob {
            plaintext_md5,
            plaintext_len,
            iv,
            ciphertext: Vec::new(),
        })
    }

    /// Length of the ciphertext for this blob (plaintext length padded to 16 bytes).
    pub fn ciphertext_len(&self) -> usize {
        let len = self.plaintext_len as usize;
        if len % 16 != 0 {
            len + 16 - (len % 16)
        } else {
            len
        }
    }

    /// Total size of the blob (header + ciphertext).
    pub fn total_len(&self) -> usize {
        EncryptedBlob::HEADER_SIZE + self.ciphertext_len()
    }

    /// Decrypts the blob and verifies the plaintext MD5 against the stored one.
    pub fn decrypt(&self, key: &[u8; KEY_LEN]) -> Option<Vec<u8>> {
        let mut plain = cfb_decrypt(&self.ciphertext, key, &self.iv);
        if plain.len() < self.plaintext_len as usize {
            return None;
        }
        plain.truncate(self.plaintext_len as usize);
        if md5(&plain) != self.plaintext_md5 {
            return None;
        }
        Some(plain)
    }

    /// Parses a complete blob (header + ciphertext) from the start of `buf`.
    pub fn parse(buf: &[u8]) -> Option<(EncryptedBlob, usize)> {
        let mut blob = EncryptedBlob::parse_header(buf)?;
        let end = blob.total_len();
        if buf.len() < end {
            return None;
        }
        blob.ciphertext = buf[EncryptedBlob::HEADER_SIZE..end].to_vec();
        Some((blob, end))
    }
}

/// Derives a 32 byte key from a password the way `FileAccessEncrypted::open_and_parse_password`
/// does: the MD5 of the password, as its 32 character hex text.
pub fn key_from_password(password: &str) -> [u8; KEY_LEN] {
    let hex = md5(password.as_bytes());
    let mut out = [0u8; KEY_LEN];
    for (i, byte) in hex.iter().enumerate() {
        out[i * 2] = hex_digit(byte >> 4);
        out[i * 2 + 1] = hex_digit(byte & 0x0f);
    }
    out
}

fn hex_digit(v: u8) -> u8 {
    match v {
        0..=9 => b'0' + v,
        _ => b'a' + (v - 10),
    }
}

/// Parses a 64 character hex string into a 32 byte key.
pub fn parse_hex_key(s: &str) -> Option<[u8; KEY_LEN]> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; KEY_LEN];
    let bytes = s.as_bytes();
    for i in 0..KEY_LEN {
        let hi = (bytes[i * 2] as char).to_digit(16)?;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// Formats a key as the 64 character hex string Godot and GDRE expect.
pub fn format_hex_key(key: &[u8; KEY_LEN]) -> String {
    let mut s = String::with_capacity(64);
    for byte in key {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let key = [7u8; 32];
        let hex = format_hex_key(&key);
        assert_eq!(hex.len(), 64);
        assert_eq!(parse_hex_key(&hex).unwrap(), key);
        assert!(parse_hex_key("deadbeef").is_none());
    }

    #[test]
    fn cfb_is_symmetric_with_encrypt_side() {
        // CFB uses the encrypt direction for both, so encrypt then decrypt round-trips.
        let key = [0x11u8; 32];
        let iv = [0x22u8; 16];
        for plain in [
            b"res://icon.png".to_vec(),
            b"".to_vec(),
            vec![0xABu8; 16],
            vec![0xCBu8; 37],
        ] {
            let ct = cfb_encrypt(&plain, &key, &iv);
            assert_eq!(ct.len(), plain.len());
            assert_eq!(cfb_decrypt(&ct, &key, &iv), plain);
        }
    }

    #[test]
    fn password_derivation_matches_godot() {
        // Godot uses the MD5 text of the password as the 32 byte key.
        let key = key_from_password("password");
        assert_eq!(&key, b"5f4dcc3b5aa765d61d8327deb882cf99");
    }
}
