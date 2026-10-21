//! Parser for Godot's `.pck` pack format (Godot 4.x, formats v2/v3/v4).
//!
//! Reference: `core/io/file_access_pack.cpp` of the Godot engine.

use anyhow::{bail, Context, Result};

use crate::crypto::{self, KEY_LEN};

/// "GDPC" in little endian.
pub const PACK_MAGIC: u32 = 0x4350_4447;

pub const PACK_FORMAT_V0: u32 = 0;
pub const PACK_FORMAT_V1: u32 = 1;
pub const PACK_FORMAT_V2: u32 = 2;
pub const PACK_FORMAT_V3: u32 = 3;
pub const PACK_FORMAT_V4: u32 = 4;

/// Directory of the pack is encrypted.
pub const PACK_DIR_ENCRYPTED: u32 = 1 << 0;
/// `file_base` is relative to the start of the pack.
pub const PACK_REL_FILEBASE: u32 = 1 << 1;
/// Sparse bundle (Android/iOS).
pub const PACK_SPARSE_BUNDLE: u32 = 1 << 2;

/// The file content is encrypted.
pub const PACK_FILE_ENCRYPTED: u32 = 1 << 0;
/// The file was removed by a delta pack.
pub const PACK_FILE_REMOVAL: u32 = 1 << 1;
/// The file is a delta patch.
pub const PACK_FILE_DELTA: u32 = 1 << 2;

/// Parsed pack header.
#[derive(Debug, Clone)]
pub struct PckHeader {
    /// Offset of the `GDPC` magic inside the containing file.
    pub start: u64,
    pub format_version: u32,
    pub engine_major: u32,
    pub engine_minor: u32,
    pub engine_patch: u32,
    pub flags: u32,
    /// Base offset used for file data.
    pub file_base: u64,
    /// Absolute offset of the file table.
    pub dir_offset: u64,
}

impl PckHeader {
    pub fn dir_encrypted(&self) -> bool {
        self.flags & PACK_DIR_ENCRYPTED != 0
    }

    pub fn rel_filebase(&self) -> bool {
        self.flags & PACK_REL_FILEBASE != 0
    }

    /// Parses the header of a pack located at `start` inside `data`.
    pub fn parse(data: &[u8], start: u64, file_len: u64) -> Result<PckHeader> {
        let s = start as usize;
        let need = 40;
        if data.len() < s + need {
            bail!("pack header truncated at offset {start}");
        }
        let magic = u32::from_le_bytes(data[s..s + 4].try_into()?);
        if magic != PACK_MAGIC {
            bail!("bad magic {magic:#010x} at offset {start}");
        }
        let format_version = u32::from_le_bytes(data[s + 4..s + 8].try_into()?);
        let engine_major = u32::from_le_bytes(data[s + 8..s + 12].try_into()?);
        let engine_minor = u32::from_le_bytes(data[s + 12..s + 16].try_into()?);
        let engine_patch = u32::from_le_bytes(data[s + 16..s + 20].try_into()?);

        // v0 (Godot 2.x) and v1 (Godot 3.x) have neither flags nor a file base: the header is
        // followed by 16 reserved u32 and then the file count.
        if format_version <= PACK_FORMAT_V1 {
            let dir_offset = start + 20 + 64;
            if dir_offset + 4 > file_len {
                bail!("directory offset {dir_offset} is outside the file (size {file_len})");
            }
            return Ok(PckHeader {
                start,
                format_version,
                engine_major,
                engine_minor,
                engine_patch,
                flags: 0,
                file_base: 0,
                dir_offset,
            });
        }

        let flags = u32::from_le_bytes(data[s + 20..s + 24].try_into()?);
        let raw_file_base = u64::from_le_bytes(data[s + 24..s + 32].try_into()?);

        let mut file_base = raw_file_base;
        if format_version >= PACK_FORMAT_V3
            || (format_version == PACK_FORMAT_V2 && flags & PACK_REL_FILEBASE != 0)
        {
            file_base += start;
        }

        let dir_offset = if format_version >= PACK_FORMAT_V3 {
            let d = u64::from_le_bytes(data[s + 32..s + 40].try_into()?);
            d + start
        } else {
            // v2: the directory directly follows the header (plus 64 reserved bytes).
            start + 32 + 64
        };

        if dir_offset + 4 > file_len {
            bail!("directory offset {dir_offset} is outside the file (size {file_len})");
        }
        if file_base > file_len {
            bail!("file base {file_base} is outside the file (size {file_len})");
        }

        Ok(PckHeader {
            start,
            format_version,
            engine_major,
            engine_minor,
            engine_patch,
            flags,
            file_base,
            dir_offset,
        })
    }

    /// Heuristic check used while scanning a file for embedded packs.
    pub fn looks_valid(&self, file_len: u64) -> bool {
        if self.format_version > PACK_FORMAT_V4 {
            return false;
        }
        if self.format_version == PACK_FORMAT_V0 {
            // Godot 2.x leaves the engine version fields empty, so there is nothing to
            // check besides the table being inside the file.
            return self.dir_offset + 4 <= file_len;
        }
        if self.engine_major == 0 || self.engine_major > 6 {
            return false;
        }
        if self.dir_offset + 4 > file_len || self.file_base > file_len {
            return false;
        }
        true
    }
}

/// A single entry of the pack's file table.
#[derive(Debug, Clone)]
pub struct PckEntry {
    pub path: String,
    /// Offset of the file data, relative to the pack start.
    pub offset: u64,
    pub size: u64,
    pub md5: [u8; 16],
    pub flags: u32,
}

impl PckEntry {
    pub fn encrypted(&self) -> bool {
        self.flags & PACK_FILE_ENCRYPTED != 0
    }
    pub fn removed(&self) -> bool {
        self.flags & PACK_FILE_REMOVAL != 0
    }
    pub fn delta(&self) -> bool {
        self.flags & PACK_FILE_DELTA != 0
    }
}

/// Checks that the header is plausible and that the file table it points to looks real.
fn accept(data: &[u8], header: &PckHeader) -> bool {
    if !header.looks_valid(data.len() as u64) {
        return false;
    }
    let dir = header.dir_offset as usize;
    if dir + 4 > data.len() {
        return false;
    }
    let count = u32::from_le_bytes(data[dir..dir + 4].try_into().unwrap());
    // A file entry needs at least 36 bytes, so this is a lower bound of the table size.
    count > 0 && count < 1_000_000 && dir + 4 + (count as usize).saturating_mul(32) <= data.len()
}

/// Finds the offset of a pack inside `data`.
///
/// Handles standalone `.pck` files, self-contained executables (pack appended at the end of
/// the binary) and packs embedded in the middle of a binary.
pub fn locate(data: &[u8]) -> Option<u64> {
    let file_len = data.len() as u64;

    // 1) Standalone pack.
    if data.len() >= 4 && u32::from_le_bytes(data[0..4].try_into().ok()?) == PACK_MAGIC {
        if let Ok(h) = PckHeader::parse(data, 0, file_len) {
            if accept(data, &h) {
                return Some(0);
            }
        }
    }

    // 2) Self contained executable: the pack is appended, its header is referenced from the
    //    very end of the file (see `PackedSourcePCK::try_open_pack`).
    if data.len() > 32 {
        let tail = &data[data.len() - 4..];
        if u32::from_le_bytes(tail.try_into().ok()?) == PACK_MAGIC {
            // seek back 12 bytes -> ds (u64), then the header is at len - 4 - 12 - ds - 8
            let ds_off = data.len() - 16;
            let ds = u64::from_le_bytes(data[ds_off..ds_off + 8].try_into().ok()?);
            let head = data.len() as u64 - 16 - ds - 8;
            if (head as usize) + 4 <= data.len()
                && u32::from_le_bytes(data[head as usize..head as usize + 4].try_into().ok()?)
                    == PACK_MAGIC
            {
                if let Ok(h) = PckHeader::parse(data, head, file_len) {
                    if accept(data, &h) {
                        return Some(head);
                    }
                }
            }
        }
    }

    // 3) Generic scan for the magic.
    let needle = PACK_MAGIC.to_le_bytes();
    let mut pos = 0usize;
    while let Some(idx) = find(&data[pos..], &needle) {
        let abs = pos + idx;
        if let Ok(h) = PckHeader::parse(data, abs as u64, file_len) {
            if accept(data, &h) {
                return Some(abs as u64);
            }
        }
        pos = abs + 1;
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The whole pack: header plus its (decrypted) file table.
pub struct Pck {
    pub header: PckHeader,
    pub entries: Vec<PckEntry>,
}

impl Pck {
    /// Reads the file table. `key` is required when the directory is encrypted.
    pub fn open(data: &[u8], header: PckHeader, key: Option<&[u8; KEY_LEN]>) -> Result<Pck> {
        if header.flags & PACK_SPARSE_BUNDLE != 0 {
            bail!(
                "this pack uses the sparse bundle format, which is not supported yet \
                 (recover it with GDRE Tools directly)"
            );
        }
        let dir = header.dir_offset as usize;
        if dir + 4 > data.len() {
            bail!("directory offset out of range");
        }
        let file_count = u32::from_le_bytes(data[dir..dir + 4].try_into()?);

        let table: Vec<u8> = if header.dir_encrypted() {
            let key = key.context("the pack directory is encrypted but no key was supplied")?;
            let (blob, _) = crypto::EncryptedBlob::parse(&data[dir + 4..])
                .context("cannot parse the encrypted directory header")?;
            blob.decrypt(key).context(
                "cannot decrypt the directory: wrong key or corrupted pack (MD5 mismatch)",
            )?
        } else {
            // The rest of the file is the table; it ends at the end of the pack.
            let end = data.len();
            data[dir + 4..end].to_vec()
        };

        let mut cursor = 0usize;
        // Guard against a corrupted file count asking for a huge allocation.
        let capacity = (file_count as usize).min(table.len() / 32 + 1);
        let mut entries = Vec::with_capacity(capacity);
        // v0 (Godot 2.x) and v1 (Godot 3.x) entries have no flags field.
        let legacy = header.format_version <= PACK_FORMAT_V1;
        for _ in 0..file_count {
            if cursor + 4 > table.len() {
                bail!("file table truncated after {} entries", entries.len());
            }
            let len = u32::from_le_bytes(table[cursor..cursor + 4].try_into()?) as usize;
            cursor += 4;
            let entry_len = 8 + 8 + 16 + if legacy { 0 } else { 4 };
            if cursor + len + entry_len > table.len() {
                bail!("file table entry {cursor} is truncated");
            }
            let mut raw = &table[cursor..cursor + len];
            cursor += len;
            // The path can be zero padded to a multiple of 4 bytes. Godot 3 does not pad it,
            // but other writers (GDRE Tools) do, and trimming is harmless in both cases.
            while raw.last() == Some(&0) {
                raw = &raw[..raw.len() - 1];
            }
            let path = String::from_utf8_lossy(raw).to_string();
            let offset = u64::from_le_bytes(table[cursor..cursor + 8].try_into()?);
            let size = u64::from_le_bytes(table[cursor + 8..cursor + 16].try_into()?);
            cursor += 16;
            let mut md5 = [0u8; 16];
            md5.copy_from_slice(&table[cursor..cursor + 16]);
            cursor += 16;
            let flags = if legacy {
                0
            } else {
                let f = u32::from_le_bytes(table[cursor..cursor + 4].try_into()?);
                cursor += 4;
                f
            };
            entries.push(PckEntry {
                path,
                offset,
                size,
                md5,
                flags,
            });
        }

        Ok(Pck { header, entries })
    }

    /// Absolute offset of a file's data inside the container.
    ///
    /// Godot always stores the offset of every entry relative to the file base, and the
    /// file base itself is relative to the start of the pack when `PACK_REL_FILEBASE` is
    /// set (which is always the case from v3 on). Both adjustments are already applied
    /// when the header is parsed.
    pub fn data_offset(&self, entry: &PckEntry) -> u64 {
        self.header.file_base + entry.offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage() {
        let data = vec![0u8; 128];
        assert!(locate(&data).is_none());
    }

    #[test]
    fn parses_a_minimal_header() {
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(&PACK_MAGIC.to_le_bytes());
        data[4..8].copy_from_slice(&PACK_FORMAT_V4.to_le_bytes());
        data[8..12].copy_from_slice(&4u32.to_le_bytes());
        data[12..16].copy_from_slice(&7u32.to_le_bytes());
        data[16..20].copy_from_slice(&1u32.to_le_bytes());
        data[20..24].copy_from_slice(&PACK_DIR_ENCRYPTED.to_le_bytes());
        data[24..32].copy_from_slice(&112u64.to_le_bytes());
        data[32..40].copy_from_slice(&128u64.to_le_bytes());
        let h = PckHeader::parse(&data, 0, 256).unwrap();
        assert_eq!(h.format_version, PACK_FORMAT_V4);
        assert_eq!(h.engine_minor, 7);
        assert!(h.dir_encrypted());
        assert_eq!(h.dir_offset, 128);
    }
}
