//! Minimal PE / ELF section readers.
//!
//! They are used to narrow the key search to the sections that actually contain
//! initialised data (`.data`, `.rdata`, `.rodata`), which is where the Godot exporter
//! stores the encryption key blob.

use std::ops::Range;

/// A named region of the file.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub range: Range<usize>,
}

/// Returns the data sections of a PE (Windows) binary.
pub fn pe_sections(data: &[u8]) -> Option<Vec<Section>> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return None;
    }
    let pe_off = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
    if pe_off + 24 > data.len() || &data[pe_off..pe_off + 4] != b"PE\0\0" {
        return None;
    }
    let coff = pe_off + 4;
    let num_sections = u16::from_le_bytes(data[coff + 2..coff + 4].try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(data[coff + 16..coff + 18].try_into().ok()?) as usize;
    let sec_start = coff + 20 + opt_size;

    let mut out = Vec::new();
    for i in 0..num_sections {
        let sh = sec_start + i * 40;
        if sh + 40 > data.len() {
            break;
        }
        let name_bytes = &data[sh..sh + 8];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();
        let size_raw = u32::from_le_bytes(data[sh + 16..sh + 20].try_into().ok()?) as usize;
        let ptr_raw = u32::from_le_bytes(data[sh + 20..sh + 24].try_into().ok()?) as usize;
        if ptr_raw == 0 || size_raw == 0 {
            continue;
        }
        let end = (ptr_raw + size_raw).min(data.len());
        if ptr_raw >= end {
            continue;
        }
        out.push(Section {
            name,
            range: ptr_raw..end,
        });
    }
    Some(out)
}

/// Returns the data sections of an ELF (Linux/macOS) binary.
pub fn elf_sections(data: &[u8]) -> Option<Vec<Section>> {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return None;
    }
    let is64 = data[4] == 2;
    let little = data[5] == 1;
    if !is64 {
        return None;
    }
    let rd_u64 = |off: usize| -> Option<u64> {
        let bytes: [u8; 8] = data.get(off..off + 8)?.try_into().ok()?;
        Some(if little {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        })
    };
    let rd_u16 = |off: usize| -> Option<u16> {
        let bytes: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
        Some(if little {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        })
    };

    let shoff = rd_u64(0x28)? as usize;
    let shentsize = rd_u16(0x3a)? as usize;
    let shnum = rd_u16(0x3c)? as usize;
    let shstrndx = rd_u16(0x3e)? as usize;
    if shoff == 0 || shnum == 0 || shentsize < 64 {
        return None;
    }
    let str_hdr = shoff + shstrndx * shentsize;
    let str_off = rd_u64(str_hdr + 24)? as usize;

    let mut out = Vec::new();
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        if sh + 64 > data.len() {
            break;
        }
        let name_off = u32::from_le_bytes(data[sh..sh + 4].try_into().ok()?) as usize;
        let sh_type = rd_u64(sh + 4)?;
        let offset = rd_u64(sh + 24)? as usize;
        let size = rd_u64(sh + 32)? as usize;
        if sh_type == 8 || size == 0 || offset == 0 {
            continue; // NOBITS or empty
        }
        let end = (offset + size).min(data.len());
        if offset >= end {
            continue;
        }
        let name_start = str_off + name_off;
        let name_end = data[name_start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_start + p)
            .unwrap_or(name_start);
        let name = String::from_utf8_lossy(&data[name_start..name_end.min(data.len())]).to_string();
        out.push(Section {
            name,
            range: offset..end,
        });
    }
    Some(out)
}

/// The candidate regions to scan for the encryption key: initialised data sections.
pub fn candidate_ranges(data: &[u8]) -> Vec<Range<usize>> {
    let sections = pe_sections(data).or_else(|| elf_sections(data));
    let mut ranges: Vec<Range<usize>> = Vec::new();
    if let Some(sections) = sections {
        for s in sections {
            let interesting = s.name.contains(".data")
                || s.name.contains(".rdata")
                || s.name.contains(".rodata")
                || s.name.contains("data");
            if interesting {
                ranges.push(s.range);
            }
        }
    }
    if ranges.is_empty() {
        ranges.push(0..data.len());
    }
    ranges
}

/// Human readable description of the container format.
pub fn container_kind(data: &[u8]) -> &'static str {
    if data.len() >= 4 && &data[0..2] == b"MZ" {
        "PE (Windows)"
    } else if data.len() >= 4 && &data[0..4] == b"\x7fELF" {
        "ELF (Linux/macOS)"
    } else if data.len() >= 4 && &data[0..4] == b"\xcf\xfa\xed\xfe" {
        "Mach-O (macOS)"
    } else if data.len() >= 4 && &data[0..4] == b"\xca\xfe\xba\xbe" {
        "Mach-O fat (macOS)"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_nothing_in_garbage() {
        let data = vec![0u8; 256];
        assert!(pe_sections(&data).is_none());
        assert!(elf_sections(&data).is_none());
        assert_eq!(container_kind(&data), "unknown");
    }
}
