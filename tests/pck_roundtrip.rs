//! End to end tests: build synthetic Godot packs (encrypted and plain) and check that
//! `gore` can parse, decrypt and extract them again.

use gore::crypto::{self, KEY_LEN};
use gore::keyfind::{scan, Oracle, Tier};
use gore::pck::{locate, Pck, PckHeader, PACK_DIR_ENCRYPTED, PACK_FILE_ENCRYPTED, PACK_MAGIC};

/// Encrypts `data` the way Godot's `FileAccessEncrypted` does.
fn encrypt_blob(data: &[u8], key: &[u8; KEY_LEN], iv: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&crypto::md5(data));
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(iv);
    let mut padded = data.to_vec();
    while padded.len() % 16 != 0 {
        padded.push(0);
    }
    let mut prev = *iv;
    for chunk in padded.chunks_mut(16) {
        let ks = crypto::aes_encrypt_block(key, &prev);
        for (i, b) in chunk.iter_mut().enumerate() {
            *b ^= ks[i];
        }
        prev.copy_from_slice(chunk);
    }
    out.extend_from_slice(&padded);
    out
}

/// Builds a pack containing `files` (path -> content), optionally encrypted.
fn build_pack(files: &[(&str, &[u8])], key: Option<&[u8; KEY_LEN]>) -> Vec<u8> {
    let mut data_section: Vec<u8> = Vec::new();
    let mut table: Vec<u8> = Vec::new();

    for (path, content) in files {
        let mut path_bytes = path.as_bytes().to_vec();
        while path_bytes.len() % 4 != 0 {
            path_bytes.push(0);
        }
        // In v3/v4 the entry offset is relative to the pack file base.
        let offset = data_section.len() as u64;
        let (stored, size, flags) = match key {
            Some(key) => {
                let blob = encrypt_blob(content, key, &[0x7bu8; 16]);
                data_section.extend_from_slice(&blob);
                (blob, content.len() as u64, PACK_FILE_ENCRYPTED)
            }
            None => {
                data_section.extend_from_slice(content);
                (content.to_vec(), content.len() as u64, 0)
            }
        };
        let _ = stored;

        table.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
        table.extend_from_slice(&path_bytes);
        table.extend_from_slice(&offset.to_le_bytes());
        table.extend_from_slice(&size.to_le_bytes());
        table.extend_from_slice(&crypto::md5(content));
        table.extend_from_slice(&flags.to_le_bytes());
    }

    let dir_offset = 112 + data_section.len() as u64;
    let mut pack: Vec<u8> = Vec::new();
    pack.extend_from_slice(&PACK_MAGIC.to_le_bytes());
    pack.extend_from_slice(&4u32.to_le_bytes()); // format version
    pack.extend_from_slice(&4u32.to_le_bytes()); // engine major
    pack.extend_from_slice(&3u32.to_le_bytes()); // engine minor
    pack.extend_from_slice(&0u32.to_le_bytes()); // engine patch
    let flags = if key.is_some() { PACK_DIR_ENCRYPTED } else { 0 };
    pack.extend_from_slice(&flags.to_le_bytes());
    pack.extend_from_slice(&112u64.to_le_bytes()); // file base
    pack.extend_from_slice(&dir_offset.to_le_bytes());
    while pack.len() < 112 {
        pack.push(0);
    }
    pack.extend_from_slice(&data_section);
    pack.extend_from_slice(&(files.len() as u32).to_le_bytes());
    match key {
        Some(key) => pack.extend_from_slice(&encrypt_blob(&table, key, &[0x33u8; 16])),
        None => pack.extend_from_slice(&table),
    }
    pack
}

#[test]
fn extracts_a_plain_pack() {
    let files: Vec<(&str, &[u8])> = vec![
        ("res://icon.svg", b"<svg/>"),
        ("res://levels/one.tscn", b"[gd_scene format=3]\n"),
    ];
    let pack = build_pack(&files, None);
    let start = locate(&pack).expect("the pack must be found");
    assert_eq!(start, 0);
    let header = PckHeader::parse(&pack, start, pack.len() as u64).unwrap();
    assert!(!header.dir_encrypted());
    let opened = Pck::open(&pack, header, None).unwrap();
    assert_eq!(opened.entries.len(), 2);
    assert_eq!(opened.entries[0].path, "res://icon.svg");
    assert_eq!(opened.entries[1].path, "res://levels/one.tscn");
}

#[test]
fn extracts_an_encrypted_pack() {
    let key = [0x5au8; KEY_LEN];
    let files: Vec<(&str, &[u8])> = vec![
        ("res://main.gd", b"extends Node\n"),
        (
            "res://art/icon.png",
            &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a],
        ),
    ];
    let pack = build_pack(&files, Some(&key));
    let start = locate(&pack).expect("the pack must be found");
    let header = PckHeader::parse(&pack, start, pack.len() as u64).unwrap();
    assert!(header.dir_encrypted());

    // Without the key the table cannot be read.
    assert!(Pck::open(&pack, header.clone(), None).is_err());
    // With a wrong key the MD5 check rejects it.
    assert!(Pck::open(&pack, header.clone(), Some(&[0u8; KEY_LEN])).is_err());

    let opened = Pck::open(&pack, header, Some(&key)).unwrap();
    assert_eq!(opened.entries.len(), 2);

    // And the files decrypt back to their original content.
    let dir = tempfile::tempdir().unwrap();
    let stats = gore::extract::extract(&pack, &opened, dir.path(), Some(&key)).unwrap();
    assert_eq!(stats.written, 2);
    assert_eq!(stats.decrypted, 2);
    assert!(stats.checksum_errors.is_empty());
    assert_eq!(
        std::fs::read(dir.path().join("main.gd")).unwrap(),
        b"extends Node\n"
    );
    assert_eq!(
        std::fs::read(dir.path().join("art/icon.png")).unwrap(),
        files[1].1
    );
}

#[test]
fn finds_the_key_hidden_in_a_binary() {
    let key = [0x11u8; KEY_LEN];
    let files: Vec<(&str, &[u8])> = vec![("res://main.gd", b"extends Node\n")];
    let pack = build_pack(&files, Some(&key));

    let start = locate(&pack).unwrap();
    let header = PckHeader::parse(&pack, start, pack.len() as u64).unwrap();
    let dir_offset = header.dir_offset as usize + 4;
    let oracle = Oracle::new(&pack[dir_offset..]).unwrap();

    // A fake binary with the key buried in it.
    let mut binary = vec![0xCCu8; 8192];
    binary[4096..4096 + KEY_LEN].copy_from_slice(&key);

    let range = 0..binary.len();
    let hit = scan(
        &binary,
        &oracle,
        std::slice::from_ref(&range),
        1,
        Tier::Strict,
    )
    .expect("key must be found");
    assert_eq!(hit.offset, 4096);
    assert_eq!(hit.key, key);
}

#[test]
fn rejects_a_file_that_is_not_a_pack() {
    let data = vec![0u8; 1024];
    assert!(locate(&data).is_none());
}
