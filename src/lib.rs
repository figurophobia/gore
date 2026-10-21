//! `gore` — Godot Reverse Engineering toolkit.
//!
//! The library half of the tool: parsing Godot packs, decrypting them and recovering
//! the pack encryption key from a game binary.

pub mod binfmt;
pub mod crypto;
pub mod extract;
pub mod gdre;
pub mod keyfind;
pub mod pck;
