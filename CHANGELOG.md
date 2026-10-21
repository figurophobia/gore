# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.3] — 2026-10-21

### Added

* `CHANGELOG.md`, and a README rewritten around what the tool actually does: real output, pack
  format support, tested games, and the limitations.

### Fixed

* `gore info` called standalone packs `unknown`; it now says `PCK (standalone pack)`.

## [0.3.2] — 2026-10-21

### Fixed

* `gore` no longer panics when the reader of its output disappears
  (`gore info game.pck | head`). It restores the default `SIGPIPE` handling on Unix and exits
  quietly like any other command line tool.

## [0.3.1] — 2026-10-21

### Changed

* The DLC merge instructions (README and the warning printed by `gore recover`) now say to
  extract the extra packs first and the base pack **last**. Only `project.binary` differs
  between the base pack and a DLC pack, and the base one is authoritative, so extracting it last
  keeps settings such as `_custom_features`.

## [0.3.0] — 2026-10-21

### Added

* `gore recover` accepts an already extracted directory. This is how you recover a game whose
  DLC or patch ships as a separate pack: extract both into one directory and recover that.
* `gore recover` warns when other `.pck` files sit next to the one given.
* `gore info` names standalone packs as `PCK (standalone pack)` instead of `unknown`.
* The release workflow fails when the tag does not match the version in `Cargo.toml`.

### Fixed

* `gore info`/`extract` on a directory reported `No such device` (it tried to memory map the
  directory); it now explains that only `recover` takes directories.
* The crate version was still `0.1.0` in builds published as newer releases.

### Tested

* Brotato: two packs, Godot 3.7.0, pack `v1`, 9285 files, all MD5s verified.

## [0.2.0] — 2026-10-21

### Added

* Godot 2.x support (pack `v0`), where the header carries no engine version and the file table
  has no flags or MD5s.
* Pack detection now validates that the file table actually fits inside the file before
  accepting a candidate, which avoids bogus matches in large binaries.

### Fixed

* **Pack `v2`: file offsets are relative to `file_base`** (as in `v3`/`v4`). They were used as
  absolute, which silently produced corrupt files for Godot 4.0/4.1 games.
* **Pack `v1`: file paths padded with NUL bytes** (as written by some exporters) are trimmed
  before writing them to disk.

### Tested

* Buckshot Roulette: self contained executable, Godot 4.1.1, pack `v2`, 3572 files, all MD5s
  verified.

## [0.1.1] — 2026-10-21

### Fixed

* Release archives keep the expected binary name (`gore`, `gore.exe`).
* Windows archives are built with PowerShell's `Compress-Archive`.

## [0.1.0] — 2026-10-21

### Added

* Locate the pack inside a standalone `.pck`, a self contained executable, or a pack appended to
  the binary.
* Parse pack formats `v2` to `v4` (Godot 4.x), with `v1` (Godot 3.x) detection, and extract
  their contents, verifying the MD5 of every file.
* Read encrypted file tables and individually encrypted files (AES-256-CFB).
* Recover the pack key automatically by scanning the game binary with the pack as an oracle,
  with the file table MD5 as the final check, plus a password wordlist fallback.
* Hand the unpacked game over to GDRE Tools, downloading it with `gore setup`.
* Cross platform releases: Linux and macOS (x86_64, arm64) and Windows (x86_64).

### Tested

* SNAPTIC Demo: Godot 4.7.1, pack `v4`, encrypted, key recovered automatically, 7756 files.
* Lucid Blocks: Godot 4.6.0, pack `v3`, 5951 files.

[Unreleased]: https://github.com/figurophobia/gore/compare/v0.3.3...HEAD
[0.3.3]: https://github.com/figurophobia/gore/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/figurophobia/gore/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/figurophobia/gore/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/figurophobia/gore/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/figurophobia/gore/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/figurophobia/gore/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/figurophobia/gore/releases/tag/v0.1.0
