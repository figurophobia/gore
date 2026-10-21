# gore

**Godot Reverse Engineering toolkit** — turn any Godot game into an openable Godot project.

[![CI](https://github.com/figurophobia/gore/actions/workflows/ci.yml/badge.svg)](https://github.com/figurophobia/gore/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/figurophobia/gore)](https://github.com/figurophobia/gore/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`gore` finds the Godot pack inside a game (standalone `.pck`, self-contained `.exe`/`.x86_64`,
or a pack appended to the binary), **recovers the pack encryption key automatically** when the
game uses one, extracts and decrypts the contents, and hands the result over to
[GDRE Tools][gdre] for full project recovery (decompiled GDScript, converted textures, import
files, `project.godot`).

One command, from a binary you downloaded to a project you can open in the Godot editor:

```bash
gore recover "C:\Games\My Game\game.exe" -o ./recovered
gore recover ./game.pck -o ./recovered
```

[gdre]: https://github.com/GDRETools/gdsdecomp

---

## What it looks like

`gore info` tells you everything about the pack without unpacking it:

```
$ gore info Brotato.pck
file             Brotato.pck
size             141.06 MiB (PCK (standalone pack))
pack offset      0
pack version     v1
engine version   3.7.0
flags            0x0000
  dir encrypted  false
  rel file base  false
file base        0
dir offset       84
files            7416
first entry      res://.import/0.png-fc03a4d26944e6367f6a4ff8e557a1b1.stex
last entry       res://zones/zone_data.gdc
```

`gore extract` writes the raw contents and verifies the MD5 of every file when the pack stores
one:

```
* extracting 7416 files to ./raw
* done in 0.6s: 7416 written, 0 decrypted, 0 skipped
```

`gore recover` runs GDRE Tools on the result and leaves a project you can open:

```
* running ~/.local/share/gdre_tools/gdre_tools.x86_64
  --headless
  --recover=Brotato.pck
  --output=./brotato_project
...
Use Godot editor version 3.7.0 to edit the project.
* project recovered into ./brotato_project
```

---

## Why this exists

Recovering a Godot game is a two step job:

1. **Unpack** the `.pck` (and decrypt it if the developer enabled encryption).
2. **Recover the project** (decompile the scripts, convert the imported resources).

Existing tools only cover part of it:

| Tool | Unpacks | Decrypts | Recovers the project | Finds the key |
|---|---|---|---|---|
| [GDRE Tools][gdre] | yes | yes, with a key you type by hand | yes | **no** |
| [KeyDot][keydot] | no | no | no | yes (Windows PE / WASM only) |
| [GodotPCKExplorer][pckexp] | yes | yes, with a key you type by hand | no | no (slow byte scanner) |
| `gore` | yes | yes | yes | **yes, automatically** |

The key is the annoying part: GDRE refuses to open an encrypted pack unless you paste a 64
character hex key, and nothing in the ecosystem reliably tells you where that key came from.
`gore` finds it by brute force with the pack itself acting as the oracle, so you never have to
look for it.

[keydot]: https://github.com/Titoot/KeyDot
[pckexp]: https://github.com/DmitriySalnikov/GodotPCKExplorer

---

## Install

### From a release (recommended)

Download the binary for your platform from the [releases page][releases], unpack it and put
`gore` (`gore.exe` on Windows) in your `PATH`. Builds are provided for Linux and macOS on
x86_64 and arm64, and for Windows on x86_64.

[releases]: https://github.com/figurophobia/gore/releases

### From source

```bash
cargo install --path .          # or: cargo build --release
```

Rust 1.74 or newer.

### GDRE Tools

`gore recover` needs GDRE Tools for the project recovery step. Install it with:

```bash
gore setup
```

It downloads the latest release to `~/.local/share/gore` (use `--dir` to change it) and keeps the
`.so` that ships next to the binary, which GDRE needs. If you already have it, `gore` finds it
automatically in `PATH`, in `GORE_GDRE`, or in the usual folders (`~/.local/share/gdre_tools`,
`~/bin`, `/usr/local/bin`).

---

## Usage

```
gore <COMMAND> [OPTIONS]

Commands:
  info      Show information about the pack inside a Godot game
  key       Recover the pack encryption key
  extract   Extract the pack contents (decrypting them when needed)
  recover   Recover the full Godot project (needs GDRE Tools)
  setup     Download GDRE Tools (the project recovery backend)

Options:
  -k, --key <HEX>     Encryption key as 64 hex characters (recovered automatically when omitted)
  -o, --out <DIR>     Output directory
      --gdre <PATH>   Path to the GDRE Tools binary
      --scan <PATH>   Extra files to scan for the encryption key
      --wordlist <F>  Wordlist for password based key recovery
  -v, --verbose       Print more details
```

`gore recover` takes the game file **or** an already extracted pack directory. The latter is
what you need for games that ship extra packs (a DLC, a patch): see below.

### Examples

Recover a whole project from a game binary:

```bash
gore recover game.exe -o ./game_project
```

Recover from a `.pck` whose key lives in the neighbouring executable (the usual layout):

```bash
gore recover game.pck -o ./game_project
```

A game that ships a DLC as a **second pack** needs both merged. Extract every extra pack
first and the base pack **last**, so the base pack's `project.binary` (the authoritative
project settings) wins, then recover the directory:

```bash
gore extract dlc.pck       -o ./merged
gore extract game.pck      -o ./merged
gore recover ./merged      -o ./game_project
```

`gore recover` warns you when it sees other `.pck` files next to the one you passed, so you
never end up with a project that is missing the DLC.

Just unpack the raw contents, without touching GDRE:

```bash
gore extract game.pck -o ./raw
```

Find out what is inside, and whether it is encrypted:

```bash
gore info game.exe
```

Recover only the key (prints it in hex, so it can be piped into GDRE):

```bash
gore key game.pck
```

Print what `gore recover` would run, without running it:

```bash
gore recover game.pck --dry-run
```

---

## How the key recovery works

The Godot exporter embeds the 256 bit pack key inside the game binary. `gore` uses the pack
itself as an **oracle** to tell a real key from the millions of random 32 byte windows in a
binary:

1. The encrypted file table is read from the pack. Its header is
   `[MD5 of the plaintext][plaintext length][IV][AES-256-CFB ciphertext]`.
2. The table always starts with the length of the first file path, followed by the path itself,
   so a correct key produces a plausible path header and a wrong one produces noise.
3. Every 32 byte window of the binary (or of the executable sitting next to the pack) is tried.
   The first blocks are decrypted and checked against the expected structure — this is cheap
   enough to scan a 1 GB binary in seconds, and it runs on every core.
4. Every surviving candidate is confirmed by decrypting the **whole** file table and comparing
   its MD5, so a reported key is never a false positive.
5. If no key is embedded in the binary, `gore` falls back to a password wordlist, deriving the
   key the way Godot does (`MD5(password)` as its 32 character hex text) or using the password
   verbatim.

The scan runs in tiers, from strict to loose, and stops at the first verified hit: paths that
look like real paths first, then any plausible text, then any printable ASCII. Searching the
data sections (`.data`, `.rdata`, `.rodata`) of PE and ELF binaries first keeps the scan short;
the whole file is searched if that fails.

That is also why encrypted games are rare in practice: enabling pack encryption requires
building custom export templates, so almost every commercial Godot game ships unencrypted.

---

## What `gore` understands

**Pack formats**

| Format | Engine | Verified with |
|---|---|---|
| v0 | Godot 2.x | pack generated with GDRE Tools (Godot 2.1 writes `0.0.0` in the header, so detection relies on the magic and the table sanity) |
| v1 | Godot 3.x | **Brotato** (3.7.0, 7416 files) |
| v2 | Godot 4.x | **Buckshot Roulette** (4.1.1, 3572 files, self contained exe) |
| v3 | Godot 4.x | **Lucid Blocks** (4.6.0, 5951 files) |
| v4 | Godot 4.x | **SNAPTIC Demo** (4.7.1, 7756 files, encrypted) |

**Containers**

* standalone `.pck`;
* packs appended at the end of an executable;
* packs embedded in a PE section (the `pck` section of self contained Windows builds);
* an already extracted directory, to merge several packs before recovery.

**Encryption**

Encrypted file tables and individually encrypted files (AES-256-CFB), with the MD5 of every
file verified after decryption. A wrong key fails loudly instead of writing garbage.

**Binary formats** used by the key search: PE (Windows) and ELF (Linux, macOS).

### Tested games

| Game | Engine | Pack | Encrypted | Result |
|---|---|---|---|---|
| SNAPTIC Demo | 4.7.1 | v4 | yes | key recovered automatically, 7756 files verified |
| Lucid Blocks | 4.6.0 | v3 | no | 5951 files verified |
| Buckshot Roulette | 4.1.1 | v2 | no | self contained exe, 3572 files verified |
| Brotato | 3.7.0 | v1 | no | base pack + DLC pack merged, 9285 files verified |

Every one of them was recovered into a project with no broken references, apart from the
dangling references the games themselves ship (unused `tests/` folders, GDNative bindings for
other stores). Real games run custom engine builds, so use the editor version GDRE reports.

---

## Limitations and things to know

* **APK is not supported.** Packs inside Android packages are not handled; point `gore` at a
  `.pck`, an executable or an extracted directory.
* **Sparse bundle packs are rejected** with an explicit error rather than a confusing crash.
* **Custom engine builds.** Games can ship a patched Godot (Brotato uses 3.7.0 with a `steam`
  feature, Buckshot Roulette needs GodotSteam, Lucid Blocks a `double` precision build). The
  unpacking is unaffected; opening the project in the editor is not, and that is a limitation of
  the engine, not of `gore`.
* **C# projects** are extracted like any other, but recovering the C# side needs the game's
  assembly; `gore` does not pass it to GDRE yet.
* **The output can be big.** Converted textures and audio easily add up to a few gigabytes, so
  point `-o` somewhere with room.
* **Use it on games you are allowed to inspect.** `gore` is a reverse engineering tool; what you
  do with the output is on you, and the output remains covered by the game's licence.

---

## Development

```bash
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
```

The test suite builds synthetic packs for every format (`v0`, `v1`, `v2`, `v4`), an encrypted
pack with a known key, a pack appended to a fake binary and a key hidden in a binary, then checks
that each one is parsed, decrypted and extracted again. Two extra tests cover the CLI surface.

Layout:

| Path | What lives there |
|---|---|
| `src/pck.rs` | header parsing (v0–v4), pack location and file table |
| `src/crypto.rs` | AES-256-CFB, encrypted blob layout, MD5, hex keys |
| `src/keyfind.rs` | the oracle based key search, tiers and wordlist |
| `src/extract.rs` | extraction, decryption, MD5 verification, path sanitising |
| `src/binfmt.rs` | PE/ELF section parsing for the key search |
| `src/gdre.rs` | GDRE Tools lookup and download |
| `src/main.rs` | the CLI |

## License

MIT — see [LICENSE](LICENSE).

`gore` does not include GDRE Tools; it only calls it. GDRE Tools is licensed under its own terms.
