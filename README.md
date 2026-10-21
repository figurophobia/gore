# gore

**Godot Reverse Engineering toolkit** — turn any Godot game into an openable Godot project.

`gore` finds the Godot pack inside a game (standalone `.pck`, self-contained `.exe`/`.x86_64`),
**recovers the pack encryption key automatically** when the game uses one, extracts and
decrypts the contents, and hands the result over to [GDRE Tools][gdre] for full project recovery
(decompiled GDScript, converted textures, import files, `project.godot`).

One command, from a binary you downloaded to a project you can open in the Godot editor.

```
gore recover "C:\Games\My Game\game.exe" -o ./recovered
```

[gdre]: https://github.com/GDRETools/gdsdecomp

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

Download the binary for your platform from the [releases page][releases] and put it in your `PATH`.

[releases]: https://github.com/figurophobia/gore/releases

### From source

```bash
cargo install --path .          # or: cargo build --release
```

### GDRE Tools

`gore recover` needs GDRE Tools for the project recovery step. Install it with:

```bash
gore setup
```

It downloads the latest release to `~/.local/share/gore` (use `--dir` to change it). If you already
have it, `gore` finds it automatically in `PATH`, in `GORE_GDRE`, or in the usual folders
(`~/.local/share/gdre_tools`, `~/bin`, `/usr/local/bin`).

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

### Examples

Recover a whole project from a game binary:

```bash
gore recover game.exe -o ./game_project
```

Recover from a `.pck` whose key lives in the neighbouring executable (the usual layout):

```bash
gore recover game.pck -o ./game_project
```

A game that ships a DLC as a **second pack** needs both merged. Extract each pack into the
same directory (the DLC last, so it overwrites) and recover that directory:

```bash
gore extract game.pck      -o ./merged
gore extract dlc.pck       -o ./merged
gore recover ./merged      -o ./game_project
```

`gore recover` warns you when it sees other `.pck` files next to the one you passed.

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

Searching the data sections (`.data`, `.rdata`, `.rodata`) of PE and ELF binaries first keeps
the scan short; the whole file is searched if that fails.

---

## What `gore` understands

* **Pack formats** v0 (Godot 2.x), v1 (Godot 3.x), v2, v3 and v4 (Godot 4.x). Encrypted packs need the
  key; `gore` finds it on its own in the usual cases.
* **Containers**: standalone `.pck`, packs appended to an executable, packs embedded in a PE
  section (the `pck` section of self contained Windows builds).
* **Encryption**: encrypted file tables and individually encrypted files, AES-256-CFB, with the
  MD5 of every file verified after decryption.
* **Binary formats** for the key search: PE (Windows) and ELF (Linux, macOS).

## Supported engines

| Game | Engine | Pack | Encrypted | Result |
|---|---|---|---|---|
| SNAPTIC Demo | 4.7.1 | v4 | yes | key recovered automatically, 7756 files verified |
| Lucid Blocks | 4.6.0 | v3 | no | 5951 files verified |
| Buckshot Roulette | 4.1.1 | v2 | no | self contained exe, 3572 files verified |
| Brotato | 3.7.0 | v1 | no | base pack + DLC pack merged, 9285 files verified |

Godot 3.x games (`v1` packs) and Godot 2.x games (`v0` packs) are supported too: they are not
encrypted, so there is no key to look for.

---

## Development

```bash
cargo build --release
cargo test
```

The test suite builds synthetic encrypted packs and checks that they can be parsed, decrypted
and extracted again.

## License

MIT — see [LICENSE](LICENSE).

`gore` does not include GDRE Tools; it only calls it. GDRE Tools is licensed under its own terms.
