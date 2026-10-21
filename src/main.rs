//! `gore` — Godot Reverse Engineering toolkit.
//!
//! Turns a Godot game (`.pck`, `.exe`, self contained binary) into an openable
//! Godot project, recovering the pack encryption key automatically when needed.

use gore::binfmt;
use gore::crypto;
use gore::extract;
use gore::gdre;
use gore::keyfind;
use gore::pck;

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use memmap2::Mmap;

use gore::crypto::KEY_LEN;
use gore::keyfind::{Oracle, Tier};
use gore::pck::{Pck, PckHeader};

#[derive(Parser, Debug)]
#[command(
    name = "gore",
    version,
    about = "Turn any Godot game into an openable Godot project.",
    long_about = "gore locates the Godot pack inside a game (standalone .pck, self contained \
                  .exe/.x86_64), recovers the pack encryption key when it is needed, \
                  extracts the contents and hands the project over to GDRE Tools for full \
                  recovery (decompiled scripts, converted resources)."
)]
struct Cli {
    /// Encryption key as 64 hex characters (recovered automatically when omitted)
    #[arg(short = 'k', long, global = true, value_name = "HEX")]
    key: Option<String>,

    /// Output directory
    #[arg(short = 'o', long, global = true, value_name = "DIR")]
    out: Option<PathBuf>,

    /// Path to the GDRE Tools binary
    #[arg(long, global = true, value_name = "PATH")]
    gdre: Option<PathBuf>,

    /// Extra files to scan for the encryption key
    #[arg(long, global = true, value_name = "PATH")]
    scan: Vec<PathBuf>,

    /// Wordlist used for password based key recovery
    #[arg(long, global = true, value_name = "FILE")]
    wordlist: Option<PathBuf>,

    /// Print more details
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Show information about the pack inside a Godot game
    Info {
        /// The game file (.pck, .exe, .x86_64, ...)
        file: PathBuf,
        /// Do not try to recover the encryption key
        #[arg(long)]
        no_key: bool,
    },
    /// Recover the pack encryption key
    Key {
        /// The game file
        file: PathBuf,
    },
    /// Extract the pack contents (decrypting them when needed)
    Extract {
        /// The game file
        file: PathBuf,
    },
    /// Recover the full Godot project (needs GDRE Tools)
    Recover {
        /// The game file, or an already extracted pack directory (handy to merge
        /// a base pack with a DLC shipped as a separate pack)
        file: PathBuf,
        /// Only print the command that would be run
        #[arg(long)]
        dry_run: bool,
    },
    /// Download GDRE Tools (the project recovery backend)
    Setup {
        /// Installation directory
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
    },
}

fn main() {
    if let Err(err) = run() {
        eprintln!("gore: error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Command::Info { file, no_key } => cmd_info(&cli, file, *no_key),
        Command::Key { file } => cmd_key(&cli, file),
        Command::Extract { file } => cmd_extract(&cli, file),
        Command::Recover { file, dry_run } => cmd_recover(&cli, file, *dry_run),
        Command::Setup { dir } => cmd_setup(&cli, dir.clone()),
    }
}

/// A mapped game file plus the pack header found inside it.
struct Game {
    path: PathBuf,
    data: Mmap,
    header: PckHeader,
}

impl Game {
    fn open(path: &Path) -> Result<Game> {
        if path.is_dir() {
            bail!(
                "{} is a directory (only `gore recover` accepts an extracted project directory)",
                path.display()
            );
        }
        let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        let len = file.metadata()?.len();
        if len == 0 {
            bail!("{} is empty", path.display());
        }
        // SAFETY: the file is opened read only and we only read from the map.
        let data = unsafe { Mmap::map(&file)? };
        let start = pck::locate(&data)
            .with_context(|| format!("no Godot pack found in {}", path.display()))?;
        let header = PckHeader::parse(&data, start, data.len() as u64)
            .with_context(|| format!("cannot parse the pack header in {}", path.display()))?;
        Ok(Game {
            path: path.to_path_buf(),
            data,
            header,
        })
    }

    /// The encrypted file table (only present when the directory is encrypted).
    fn encrypted_dir(&self) -> Option<Vec<u8>> {
        if !self.header.dir_encrypted() {
            return None;
        }
        let start = self.header.dir_offset as usize + 4;
        self.data.get(start..).map(|s| s.to_vec())
    }
}

fn cmd_info(cli: &Cli, file: &Path, no_key: bool) -> Result<()> {
    let game = Game::open(file)?;
    let header = &game.header;
    println!("file             {}", game.path.display());
    println!(
        "size             {:.2} MiB ({})",
        game.data.len() as f64 / (1024.0 * 1024.0),
        binfmt::container_kind(&game.data)
    );
    println!("pack offset      {}", header.start);
    println!("pack version     v{}", header.format_version);
    if header.format_version == pck::PACK_FORMAT_V0 {
        // Godot 2.x leaves the engine version fields empty.
        println!("engine version   2.x (legacy)");
    } else {
        println!(
            "engine version   {}.{}.{}",
            header.engine_major, header.engine_minor, header.engine_patch
        );
    }
    println!("flags            {:#06x}", header.flags);
    println!("  dir encrypted  {}", header.dir_encrypted());
    println!("  rel file base  {}", header.rel_filebase());
    println!("file base        {}", header.file_base);
    println!("dir offset       {}", header.dir_offset);

    let mut key: Option<[u8; KEY_LEN]> = cli.key.as_deref().and_then(parse_key);
    if header.dir_encrypted() && key.is_none() && !no_key {
        eprintln!("* directory is encrypted, recovering the key...");
        key = recover_key(cli, &game)?;
    }

    match key {
        Some(k) => {
            println!("key              {}", crypto::format_hex_key(&k));
            match Pck::open(&game.data, header.clone(), Some(&k)) {
                Ok(p) => print_entries(&p),
                Err(e) => eprintln!("* cannot open the pack with that key: {e:#}"),
            }
        }
        None => {
            if header.dir_encrypted() {
                println!("key              <unknown, run `gore key` to recover it>");
            } else {
                match Pck::open(&game.data, header.clone(), None) {
                    Ok(p) => print_entries(&p),
                    Err(e) => eprintln!("* cannot read the file table: {e:#}"),
                }
            }
        }
    }
    Ok(())
}

fn print_entries(p: &Pck) {
    let encrypted = p.entries.iter().filter(|e| e.encrypted()).count();
    let removed = p.entries.iter().filter(|e| e.removed()).count();
    println!("files            {}", p.entries.len());
    if encrypted > 0 {
        println!("  encrypted      {encrypted}");
    }
    if removed > 0 {
        println!("  removed        {removed}");
    }
    if let Some(first) = p.entries.first() {
        println!("first entry      {}", first.path);
    }
    if let Some(last) = p.entries.last() {
        println!("last entry       {}", last.path);
    }
}

fn cmd_key(cli: &Cli, file: &Path) -> Result<()> {
    let game = Game::open(file)?;
    if !game.header.dir_encrypted() {
        println!("the pack directory is not encrypted, no key needed");
        return Ok(());
    }
    if let Some(key) = cli.key.as_deref().and_then(parse_key) {
        println!("{}", crypto::format_hex_key(&key));
        return Ok(());
    }
    match recover_key(cli, &game)? {
        Some(key) => {
            println!("{}", crypto::format_hex_key(&key));
            Ok(())
        }
        None => bail!("could not recover the encryption key automatically, provide it with --key"),
    }
}

fn cmd_extract(cli: &Cli, file: &Path) -> Result<()> {
    let game = Game::open(file)?;
    let out = cli
        .out
        .clone()
        .unwrap_or_else(|| default_out(&game.path, "extracted"));
    let key = match cli.key.as_deref().and_then(parse_key) {
        Some(k) => Some(k),
        None => {
            if game.header.dir_encrypted() {
                eprintln!("* directory is encrypted, recovering the key...");
                recover_key(cli, &game)?
            } else {
                None
            }
        }
    };
    let pck =
        Pck::open(&game.data, game.header.clone(), key.as_ref()).context("cannot open the pack")?;
    eprintln!(
        "* extracting {} files to {}",
        pck.entries.len(),
        out.display()
    );
    let start = Instant::now();
    let stats = extract::extract(&game.data, &pck, &out, key.as_ref())?;
    eprintln!(
        "* done in {:.1}s: {} written, {} decrypted, {} skipped",
        start.elapsed().as_secs_f64(),
        stats.written,
        stats.decrypted,
        stats.skipped
    );
    if !stats.checksum_errors.is_empty() {
        eprintln!(
            "* warning: {} files failed the MD5 check (first: {})",
            stats.checksum_errors.len(),
            stats.checksum_errors[0]
        );
    }
    Ok(())
}

fn cmd_recover(cli: &Cli, file: &Path, dry_run: bool) -> Result<()> {
    let gdre_path = gdre::locate(cli.gdre.as_deref()).ok_or_else(|| {
        anyhow::anyhow!(
            "GDRE Tools was not found. Install it with `gore setup` or point at it with --gdre."
        )
    })?;

    // A directory is already an unpacked project. This is what you want when a
    // game ships extra packs (a DLC, for instance): extract every pack into the
    // same directory, later packs overwriting earlier ones, and recover that.
    let (target, key) = if file.is_dir() {
        (file.to_path_buf(), None)
    } else {
        let game = Game::open(file)?;
        let key = match cli.key.as_deref().and_then(parse_key) {
            Some(k) => Some(k),
            None => {
                if game.header.dir_encrypted() {
                    eprintln!("* directory is encrypted, recovering the key...");
                    recover_key(cli, &game)?
                } else {
                    None
                }
            }
        };
        (game.path.clone(), key)
    };

    let out = cli
        .out
        .clone()
        .unwrap_or_else(|| default_out(&target, "recovered"));

    if !file.is_dir() {
        if let Some(siblings) = sibling_packs(&target) {
            eprintln!("* other packs next to this one: {}", siblings.join(", "));
            eprintln!(
                "* if they are DLC or patches, merge them into a directory first (extras first, \
                 this base pack last so its project.binary wins) and recover that directory \
                 with `gore recover <dir>`"
            );
        }
    }

    let mut args: Vec<String> = vec![
        "--headless".to_string(),
        format!("--recover={}", target.display()),
    ];
    if let Some(k) = key.as_ref() {
        args.push(format!("--key={}", crypto::format_hex_key(k)));
    }
    args.push(format!("--output={}", out.display()));

    eprintln!("* running {}", gdre_path.display());
    for a in &args {
        eprintln!("  {a}");
    }
    if dry_run {
        return Ok(());
    }
    gdre::run(&gdre_path, &args)?;
    eprintln!("* project recovered into {}", out.display());
    Ok(())
}

/// Other `.pck` files shipped next to `target` (a DLC distributed as its own pack).
fn sibling_packs(target: &Path) -> Option<Vec<String>> {
    let dir = target.parent()?;
    let stem = target.file_stem()?.to_string_lossy().to_lowercase();
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("pck"))
        })
        .filter(|e| {
            e.path()
                .file_stem()
                .map(|s| s.to_string_lossy().to_lowercase() != stem)
                .unwrap_or(false)
        })
        .filter_map(|e| e.file_name().to_str().map(str::to_owned))
        .collect();
    names.sort();
    (!names.is_empty()).then_some(names)
}

fn cmd_setup(cli: &Cli, dir: Option<PathBuf>) -> Result<()> {
    let dest = dir.unwrap_or_else(|| {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        home.join(".local/share/gore")
    });
    let installed = gdre::download_latest(&dest)?;
    println!("{}", installed.display());
    let _ = cli;
    Ok(())
}

fn default_out(input: &Path, suffix: &str) -> PathBuf {
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "godot_game".to_string());
    PathBuf::from(format!("{stem}_{suffix}"))
}

fn parse_key(s: &str) -> Option<[u8; KEY_LEN]> {
    crypto::parse_hex_key(s).or_else(|| {
        eprintln!("gore: the key must be 64 hex characters");
        None
    })
}

/// Recovers the pack encryption key.
///
/// Strategy list, from fast to exhaustive:
///  1. the `--key` option,
///  2. scan the game binary (and its siblings) for the key blob, validated with the
///     pack itself as an oracle,
///  3. password wordlist.
fn recover_key(cli: &Cli, game: &Game) -> Result<Option<[u8; KEY_LEN]>> {
    let dir_data = game
        .encrypted_dir()
        .context("the pack directory is not encrypted")?;
    let oracle = Oracle::new(&dir_data).context("cannot read the encrypted file table")?;

    let sources = key_sources(cli, game);
    if sources.is_empty() {
        eprintln!("* no candidate file to scan for the key");
    }

    for source in &sources {
        let data = match File::open(source) {
            Ok(f) => match unsafe { Mmap::map(&f) } {
                Ok(m) => m,
                Err(_) => continue,
            },
            Err(_) => continue,
        };
        let ranges = binfmt::candidate_ranges(&data);
        let total: usize = ranges.iter().map(|r| r.len()).sum();
        eprintln!(
            "* scanning {} ({:.1} MiB of data sections) for the key",
            source.display(),
            total as f64 / (1024.0 * 1024.0)
        );
        let started = Instant::now();

        // The pack is the oracle: only a key that really decrypts the file table is
        // accepted, so false positives are impossible.
        let verify = |key: &[u8; KEY_LEN]| -> bool {
            Pck::open(data_view(game), game.header.clone(), Some(key)).is_ok()
        };

        for (tier, step, narrowed) in [
            (Tier::Strict, 1, true),
            (Tier::Loose, 1, true),
            (Tier::Strict, 8, false),
            (Tier::Strict, 1, false),
            (Tier::Loose, 8, false),
            (Tier::Loose, 1, false),
            (Tier::Weak, 8, false),
            (Tier::Weak, 1, false),
        ] {
            let scan_ranges: Vec<std::ops::Range<usize>> = if narrowed {
                ranges.clone()
            } else {
                let whole = 0..data.len();
                vec![whole]
            };
            let hit = keyfind::scan_verified(&data, &oracle, &scan_ranges, step, tier, &verify);
            if let Some(hit) = hit {
                eprintln!(
                    "* key found at offset {} of {} ({:.1}s)",
                    hit.offset,
                    source.display(),
                    started.elapsed().as_secs_f64()
                );
                return Ok(Some(hit.key));
            }
        }
    }

    // Password based recovery.
    let passwords = load_wordlist(cli)?;
    if !passwords.is_empty() {
        eprintln!("* trying {} passwords", passwords.len());
        if let Some(hit) = keyfind::try_passwords(&oracle, &passwords) {
            eprintln!("* key recovered from the wordlist");
            return Ok(Some(hit.key));
        }
    }
    Ok(None)
}

/// Small helper so the verification closure can borrow the game's data.
fn data_view(game: &Game) -> &[u8] {
    &game.data
}

/// The files that may contain the key: the game binary itself and its siblings.
fn key_sources(cli: &Cli, game: &Game) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let push = |p: PathBuf, out: &mut Vec<PathBuf>| {
        if !out.contains(&p) {
            out.push(p);
        }
    };

    // The input file, unless it is the pack itself (a pack holds no key).
    let input_is_pack = game.header.start == 0 && &game.data[0..4] == b"GDPC";
    if !input_is_pack {
        push(game.path.clone(), &mut out);
    }

    // Sibling files: the executable usually sits next to the .pck.
    if let Some(dir) = game.path.parent() {
        if let Ok(entries) = std::fs::read_dir(dir) {
            let mut siblings: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p != &game.path && p.is_file())
                .filter(|p| {
                    let ext = p
                        .extension()
                        .map(|e| e.to_string_lossy().to_lowercase())
                        .unwrap_or_default();
                    matches!(
                        ext.as_str(),
                        "exe" | "x86_64" | "x86_32" | "bin" | "dll" | "so" | "dylib"
                    ) || (ext.is_empty()
                        && std::fs::metadata(p)
                            .map(|m| m.len() > 1 << 20)
                            .unwrap_or(false))
                })
                .collect();
            siblings.sort();
            for s in siblings {
                push(s, &mut out);
            }
        }
    }

    for extra in &cli.scan {
        push(extra.clone(), &mut out);
    }
    out
}

fn load_wordlist(cli: &Cli) -> Result<Vec<String>> {
    if let Some(path) = &cli.wordlist {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read the wordlist {}", path.display()))?;
        Ok(text
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect())
    } else {
        Ok(keyfind::DEFAULT_PASSWORDS
            .iter()
            .map(|s| s.to_string())
            .collect())
    }
}
