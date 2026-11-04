//! Restores the native libraries of GDExtension plugins in a recovered project.
//!
//! A game ships only the libraries for the platform it was exported for (and only the
//! release build), so a recovered project usually cannot load its GDExtensions in the
//! editor: `fmod`, `spine`, `sentry`, ... are left without the `.so`/`.dll` the editor
//! needs. This module reads every `.gdextension` file, works out which files the
//! editor on this machine will look for and fills the gaps:
//!
//! 1. from the game folder, when the game was exported for this platform;
//! 2. from the upstream release of the plugins gore knows about.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::download;

/// One `.gdextension` file of the project.
#[derive(Debug, Clone)]
pub struct Extension {
    /// The `.gdextension` file.
    pub file: PathBuf,
    /// Plugin name (the folder under `addons/`).
    pub name: String,
    /// `entry_symbol` from `[configuration]`.
    pub entry_symbol: String,
    /// Files the editor on this machine needs, as absolute paths.
    pub needed: Vec<PathBuf>,
}

impl Extension {
    pub fn missing(&self) -> Vec<PathBuf> {
        self.needed
            .iter()
            .filter(|p| !p.exists())
            .cloned()
            .collect()
    }
}

/// What happened to one plugin.
#[derive(Debug)]
pub struct Outcome {
    pub name: String,
    pub restored: usize,
    pub still_missing: Vec<PathBuf>,
    pub source: Option<String>,
}

/// Restores the native libraries of every GDExtension in `project`.
///
/// `game_dir` is the folder the game was recovered from (searched for libraries first)
/// and `engine` the Godot version of the game (`4.5.1`), used to pick plugin builds.
pub fn restore(project: &Path, game_dir: Option<&Path>, engine: Option<&str>) -> Vec<Outcome> {
    let mut outcomes = Vec::new();
    for ext in find_extensions(project) {
        if ext.missing().is_empty() {
            continue;
        }
        let mut source = None;
        let mut restored = 0;

        if let Some(dir) = game_dir {
            let n = copy_from_folder(&ext, dir);
            if n > 0 {
                restored += n;
                source = Some(format!("game folder {}", dir.display()));
            }
        }

        if !ext.missing().is_empty() {
            match fetch_upstream(&ext, project, game_dir, engine) {
                Ok(Some((n, from))) => {
                    restored += n;
                    source = Some(from);
                }
                Ok(None) => {}
                Err(err) => eprintln!("  {}: {err:#}", ext.name),
            }
        }

        outcomes.push(Outcome {
            name: ext.name.clone(),
            restored,
            still_missing: ext.missing(),
            source,
        });
    }
    outcomes
}

/// Every `.gdextension` under `addons/` (or anywhere in the project when there is no
/// `addons/` folder), skipping `.godot/`.
pub fn find_extensions(project: &Path) -> Vec<Extension> {
    let mut files = Vec::new();
    collect(project, 0, &mut files);
    files.sort();
    files
        .into_iter()
        .filter_map(|f| parse_extension(project, &f).ok())
        .collect()
}

fn collect(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 6 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if name.starts_with('.') || name == "bin" || name == "obj" {
                continue;
            }
            collect(&path, depth + 1, out);
        } else if name.ends_with(".gdextension") {
            out.push(path);
        }
    }
}

/// Host feature tags as Godot uses them in `.gdextension` keys.
fn host_tags() -> (&'static str, &'static str) {
    let os = if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86") {
        "x86_32"
    } else {
        "x86_64"
    };
    (os, arch)
}

/// True when a `.gdextension` key (`linux.editor.x86_64`) applies to this host.
fn key_matches_host(key: &str) -> bool {
    let (os, arch) = host_tags();
    let tags: Vec<&str> = key.split('.').map(str::trim).collect();
    if tags.first() != Some(&os) {
        return false;
    }
    const ARCHES: &[&str] = &[
        "x86_64",
        "x86_32",
        "arm64",
        "arm32",
        "rv64",
        "wasm32",
        "universal",
    ];
    let key_arch = tags.iter().find(|t| ARCHES.contains(t));
    match key_arch {
        Some(a) => *a == arch || *a == "universal",
        None => true,
    }
}

/// Parses the parts of a `.gdextension` file gore needs.
pub fn parse_extension(project: &Path, file: &Path) -> Result<Extension> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("cannot read {}", file.display()))?;
    let base = file.parent().unwrap_or(project);
    let name = plugin_name(project, file);

    let mut section = String::new();
    let mut entry_symbol = String::new();
    let mut needed: BTreeSet<PathBuf> = BTreeSet::new();
    // Inside a `key = { ... }` dependency block, whether the key applies to this host.
    let mut in_block: Option<bool> = None;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(applies) = in_block {
            if applies {
                if let Some(path) = first_quoted(line) {
                    if !path.is_empty() {
                        needed.insert(resolve(project, base, &path));
                    }
                }
            }
            if line.contains('}') {
                in_block = None;
            }
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match section.as_str() {
            "configuration" if key == "entry_symbol" => {
                entry_symbol = value.trim_matches('"').to_string();
            }
            "libraries" => {
                if key_matches_host(key) {
                    if let Some(path) = first_quoted(value) {
                        needed.insert(resolve(project, base, &path));
                    }
                }
            }
            "dependencies" => {
                let applies = key_matches_host(key);
                if value.starts_with('{') {
                    if applies {
                        // Single line block: `key = { "a": "", "b": "" }`
                        for path in all_quoted_keys(value) {
                            needed.insert(resolve(project, base, &path));
                        }
                    }
                    if !value.contains('}') {
                        in_block = Some(applies);
                    }
                }
            }
            _ => {}
        }
    }

    // A dependency key such as `linux.x86_64` applies to editor, debug and release
    // alike, but a missing library only hurts for the build that loads it. Keep them all:
    // copying an extra file is harmless.
    Ok(Extension {
        file: file.to_path_buf(),
        name,
        entry_symbol,
        needed: needed.into_iter().collect(),
    })
}

fn plugin_name(project: &Path, file: &Path) -> String {
    let rel = file.strip_prefix(project).unwrap_or(file);
    let mut comps = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string());
    match comps.next().as_deref() {
        Some("addons") => comps.next().unwrap_or_default(),
        _ => file
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default(),
    }
}

fn first_quoted(s: &str) -> Option<String> {
    let start = s.find('"')? + 1;
    let end = start + s[start..].find('"')?;
    Some(s[start..end].to_string())
}

/// The keys of an inline dictionary: `{ "a": "", "b": "x" }` gives `a`, `b`.
fn all_quoted_keys(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in s.trim_matches(|c| c == '{' || c == '}').split(',') {
        if let Some((k, _)) = part.split_once(':') {
            if let Some(q) = first_quoted(k) {
                out.push(q);
            }
        }
    }
    out
}

fn resolve(project: &Path, base: &Path, path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("res://") {
        project.join(rest)
    } else {
        base.join(path)
    }
}

// ---------------------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------------------

/// Copies missing files found (by file name) in the game folder.
fn copy_from_folder(ext: &Extension, dir: &Path) -> usize {
    let mut found = Vec::new();
    list_files(dir, 0, 3, &mut found);
    let mut copied = 0;
    for target in ext.missing() {
        let Some(name) = target.file_name() else {
            continue;
        };
        if let Some(src) = found.iter().find(|p| p.file_name() == Some(name)) {
            if place(src, &target).is_ok() {
                copied += 1;
            }
        }
    }
    copied
}

fn list_files(dir: &Path, depth: usize, max: usize, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            if depth < max {
                list_files(&p, depth + 1, max, out);
            }
        } else {
            out.push(p);
        }
    }
}

fn place(src: &Path, target: &Path) -> Result<()> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(src, target)
        .with_context(|| format!("cannot copy {} to {}", src.display(), target.display()))?;
    Ok(())
}

/// A plugin gore knows where to download.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Known {
    Fmod,
    Spine,
    Sentry,
}

pub fn identify(ext: &Extension) -> Option<Known> {
    match ext.entry_symbol.as_str() {
        "fmod_library_init" => Some(Known::Fmod),
        "spine_godot_library_init" => Some(Known::Spine),
        "sentry_gdextension_init" => Some(Known::Sentry),
        _ => None,
    }
}

/// Downloads the plugin release and copies the missing files out of it.
fn fetch_upstream(
    ext: &Extension,
    project: &Path,
    game_dir: Option<&Path>,
    engine: Option<&str>,
) -> Result<Option<(usize, String)>> {
    let Some(kind) = identify(ext) else {
        return Ok(None);
    };
    let (url, cache_name) = match kind {
        Known::Fmod => fmod_release(engine)?,
        Known::Sentry => sentry_release(game_dir)?,
        Known::Spine => spine_release(project, engine)?,
    };
    eprintln!("* {}: downloading {url}", ext.name);
    let archive = download::fetch_cached(&url, &cache_name)?;
    let n = copy_from_zip(ext, &archive)?;
    Ok(Some((n, url)))
}

/// `major.minor` of an engine version (`4.5.1` gives `4.5`).
fn major_minor(v: &str) -> String {
    v.split('.').take(2).collect::<Vec<_>>().join(".")
}

/// utopia-rise/fmod-gdextension tags look like `6.1.0-4.5.0`: plugin version, then the
/// Godot version it targets. Pick the newest release built for this Godot `major.minor`,
/// or else the newest one built for an older Godot.
fn fmod_release(engine: Option<&str>) -> Result<(String, String)> {
    let releases = download::get_json(
        "https://api.github.com/repos/utopia-rise/fmod-gdextension/releases?per_page=100",
    )?;
    let releases = releases.as_array().cloned().unwrap_or_default();
    let want = engine.map(major_minor);
    let godot_of = |tag: &str| -> Option<(u32, u32)> {
        let g = tag.split_once('-')?.1;
        let mut it = g.split('.').map(|x| x.parse::<u32>().ok());
        Some((it.next()??, it.next()??))
    };
    let want_v = want.as_deref().and_then(|w| {
        let mut it = w.split('.').map(|x| x.parse::<u32>().ok());
        Some((it.next()??, it.next()??))
    });
    let pick = releases
        .iter()
        .filter(|r| {
            !r.get("prerelease")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        })
        .filter_map(|r| {
            let tag = r.get("tag_name")?.as_str()?.to_string();
            let g = godot_of(&tag)?;
            Some((tag, g, r))
        })
        .filter(|(_, g, _)| want_v.map_or(true, |w| *g <= w))
        // The API lists newest first, so the first exact match (or the first older
        // one when there is none) is the release to use.
        .min_by_key(|(_, g, _)| match want_v {
            Some(w) if *g == w => 0,
            _ => 1,
        })
        .ok_or_else(|| anyhow::anyhow!("no fmod-gdextension release fits Godot {want:?}"))?;
    let (tag, _, release) = pick;
    let asset = release
        .get("assets")
        .and_then(|a| a.as_array())
        .and_then(|a| {
            a.iter()
                .find(|x| x.get("name").and_then(|n| n.as_str()) == Some("addons.zip"))
        })
        .and_then(|x| x.get("browser_download_url"))
        .and_then(|u| u.as_str())
        .ok_or_else(|| anyhow::anyhow!("fmod-gdextension {tag} has no addons.zip"))?;
    Ok((asset.to_string(), format!("fmod-gdextension-{tag}.zip")))
}

/// getsentry/sentry-godot: use the version the game shipped (it is embedded in the
/// library as `2.1.0+f8cb981`), or else the latest release.
fn sentry_release(game_dir: Option<&Path>) -> Result<(String, String)> {
    let version = game_dir.and_then(sentry_version_in);
    let url = match &version {
        Some(v) => format!(
            "https://api.github.com/repos/getsentry/sentry-godot/releases/tags/{}",
            v.split('+').next().unwrap_or(v)
        ),
        None => "https://api.github.com/repos/getsentry/sentry-godot/releases/latest".into(),
    };
    let release = download::get_json(&url).or_else(|_| {
        download::get_json("https://api.github.com/repos/getsentry/sentry-godot/releases/latest")
    })?;
    let tag = release
        .get("tag_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let asset = release
        .get("assets")
        .and_then(|a| a.as_array())
        .and_then(|a| {
            a.iter().find(|x| {
                let n = x.get("name").and_then(|n| n.as_str()).unwrap_or("");
                n.starts_with("sentry-godot-")
                    && n.ends_with(".zip")
                    && !n.contains("debug-symbols")
                    && !n.contains("demo")
            })
        })
        .and_then(|x| x.get("browser_download_url"))
        .and_then(|u| u.as_str())
        .ok_or_else(|| anyhow::anyhow!("sentry-godot {tag} has no plugin zip"))?;
    Ok((asset.to_string(), format!("sentry-godot-{tag}.zip")))
}

fn sentry_version_in(dir: &Path) -> Option<String> {
    let mut files = Vec::new();
    list_files(dir, 0, 3, &mut files);
    let lib = files.iter().find(|p| {
        p.file_name()
            .map(|n| n.to_string_lossy().starts_with("libsentry."))
            .unwrap_or(false)
    })?;
    let data = std::fs::read(lib).ok()?;
    find_version_with_hash(&data)
}

/// Finds `X.Y.Z+abcdef1` (a version followed by a short commit hash) in a binary.
fn find_version_with_hash(data: &[u8]) -> Option<String> {
    let is_digit = |b: u8| b.is_ascii_digit();
    let n = data.len();
    let mut i = 0;
    while i < n {
        if !is_digit(data[i]) || (i > 0 && (is_digit(data[i - 1]) || data[i - 1] == b'.')) {
            i += 1;
            continue;
        }
        let start = i;
        let mut dots = 0;
        let mut j = i;
        while j < n && (is_digit(data[j]) || data[j] == b'.') {
            if data[j] == b'.' {
                dots += 1;
            }
            j += 1;
        }
        if dots == 2 && j < n && data[j] == b'+' {
            let mut k = j + 1;
            while k < n && data[k].is_ascii_hexdigit() {
                k += 1;
            }
            let hash_len = k - j - 1;
            let ends_clean = k >= n || data[k] == 0;
            if (7..=12).contains(&hash_len) && ends_clean {
                return Some(String::from_utf8_lossy(&data[start..k]).to_string());
            }
        }
        i = j.max(i + 1);
    }
    None
}

/// Esoteric Software publishes spine-godot GDExtension builds per Spine runtime branch
/// and Godot tag: `https://spine-godot.s3.eu-central-1.amazonaws.com/4.2/4.5.1-stable/
/// spine-godot-extension-4.2-4.5.1-stable.zip`.
fn spine_release(project: &Path, engine: Option<&str>) -> Result<(String, String)> {
    const BASE: &str = "https://spine-godot.s3.eu-central-1.amazonaws.com";
    let engine = engine.ok_or_else(|| {
        anyhow::anyhow!("the Godot version is unknown, cannot pick a spine-godot build")
    })?;
    let mut branches: Vec<String> = Vec::new();
    if let Some(b) = spine_runtime_in(project) {
        branches.push(b);
    }
    for b in ["4.2", "4.3", "4.1"] {
        if !branches.iter().any(|x| x == b) {
            branches.push(b.to_string());
        }
    }
    let tag = format!("{engine}-stable");
    for branch in &branches {
        let name = format!("spine-godot-extension-{branch}-{tag}.zip");
        let url = format!("{BASE}/{branch}/{tag}/{name}");
        if download::exists(&url) {
            return Ok((url, name));
        }
    }
    anyhow::bail!(
        "no spine-godot GDExtension build found for Godot {engine} (tried Spine {})",
        branches.join(", ")
    )
}

/// Spine runtime branch (`4.2`) from the first skeleton file of the project.
fn spine_runtime_in(project: &Path) -> Option<String> {
    let mut stack = vec![project.to_path_buf()];
    let mut checked = 0;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if p.is_dir() {
                if !name.starts_with('.') {
                    stack.push(p);
                }
                continue;
            }
            let is_skel = name.ends_with(".skel") || name.ends_with(".spine-json");
            if !is_skel {
                continue;
            }
            checked += 1;
            if checked > 20 {
                return None;
            }
            let Ok(data) = std::fs::read(&p) else {
                continue;
            };
            // Both formats store the editor version (`4.2.43`) near the start.
            let head = &data[..data.len().min(256)];
            let text = String::from_utf8_lossy(head);
            if let Some(pos) = text.find("4.") {
                let v: String = text[pos..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                let mm = major_minor(&v);
                if mm.len() >= 3 {
                    return Some(mm);
                }
            }
        }
    }
    None
}

/// Copies the missing files out of a plugin archive. Entries are matched by file name,
/// preferring the one whose path shares the longest tail with the target
/// (`bin/linux/x86_64/crashpad_handler` over `bin/linux/arm64/crashpad_handler`).
fn copy_from_zip(ext: &Extension, archive: &Path) -> Result<usize> {
    let file = std::fs::File::open(archive)?;
    let mut zip =
        zip::ZipArchive::new(file).with_context(|| format!("cannot open {}", archive.display()))?;
    let names: Vec<String> = (0..zip.len())
        .filter_map(|i| zip.by_index(i).ok().map(|e| e.name().to_string()))
        .collect();

    let mut copied = 0;
    for target in ext.missing() {
        let target_parts: Vec<String> = target
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .collect();
        let Some(target_name) = target_parts.last().cloned() else {
            continue;
        };
        let best = names
            .iter()
            .filter(|n| !n.ends_with('/'))
            .filter(|n| n.rsplit('/').next() == Some(target_name.as_str()))
            .max_by_key(|n| {
                n.rsplit('/')
                    .zip(target_parts.iter().rev())
                    .take_while(|(a, b)| a == b)
                    .count()
            });
        let Some(best) = best else {
            continue;
        };
        let mut entry = zip.by_name(best)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = std::fs::File::create(&target)
            .with_context(|| format!("cannot create {}", target.display()))?;
        std::io::copy(&mut entry, &mut out)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = entry.unix_mode().unwrap_or(0o644) & 0o777;
            let mode = if mode == 0 { 0o644 } else { mode };
            // Shared libraries and helpers such as `crashpad_handler` must be executable.
            let mode = if target_name.ends_with(".gdextension") {
                mode
            } else {
                mode | 0o111
            };
            let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode));
        }
        copied += 1;
    }
    Ok(copied)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_libraries_and_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        let addon = dir.path().join("addons/demo");
        std::fs::create_dir_all(&addon).unwrap();
        let file = addon.join("demo.gdextension");
        std::fs::write(
            &file,
            r#"[configuration]
entry_symbol = "demo_init"

[libraries]
windows.release.x86_64 = "res://addons/demo/win/demo.dll"
linux.editor.x86_64 = "res://addons/demo/linux/demo.editor.so"
linux.release.arm64 = "linux/demo.arm64.so"
macos.release = "mac/demo.dylib"

[dependencies]
linux.x86_64 = {
	"res://addons/demo/linux/helper" : ""
}
windows.x86_64 = { "res://addons/demo/win/helper.exe": "" }
"#,
        )
        .unwrap();
        let ext = parse_extension(dir.path(), &file).unwrap();
        assert_eq!(ext.name, "demo");
        assert_eq!(ext.entry_symbol, "demo_init");
        let needed: Vec<String> = ext
            .needed
            .iter()
            .map(|p| p.strip_prefix(dir.path()).unwrap().display().to_string())
            .collect();
        if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            assert_eq!(
                needed,
                vec![
                    "addons/demo/linux/demo.editor.so",
                    "addons/demo/linux/helper"
                ]
            );
        }
    }

    #[test]
    fn finds_sentry_style_versions() {
        let data = b"\0junk 1.2\0sentry 2.1.0+f8cb981\0more";
        assert_eq!(
            find_version_with_hash(data).as_deref(),
            Some("2.1.0+f8cb981")
        );
        assert_eq!(find_version_with_hash(b"0.15.3\0"), None);
    }
}
