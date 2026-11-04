//! Finding out which Godot editor a recovered project needs, and installing it.
//!
//! A recovered project must be opened with the same Godot version the game was made
//! with, and a C# game needs the .NET ("mono") build of the editor: the regular build
//! cannot load `.cs` scripts at all and reports them as missing dependencies.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::download;

/// The editor a project needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditorSpec {
    /// Full version, e.g. `4.5.1` (a pre-release looks like `4.6-beta2`).
    pub version: String,
    /// True for the .NET build.
    pub mono: bool,
}

impl EditorSpec {
    /// `4.5.1-stable` (or `4.6-beta2` for pre-releases).
    pub fn tag(&self) -> String {
        if self.version.contains('-') {
            self.version.clone()
        } else {
            format!("{}-stable", self.version)
        }
    }

    pub fn label(&self) -> String {
        if self.mono {
            format!("Godot {} (.NET)", self.version)
        } else {
            format!("Godot {}", self.version)
        }
    }
}

/// Works out the editor version for a recovered project.
///
/// Sources, most precise first: the `Godot.NET.Sdk/x.y.z` of the C# project, the
/// `Use Godot editor version ...` line GDRE writes to `gdre_export.log`, and the
/// `config/features` of `project.godot` (only `major.minor`).
pub fn detect(project: &Path) -> Option<EditorSpec> {
    let mono = is_mono(project);

    if let Some(v) = csproj_sdk_version(project) {
        return Some(EditorSpec {
            version: v,
            mono: true,
        });
    }
    if let Ok(log) = std::fs::read_to_string(project.join("gdre_export.log")) {
        for line in log.lines() {
            if let Some(rest) = line.trim().strip_prefix("Use Godot editor version ") {
                let version = rest
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_end_matches(['.', ','])
                    .to_string();
                if !version.is_empty() {
                    let mono = mono || rest.contains("Mono") || rest.contains(".NET");
                    return Some(EditorSpec { version, mono });
                }
            }
        }
        for line in log.lines() {
            if let Some(rest) = line.trim().strip_prefix("Detected Engine Version:") {
                let version = rest.trim().to_string();
                if !version.is_empty() {
                    return Some(EditorSpec { version, mono });
                }
            }
        }
    }
    None
}

/// True when the project has C# code.
pub fn is_mono(project: &Path) -> bool {
    std::fs::read_dir(project)
        .map(|it| {
            it.flatten().any(|e| {
                e.path()
                    .extension()
                    .is_some_and(|x| x.eq_ignore_ascii_case("csproj"))
            })
        })
        .unwrap_or(false)
}

fn csproj_sdk_version(project: &Path) -> Option<String> {
    for e in std::fs::read_dir(project).ok()?.flatten() {
        let p = e.path();
        if !p
            .extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("csproj"))
        {
            continue;
        }
        let text = std::fs::read_to_string(&p).ok()?;
        let pos = text.find("Godot.NET.Sdk/")? + "Godot.NET.Sdk/".len();
        let v: String = text[pos..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
            .collect();
        if !v.is_empty() {
            return Some(v);
        }
    }
    None
}

/// Folder where gore installs a given editor.
pub fn install_dir(spec: &EditorSpec) -> PathBuf {
    let name = if spec.mono {
        format!("{}-mono", spec.version)
    } else {
        spec.version.clone()
    };
    download::data_dir().join("godot").join(name)
}

/// Platform part of the official archive names.
fn platform() -> Result<(&'static str, &'static str)> {
    // (regular build suffix, .NET build suffix)
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Ok(("linux.x86_64", "linux_x86_64"))
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Ok(("linux.arm64", "linux_arm64"))
    } else if cfg!(all(windows, target_arch = "x86_64")) {
        Ok(("win64.exe", "win64"))
    } else if cfg!(target_os = "macos") {
        Ok(("macos.universal", "macos.universal"))
    } else {
        bail!("no official Godot editor build for this platform")
    }
}

/// Download URL of the official editor archive.
pub fn editor_url(spec: &EditorSpec) -> Result<String> {
    let (mut plain, mut mono) = platform()?;
    // Godot 3 called the Linux build "x11".
    if spec.version.starts_with("3.") && cfg!(target_os = "linux") {
        (plain, mono) = ("x11.64", "x11_64");
    }
    let tag = spec.tag();
    let file = if spec.mono {
        format!("Godot_v{tag}_mono_{mono}.zip")
    } else {
        format!("Godot_v{tag}_{plain}.zip")
    };
    Ok(format!(
        "https://github.com/godotengine/godot-builds/releases/download/{tag}/{file}"
    ))
}

/// Download URL of the export templates.
pub fn templates_url(spec: &EditorSpec) -> String {
    let tag = spec.tag();
    let file = if spec.mono {
        format!("Godot_v{tag}_mono_export_templates.tpz")
    } else {
        format!("Godot_v{tag}_export_templates.tpz")
    };
    format!("https://github.com/godotengine/godot-builds/releases/download/{tag}/{file}")
}

/// The editor executable inside an install folder, if it is there.
pub fn find_editor(dir: &Path) -> Option<PathBuf> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).ok()?.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if p.is_dir() {
                if name.ends_with(".app") {
                    let bin = p.join("Contents/MacOS/Godot");
                    if bin.exists() {
                        return Some(bin);
                    }
                }
                if !name.starts_with("GodotSharp") && !name.starts_with("data_") {
                    stack.push(p);
                }
                continue;
            }
            let is_editor = name.starts_with("Godot_v")
                && !name.ends_with(".zip")
                && !name.ends_with(".tpz")
                && !name.contains("console");
            if is_editor {
                return Some(p);
            }
        }
    }
    None
}

/// A Godot editor already installed on the system (`godot-mono`, `godot`, ...) whose
/// version matches `spec` exactly, e.g. the one from the distribution packages.
pub fn find_system(spec: &EditorSpec) -> Option<PathBuf> {
    let names: &[&str] = if spec.mono {
        &["godot-mono", "godot4-mono", "godot", "godot4"]
    } else {
        &["godot", "godot4"]
    };
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        for name in names {
            let bin = dir.join(name);
            if !bin.is_file() {
                continue;
            }
            let Ok(out) = std::process::Command::new(&bin)
                .arg("--version")
                .stdin(std::process::Stdio::null())
                .output()
            else {
                continue;
            };
            // `4.7.2.stable.mono.arch_linux.ed1daf0bf`
            let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if version_matches(&v, spec) {
                return Some(bin);
            }
        }
    }
    None
}

fn version_matches(reported: &str, spec: &EditorSpec) -> bool {
    let parts: Vec<&str> = reported.split('.').collect();
    let number: Vec<&str> = parts
        .iter()
        .take_while(|p| p.chars().all(|c| c.is_ascii_digit()))
        .copied()
        .collect();
    let rest = &parts[number.len()..];
    let status = rest.first().copied().unwrap_or("");
    let mono = rest.contains(&"mono");
    let mut want = spec.version.split('-');
    let want_number = want.next().unwrap_or("");
    let want_status = want.next().unwrap_or("stable");
    // `4.5` and `4.5.0` are the same release.
    let norm = |v: &str| v.trim_end_matches(".0").to_string();
    norm(&number.join(".")) == norm(want_number) && status == want_status && mono == spec.mono
}

/// Installs the editor (when it is not there yet) and returns its executable.
pub fn ensure_editor(spec: &EditorSpec) -> Result<PathBuf> {
    let dir = install_dir(spec);
    if let Some(bin) = find_editor(&dir) {
        return Ok(bin);
    }
    let url = editor_url(spec)?;
    eprintln!("* downloading {} from {url}", spec.label());
    std::fs::create_dir_all(&dir)?;
    let archive = dir.join("editor.zip");
    download::download(&url, &archive).with_context(|| {
        format!(
            "cannot download {} (does that version exist?)",
            spec.label()
        )
    })?;
    unzip(&archive, &dir)?;
    let _ = std::fs::remove_file(&archive);
    let bin = find_editor(&dir)
        .ok_or_else(|| anyhow::anyhow!("the archive did not contain a Godot editor"))?;
    // Self-contained mode: settings, templates and caches live next to the editor
    // instead of mixing with the system Godot (`~/.local/share/godot`).
    if let Some(parent) = bin.parent() {
        let _ = std::fs::write(parent.join("._sc_"), b"");
    }
    Ok(bin)
}

/// Installs the export templates for `spec` where the editor installed by gore finds
/// them (its self-contained `editor_data/export_templates/<version>.<status>[.mono]`).
pub fn ensure_templates(spec: &EditorSpec, editor: &Path) -> Result<PathBuf> {
    let (number, status) = match spec.tag().split_once('-') {
        Some((n, s)) => (n.to_string(), s.to_string()),
        None => (spec.version.clone(), "stable".to_string()),
    };
    let folder = if spec.mono {
        format!("{number}.{status}.mono")
    } else {
        format!("{number}.{status}")
    };
    let base = editor
        .parent()
        .unwrap_or(Path::new("."))
        .join("editor_data/export_templates");
    let dest = base.join(&folder);
    if dest.join("version.txt").exists() {
        return Ok(dest);
    }
    let url = templates_url(spec);
    eprintln!("* downloading the export templates from {url}");
    std::fs::create_dir_all(&base)?;
    let archive = base.join(format!("{folder}.tpz"));
    download::download(&url, &archive)?;
    // The archive holds a `templates/` folder.
    let tmp = base.join(format!("{folder}.tmp"));
    let _ = std::fs::remove_dir_all(&tmp);
    unzip(&archive, &tmp)?;
    let inner = tmp.join("templates");
    let _ = std::fs::remove_dir_all(&dest);
    std::fs::rename(if inner.is_dir() { &inner } else { &tmp }, &dest)?;
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::remove_file(&archive);
    Ok(dest)
}

fn unzip(archive: &Path, dest: &Path) -> Result<()> {
    let file = std::fs::File::open(archive)?;
    let mut zip =
        zip::ZipArchive::new(file).with_context(|| format!("cannot open {}", archive.display()))?;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let Some(name) = entry.enclosed_name() else {
            continue;
        };
        let target = dest.join(name);
        if entry.is_dir() {
            std::fs::create_dir_all(&target)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = std::fs::File::create(&target)?;
        std::io::copy(&mut entry, &mut out)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = entry.unix_mode() {
                let _ = std::fs::set_permissions(
                    &target,
                    std::fs::Permissions::from_mode(mode & 0o777),
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_version_from_the_csproj() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("game.csproj"),
            r#"<Project Sdk="Godot.NET.Sdk/4.5.1"></Project>"#,
        )
        .unwrap();
        let spec = detect(dir.path()).unwrap();
        assert_eq!(
            spec,
            EditorSpec {
                version: "4.5.1".into(),
                mono: true
            }
        );
        assert!(editor_url(&spec)
            .unwrap()
            .contains("/4.5.1-stable/Godot_v4.5.1-stable_mono_"));
    }

    #[test]
    fn matches_system_editor_versions() {
        let spec = EditorSpec {
            version: "4.7.2".into(),
            mono: true,
        };
        assert!(version_matches(
            "4.7.2.stable.mono.arch_linux.ed1daf0bf",
            &spec
        ));
        assert!(!version_matches("4.7.2.stable.arch_linux.ed1daf0bf", &spec));
        assert!(!version_matches(
            "4.5.1.stable.mono.official.f62fdbde1",
            &spec
        ));
        let spec = EditorSpec {
            version: "4.5".into(),
            mono: false,
        };
        assert!(version_matches("4.5.stable.official.876b29033", &spec));
    }

    #[test]
    fn reads_the_version_from_the_gdre_log() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("gdre_export.log"),
            "Detected Engine Version: 4.3.0\nUse Godot editor version 4.3 to edit the project.\n",
        )
        .unwrap();
        let spec = detect(dir.path()).unwrap();
        assert_eq!(
            spec,
            EditorSpec {
                version: "4.3".into(),
                mono: false
            }
        );
        assert_eq!(spec.tag(), "4.3-stable");
    }
}
