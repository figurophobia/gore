//! Integration with GDRE Tools (https://github.com/GDRETools/gdsdecomp), the reference
//! implementation for full Godot project recovery.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

const RELEASES_API: &str = "https://api.github.com/repos/GDRETools/gdsdecomp/releases/latest";

/// Looks for the GDRE Tools binary.
pub fn locate(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }
    if let Ok(env) = std::env::var("GORE_GDRE") {
        let path = PathBuf::from(env);
        if path.exists() {
            return Some(path);
        }
    }
    let exe_name = if cfg!(windows) {
        "gdre_tools.exe"
    } else {
        "gdre_tools"
    };
    // 1) PATH
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            let candidate = Path::new(dir).join(exe_name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    // 2) Common installation folders
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        candidates.push(home.join(".local/share/gdre_tools/gdre_tools.x86_64"));
        candidates.push(home.join(".local/share/gdre_tools/gdre_tools.exe"));
        candidates.push(home.join(".local/share/gore/gdre_tools.x86_64"));
        candidates.push(home.join(".local/share/gore/gdre_tools.exe"));
        candidates.push(home.join("bin/gdre_tools"));
        candidates.push(home.join("Applications/gdre_tools"));
    }
    candidates.push(PathBuf::from("/usr/local/bin/gdre_tools"));
    candidates.push(PathBuf::from("/usr/bin/gdre_tools"));
    candidates.into_iter().find(|candidate| candidate.exists())
}

/// Runs GDRE Tools with the given arguments.
pub fn run(gdre: &Path, args: &[String]) -> Result<()> {
    let status = Command::new(gdre)
        .args(args)
        .status()
        .with_context(|| format!("cannot run {}", gdre.display()))?;
    if !status.success() {
        bail!("GDRE Tools exited with {status}");
    }
    Ok(())
}

/// Downloads the latest GDRE Tools release for this platform into `dest`.
pub fn download_latest(dest: &Path) -> Result<PathBuf> {
    let response = ureq::get(RELEASES_API)
        .set("User-Agent", "gore")
        .call()
        .context("cannot query the GDRE Tools releases")?;
    let release: serde_json::Value = serde_json::from_str(&response.into_string()?)
        .context("cannot parse the release metadata")?;
    let tag = release
        .get("tag_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let wanted = if cfg!(windows) {
        "win"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };

    let assets = release
        .get("assets")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let asset = assets
        .iter()
        .find(|a| {
            let name = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
            name.contains(wanted) && name.ends_with(".zip")
        })
        .or_else(|| {
            assets.iter().find(|a| {
                let name = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
                name.ends_with(".zip")
            })
        })
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no downloadable asset found in release {tag}"))?;

    let url = asset
        .get("browser_download_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("release asset without download url"))?
        .to_string();
    let name = asset
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("gdre.zip")
        .to_string();

    println!("* downloading GDRE Tools {tag} ({name})");
    let mut data = Vec::new();
    ureq::get(&url)
        .set("User-Agent", "gore")
        .call()
        .context("cannot download the release")?
        .into_reader()
        .read_to_end(&mut data)
        .context("cannot read the downloaded archive")?;

    std::fs::create_dir_all(dest)?;
    let archive = dest.join("gdre_tools.zip");
    std::fs::write(&archive, &data)?;

    let file = std::fs::File::open(&archive)?;
    let mut zip = zip::ZipArchive::new(file).context("cannot open the downloaded zip")?;
    let mut installed: Option<PathBuf> = None;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let Some(name) = entry.enclosed_name() else {
            continue;
        };
        let file_name = name
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        // The binary needs its companion libraries next to it (RUNPATH=$ORIGIN).
        let target = dest.join(&name);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = std::fs::File::create(&target)?;
        std::io::copy(&mut entry, &mut out)?;

        let is_binary = file_name.starts_with("gdre_tools")
            && !file_name.ends_with(".pck")
            && !file_name.ends_with(".dll")
            && !file_name.ends_with(".so")
            && !file_name.ends_with(".zip");
        if is_binary {
            installed = Some(target);
        }
    }
    let installed =
        installed.ok_or_else(|| anyhow::anyhow!("the archive does not contain the GDRE binary"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&installed)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&installed, perms)?;
    }
    Ok(installed)
}
