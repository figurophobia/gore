//! Integration with GDRE Tools (https://github.com/GDRETools/gdsdecomp), the reference
//! implementation for full Godot project recovery.

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

    // The binary is called `gdre_tools` everywhere, with the architecture as a suffix.
    let bin_names: &[&str] = if cfg!(windows) {
        &["gdre_tools.exe"]
    } else if cfg!(target_os = "macos") {
        &["gdre_tools", "gdre_tools.arm64", "gdre_tools.x86_64"]
    } else {
        &["gdre_tools", "gdre_tools.x86_64", "gdre_tools.aarch64"]
    };

    // 1) PATH
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            for name in bin_names {
                let candidate = dir.join(name);
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }
    }

    // 2) Common installation folders
    let mut dirs: Vec<PathBuf> = Vec::new();
    for var in ["HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA"] {
        if let Some(value) = std::env::var_os(var) {
            let home = PathBuf::from(value);
            dirs.push(home.join(".local/share/gdre_tools"));
            dirs.push(home.join(".local/share/gore"));
            dirs.push(home.join("bin"));
            dirs.push(home.join("Applications"));
        }
    }
    dirs.push(PathBuf::from("/usr/local/bin"));
    dirs.push(PathBuf::from("/usr/bin"));

    for dir in dirs {
        for name in bin_names {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Runs GDRE Tools with the given arguments.
///
/// GDRE draws its progress bars by rewriting one line with `\r`, while warnings,
/// errors and the output of the tools it spawns (`dotnet`) land in the middle of that
/// line. Its output is piped through [`Renderer`], which keeps the progress bar on one
/// line of its own and prints every other message above it.
pub fn run(gdre: &Path, args: &[String]) -> Result<()> {
    let mut child = Command::new(gdre)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("cannot run {}", gdre.display()))?;

    let renderer = Arc::new(Mutex::new(Renderer::new(stderr_is_tty())));
    let mut threads = Vec::new();
    if let Some(out) = child.stdout.take() {
        let r = Arc::clone(&renderer);
        threads.push(std::thread::spawn(move || pump(out, &r)));
    }
    if let Some(err) = child.stderr.take() {
        let r = Arc::clone(&renderer);
        threads.push(std::thread::spawn(move || pump(err, &r)));
    }
    let status = child
        .wait()
        .with_context(|| format!("cannot wait for {}", gdre.display()))?;
    for t in threads {
        let _ = t.join();
    }
    if let Ok(mut r) = renderer.lock() {
        r.finish();
    }
    if !status.success() {
        bail!("GDRE Tools exited with {status}");
    }
    Ok(())
}

/// True when stderr is an interactive terminal.
pub fn stderr_is_tty() -> bool {
    std::io::stderr().is_terminal()
}

/// Reads one output stream of the child and feeds it to the renderer one segment
/// (text up to a `\r` or `\n`) at a time.
fn pump(mut stream: impl Read, renderer: &Mutex<Renderer>) {
    let mut buf = [0u8; 8192];
    let mut pending: Vec<u8> = Vec::new();
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        for &b in &buf[..n] {
            if b == b'\r' || b == b'\n' {
                let text = String::from_utf8_lossy(&pending).to_string();
                pending.clear();
                if let Ok(mut r) = renderer.lock() {
                    r.segment(&text);
                }
            } else {
                pending.push(b);
            }
        }
    }
    if !pending.is_empty() {
        let text = String::from_utf8_lossy(&pending).to_string();
        if let Ok(mut r) = renderer.lock() {
            r.segment(&text);
        }
    }
}

/// One running GDRE task (`Exporting resources`) and how far it got.
struct Task {
    name: String,
    percent: u32,
    seen: Instant,
}

/// A task that has not reported for this long is considered finished.
const TASK_STALE: Duration = Duration::from_millis(2500);

/// Keeps a single progress line at the bottom of the terminal.
///
/// GDRE runs some tasks in parallel (exporting resources while compiling the C# project
/// and generating the filesystem cache) and every one of them redraws its own bar on the
/// same line, so the line flickered between them. The renderer tracks each task and
/// draws all the running ones together.
struct Renderer {
    tty: bool,
    /// Last raw progress text, used to recognise text written into the middle of it.
    progress: Option<String>,
    tasks: Vec<Task>,
    /// What is on screen now, to skip redundant redraws.
    drawn: String,
    /// Start of a progress line that something else wrote into (see [`split_glued`]).
    partial: Option<String>,
}

impl Renderer {
    fn new(tty: bool) -> Self {
        Self {
            tty,
            progress: None,
            tasks: Vec::new(),
            drawn: String::new(),
            partial: None,
        }
    }

    fn segment(&mut self, raw: &str) {
        let text = strip_ansi(raw);
        let mut text = text.trim_end().to_string();
        if text.trim().is_empty() {
            return;
        }
        // The rest of a progress line whose start arrived before an intruding message.
        if let Some(head) = self.partial.take() {
            let joined = format!("{head}{text}");
            if is_progress(&joined) {
                text = joined;
            }
        }
        // `Decompiling 10.0.114`: the start of the bar, then the intruding text.
        if !is_progress(&text) {
            if let Some((head, tail)) = split_bar_prefix(&text, self.progress.as_deref()) {
                self.partial = Some(head.to_string());
                let tail = tail.to_string();
                self.line(&tail);
                return;
            }
        }
        // Programs GDRE runs share its stdout, so their output can land in the middle
        // of a progress line: `Decompiling... [=====9.0.121`. Keep the bar, print the rest.
        if let Some((head, tail)) = split_glued(&text) {
            self.partial = Some(head.to_string());
            let tail = tail.to_string();
            self.line(&tail);
            return;
        }
        let text = text.as_str();
        if is_progress(text) {
            if !self.tty {
                return;
            }
            if self.progress.as_deref() == Some(text) {
                return;
            }
            self.progress = Some(text.to_string());
            if let Some((name, percent)) = parse_progress(text) {
                self.update_task(name, percent);
            }
            self.draw_progress();
        } else {
            self.line(text);
        }
    }

    /// Prints a regular message above the progress line.
    fn line(&mut self, text: &str) {
        // GDRE runs `dotnet --version` to look for the SDK; the bare answer is noise.
        if is_bare_version(text) {
            return;
        }
        {
            let mut err = std::io::stderr().lock();
            let shown = self.tty && !self.drawn.is_empty();
            if shown {
                let _ = write!(err, "\r\x1b[2K");
            }
            let _ = writeln!(err, "{text}");
            drop(err);
            if shown {
                self.drawn.clear();
                self.draw_progress();
            }
        }
    }

    fn update_task(&mut self, name: &str, percent: u32) {
        let now = Instant::now();
        // Tasks come and go only when they stop reporting: dropping one the moment it
        // reaches 100% made a task that sits at 100% blink in and out of the line.
        self.tasks
            .retain(|t| t.name == name || now - t.seen < TASK_STALE);
        match self.tasks.iter_mut().find(|t| t.name == name) {
            Some(t) => {
                t.percent = percent;
                t.seen = now;
            }
            None => self.tasks.push(Task {
                name: name.to_string(),
                percent,
                seen: now,
            }),
        }
    }

    fn draw_progress(&mut self) {
        if self.tasks.is_empty() {
            return;
        }
        // A line wider than the terminal wraps, and `\r` then only rewinds the last
        // row: that is what made the bar jump around. Never draw past the last column.
        let width = terminal_width().saturating_sub(1).max(10);
        let line = compose(&self.tasks, width);
        if line == self.drawn {
            return;
        }
        let mut err = std::io::stderr().lock();
        let _ = write!(err, "\r\x1b[2K{line}");
        let _ = err.flush();
        self.drawn = line;
    }

    fn finish(&mut self) {
        self.progress = None;
        self.tasks.clear();
        if self.tty && !std::mem::take(&mut self.drawn).is_empty() {
            let mut err = std::io::stderr().lock();
            let _ = write!(err, "\r\x1b[2K");
            let _ = err.flush();
        }
    }
}

/// Splits `Doing something... [=====9.0.121` into the bar and the intruding text.
fn split_glued(text: &str) -> Option<(&str, &str)> {
    let start = text.find("... [")? + "... [".len();
    let bar_len = text[start..]
        .chars()
        .take_while(|c| *c == '=' || *c == ' ')
        .count();
    let end = start + bar_len;
    let rest = &text[end..];
    if rest.is_empty() || rest.starts_with(']') {
        return None;
    }
    Some((&text[..end], rest))
}

/// Splits `Decompiling 10.0.114` into the start of the current progress line and the
/// text written into it, when the start matches the bar on screen.
fn split_bar_prefix<'a>(text: &'a str, progress: Option<&str>) -> Option<(&'a str, &'a str)> {
    let progress = progress?;
    // Longest prefix of `text` that is also a prefix of the bar, cut at a char boundary.
    let mut cut = 0;
    for ((i, a), b) in text.char_indices().zip(progress.chars()) {
        if a != b {
            break;
        }
        cut = i + a.len_utf8();
    }
    if cut == 0 || cut == text.len() {
        return None;
    }
    let (head, tail) = text.split_at(cut);
    is_bare_version(tail).then_some((head, tail))
}

/// `9.0.121` alone on a line.
fn is_bare_version(text: &str) -> bool {
    let t = text.trim();
    t.split('.').count() >= 2
        && t.split('.')
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// `Doing something... [=====     ] 42%` gives (`Doing something`, 42).
fn parse_progress(text: &str) -> Option<(&str, u32)> {
    let t = text.trim();
    let name = t[..t.find("... [")?].trim();
    let digits: String = t
        .trim_end_matches('%')
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    Some((name, digits.parse().ok()?))
}

/// Draws the running tasks on one line no wider than `width`, shrinking the bars until
/// everything fits: `Exporting resources [=====     ] 52% │ Compiling C# project [  ] 0%`.
fn compose(tasks: &[Task], width: usize) -> String {
    // `Reading folder /a/very/long/path` would eat the whole line.
    let short = |name: &str| -> String {
        const MAX: usize = 28;
        if name.chars().count() <= MAX {
            name.to_string()
        } else {
            let head: String = name.chars().take(MAX - 1).collect();
            format!("{head}…")
        }
    };
    let render = |bar: usize| -> String {
        tasks
            .iter()
            .map(|t| {
                let name = short(&t.name);
                if bar == 0 {
                    return format!("{name} {}%", t.percent);
                }
                let filled = (t.percent.min(100) as usize * bar) / 100;
                format!(
                    "{name} [{}{}] {}%",
                    "=".repeat(filled),
                    " ".repeat(bar - filled),
                    t.percent
                )
            })
            .collect::<Vec<_>>()
            .join(" │ ")
    };
    for bar in [30, 20, 12, 8, 0] {
        let line = render(bar);
        if line.chars().count() <= width {
            return line;
        }
    }
    render(0).chars().take(width).collect()
}

/// `Doing something... [=====     ] 42%`
fn is_progress(text: &str) -> bool {
    let t = text.trim();
    t.ends_with('%') && t.contains("... [") && t.contains(']')
}

/// Removes ANSI escape sequences (`dotnet` sends a few even through a pipe).
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.peek() {
                Some('[') => {
                    chars.next();
                    // Parameters and intermediates, then one final byte in @..~
                    for c in chars.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                Some(_) => {
                    chars.next();
                }
                None => {}
            }
        } else if c != '\x07' {
            out.push(c);
        }
    }
    out
}

/// Terminal width in columns (80 when unknown).
fn terminal_width() -> usize {
    #[cfg(unix)]
    {
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        let ok = unsafe { libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &mut ws) } == 0;
        if ok && ws.ws_col > 0 {
            return ws.ws_col as usize;
        }
    }
    std::env::var("COLUMNS")
        .ok()
        .and_then(|c| c.parse().ok())
        .unwrap_or(80)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draws_parallel_tasks_on_one_line() {
        assert_eq!(
            parse_progress("Exporting resources... [====      ] 42%"),
            Some(("Exporting resources", 42))
        );
        let now = Instant::now();
        let tasks = vec![
            Task {
                name: "Exporting resources".into(),
                percent: 50,
                seen: now,
            },
            Task {
                name: "Compiling C# project".into(),
                percent: 0,
                seen: now,
            },
        ];
        let wide = compose(&tasks, 200);
        assert!(wide.contains("Exporting resources [===============               ] 50%"));
        assert!(wide.contains(" │ Compiling C# project ["));
        let narrow = compose(&tasks, 60);
        assert!(narrow.chars().count() <= 60, "{narrow}");
        assert!(narrow.contains("50%") && narrow.contains("0%"), "{narrow}");
    }

    #[test]
    fn recognises_progress_lines() {
        assert!(is_progress("Decompiling C# scripts... [=====     ] 42%"));
        assert!(!is_progress("Extracted 15890 files, no errors detected!"));
        assert!(!is_progress("9.0.121"));
    }

    #[test]
    fn separates_text_glued_into_a_progress_line() {
        let (head, tail) = split_glued("Decompiling C# scripts... [====9.0.121").unwrap();
        assert_eq!(head, "Decompiling C# scripts... [====");
        assert_eq!(tail, "9.0.121");
        assert!(split_glued("Decompiling C# scripts... [====   ] 40%").is_none());
        let bar = "Decompiling C# scripts... [=====] 100%";
        assert_eq!(
            split_bar_prefix("Decompiling 10.0.114", Some(bar)),
            Some(("Decompiling ", "10.0.114"))
        );
        assert_eq!(split_bar_prefix("Saved project config.", Some(bar)), None);
        assert!(is_bare_version("9.0.121"));
        assert!(!is_bare_version("Version: 4.5.1"));
    }

    #[test]
    fn strips_escape_sequences() {
        assert_eq!(strip_ansi("\x1b[?1h9.0.121"), "9.0.121");
        assert_eq!(strip_ansi("\x1b[31mred\x1b[0m"), "red");
    }
}
