use std::process::Command;

fn gore(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_gore"))
        .args(args)
        .output()
        .expect("cannot run the gore binary")
}

#[test]
fn info_rejects_a_directory_with_a_clear_message() {
    let out = gore(&["info", env!("CARGO_MANIFEST_DIR")]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("is a directory"),
        "unexpected error: {stderr}"
    );
    assert!(
        stderr.contains("gore recover"),
        "the message should point at the command that accepts directories: {stderr}"
    );
}

#[test]
fn info_reports_a_missing_file() {
    let out = gore(&["info", "/nonexistent/gore-test.pck"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot open"), "unexpected error: {stderr}");
}
