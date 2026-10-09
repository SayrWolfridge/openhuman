use super::*;
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(unix)]
use std::path::{Path, PathBuf};

#[cfg(unix)]
const TOOLCHAIN_PATH_HEX_PROBE: &str = r#"printf '%s\n' "${RUSTUP_HOME+x}:$(printf '%s' "$RUSTUP_HOME" | od -An -tx1 | tr -d ' \n')" "${CARGO_HOME+x}:$(printf '%s' "$CARGO_HOME" | od -An -tx1 | tr -d ' \n')""#;

#[cfg(unix)]
fn non_utf8_child(parent: &Path, name: &[u8]) -> PathBuf {
    parent.join(std::ffi::OsString::from_vec(name.to_vec()))
}

#[cfg(unix)]
fn hex_path(path: &Path) -> String {
    let mut hex = String::new();
    for byte in path.as_os_str().as_bytes() {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[cfg(unix)]
#[tokio::test]
async fn local_jail_forwards_non_utf8_toolchain_homes_without_cargo() {
    let action = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let homes = tempfile::tempdir().unwrap();
    let rustup_home = non_utf8_child(homes.path(), b"rustup-\xff-home");
    let cargo_home = non_utf8_child(homes.path(), b"cargo-\xfe-home");
    std::fs::create_dir_all(&rustup_home).unwrap();
    std::fs::create_dir_all(&cargo_home).unwrap();
    let expected = format!(
        "x:{}\nx:{}\n",
        hex_path(&rustup_home),
        hex_path(&cargo_home)
    );
    let _env = crate::config::test_env::EnvVarGuard::locked_async()
        .await
        .with("RUSTUP_HOME", rustup_home.as_os_str())
        .with("CARGO_HOME", cargo_home.as_os_str());
    let unsandboxed_policy = resolve_sandbox_policy(
        SandboxMode::None,
        action.path(),
        state.path(),
        &RuntimeConfig::default(),
        false,
    );
    let unsandboxed = run_local(&unsandboxed_policy, TOOLCHAIN_PATH_HEX_PROBE).await;
    assert!(
        unsandboxed.success(),
        "unsandboxed toolchain-home probe failed: {}",
        unsandboxed.stderr
    );
    assert_eq!(
        unsandboxed.stdout, expected,
        "unsandboxed spawn must forward non-UTF-8 toolchain paths byte-for-byte"
    );
    let policy = local_policy(action.path(), state.path());

    // Hex makes the child's view inspectable without converting its raw path
    // bytes through a lossy String representation.
    let result = run_local(&policy, TOOLCHAIN_PATH_HEX_PROBE).await;
    assert!(
        result.success(),
        "toolchain-home probe failed: {}",
        result.stderr
    );
    assert_eq!(
        result.stdout, expected,
        "local sandbox must forward non-UTF-8 toolchain paths byte-for-byte"
    );

    drop(_env);
    let _env = crate::config::test_env::EnvVarGuard::locked_async()
        .await
        .with("RUSTUP_HOME", "")
        .with("CARGO_HOME", "relative/cargo");
    let policy = local_policy(action.path(), state.path());
    let result = run_local(&policy, TOOLCHAIN_PATH_HEX_PROBE).await;
    assert!(
        result.success(),
        "relative-value probe failed: {}",
        result.stderr
    );
    assert_eq!(
        result.stdout, "x:\nx:72656c61746976652f636172676f\n",
        "empty and relative host paths must retain exact forwarding"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn landlock_non_utf8_custom_toolchain_homes_keep_selective_access() {
    if !landlock_in_force() {
        return;
    }
    let action = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let homes = tempfile::tempdir().unwrap();
    let rustup_home = non_utf8_child(homes.path(), b"rustup-\xff-home");
    let cargo_home = non_utf8_child(homes.path(), b"cargo-\xfe-home");
    std::fs::create_dir_all(&rustup_home).unwrap();
    std::fs::create_dir_all(&cargo_home).unwrap();
    for child in ["bin", "registry", "git"] {
        std::fs::create_dir(cargo_home.join(child)).unwrap();
    }
    std::fs::write(rustup_home.join("toolchain"), "rust-fixture").unwrap();
    std::fs::write(cargo_home.join("bin/tool"), "cargo-fixture").unwrap();
    std::fs::write(cargo_home.join("credentials.toml"), "fixture-secret").unwrap();
    let _env = crate::config::test_env::EnvVarGuard::locked_async()
        .await
        .with("RUSTUP_HOME", rustup_home.as_os_str())
        .with("CARGO_HOME", cargo_home.as_os_str());
    let policy = local_policy(action.path(), state.path());
    let reads = run_local(
        &policy,
        "cat \"$RUSTUP_HOME/toolchain\"; cat \"$CARGO_HOME/bin/tool\"",
    )
    .await;
    assert!(
        reads.success(),
        "custom toolchain reads failed: {}",
        reads.stderr
    );
    assert_eq!(reads.stdout, "rust-fixturecargo-fixture");
    let caches = run_local(
        &policy,
        "printf registry > \"$CARGO_HOME/registry/probe\" && printf git > \"$CARGO_HOME/git/probe\"",
    )
    .await;
    assert!(
        caches.success(),
        "Cargo cache writes failed: {}",
        caches.stderr
    );
    for command in [
        "printf denied > \"$RUSTUP_HOME/toolchain\"",
        "printf denied > \"$CARGO_HOME/bin/tool\"",
        "cat \"$CARGO_HOME/credentials.toml\"",
        "printf denied > \"$CARGO_HOME/credentials.toml\"",
    ] {
        let result = run_local(&policy, command).await;
        assert!(!result.success(), "selective access allowed {command}");
    }
    assert_eq!(
        std::fs::read_to_string(rustup_home.join("toolchain")).unwrap(),
        "rust-fixture"
    );
    assert_eq!(
        std::fs::read_to_string(cargo_home.join("bin/tool")).unwrap(),
        "cargo-fixture"
    );
    assert_eq!(
        std::fs::read_to_string(cargo_home.join("registry/probe")).unwrap(),
        "registry"
    );
    assert_eq!(
        std::fs::read_to_string(cargo_home.join("git/probe")).unwrap(),
        "git"
    );

    drop(_env);
    let alias_cargo = non_utf8_child(homes.path(), b"alias-cargo-\xfd-home");
    std::fs::create_dir(alias_cargo.join("bin")).unwrap();
    std::fs::create_dir(alias_cargo.join("git")).unwrap();
    std::os::unix::fs::symlink(&rustup_home, alias_cargo.join("registry")).unwrap();
    let _env = crate::config::test_env::EnvVarGuard::locked_async()
        .await
        .with("RUSTUP_HOME", rustup_home.as_os_str())
        .with("CARGO_HOME", alias_cargo.as_os_str());
    let alias_policy = local_policy(action.path(), state.path());
    let cache_alias_write = run_local(
        &alias_policy,
        "printf denied > \"$CARGO_HOME/registry/toolchain\"",
    )
    .await;
    assert!(
        !cache_alias_write.success(),
        "Cargo cache alias wrote through to RUSTUP_HOME"
    );
    assert_eq!(
        std::fs::read_to_string(rustup_home.join("toolchain")).unwrap(),
        "rust-fixture"
    );
    let alias_cache_write =
        run_local(&alias_policy, "printf git > \"$CARGO_HOME/git/probe\"").await;
    assert!(
        alias_cache_write.success(),
        "dedicated Cargo git cache lost RW access: {}",
        alias_cache_write.stderr
    );
    assert_eq!(
        std::fs::read_to_string(alias_cargo.join("git/probe")).unwrap(),
        "git"
    );
}
