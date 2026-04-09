//! TOML-based configuration loading, parsing, and validation.
//!
//! Supports multiple IMAP accounts with flexible password resolution
//! (command, file, or plaintext fallback). Validates all fields at load
//! time so downstream code can trust the configuration.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::error::ConfigError;

/// Default log level.
const DEFAULT_LOG_LEVEL: &str = "info";

/// Default sync interval in seconds (5 minutes).
const DEFAULT_SYNC_INTERVAL_SECONDS: u64 = 300;

/// Minimum allowed sync interval in seconds.
const MIN_SYNC_INTERVAL_SECONDS: u64 = 60;

/// Default stale threshold in days before warning about no successful sync.
const DEFAULT_STALE_THRESHOLD_DAYS: u64 = 7;

/// Default maximum email size in bytes (100 MB).
const DEFAULT_MAX_EMAIL_SIZE_BYTES: u64 = 100 * 1024 * 1024;

/// Default IMAP operation timeout in seconds.
const DEFAULT_IMAP_TIMEOUT_SECONDS: u64 = 60;

/// Default IMAP TLS port.
const DEFAULT_IMAP_PORT: u16 = 993;

/// Root configuration structure loaded from the TOML file.
#[derive(Debug, Clone)]
pub struct Config {
    /// General settings that apply to the entire backup process.
    pub general: GeneralConfig,
    /// Per-account IMAP connection and sync settings.
    pub accounts: Vec<AccountConfig>,
}

/// General settings for the backup tool.
#[derive(Debug, Clone)]
pub struct GeneralConfig {
    /// Root directory for Maildir storage.
    pub maildir_path: PathBuf,
    /// Path to the SQLite state database.
    pub state_db: PathBuf,
    /// Logging verbosity level.
    pub log_level: String,
    /// Polling interval in seconds for daemon mode.
    pub sync_interval_seconds: u64,
    /// Warn if no successful sync in this many days.
    pub stale_threshold_days: u64,
    /// Maximum email body size to download in bytes.
    pub max_email_size_bytes: u64,
    /// IMAP operation timeout in seconds.
    pub imap_timeout_seconds: u64,
    /// Whether to fsync Maildir writes for crash safety.
    pub fsync_on_write: bool,
}

/// Per-account IMAP configuration.
#[derive(Debug, Clone)]
pub struct AccountConfig {
    /// Human-readable account name (must be unique).
    pub name: String,
    /// IMAP server hostname.
    pub host: String,
    /// IMAP server port.
    pub port: u16,
    /// Whether to use TLS for the connection.
    pub tls: bool,
    /// IMAP username.
    pub username: String,
    /// Password resolution strategy.
    pub password_source: PasswordSource,
    /// Glob-style folder patterns controlling which folders to sync.
    ///
    /// Patterns are evaluated in order; the last matching pattern wins.
    /// A `!` prefix negates the pattern (excludes matching folders).
    /// Supports `*` (any characters) and `?` (single character) wildcards.
    /// Defaults to `["*"]` (include all folders).
    pub folder_patterns: Vec<String>,
}

/// How to obtain the password for an account.
#[derive(Clone)]
pub enum PasswordSource {
    /// Run a shell command that prints the password to stdout.
    Command(String),
    /// Read the password from a file.
    File(PathBuf),
    /// Read the password from an environment variable.
    Environment(String),
    /// Use a plaintext password (not recommended).
    Plaintext(String),
}

impl std::fmt::Debug for PasswordSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Command(cmd) => f.debug_tuple("Command").field(cmd).finish(),
            Self::File(path) => f.debug_tuple("File").field(path).finish(),
            Self::Environment(var) => f.debug_tuple("Environment").field(var).finish(),
            Self::Plaintext(_) => f.debug_tuple("Plaintext").field(&"[REDACTED]").finish(),
        }
    }
}

// --- Raw TOML deserialization structures ---

/// Raw TOML structure for the configuration file.
#[derive(Deserialize)]
struct RawConfig {
    general: RawGeneralConfig,
    #[serde(default, rename = "account")]
    accounts: Vec<RawAccountConfig>,
}

/// Raw TOML structure for general settings.
#[derive(Deserialize)]
struct RawGeneralConfig {
    maildir_path: Option<String>,
    state_db: Option<String>,
    log_level: Option<String>,
    sync_interval_seconds: Option<u64>,
    stale_threshold_days: Option<u64>,
    max_email_size_bytes: Option<u64>,
    imap_timeout_seconds: Option<u64>,
    fsync_on_write: Option<bool>,
}

/// Raw TOML structure for an account.
#[derive(Deserialize)]
struct RawAccountConfig {
    name: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    tls: Option<bool>,
    username: Option<String>,
    password_command: Option<String>,
    password_file: Option<String>,
    password_env: Option<String>,
    password: Option<String>,
    folder_patterns: Option<Vec<String>>,
}

/// Load and validate a configuration from the given TOML file path.
pub fn load_config(path: &Path) -> Result<Config, ConfigError> {
    let content = read_config_file(path)?;
    let raw = parse_toml(&content, path)?;
    let general = build_general_config(raw.general)?;
    let accounts = build_account_configs(raw.accounts)?;
    validate_no_duplicate_accounts(&accounts)?;
    Ok(Config { general, accounts })
}

/// Resolve the password for an account using its configured source.
///
/// Tries the configured password source and returns the password wrapped
/// in `Zeroizing` for secure memory handling. Warns via tracing if a
/// plaintext password is used.
pub fn resolve_password(
    account_name: &str,
    source: &PasswordSource,
) -> Result<Zeroizing<String>, ConfigError> {
    match source {
        PasswordSource::Command(cmd) => resolve_password_command(account_name, cmd),
        PasswordSource::File(path) => resolve_password_file(account_name, path),
        PasswordSource::Environment(var) => resolve_password_env(account_name, var),
        PasswordSource::Plaintext(pw) => {
            tracing::warn!(
                account = account_name,
                "using plaintext password from config file — consider using password_command, password_file, or password_env instead"
            );
            Ok(Zeroizing::new(pw.clone()))
        }
    }
}

/// Validate that configured paths exist and are accessible.
///
/// Checks that the parent directories of `maildir_path` and `state_db`
/// exist. Returns an error if either parent directory is missing.
pub fn validate_paths(config: &GeneralConfig) -> Result<(), ConfigError> {
    validate_parent_directory(&config.maildir_path, "maildir_path")?;
    validate_parent_directory(&config.state_db, "state_db")?;
    Ok(())
}

// --- Private helper functions ---

fn read_config_file(path: &Path) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
        path: path.display().to_string(),
        source,
    })
}

fn parse_toml(content: &str, path: &Path) -> Result<RawConfig, ConfigError> {
    toml::from_str(content).map_err(|source| ConfigError::ParseToml {
        path: path.display().to_string(),
        source,
    })
}

fn build_general_config(raw: RawGeneralConfig) -> Result<GeneralConfig, ConfigError> {
    let maildir_path = PathBuf::from(require_field(raw.maildir_path, "general.maildir_path")?);
    let state_db = PathBuf::from(require_field(raw.state_db, "general.state_db")?);
    let log_level = raw
        .log_level
        .unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_owned());
    let sync_interval_seconds = raw
        .sync_interval_seconds
        .unwrap_or(DEFAULT_SYNC_INTERVAL_SECONDS);
    let stale_threshold_days = raw
        .stale_threshold_days
        .unwrap_or(DEFAULT_STALE_THRESHOLD_DAYS);
    let max_email_size_bytes = raw
        .max_email_size_bytes
        .unwrap_or(DEFAULT_MAX_EMAIL_SIZE_BYTES);
    let imap_timeout_seconds = raw
        .imap_timeout_seconds
        .unwrap_or(DEFAULT_IMAP_TIMEOUT_SECONDS);
    let fsync_on_write = raw.fsync_on_write.unwrap_or(true);

    validate_sync_interval(sync_interval_seconds)?;

    Ok(GeneralConfig {
        maildir_path,
        state_db,
        log_level,
        sync_interval_seconds,
        stale_threshold_days,
        max_email_size_bytes,
        imap_timeout_seconds,
        fsync_on_write,
    })
}

fn build_account_configs(
    raw_accounts: Vec<RawAccountConfig>,
) -> Result<Vec<AccountConfig>, ConfigError> {
    raw_accounts
        .into_iter()
        .enumerate()
        .map(|(index, raw)| build_single_account(raw, index))
        .collect()
}

fn build_single_account(raw: RawAccountConfig, index: usize) -> Result<AccountConfig, ConfigError> {
    let context = format!("account[{index}]");
    let name = require_field(raw.name, &format!("{context}.name"))?;
    let host = require_field(raw.host, &format!("{context}.host"))?;
    let port = raw.port.unwrap_or(DEFAULT_IMAP_PORT);
    let tls = raw.tls.unwrap_or(true);
    let username = require_field(raw.username, &format!("{context}.username"))?;
    let password_source = resolve_password_source(
        &name,
        raw.password_command,
        raw.password_file,
        raw.password_env,
        raw.password,
    )?;

    let folder_patterns = raw.folder_patterns.unwrap_or_else(|| vec!["*".to_owned()]);
    validate_folder_patterns(&folder_patterns, &context)?;

    validate_port(port, &context)?;
    validate_tls(tls, &context)?;

    Ok(AccountConfig {
        name,
        host,
        port,
        tls,
        username,
        password_source,
        folder_patterns,
    })
}

fn resolve_password_source(
    account_name: &str,
    command: Option<String>,
    file: Option<String>,
    env: Option<String>,
    plaintext: Option<String>,
) -> Result<PasswordSource, ConfigError> {
    if let Some(cmd) = command {
        return Ok(PasswordSource::Command(cmd));
    }
    if let Some(path) = file {
        return Ok(PasswordSource::File(PathBuf::from(path)));
    }
    if let Some(var) = env {
        return Ok(PasswordSource::Environment(var));
    }
    if let Some(pw) = plaintext {
        return Ok(PasswordSource::Plaintext(pw));
    }
    Err(ConfigError::PasswordResolution {
        account: account_name.to_owned(),
        reason:
            "no password source configured — set password_command, password_file, password_env, or password"
                .to_owned(),
    })
}

/// Execute a shell command to retrieve a password.
///
/// # Security
///
/// The command is executed via `sh -c`, which means full shell interpretation
/// (variable expansion, piping, subshells, etc.) is applied. This is intentional:
/// the command comes from a trusted, locally-owned configuration file and the
/// operator is responsible for ensuring the command is safe. This design supports
/// tools like `pass`, `gpg`, `secret-tool`, and similar utilities that require
/// shell features to function correctly.
fn resolve_password_command(
    account_name: &str,
    cmd: &str,
) -> Result<Zeroizing<String>, ConfigError> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(|source| ConfigError::PasswordCommand {
            account: account_name.to_owned(),
            source,
        })?;

    if !output.status.success() {
        return Err(ConfigError::PasswordResolution {
            account: account_name.to_owned(),
            reason: format!("password command exited with status {}", output.status),
        });
    }

    let password = String::from_utf8(output.stdout.clone())
        .map_err(|_| ConfigError::PasswordResolution {
            account: account_name.to_owned(),
            reason: "password command output is not valid UTF-8".to_owned(),
        })?
        .trim()
        .to_owned();
    if password.is_empty() {
        return Err(ConfigError::PasswordResolution {
            account: account_name.to_owned(),
            reason: "password command produced empty output".to_owned(),
        });
    }

    Ok(Zeroizing::new(password))
}

fn resolve_password_env(
    account_name: &str,
    var_name: &str,
) -> Result<Zeroizing<String>, ConfigError> {
    let value = std::env::var(var_name).map_err(|_| ConfigError::PasswordResolution {
        account: account_name.to_owned(),
        reason: format!("environment variable '{var_name}' is not set"),
    })?;

    let password = value.trim().to_owned();
    if password.is_empty() {
        return Err(ConfigError::PasswordResolution {
            account: account_name.to_owned(),
            reason: format!("environment variable '{var_name}' is empty"),
        });
    }

    Ok(Zeroizing::new(password))
}

fn resolve_password_file(
    account_name: &str,
    path: &Path,
) -> Result<Zeroizing<String>, ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|source| ConfigError::PasswordFile {
        account: account_name.to_owned(),
        path: path.display().to_string(),
        source,
    })?;

    let password = content.trim().to_owned();
    if password.is_empty() {
        return Err(ConfigError::PasswordResolution {
            account: account_name.to_owned(),
            reason: format!("password file '{}' is empty", path.display()),
        });
    }

    Ok(Zeroizing::new(password))
}

fn validate_parent_directory(path: &Path, field_name: &str) -> Result<(), ConfigError> {
    let parent = path.parent().ok_or_else(|| ConfigError::PathValidation {
        field: field_name.to_owned(),
        reason: format!("'{}' has no parent directory", path.display()),
    })?;

    if !parent.exists() {
        return Err(ConfigError::PathValidation {
            field: field_name.to_owned(),
            reason: format!("parent directory '{}' does not exist", parent.display()),
        });
    }

    Ok(())
}

fn validate_sync_interval(seconds: u64) -> Result<(), ConfigError> {
    if seconds < MIN_SYNC_INTERVAL_SECONDS {
        return Err(ConfigError::InvalidValue {
            field: "general.sync_interval_seconds".to_owned(),
            reason: format!("must be at least {MIN_SYNC_INTERVAL_SECONDS} seconds, got {seconds}"),
        });
    }
    Ok(())
}

fn validate_port(port: u16, context: &str) -> Result<(), ConfigError> {
    if port == 0 {
        return Err(ConfigError::InvalidValue {
            field: format!("{context}.port"),
            reason: "port must be between 1 and 65535".to_owned(),
        });
    }
    Ok(())
}

fn validate_tls(tls: bool, context: &str) -> Result<(), ConfigError> {
    if !tls {
        return Err(ConfigError::InvalidValue {
            field: format!("{context}.tls"),
            reason: "plaintext IMAP connections are not supported — TLS is required for security"
                .to_owned(),
        });
    }
    Ok(())
}

fn validate_folder_patterns(patterns: &[String], context: &str) -> Result<(), ConfigError> {
    for (i, pattern) in patterns.iter().enumerate() {
        let raw = pattern.strip_prefix('!').unwrap_or(pattern);
        if raw.is_empty() {
            return Err(ConfigError::InvalidValue {
                field: format!("{context}.folder_patterns[{i}]"),
                reason: "pattern must not be empty".to_owned(),
            });
        }
    }
    Ok(())
}

/// Check whether a folder name matches a set of glob-style patterns.
///
/// Patterns are evaluated in order. The last matching pattern determines
/// the result. A `!` prefix negates a pattern. If no patterns match,
/// the folder is excluded (returns `false`).
pub fn matches_folder_patterns(folder_name: &str, patterns: &[String]) -> bool {
    let mut result = false;
    for pattern in patterns {
        if let Some(negated) = pattern.strip_prefix('!') {
            if glob_match(negated, folder_name) {
                result = false;
            }
        } else if glob_match(pattern, folder_name) {
            result = true;
        }
    }
    result
}

/// Simple glob matching supporting `*` (any characters) and `?` (single character).
fn glob_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    glob_match_inner(&pat, &txt)
}

fn glob_match_inner(pattern: &[char], text: &[char]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi = None;
    let mut star_ti = 0;

    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == '?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == '*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }

    pi == pattern.len()
}

fn validate_no_duplicate_accounts(accounts: &[AccountConfig]) -> Result<(), ConfigError> {
    let mut seen = HashSet::new();
    for account in accounts {
        if !seen.insert(&account.name) {
            return Err(ConfigError::DuplicateAccount {
                name: account.name.clone(),
            });
        }
    }
    Ok(())
}

fn require_field(value: Option<String>, field_name: &str) -> Result<String, ConfigError> {
    value.ok_or_else(|| ConfigError::MissingField {
        field: field_name.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp_config(dir: &tempfile::TempDir, content: &str) -> PathBuf {
        let path = dir.path().join("config.toml");
        std::fs::write(&path, content).unwrap();
        path
    }

    fn minimal_valid_config(dir: &tempfile::TempDir) -> String {
        format!(
            r#"
[general]
maildir_path = "{maildir}"
state_db = "{state_db}"

[[account]]
name = "test"
host = "imap.example.com"
username = "user@example.com"
password = "secret"
"#,
            maildir = dir.path().join("mail").display(),
            state_db = dir.path().join("state.db").display(),
        )
    }

    #[test]
    fn load_minimal_valid_config() {
        let dir = tempfile::tempdir().unwrap();
        // Create the maildir subdirectory parent (already exists: tempdir itself)
        let config_content = minimal_valid_config(&dir);
        let config_path = write_temp_config(&dir, &config_content);

        let config = load_config(&config_path).unwrap();
        assert_eq!(config.general.log_level, "info");
        assert_eq!(config.general.sync_interval_seconds, 300);
        assert_eq!(config.general.stale_threshold_days, 7);
        assert_eq!(config.general.max_email_size_bytes, 100 * 1024 * 1024);
        assert_eq!(config.general.imap_timeout_seconds, 60);
        assert!(config.general.fsync_on_write);
        assert_eq!(config.accounts.len(), 1);
        assert_eq!(config.accounts[0].name, "test");
        assert_eq!(config.accounts[0].port, 993);
        assert!(config.accounts[0].tls);
    }

    #[test]
    fn load_config_with_all_general_fields() {
        let dir = tempfile::tempdir().unwrap();
        let config_content = format!(
            r#"
[general]
maildir_path = "{maildir}"
state_db = "{state_db}"
log_level = "debug"
sync_interval_seconds = 120
stale_threshold_days = 14
max_email_size_bytes = 50000000
imap_timeout_seconds = 30
fsync_on_write = false

[[account]]
name = "test"
host = "imap.example.com"
username = "user@example.com"
password = "secret"
"#,
            maildir = dir.path().join("mail").display(),
            state_db = dir.path().join("state.db").display(),
        );
        let config_path = write_temp_config(&dir, &config_content);

        let config = load_config(&config_path).unwrap();
        assert_eq!(config.general.log_level, "debug");
        assert_eq!(config.general.sync_interval_seconds, 120);
        assert_eq!(config.general.stale_threshold_days, 14);
        assert_eq!(config.general.max_email_size_bytes, 50_000_000);
        assert_eq!(config.general.imap_timeout_seconds, 30);
        assert!(!config.general.fsync_on_write);
    }

    #[test]
    fn reject_sync_interval_below_minimum() {
        let dir = tempfile::tempdir().unwrap();
        let config_content = format!(
            r#"
[general]
maildir_path = "{maildir}"
state_db = "{state_db}"
sync_interval_seconds = 30

[[account]]
name = "test"
host = "imap.example.com"
username = "user@example.com"
password = "secret"
"#,
            maildir = dir.path().join("mail").display(),
            state_db = dir.path().join("state.db").display(),
        );
        let config_path = write_temp_config(&dir, &config_content);

        let err = load_config(&config_path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("at least 60 seconds"), "got: {msg}");
    }

    #[test]
    fn reject_missing_maildir_path() {
        let dir = tempfile::tempdir().unwrap();
        let config_content = format!(
            r#"
[general]
state_db = "{state_db}"

[[account]]
name = "test"
host = "imap.example.com"
username = "user@example.com"
password = "secret"
"#,
            state_db = dir.path().join("state.db").display(),
        );
        let config_path = write_temp_config(&dir, &config_content);

        let err = load_config(&config_path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("maildir_path"), "got: {msg}");
    }

    #[test]
    fn reject_duplicate_account_names() {
        let dir = tempfile::tempdir().unwrap();
        let config_content = format!(
            r#"
[general]
maildir_path = "{maildir}"
state_db = "{state_db}"

[[account]]
name = "personal"
host = "imap.example.com"
username = "user@example.com"
password = "secret"

[[account]]
name = "personal"
host = "imap.other.com"
username = "other@example.com"
password = "secret2"
"#,
            maildir = dir.path().join("mail").display(),
            state_db = dir.path().join("state.db").display(),
        );
        let config_path = write_temp_config(&dir, &config_content);

        let err = load_config(&config_path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("duplicate account name"), "got: {msg}");
    }

    #[test]
    fn reject_zero_port() {
        let dir = tempfile::tempdir().unwrap();
        let config_content = format!(
            r#"
[general]
maildir_path = "{maildir}"
state_db = "{state_db}"

[[account]]
name = "test"
host = "imap.example.com"
port = 0
username = "user@example.com"
password = "secret"
"#,
            maildir = dir.path().join("mail").display(),
            state_db = dir.path().join("state.db").display(),
        );
        let config_path = write_temp_config(&dir, &config_content);

        let err = load_config(&config_path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("port must be between"), "got: {msg}");
    }

    #[test]
    fn reject_missing_password_source() {
        let dir = tempfile::tempdir().unwrap();
        let config_content = format!(
            r#"
[general]
maildir_path = "{maildir}"
state_db = "{state_db}"

[[account]]
name = "test"
host = "imap.example.com"
username = "user@example.com"
"#,
            maildir = dir.path().join("mail").display(),
            state_db = dir.path().join("state.db").display(),
        );
        let config_path = write_temp_config(&dir, &config_content);

        let err = load_config(&config_path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no password source"), "got: {msg}");
    }

    #[test]
    fn password_command_takes_priority() {
        let dir = tempfile::tempdir().unwrap();
        let config_content = format!(
            r#"
[general]
maildir_path = "{maildir}"
state_db = "{state_db}"

[[account]]
name = "test"
host = "imap.example.com"
username = "user@example.com"
password_command = "echo hunter2"
password = "plaintext"
"#,
            maildir = dir.path().join("mail").display(),
            state_db = dir.path().join("state.db").display(),
        );
        let config_path = write_temp_config(&dir, &config_content);

        let config = load_config(&config_path).unwrap();
        assert!(
            matches!(
                config.accounts[0].password_source,
                PasswordSource::Command(_)
            ),
            "expected Command variant"
        );
    }

    #[test]
    fn password_file_takes_priority_over_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let pw_file = dir.path().join("password.txt");
        std::fs::write(&pw_file, "file-password\n").unwrap();

        let config_content = format!(
            r#"
[general]
maildir_path = "{maildir}"
state_db = "{state_db}"

[[account]]
name = "test"
host = "imap.example.com"
username = "user@example.com"
password_file = "{pw_file}"
password = "plaintext"
"#,
            maildir = dir.path().join("mail").display(),
            state_db = dir.path().join("state.db").display(),
            pw_file = pw_file.display(),
        );
        let config_path = write_temp_config(&dir, &config_content);

        let config = load_config(&config_path).unwrap();
        assert!(
            matches!(config.accounts[0].password_source, PasswordSource::File(_)),
            "expected File variant"
        );
    }

    #[test]
    fn resolve_password_from_command() {
        let password =
            resolve_password("test", &PasswordSource::Command("echo hunter2".to_owned())).unwrap();
        assert_eq!(*password, "hunter2");
    }

    #[test]
    fn resolve_password_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let pw_file = dir.path().join("password.txt");
        std::fs::write(&pw_file, "file-password\n").unwrap();

        let password = resolve_password("test", &PasswordSource::File(pw_file)).unwrap();
        assert_eq!(*password, "file-password");
    }

    #[test]
    fn resolve_password_from_plaintext() {
        let password =
            resolve_password("test", &PasswordSource::Plaintext("plain".to_owned())).unwrap();
        assert_eq!(*password, "plain");
    }

    #[test]
    fn reject_empty_password_file() {
        let dir = tempfile::tempdir().unwrap();
        let pw_file = dir.path().join("empty.txt");
        std::fs::write(&pw_file, "").unwrap();

        let err = resolve_password("test", &PasswordSource::File(pw_file)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("empty"), "got: {msg}");
    }

    #[test]
    fn reject_tls_false() {
        let dir = tempfile::tempdir().unwrap();
        let config_content = format!(
            r#"
[general]
maildir_path = "{maildir}"
state_db = "{state_db}"

[[account]]
name = "test"
host = "imap.example.com"
tls = false
username = "user@example.com"
password = "secret"
"#,
            maildir = dir.path().join("mail").display(),
            state_db = dir.path().join("state.db").display(),
        );
        let config_path = write_temp_config(&dir, &config_content);

        let err = load_config(&config_path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("TLS is required"),
            "expected TLS rejection error, got: {msg}"
        );
    }

    #[test]
    fn account_folder_patterns() {
        let dir = tempfile::tempdir().unwrap();
        let config_content = format!(
            r#"
[general]
maildir_path = "{maildir}"
state_db = "{state_db}"

[[account]]
name = "test"
host = "imap.example.com"
username = "user@example.com"
password = "secret"
folder_patterns = ["*", "!Trash", "!Spam"]
"#,
            maildir = dir.path().join("mail").display(),
            state_db = dir.path().join("state.db").display(),
        );
        let config_path = write_temp_config(&dir, &config_content);

        let config = load_config(&config_path).unwrap();
        let account = &config.accounts[0];
        assert_eq!(
            account.folder_patterns,
            vec!["*".to_owned(), "!Trash".to_owned(), "!Spam".to_owned()]
        );
    }

    #[test]
    fn account_folder_patterns_default() {
        let dir = tempfile::tempdir().unwrap();
        let config_content = minimal_valid_config(&dir);
        let config_path = write_temp_config(&dir, &config_content);

        let config = load_config(&config_path).unwrap();
        let account = &config.accounts[0];
        assert_eq!(account.folder_patterns, vec!["*".to_owned()]);
    }

    #[test]
    fn reject_empty_folder_pattern() {
        let dir = tempfile::tempdir().unwrap();
        let config_content = format!(
            r#"
[general]
maildir_path = "{maildir}"
state_db = "{state_db}"

[[account]]
name = "test"
host = "imap.example.com"
username = "user@example.com"
password = "secret"
folder_patterns = ["*", ""]
"#,
            maildir = dir.path().join("mail").display(),
            state_db = dir.path().join("state.db").display(),
        );
        let config_path = write_temp_config(&dir, &config_content);

        let err = load_config(&config_path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("pattern must not be empty"), "got: {msg}");
    }

    #[test]
    fn reject_empty_negated_folder_pattern() {
        let dir = tempfile::tempdir().unwrap();
        let config_content = format!(
            r#"
[general]
maildir_path = "{maildir}"
state_db = "{state_db}"

[[account]]
name = "test"
host = "imap.example.com"
username = "user@example.com"
password = "secret"
folder_patterns = ["!"]
"#,
            maildir = dir.path().join("mail").display(),
            state_db = dir.path().join("state.db").display(),
        );
        let config_path = write_temp_config(&dir, &config_content);

        let err = load_config(&config_path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("pattern must not be empty"), "got: {msg}");
    }

    // --- matches_folder_patterns tests ---

    #[test]
    fn pattern_default_star_includes_everything() {
        let patterns = vec!["*".to_owned()];
        assert!(matches_folder_patterns("INBOX", &patterns));
        assert!(matches_folder_patterns("Sent", &patterns));
        assert!(matches_folder_patterns("Trash", &patterns));
        assert!(matches_folder_patterns("Archive/2024", &patterns));
    }

    #[test]
    fn pattern_star_exclude_trash() {
        let patterns = vec!["*".to_owned(), "!Trash".to_owned()];
        assert!(matches_folder_patterns("INBOX", &patterns));
        assert!(matches_folder_patterns("Sent", &patterns));
        assert!(!matches_folder_patterns("Trash", &patterns));
    }

    #[test]
    fn pattern_star_exclude_multiple() {
        let patterns = vec![
            "*".to_owned(),
            "!Trash".to_owned(),
            "!Spam".to_owned(),
            "!Drafts".to_owned(),
        ];
        assert!(matches_folder_patterns("INBOX", &patterns));
        assert!(matches_folder_patterns("Sent", &patterns));
        assert!(!matches_folder_patterns("Trash", &patterns));
        assert!(!matches_folder_patterns("Spam", &patterns));
        assert!(!matches_folder_patterns("Drafts", &patterns));
    }

    #[test]
    fn pattern_explicit_include_only() {
        let patterns = vec!["INBOX".to_owned(), "Sent".to_owned()];
        assert!(matches_folder_patterns("INBOX", &patterns));
        assert!(matches_folder_patterns("Sent", &patterns));
        assert!(!matches_folder_patterns("Trash", &patterns));
        assert!(!matches_folder_patterns("Spam", &patterns));
    }

    #[test]
    fn pattern_wildcard_exclude_drafts() {
        let patterns = vec!["*".to_owned(), "!Draft*".to_owned()];
        assert!(matches_folder_patterns("INBOX", &patterns));
        assert!(!matches_folder_patterns("Drafts", &patterns));
        assert!(!matches_folder_patterns("Drafts/subfolder", &patterns));
    }

    #[test]
    fn pattern_archive_subfolders() {
        let patterns = vec!["Archive/*".to_owned()];
        assert!(matches_folder_patterns("Archive/2024", &patterns));
        assert!(matches_folder_patterns("Archive/old", &patterns));
        assert!(!matches_folder_patterns("Archive", &patterns));
        assert!(!matches_folder_patterns("INBOX", &patterns));
    }

    #[test]
    fn pattern_empty_includes_nothing() {
        let patterns: Vec<String> = vec![];
        assert!(!matches_folder_patterns("INBOX", &patterns));
        assert!(!matches_folder_patterns("Sent", &patterns));
    }

    #[test]
    fn pattern_last_match_wins() {
        let patterns = vec!["!INBOX".to_owned(), "INBOX".to_owned()];
        assert!(matches_folder_patterns("INBOX", &patterns));
    }

    #[test]
    fn pattern_last_match_wins_negation() {
        let patterns = vec!["*".to_owned(), "!INBOX".to_owned()];
        assert!(!matches_folder_patterns("INBOX", &patterns));
        assert!(matches_folder_patterns("Sent", &patterns));
    }

    #[test]
    fn pattern_question_mark_wildcard() {
        let patterns = vec!["Sent?".to_owned()];
        assert!(matches_folder_patterns("Sent1", &patterns));
        assert!(matches_folder_patterns("SentX", &patterns));
        assert!(!matches_folder_patterns("Sent", &patterns));
        assert!(!matches_folder_patterns("Sent12", &patterns));
    }

    // --- glob_match tests ---

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("INBOX", "INBOX"));
        assert!(!glob_match("INBOX", "Sent"));
    }

    #[test]
    fn glob_match_star_matches_everything() {
        assert!(glob_match("*", "INBOX"));
        assert!(glob_match("*", "anything/at/all"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn glob_match_star_prefix() {
        assert!(glob_match("Archive/*", "Archive/2024"));
        assert!(glob_match("Archive/*", "Archive/old/deep"));
        assert!(!glob_match("Archive/*", "Archive"));
    }

    #[test]
    fn glob_match_star_suffix() {
        assert!(glob_match("Draft*", "Drafts"));
        assert!(glob_match("Draft*", "Draft"));
        assert!(glob_match("Draft*", "Drafts/subfolder"));
        assert!(!glob_match("Draft*", "MyDraft"));
    }

    #[test]
    fn glob_match_question_mark() {
        assert!(glob_match("Sent?", "Sent1"));
        assert!(!glob_match("Sent?", "Sent"));
        assert!(!glob_match("Sent?", "Sent12"));
    }

    #[test]
    fn glob_match_combined() {
        assert!(glob_match("A?c*", "Abc"));
        assert!(glob_match("A?c*", "AxcDEF"));
        assert!(!glob_match("A?c*", "Ac"));
    }

    #[test]
    fn validate_paths_rejects_missing_parent() {
        let config = GeneralConfig {
            maildir_path: PathBuf::from("/nonexistent/parent/mail"),
            state_db: PathBuf::from("/tmp/state.db"),
            log_level: "info".to_owned(),
            sync_interval_seconds: 300,
            stale_threshold_days: 7,
            max_email_size_bytes: 100 * 1024 * 1024,
            imap_timeout_seconds: 60,
            fsync_on_write: true,
        };

        let err = validate_paths(&config).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("does not exist"), "got: {msg}");
    }

    #[test]
    fn password_env_resolves_from_environment() {
        // HOME is always set on Unix systems and is a safe, non-empty variable.
        let var_name = "HOME";
        let password =
            resolve_password("test", &PasswordSource::Environment(var_name.to_owned())).unwrap();
        assert!(!password.is_empty());
    }

    #[test]
    fn password_env_error_on_missing_var() {
        // Use a variable name that will never be set in any environment.
        let var_name = "EMAIL_BACKUPS_TEST_NONEXISTENT_VAR_9f8a7b6c";

        let err = resolve_password("test", &PasswordSource::Environment(var_name.to_owned()))
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not set"), "got: {msg}");
    }

    #[test]
    fn password_env_priority() {
        let dir = tempfile::tempdir().unwrap();
        let pw_file = dir.path().join("password.txt");
        std::fs::write(&pw_file, "file-password\n").unwrap();

        // command > env: command wins
        let config_content = format!(
            r#"
[general]
maildir_path = "{maildir}"
state_db = "{state_db}"

[[account]]
name = "test"
host = "imap.example.com"
username = "user@example.com"
password_command = "echo cmd-pw"
password_env = "SOME_VAR"
password = "plaintext"
"#,
            maildir = dir.path().join("mail").display(),
            state_db = dir.path().join("state.db").display(),
        );
        let config_path = write_temp_config(&dir, &config_content);
        let config = load_config(&config_path).unwrap();
        assert!(
            matches!(
                config.accounts[0].password_source,
                PasswordSource::Command(_)
            ),
            "expected Command to win over env"
        );

        // file > env: file wins
        let config_content = format!(
            r#"
[general]
maildir_path = "{maildir}"
state_db = "{state_db}"

[[account]]
name = "test"
host = "imap.example.com"
username = "user@example.com"
password_file = "{pw_file}"
password_env = "SOME_VAR"
password = "plaintext"
"#,
            maildir = dir.path().join("mail").display(),
            state_db = dir.path().join("state.db").display(),
            pw_file = pw_file.display(),
        );
        let config_path = write_temp_config(&dir, &config_content);
        let config = load_config(&config_path).unwrap();
        assert!(
            matches!(config.accounts[0].password_source, PasswordSource::File(_)),
            "expected File to win over env"
        );

        // env > plaintext: env wins
        let config_content = format!(
            r#"
[general]
maildir_path = "{maildir}"
state_db = "{state_db}"

[[account]]
name = "test"
host = "imap.example.com"
username = "user@example.com"
password_env = "SOME_VAR"
password = "plaintext"
"#,
            maildir = dir.path().join("mail").display(),
            state_db = dir.path().join("state.db").display(),
        );
        let config_path = write_temp_config(&dir, &config_content);
        let config = load_config(&config_path).unwrap();
        assert!(
            matches!(
                config.accounts[0].password_source,
                PasswordSource::Environment(_)
            ),
            "expected Environment to win over plaintext"
        );
    }
}
