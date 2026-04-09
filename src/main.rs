//! IMAP email backup tool with move detection and archival retention.
//!
//! Connects to one or more IMAP accounts, downloads all emails into a
//! local Maildir structure, and detects server-side moves via composite
//! fingerprinting. Emails deleted on the server are never removed locally.

mod config;
mod error;
mod fingerprint;
mod imap_client;
mod maildir;
mod recovery;
mod shutdown;
mod state;
mod sync;
mod sync_plan;
mod types;

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::config::{AccountConfig, Config};
use crate::imap_client::AsyncImapClient;
use crate::maildir::FsMaildirStore;
use crate::shutdown::{ShutdownController, ShutdownSignal, spawn_signal_handler};
use crate::state::{SqliteStateDb, StateDb};
use crate::sync::{SyncEngine, build_sync_report, log_sync_report};
use crate::types::AccountSyncReport;

/// Exit code for successful execution.
const EXIT_SUCCESS: u8 = 0;

/// Exit code for complete failure.
const EXIT_FAILURE: u8 = 1;

/// Exit code for partial failure (some accounts failed, some succeeded).
const EXIT_PARTIAL: u8 = 2;

/// Stale backup warning threshold in seconds (from config: stale_threshold_days).
const SECONDS_PER_DAY: u64 = 86400;

/// Log output format.
#[derive(Debug, Clone, clap::ValueEnum)]
enum LogFormat {
    /// Human-readable log output.
    Human,
    /// Machine-parseable JSON log output.
    Json,
}

/// IMAP email backup tool with move detection and archival retention.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, value_name = "PATH")]
    config: PathBuf,

    /// Log what would happen without making any changes.
    #[arg(long)]
    dry_run: bool,

    /// Run a single sync cycle and exit (default behavior).
    #[arg(long)]
    once: bool,

    /// Run continuously, polling at the interval from the config file.
    #[arg(long, conflicts_with = "once")]
    daemon: bool,

    /// Sync only the named account instead of all accounts.
    #[arg(long, value_name = "NAME")]
    account: Option<String>,

    /// Increase log verbosity (can be repeated: -v for debug, -vv for trace).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Log output format.
    #[arg(long, value_enum, default_value = "human")]
    log_format: LogFormat,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let cfg = match config::load_config(&cli.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(EXIT_FAILURE);
        }
    };

    let effective_log_level = effective_log_level(&cfg.general.log_level, cli.verbose);
    if let Err(e) = init_logging(&effective_log_level, &cli.log_format) {
        eprintln!("error: {e}");
        return ExitCode::from(EXIT_FAILURE);
    }

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "failed to create Tokio runtime");
            return ExitCode::from(EXIT_FAILURE);
        }
    };

    rt.block_on(async_main(&cli, &cfg))
}

/// Async entry point that runs inside the Tokio runtime.
async fn async_main(cli: &Cli, cfg: &Config) -> ExitCode {
    tracing::info!(
        config_path = %cli.config.display(),
        accounts = cfg.accounts.len(),
        dry_run = cli.dry_run,
        daemon = cli.daemon,
        "configuration loaded"
    );

    if let Err(e) = config::validate_paths(&cfg.general) {
        tracing::error!(error = %e, "path validation failed");
        return ExitCode::from(EXIT_FAILURE);
    }

    if let Some(ref name) = cli.account {
        let found = cfg.accounts.iter().any(|a| a.name == *name);
        if !found {
            tracing::error!(account = name, "account not found in configuration");
            return ExitCode::from(EXIT_FAILURE);
        }
        tracing::info!(account = name, "will sync single account");
    }

    // Open state database
    let state_db = match SqliteStateDb::open(&cfg.general.state_db) {
        Ok(db) => db,
        Err(e) => {
            tracing::error!(error = %e, "failed to open state database");
            return ExitCode::from(EXIT_FAILURE);
        }
    };

    // Run startup recovery
    let lock_file_path = lock_file_path(&cfg.general.state_db);
    if let Err(e) = recovery::run_startup_recovery(&cfg.general.maildir_path, state_db.connection())
    {
        tracing::error!(error = %e, "startup recovery failed");
        return ExitCode::from(EXIT_FAILURE);
    }

    // Acquire lock file
    if let Err(e) = acquire_lock_file(&lock_file_path) {
        tracing::error!(error = %e, "failed to acquire lock file");
        return ExitCode::from(EXIT_FAILURE);
    }

    // Check for stale backups
    check_stale_backups(&state_db, cfg);

    // Create Maildir store
    let maildir = FsMaildirStore::new(cfg.general.maildir_path.clone(), cfg.general.fsync_on_write);

    // Set up shutdown signal handling
    let (controller, shutdown_signal) = ShutdownController::new();
    spawn_signal_handler(controller);

    // Create sync engine
    let engine: SyncEngine<AsyncImapClient, _, _> =
        SyncEngine::new(state_db, maildir, cfg.general.max_email_size_bytes);

    let accounts = select_accounts(&cfg.accounts, &cli.account);

    for account in &accounts {
        tracing::info!(
            account = account.name,
            host = account.host,
            port = account.port,
            tls = account.tls,
            "account configured"
        );
    }

    if cli.dry_run {
        tracing::info!("dry-run mode: no changes will be made");
    }

    // Run the appropriate mode
    let exit_code = if cli.daemon {
        run_daemon(
            &engine,
            &accounts,
            cfg.general.imap_timeout_seconds,
            cli.dry_run,
            cfg.general.sync_interval_seconds,
            &shutdown_signal,
        )
        .await
    } else {
        run_once(
            &engine,
            &accounts,
            cfg.general.imap_timeout_seconds,
            cli.dry_run,
            &shutdown_signal,
        )
        .await
    };

    // Release lock file
    release_lock_file(&lock_file_path);

    ExitCode::from(exit_code)
}

/// Run a single sync cycle across all accounts.
async fn run_once(
    engine: &SyncEngine<AsyncImapClient, SqliteStateDb, FsMaildirStore>,
    accounts: &[&AccountConfig],
    imap_timeout: u64,
    dry_run: bool,
    shutdown: &ShutdownSignal,
) -> u8 {
    let start = Instant::now();
    let account_reports =
        sync_all_accounts(engine, accounts, imap_timeout, dry_run, shutdown).await;
    let duration = start.elapsed();

    let report = build_sync_report(account_reports, duration);
    log_sync_report(&report);

    determine_exit_code(report.errors, accounts.len() as u64)
}

/// Run in daemon mode: sync repeatedly at the configured interval.
async fn run_daemon(
    engine: &SyncEngine<AsyncImapClient, SqliteStateDb, FsMaildirStore>,
    accounts: &[&AccountConfig],
    imap_timeout: u64,
    dry_run: bool,
    sync_interval_seconds: u64,
    shutdown: &ShutdownSignal,
) -> u8 {
    let interval = std::time::Duration::from_secs(sync_interval_seconds);
    let mut last_exit_code = EXIT_SUCCESS;

    tracing::info!(
        interval_seconds = sync_interval_seconds,
        "starting daemon mode"
    );

    loop {
        if shutdown.is_shutdown_requested() {
            tracing::info!("shutdown requested, exiting daemon loop");
            break;
        }

        let start = Instant::now();
        let account_reports =
            sync_all_accounts(engine, accounts, imap_timeout, dry_run, shutdown).await;
        let duration = start.elapsed();

        let report = build_sync_report(account_reports, duration);
        log_sync_report(&report);
        last_exit_code = determine_exit_code(report.errors, accounts.len() as u64);

        tracing::info!(
            sleep_seconds = sync_interval_seconds,
            "waiting for next sync cycle"
        );

        // Sleep in small increments to check for shutdown signal
        let sleep_end = Instant::now() + interval;
        while Instant::now() < sleep_end {
            if shutdown.is_shutdown_requested() {
                tracing::info!("shutdown requested during sleep, exiting daemon loop");
                return last_exit_code;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    last_exit_code
}

/// Sync all accounts, returning per-account reports.
async fn sync_all_accounts(
    engine: &SyncEngine<AsyncImapClient, SqliteStateDb, FsMaildirStore>,
    accounts: &[&AccountConfig],
    imap_timeout: u64,
    dry_run: bool,
    shutdown: &ShutdownSignal,
) -> Vec<AccountSyncReport> {
    let mut reports = Vec::with_capacity(accounts.len());

    for account in accounts {
        if shutdown.is_shutdown_requested() {
            tracing::info!("shutdown requested, stopping account iteration");
            break;
        }

        match engine
            .sync_account(account, imap_timeout, dry_run, shutdown)
            .await
        {
            Ok(report) => reports.push(report),
            Err(e) => {
                tracing::error!(
                    account = account.name,
                    error = %e,
                    "account sync failed"
                );
                let mut error_report = AccountSyncReport {
                    account: account.name.clone(),
                    ..Default::default()
                };
                error_report.errors = 1;
                reports.push(error_report);
            }
        }
    }

    reports
}

// ---------------------------------------------------------------------------
// Lock file management
// ---------------------------------------------------------------------------

/// Derive the lock file path from the state database path.
fn lock_file_path(state_db_path: &Path) -> PathBuf {
    let mut lock_path = state_db_path.to_path_buf();
    lock_path.set_extension("lock");
    lock_path
}

/// Atomically create a lock file containing the current process PID.
///
/// Uses `O_CREAT | O_EXCL` (via `create_new`) to prevent TOCTOU races.
/// If the file already exists, checks whether the owning PID is still alive.
/// Stale locks are removed and creation is retried once.
fn acquire_lock_file(path: &Path) -> Result<(), error::AppError> {
    acquire_lock_file_inner(path, false)
}

/// Inner implementation with a `retried` guard to prevent infinite recursion.
fn acquire_lock_file_inner(path: &Path, retried: bool) -> Result<(), error::AppError> {
    let pid = std::process::id();

    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            write!(file, "{pid}").map_err(|e| {
                error::AppError::Recovery(error::RecoveryError::LockFile {
                    path: path.display().to_string(),
                    reason: format!("failed to write PID to lock file: {e}"),
                })
            })?;
            tracing::info!(path = %path.display(), pid = pid, "lock file acquired");
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if retried {
                return Err(error::AppError::Recovery(error::RecoveryError::LockFile {
                    path: path.display().to_string(),
                    reason: "lock file still exists after removing stale lock".to_owned(),
                }));
            }

            // Check whether the existing lock is stale
            let content = fs::read_to_string(path).map_err(|read_err| {
                error::AppError::Recovery(error::RecoveryError::LockFile {
                    path: path.display().to_string(),
                    reason: format!("failed to read existing lock file: {read_err}"),
                })
            })?;

            let existing_pid = content.trim().parse::<u32>().map_err(|parse_err| {
                error::AppError::Recovery(error::RecoveryError::LockFile {
                    path: path.display().to_string(),
                    reason: format!("lock file contains invalid PID: {parse_err}"),
                })
            })?;

            if recovery::is_process_running(existing_pid) {
                return Err(error::AppError::Recovery(error::RecoveryError::LockFile {
                    path: path.display().to_string(),
                    reason: format!("another instance is running (PID {existing_pid})"),
                }));
            }

            tracing::warn!(
                path = %path.display(),
                stale_pid = existing_pid,
                "removing stale lock file"
            );

            fs::remove_file(path).map_err(|rm_err| {
                error::AppError::Recovery(error::RecoveryError::LockFile {
                    path: path.display().to_string(),
                    reason: format!("failed to remove stale lock file: {rm_err}"),
                })
            })?;

            // Retry once
            acquire_lock_file_inner(path, true)
        }
        Err(e) => Err(error::AppError::Recovery(error::RecoveryError::LockFile {
            path: path.display().to_string(),
            reason: format!("failed to create lock file: {e}"),
        })),
    }
}

/// Remove the lock file, logging a warning if removal fails.
fn release_lock_file(path: &Path) {
    if path.exists() {
        if let Err(e) = fs::remove_file(path) {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "failed to remove lock file"
            );
        } else {
            tracing::info!(path = %path.display(), "lock file released");
        }
    }
}

// ---------------------------------------------------------------------------
// Stale backup detection
// ---------------------------------------------------------------------------

/// Check all accounts for stale backups and log warnings.
fn check_stale_backups(state_db: &SqliteStateDb, cfg: &Config) {
    let threshold_secs = cfg.general.stale_threshold_days * SECONDS_PER_DAY;

    for account in &cfg.accounts {
        match state_db.get_last_successful_sync(&account.name) {
            Ok(Some(timestamp_str)) => {
                if let Ok(last_sync_secs) = timestamp_str.parse::<u64>() {
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let age_secs = now_secs.saturating_sub(last_sync_secs);
                    if age_secs > threshold_secs {
                        tracing::warn!(
                            account = account.name,
                            last_sync_age_days = age_secs / SECONDS_PER_DAY,
                            threshold_days = cfg.general.stale_threshold_days,
                            "backup is stale — last successful sync exceeded threshold"
                        );
                    }
                }
            }
            Ok(None) => {
                tracing::info!(
                    account = account.name,
                    "no previous successful sync recorded"
                );
            }
            Err(e) => {
                tracing::warn!(
                    account = account.name,
                    error = %e,
                    "failed to check last successful sync"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Select accounts to sync based on the CLI `--account` filter.
fn select_accounts<'a>(
    accounts: &'a [AccountConfig],
    filter: &Option<String>,
) -> Vec<&'a AccountConfig> {
    match filter {
        Some(name) => accounts.iter().filter(|a| a.name == *name).collect(),
        None => accounts.iter().collect(),
    }
}

/// Determine the exit code based on the error count and total account count.
fn determine_exit_code(errors: u64, total_accounts: u64) -> u8 {
    if errors == 0 {
        EXIT_SUCCESS
    } else if errors >= total_accounts && total_accounts > 0 {
        EXIT_FAILURE
    } else {
        EXIT_PARTIAL
    }
}

/// Compute the effective log level by combining the config default with
/// the CLI verbosity flag.
fn effective_log_level(config_level: &str, verbose_count: u8) -> String {
    match verbose_count {
        0 => config_level.to_owned(),
        1 => "debug".to_owned(),
        _ => "trace".to_owned(),
    }
}

/// Initialize the tracing subscriber with the given log level and format.
fn init_logging(level: &str, format: &LogFormat) -> Result<(), error::AppError> {
    let env_filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

    let result = match format {
        LogFormat::Human => tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(false)
            .try_init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .json()
            .try_init(),
    };

    result.map_err(|e| error::AppError::LogInit {
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_log_level_uses_config_default() {
        assert_eq!(effective_log_level("warn", 0), "warn");
    }

    #[test]
    fn effective_log_level_verbose_once_is_debug() {
        assert_eq!(effective_log_level("info", 1), "debug");
    }

    #[test]
    fn effective_log_level_verbose_twice_is_trace() {
        assert_eq!(effective_log_level("info", 2), "trace");
        assert_eq!(effective_log_level("info", 3), "trace");
    }

    #[test]
    fn exit_code_constants_are_distinct() {
        assert_ne!(EXIT_SUCCESS, EXIT_FAILURE);
        assert_ne!(EXIT_SUCCESS, EXIT_PARTIAL);
        assert_ne!(EXIT_FAILURE, EXIT_PARTIAL);
    }

    #[test]
    fn determine_exit_code_all_success() {
        assert_eq!(determine_exit_code(0, 3), EXIT_SUCCESS);
    }

    #[test]
    fn determine_exit_code_all_failure() {
        assert_eq!(determine_exit_code(3, 3), EXIT_FAILURE);
    }

    #[test]
    fn determine_exit_code_partial_failure() {
        assert_eq!(determine_exit_code(1, 3), EXIT_PARTIAL);
    }

    #[test]
    fn determine_exit_code_more_errors_than_accounts() {
        // Edge case: more errors than accounts (shouldn't happen, but handle it)
        assert_eq!(determine_exit_code(5, 3), EXIT_FAILURE);
    }

    #[test]
    fn determine_exit_code_zero_accounts() {
        assert_eq!(determine_exit_code(0, 0), EXIT_SUCCESS);
    }

    #[test]
    fn select_accounts_no_filter() {
        let accounts = vec![make_test_account("a1"), make_test_account("a2")];
        let selected = select_accounts(&accounts, &None);
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn select_accounts_with_filter() {
        let accounts = vec![make_test_account("a1"), make_test_account("a2")];
        let selected = select_accounts(&accounts, &Some("a1".to_owned()));
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].name, "a1");
    }

    #[test]
    fn select_accounts_filter_no_match() {
        let accounts = vec![make_test_account("a1")];
        let selected = select_accounts(&accounts, &Some("nonexistent".to_owned()));
        assert!(selected.is_empty());
    }

    #[test]
    fn lock_file_path_derives_from_db_path() {
        let db_path = PathBuf::from("/var/lib/email-backups/state.db");
        let lock = lock_file_path(&db_path);
        assert_eq!(lock, PathBuf::from("/var/lib/email-backups/state.lock"));
    }

    #[test]
    fn acquire_and_release_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("test.lock");

        acquire_lock_file(&lock_path).unwrap();
        assert!(lock_path.exists());

        let content = fs::read_to_string(&lock_path).unwrap();
        let pid: u32 = content.trim().parse().unwrap();
        assert_eq!(pid, std::process::id());

        release_lock_file(&lock_path);
        assert!(!lock_path.exists());
    }

    #[test]
    fn acquire_lock_file_rejects_concurrent_instance() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("test_concurrent.lock");

        // Write our own PID as a "running" lock
        fs::write(&lock_path, std::process::id().to_string()).unwrap();

        // Acquiring should fail because the PID (ours) is alive
        let result = acquire_lock_file(&lock_path);
        assert!(result.is_err());
    }

    #[test]
    fn acquire_lock_file_removes_stale_and_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("test_stale.lock");

        // Write a PID that is extremely unlikely to be running
        fs::write(&lock_path, "4294967294").unwrap();

        // Acquiring should succeed because that PID is stale
        acquire_lock_file(&lock_path).unwrap();
        assert!(lock_path.exists());

        let content = fs::read_to_string(&lock_path).unwrap();
        let pid: u32 = content.trim().parse().unwrap();
        assert_eq!(pid, std::process::id());
    }

    #[test]
    fn release_nonexistent_lock_file_does_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("nonexistent.lock");
        release_lock_file(&lock_path);
    }

    fn make_test_account(name: &str) -> AccountConfig {
        AccountConfig {
            name: name.to_owned(),
            host: "imap.example.com".to_owned(),
            port: 993,
            tls: true,
            username: "user@example.com".to_owned(),
            password_source: config::PasswordSource::Plaintext("password".to_owned()),
            folder_patterns: vec!["*".to_owned()],
        }
    }
}
