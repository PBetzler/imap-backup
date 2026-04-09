//! Startup recovery and consistency checks.
//!
//! Runs on every startup before the first sync cycle to ensure the system
//! is in a consistent state. Cleans up orphaned temporary files, verifies
//! database integrity, and detects stale lock files.

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

use rusqlite::Connection;

use crate::error::RecoveryError;

/// Maildir spec threshold for stale temporary files (in hours).
const STALE_TMP_THRESHOLD_HOURS: u64 = 36;

/// Duration threshold for stale temporary files.
const STALE_TMP_THRESHOLD: Duration = Duration::from_secs(STALE_TMP_THRESHOLD_HOURS * 60 * 60);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run all startup recovery checks.
///
/// 1. Clean orphaned temporary files from Maildir `tmp/` directories.
/// 2. Verify SQLite database integrity.
///
/// Lock file staleness is handled atomically by the lock acquisition in
/// `main.rs`, so it is not checked here.
///
/// Returns an error if a critical check fails (e.g., database corruption).
/// Non-critical issues (stale tmp files) are cleaned up and logged as
/// warnings.
pub fn run_startup_recovery(
    maildir_base: &Path,
    db_conn: &Connection,
) -> Result<(), RecoveryError> {
    clean_orphaned_tmp_files(maildir_base)?;
    check_database_integrity(db_conn)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Orphan tmp cleanup
// ---------------------------------------------------------------------------

/// Scan all Maildir `tmp/` directories and delete files older than the
/// stale threshold.
///
/// Logs a warning for each file removed. Continues on individual file
/// deletion failures but propagates directory read errors.
pub fn clean_orphaned_tmp_files(maildir_base: &Path) -> Result<(), RecoveryError> {
    let now = SystemTime::now();
    let tmp_dirs = find_tmp_directories(maildir_base)?;

    for tmp_dir in tmp_dirs {
        clean_single_tmp_directory(&tmp_dir, now)?;
    }

    Ok(())
}

/// Find all `tmp/` directories under the maildir base.
fn find_tmp_directories(maildir_base: &Path) -> Result<Vec<std::path::PathBuf>, RecoveryError> {
    if !maildir_base.is_dir() {
        return Ok(Vec::new());
    }

    let mut tmp_dirs = Vec::new();
    collect_tmp_directories(maildir_base, &mut tmp_dirs)?;
    Ok(tmp_dirs)
}

/// Recursively collect `tmp/` directories under a base path.
fn collect_tmp_directories(
    base: &Path,
    result: &mut Vec<std::path::PathBuf>,
) -> Result<(), RecoveryError> {
    let entries = read_directory(base)?;

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("tmp") {
                result.push(path);
            } else {
                // Recurse into subdirectories (but not into cur/new/tmp themselves)
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name != "cur" && name != "new" {
                    collect_tmp_directories(&path, result)?;
                }
            }
        }
    }

    Ok(())
}

/// Read a directory's entries, mapping I/O errors to `RecoveryError`.
fn read_directory(path: &Path) -> Result<Vec<fs::DirEntry>, RecoveryError> {
    let mut entries = Vec::new();
    let read_dir = fs::read_dir(path).map_err(|source| RecoveryError::TempCleanup {
        path: path.display().to_string(),
        source,
    })?;

    for entry_result in read_dir {
        let entry = entry_result.map_err(|source| RecoveryError::TempCleanup {
            path: path.display().to_string(),
            source,
        })?;
        entries.push(entry);
    }

    Ok(entries)
}

/// Clean stale files from a single `tmp/` directory.
///
/// Continues on individual file deletion failures, logging a warning for
/// each failed file.
fn clean_single_tmp_directory(tmp_dir: &Path, now: SystemTime) -> Result<(), RecoveryError> {
    let entries = read_directory(tmp_dir)?;

    for entry in entries {
        let path = entry.path();
        if path.is_file() {
            if let Err(e) = remove_if_stale(&path, now) {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to remove stale temporary file, continuing"
                );
            }
        }
    }

    Ok(())
}

/// Remove a file if it is older than the stale threshold.
fn remove_if_stale(path: &Path, now: SystemTime) -> Result<(), RecoveryError> {
    let metadata = fs::metadata(path).map_err(|source| RecoveryError::TempCleanup {
        path: path.display().to_string(),
        source,
    })?;

    let modified = metadata
        .modified()
        .map_err(|source| RecoveryError::TempCleanup {
            path: path.display().to_string(),
            source,
        })?;

    let age = now.duration_since(modified).unwrap_or(Duration::ZERO);

    if age >= STALE_TMP_THRESHOLD {
        tracing::warn!(
            path = %path.display(),
            age_hours = age.as_secs() / 3600,
            "removing stale temporary file"
        );
        fs::remove_file(path).map_err(|source| RecoveryError::TempCleanup {
            path: path.display().to_string(),
            source,
        })?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Database integrity check
// ---------------------------------------------------------------------------

/// Run `PRAGMA integrity_check` on the SQLite database.
///
/// Returns an error if the integrity check reports any issues. A failing
/// integrity check indicates database corruption — the caller should NOT
/// proceed with normal operations.
pub fn check_database_integrity(conn: &Connection) -> Result<(), RecoveryError> {
    let result: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|e| RecoveryError::IntegrityCheck {
            reason: format!("failed to run integrity check: {e}"),
        })?;

    if result != "ok" {
        return Err(RecoveryError::IntegrityCheck {
            reason: format!("integrity check failed: {result}"),
        });
    }

    tracing::info!("database integrity check passed");
    Ok(())
}

// ---------------------------------------------------------------------------
// Lock file staleness
// ---------------------------------------------------------------------------

/// Check if a lock file exists and is stale (PID no longer running).
///
/// If the lock file is stale, it is removed and a warning is logged.
/// If the PID is still active, this returns an error to prevent
/// concurrent execution.
///
/// Note: This function is retained for testing. Lock acquisition in
/// production uses the atomic `acquire_lock_file` in `main.rs`.
#[cfg(test)]
pub fn check_stale_lock_file(lock_file_path: &Path) -> Result<(), RecoveryError> {
    if !lock_file_path.exists() {
        return Ok(());
    }

    let content = fs::read_to_string(lock_file_path).map_err(|e| RecoveryError::LockFile {
        path: lock_file_path.display().to_string(),
        reason: format!("failed to read lock file: {e}"),
    })?;

    let pid = parse_lock_file_pid(&content, lock_file_path)?;

    if is_process_running(pid) {
        return Err(RecoveryError::LockFile {
            path: lock_file_path.display().to_string(),
            reason: format!("another instance is running (PID {pid})"),
        });
    }

    tracing::warn!(
        path = %lock_file_path.display(),
        stale_pid = pid,
        "removing stale lock file"
    );

    fs::remove_file(lock_file_path).map_err(|e| RecoveryError::LockFile {
        path: lock_file_path.display().to_string(),
        reason: format!("failed to remove stale lock file: {e}"),
    })?;

    Ok(())
}

/// Parse the PID from lock file content.
#[cfg(test)]
fn parse_lock_file_pid(content: &str, lock_file_path: &Path) -> Result<u32, RecoveryError> {
    content
        .trim()
        .parse::<u32>()
        .map_err(|e| RecoveryError::LockFile {
            path: lock_file_path.display().to_string(),
            reason: format!("lock file contains invalid PID: {e}"),
        })
}

/// Check whether a process with the given PID is currently running.
///
/// On Unix, sends signal 0 to the process (no-op but checks existence).
/// On non-Unix, conservatively assumes the process is running.
#[cfg(unix)]
pub fn is_process_running(pid: u32) -> bool {
    // kill(pid, 0) checks if the process exists without sending a signal.
    // Returns 0 if the process exists and we have permission to signal it.
    // SAFETY: This is not unsafe code — libc::kill is a C function, but
    // we use nix or raw syscall via std instead.
    let result = std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match result {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

#[cfg(not(unix))]
pub fn is_process_running(_pid: u32) -> bool {
    // Conservatively assume the process is running on non-Unix platforms.
    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Orphan tmp cleanup ---

    #[test]
    fn clean_removes_stale_tmp_files() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("INBOX");
        let tmp = folder.join("tmp");
        fs::create_dir_all(&tmp).unwrap();
        fs::create_dir_all(folder.join("cur")).unwrap();
        fs::create_dir_all(folder.join("new")).unwrap();

        // Create a file and backdate its modification time
        let stale_file = tmp.join("stale.msg");
        fs::write(&stale_file, "old message").unwrap();
        let old_time = filetime::FileTime::from_unix_time(0, 0);
        filetime::set_file_mtime(&stale_file, old_time).unwrap();

        clean_orphaned_tmp_files(dir.path()).unwrap();

        assert!(!stale_file.exists(), "stale file should be removed");
    }

    #[test]
    fn clean_preserves_fresh_tmp_files() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("INBOX");
        let tmp = folder.join("tmp");
        fs::create_dir_all(&tmp).unwrap();
        fs::create_dir_all(folder.join("cur")).unwrap();
        fs::create_dir_all(folder.join("new")).unwrap();

        let fresh_file = tmp.join("fresh.msg");
        fs::write(&fresh_file, "new message").unwrap();

        clean_orphaned_tmp_files(dir.path()).unwrap();

        assert!(fresh_file.exists(), "fresh file should be preserved");
    }

    #[test]
    fn clean_handles_nonexistent_base_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nonexistent = dir.path().join("does_not_exist");

        let result = clean_orphaned_tmp_files(&nonexistent);
        assert!(result.is_ok());
    }

    #[test]
    fn clean_handles_empty_tmp_directory() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("INBOX");
        fs::create_dir_all(folder.join("tmp")).unwrap();
        fs::create_dir_all(folder.join("cur")).unwrap();
        fs::create_dir_all(folder.join("new")).unwrap();

        let result = clean_orphaned_tmp_files(dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn clean_scans_nested_folders() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("Archive").join("2024");
        let tmp = nested.join("tmp");
        fs::create_dir_all(&tmp).unwrap();
        fs::create_dir_all(nested.join("cur")).unwrap();
        fs::create_dir_all(nested.join("new")).unwrap();

        let stale_file = tmp.join("stale.msg");
        fs::write(&stale_file, "old message").unwrap();
        let old_time = filetime::FileTime::from_unix_time(0, 0);
        filetime::set_file_mtime(&stale_file, old_time).unwrap();

        clean_orphaned_tmp_files(dir.path()).unwrap();

        assert!(
            !stale_file.exists(),
            "stale file in nested folder should be removed"
        );
    }

    // --- Database integrity check ---

    #[test]
    fn integrity_check_passes_on_good_database() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE test (id INTEGER PRIMARY KEY)")
            .unwrap();

        let result = check_database_integrity(&conn);
        assert!(result.is_ok());
    }

    // --- Lock file staleness ---

    #[test]
    fn no_lock_file_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("backup.lock");

        let result = check_stale_lock_file(&lock_path);
        assert!(result.is_ok());
    }

    #[test]
    fn stale_lock_file_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("backup.lock");

        // Use a PID that is extremely unlikely to be running (max u32 - 1)
        fs::write(&lock_path, "4294967294").unwrap();

        let result = check_stale_lock_file(&lock_path);
        assert!(result.is_ok());
        assert!(!lock_path.exists(), "stale lock file should be removed");
    }

    #[test]
    fn lock_file_with_invalid_pid_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("backup.lock");

        fs::write(&lock_path, "not_a_pid").unwrap();

        let result = check_stale_lock_file(&lock_path);
        assert!(result.is_err());
    }

    #[test]
    fn lock_file_with_running_pid_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("backup.lock");

        // Use our own PID, which is guaranteed to be running
        let our_pid = std::process::id();
        fs::write(&lock_path, our_pid.to_string()).unwrap();

        let result = check_stale_lock_file(&lock_path);
        assert!(result.is_err());
    }

    // --- Parse lock file PID ---

    #[test]
    fn parse_valid_pid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock");
        let pid = parse_lock_file_pid("12345\n", &path).unwrap();
        assert_eq!(pid, 12345);
    }

    #[test]
    fn parse_invalid_pid_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock");
        let result = parse_lock_file_pid("invalid", &path);
        assert!(result.is_err());
    }

    // --- Stale threshold constant ---

    #[test]
    fn stale_threshold_is_36_hours() {
        assert_eq!(STALE_TMP_THRESHOLD, Duration::from_secs(36 * 60 * 60));
    }
}
