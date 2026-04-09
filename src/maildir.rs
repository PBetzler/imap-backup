//! Maildir-format local email storage.
//!
//! The [`MaildirStore`] trait defines the contract for local message storage.
//! [`FsMaildirStore`] is the production implementation that writes messages
//! using the Maildir atomic-write pattern (write to `tmp/`, then rename to
//! `new/`) and enforces strict folder name sanitization.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use crate::error::StorageError;

/// Per-process atomic counter for generating unique filenames.
static FILENAME_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Maximum length in bytes for a single path component.
const MAX_COMPONENT_BYTES: usize = 255;

// ---------------------------------------------------------------------------
// Trait definition
// ---------------------------------------------------------------------------

/// Contract for Maildir-format local message storage.
///
/// Implementations must guarantee atomic writes (no partial files visible)
/// and strict folder name validation to prevent path traversal attacks.
pub trait MaildirStore {
    /// Store a message in the given folder using the Maildir atomic write pattern.
    ///
    /// Returns the final path where the message was stored.
    fn store_message(&self, folder: &str, content: &[u8]) -> Result<PathBuf, StorageError>;

    /// Store a message with IMAP flags preserved in the Maildir filename.
    ///
    /// If `flags` contains standard IMAP flags (e.g., `\Seen`, `\Flagged`),
    /// the message is stored in `cur/` with the appropriate Maildir info
    /// suffix. If no flags are present (or only `\Recent`), the message is
    /// stored in `new/` as with [`store_message`](Self::store_message).
    fn store_message_with_flags(
        &self,
        folder: &str,
        content: &[u8],
        flags: &[String],
    ) -> Result<PathBuf, StorageError>;

    /// Move a message file from its current path to a new folder's `cur/` directory.
    ///
    /// Returns the new path.
    fn move_message(&self, from_path: &Path, to_folder: &str) -> Result<PathBuf, StorageError>;

    /// Copy a message file to a new folder using the atomic write pattern.
    ///
    /// Returns the path of the copy.
    fn copy_message(&self, from_path: &Path, to_folder: &str) -> Result<PathBuf, StorageError>;

    /// Ensure a Maildir folder exists (with `cur/`, `new/`, `tmp/` subdirectories).
    ///
    /// Returns the path to the folder root.
    fn ensure_folder(&self, folder: &str) -> Result<PathBuf, StorageError>;

    /// Check whether a Maildir folder exists on disk.
    fn folder_exists(&self, folder: &str) -> bool;
}

// ---------------------------------------------------------------------------
// Filesystem implementation
// ---------------------------------------------------------------------------

/// Production Maildir store backed by the local filesystem.
pub struct FsMaildirStore {
    /// Root directory for all Maildir folders.
    base_dir: PathBuf,
    /// Whether to fsync files after writing (may be slow on NAS).
    fsync_on_write: bool,
}

impl FsMaildirStore {
    /// Create a new `FsMaildirStore` with the given base directory and fsync setting.
    pub fn new(base_dir: PathBuf, fsync_on_write: bool) -> Self {
        Self {
            base_dir,
            fsync_on_write,
        }
    }

    /// Return the base directory for all Maildir folders.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}

impl MaildirStore for FsMaildirStore {
    fn store_message(&self, folder: &str, content: &[u8]) -> Result<PathBuf, StorageError> {
        let folder_path = self.ensure_folder(folder)?;
        let filename = generate_unique_filename();
        let tmp_path = folder_path.join("tmp").join(&filename);
        let new_path = folder_path.join("new").join(&filename);

        write_atomic(&tmp_path, &new_path, content, self.fsync_on_write)?;

        Ok(new_path)
    }

    fn store_message_with_flags(
        &self,
        folder: &str,
        content: &[u8],
        flags: &[String],
    ) -> Result<PathBuf, StorageError> {
        let info_suffix = imap_flags_to_maildir_info(flags);

        if info_suffix.is_empty() {
            // No meaningful flags — store in new/ as a regular unread message
            return self.store_message(folder, content);
        }

        // Flags present — store in cur/ with the info suffix
        let folder_path = self.ensure_folder(folder)?;
        let base_filename = generate_unique_filename();
        let flagged_filename = format!("{base_filename}{info_suffix}");
        let tmp_path = folder_path.join("tmp").join(&base_filename);
        let cur_path = folder_path.join("cur").join(&flagged_filename);

        write_atomic(&tmp_path, &cur_path, content, self.fsync_on_write)?;

        Ok(cur_path)
    }

    fn move_message(&self, from_path: &Path, to_folder: &str) -> Result<PathBuf, StorageError> {
        let folder_path = self.ensure_folder(to_folder)?;
        let filename = extract_filename(from_path)?;
        let dest_path = folder_path.join("cur").join(filename);

        fs::rename(from_path, &dest_path).map_err(|source| StorageError::MoveFile {
            from: from_path.display().to_string(),
            to: dest_path.display().to_string(),
            source,
        })?;

        Ok(dest_path)
    }

    fn copy_message(&self, from_path: &Path, to_folder: &str) -> Result<PathBuf, StorageError> {
        let content = fs::read(from_path).map_err(|source| StorageError::ReadFile {
            path: from_path.display().to_string(),
            source,
        })?;

        let folder_path = self.ensure_folder(to_folder)?;
        let filename = generate_unique_filename();
        let tmp_path = folder_path.join("tmp").join(&filename);
        let new_path = folder_path.join("new").join(&filename);

        write_atomic(&tmp_path, &new_path, &content, self.fsync_on_write)?;

        Ok(new_path)
    }

    fn ensure_folder(&self, folder: &str) -> Result<PathBuf, StorageError> {
        let sanitized = sanitize_folder_name(folder)?;
        let folder_path = self.base_dir.join(&sanitized);

        create_maildir_subdirectories(&folder_path)?;

        Ok(folder_path)
    }

    fn folder_exists(&self, folder: &str) -> bool {
        let Ok(sanitized) = sanitize_folder_name(folder) else {
            return false;
        };
        let folder_path = self.base_dir.join(&sanitized);
        folder_path.join("cur").is_dir()
            && folder_path.join("new").is_dir()
            && folder_path.join("tmp").is_dir()
    }
}

// ---------------------------------------------------------------------------
// Private helpers — folder name sanitization
// ---------------------------------------------------------------------------

/// Sanitize a folder name to prevent path traversal and filesystem issues.
///
/// Rejects null bytes, `..` path components, and absolute paths.
/// Replaces control characters with underscores and truncates each
/// component to [`MAX_COMPONENT_BYTES`].
fn sanitize_folder_name(folder: &str) -> Result<String, StorageError> {
    reject_empty_name(folder)?;
    reject_null_bytes(folder)?;
    reject_absolute_path(folder)?;
    reject_path_traversal(folder)?;

    let sanitized = sanitize_components(folder);
    Ok(sanitized)
}

/// Reject empty folder names.
fn reject_empty_name(folder: &str) -> Result<(), StorageError> {
    if folder.is_empty() {
        return Err(StorageError::InvalidFolderName {
            name: folder.to_owned(),
            reason: "folder name must not be empty".to_owned(),
        });
    }
    Ok(())
}

/// Reject folder names containing null bytes.
fn reject_null_bytes(folder: &str) -> Result<(), StorageError> {
    if folder.contains('\0') {
        return Err(StorageError::InvalidFolderName {
            name: folder.to_owned(),
            reason: "contains null byte".to_owned(),
        });
    }
    Ok(())
}

/// Reject absolute paths.
fn reject_absolute_path(folder: &str) -> Result<(), StorageError> {
    if folder.starts_with('/') {
        return Err(StorageError::InvalidFolderName {
            name: folder.to_owned(),
            reason: "absolute paths are not allowed".to_owned(),
        });
    }
    Ok(())
}

/// Reject paths containing `..` components.
fn reject_path_traversal(folder: &str) -> Result<(), StorageError> {
    for component in Path::new(folder).components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(StorageError::InvalidFolderName {
                name: folder.to_owned(),
                reason: "path traversal (..) is not allowed".to_owned(),
            });
        }
    }
    Ok(())
}

/// Replace control characters with underscores and truncate long components.
fn sanitize_components(folder: &str) -> String {
    let components: Vec<String> = Path::new(folder)
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(os_str) => {
                let s = os_str.to_string_lossy();
                let cleaned = replace_control_chars(&s);
                Some(truncate_component(&cleaned))
            }
            _ => None,
        })
        .collect();

    components.join("/")
}

/// Replace ASCII control characters (0x00..0x1F, 0x7F) with underscores.
fn replace_control_chars(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_control() { '_' } else { c })
        .collect()
}

/// Truncate a path component to [`MAX_COMPONENT_BYTES`] at a character boundary.
fn truncate_component(s: &str) -> String {
    if s.len() <= MAX_COMPONENT_BYTES {
        return s.to_owned();
    }

    let mut end = MAX_COMPONENT_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }

    s[..end].to_owned()
}

// ---------------------------------------------------------------------------
// Private helpers — filesystem operations
// ---------------------------------------------------------------------------

/// Create the `cur/`, `new/`, `tmp/` subdirectories for a Maildir folder.
fn create_maildir_subdirectories(folder_path: &Path) -> Result<(), StorageError> {
    for subdir in &["cur", "new", "tmp"] {
        let path = folder_path.join(subdir);
        fs::create_dir_all(&path).map_err(|source| StorageError::CreateDir {
            path: path.display().to_string(),
            source,
        })?;
    }
    Ok(())
}

/// Write content atomically: write to a temporary file, optionally fsync,
/// then rename to the final path.
///
/// If the rename fails after the write succeeds, the temporary file is
/// cleaned up before the error is returned. A warning is logged if cleanup
/// also fails.
fn write_atomic(
    tmp_path: &Path,
    final_path: &Path,
    content: &[u8],
    fsync: bool,
) -> Result<(), StorageError> {
    write_and_sync(tmp_path, content, fsync)?;

    if let Err(rename_err) = rename_tmp_to_final(tmp_path, final_path) {
        if let Err(cleanup_err) = fs::remove_file(tmp_path) {
            tracing::warn!(
                tmp_path = %tmp_path.display(),
                error = %cleanup_err,
                "failed to clean up temporary file after rename failure"
            );
        }
        return Err(rename_err);
    }

    Ok(())
}

/// Write content to a file and optionally fsync.
fn write_and_sync(path: &Path, content: &[u8], fsync: bool) -> Result<(), StorageError> {
    let mut file = fs::File::create(path).map_err(|source| StorageError::WriteFile {
        path: path.display().to_string(),
        source,
    })?;

    file.write_all(content)
        .map_err(|source| StorageError::WriteFile {
            path: path.display().to_string(),
            source,
        })?;

    if fsync {
        file.sync_all().map_err(|source| StorageError::Fsync {
            path: path.display().to_string(),
            source,
        })?;
    }

    Ok(())
}

/// Rename a temporary file to its final destination.
fn rename_tmp_to_final(tmp_path: &Path, final_path: &Path) -> Result<(), StorageError> {
    fs::rename(tmp_path, final_path).map_err(|source| StorageError::MoveFile {
        from: tmp_path.display().to_string(),
        to: final_path.display().to_string(),
        source,
    })
}

/// Generate a unique filename for Maildir messages.
///
/// Format: `<unix_timestamp_secs>.<pid>.<counter>`
fn generate_unique_filename() -> String {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let pid = std::process::id();
    let counter = FILENAME_COUNTER.fetch_add(1, Ordering::Relaxed);

    format!("{timestamp}.{pid}.{counter}")
}

/// Extract the filename from a path, returning an error if it has no filename component.
fn extract_filename(path: &Path) -> Result<String, StorageError> {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_owned())
        .ok_or_else(|| StorageError::MoveFile {
            from: path.display().to_string(),
            to: String::new(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path has no filename component",
            ),
        })
}

// ---------------------------------------------------------------------------
// Flag conversion (pure)
// ---------------------------------------------------------------------------

/// Convert IMAP flag names to a Maildir info suffix string.
///
/// Returns the `:2,FLAGS` suffix if any recognized flags are present, or an
/// empty string if no flags should be encoded (e.g., empty input or only
/// `\Recent`).
///
/// The Maildir flag characters are sorted alphabetically per the spec:
/// - `D` = Draft (`\Draft`)
/// - `F` = Flagged (`\Flagged`)
/// - `R` = Replied (`\Answered`)
/// - `S` = Seen (`\Seen`)
/// - `T` = Trashed (`\Deleted`)
///
/// Unrecognized flags (including `\Recent`, which is a session-only flag)
/// are silently ignored.
pub fn imap_flags_to_maildir_info(flags: &[String]) -> String {
    let mut chars: Vec<char> = Vec::new();

    for flag in flags {
        let flag_lower = flag.to_lowercase();
        match flag_lower.as_str() {
            "\\seen" => chars.push('S'),
            "\\flagged" => chars.push('F'),
            "\\answered" => chars.push('R'),
            "\\draft" => chars.push('D'),
            "\\deleted" => chars.push('T'),
            // \Recent and unknown flags are ignored
            _ => {}
        }
    }

    // Deduplicate and sort alphabetically (Maildir spec requirement)
    chars.sort();
    chars.dedup();

    if chars.is_empty() {
        return String::new();
    }

    let flag_str: String = chars.into_iter().collect();
    format!(":2,{flag_str}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_store(dir: &Path) -> FsMaildirStore {
        FsMaildirStore::new(dir.to_path_buf(), false)
    }

    // --- Folder name sanitization ---

    #[test]
    fn sanitize_rejects_empty_name() {
        let result = sanitize_folder_name("");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_rejects_null_bytes() {
        let result = sanitize_folder_name("INBOX\0evil");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_rejects_absolute_path() {
        let result = sanitize_folder_name("/etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_rejects_path_traversal() {
        let result = sanitize_folder_name("INBOX/../../../etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_rejects_bare_dotdot() {
        let result = sanitize_folder_name("..");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_allows_normal_folders() {
        let result = sanitize_folder_name("INBOX").unwrap();
        assert_eq!(result, "INBOX");
    }

    #[test]
    fn sanitize_allows_nested_folders() {
        let result = sanitize_folder_name("Archive/2024/January").unwrap();
        assert_eq!(result, "Archive/2024/January");
    }

    #[test]
    fn sanitize_replaces_control_characters() {
        let result = sanitize_folder_name("INBOX\x01\x02test").unwrap();
        assert_eq!(result, "INBOX__test");
    }

    #[test]
    fn sanitize_truncates_long_components() {
        let long_name = "a".repeat(300);
        let result = sanitize_folder_name(&long_name).unwrap();
        assert!(result.len() <= MAX_COMPONENT_BYTES);
    }

    #[test]
    fn sanitize_allows_dot_prefix() {
        let result = sanitize_folder_name(".hidden_folder").unwrap();
        assert_eq!(result, ".hidden_folder");
    }

    // --- Unique filename generation ---

    #[test]
    fn unique_filenames_are_unique() {
        let f1 = generate_unique_filename();
        let f2 = generate_unique_filename();
        assert_ne!(f1, f2);
    }

    #[test]
    fn filename_has_expected_format() {
        let filename = generate_unique_filename();
        let parts: Vec<&str> = filename.split('.').collect();
        assert_eq!(parts.len(), 3, "filename should have 3 dot-separated parts");
    }

    // --- Store, move, copy messages ---

    #[test]
    fn store_message_creates_file_in_new() {
        let dir = tempfile::tempdir().unwrap();
        let store = create_test_store(dir.path());

        let path = store
            .store_message("INBOX", b"From: test\n\nHello")
            .unwrap();
        assert!(path.exists());
        assert!(path.to_string_lossy().contains("/new/"));
        assert_eq!(fs::read(&path).unwrap(), b"From: test\n\nHello");
    }

    #[test]
    fn store_message_does_not_leave_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = create_test_store(dir.path());

        store.store_message("INBOX", b"content").unwrap();

        let tmp_dir = dir.path().join("INBOX").join("tmp");
        let tmp_files: Vec<_> = fs::read_dir(tmp_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(tmp_files.is_empty(), "no files should remain in tmp/");
    }

    #[test]
    fn move_message_relocates_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = create_test_store(dir.path());

        let original = store.store_message("INBOX", b"message body").unwrap();
        let moved = store.move_message(&original, "Archive").unwrap();

        assert!(!original.exists());
        assert!(moved.exists());
        assert!(moved.to_string_lossy().contains("/cur/"));
        assert_eq!(fs::read(&moved).unwrap(), b"message body");
    }

    #[test]
    fn copy_message_preserves_original() {
        let dir = tempfile::tempdir().unwrap();
        let store = create_test_store(dir.path());

        let original = store.store_message("INBOX", b"message body").unwrap();
        let copied = store.copy_message(&original, "Backup").unwrap();

        assert!(original.exists());
        assert!(copied.exists());
        assert_eq!(fs::read(&original).unwrap(), b"message body");
        assert_eq!(fs::read(&copied).unwrap(), b"message body");
    }

    // --- Folder operations ---

    #[test]
    fn ensure_folder_creates_subdirectories() {
        let dir = tempfile::tempdir().unwrap();
        let store = create_test_store(dir.path());

        let path = store.ensure_folder("TestFolder").unwrap();

        assert!(path.join("cur").is_dir());
        assert!(path.join("new").is_dir());
        assert!(path.join("tmp").is_dir());
    }

    #[test]
    fn ensure_folder_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = create_test_store(dir.path());

        let path1 = store.ensure_folder("INBOX").unwrap();
        let path2 = store.ensure_folder("INBOX").unwrap();
        assert_eq!(path1, path2);
    }

    #[test]
    fn folder_exists_returns_true_after_creation() {
        let dir = tempfile::tempdir().unwrap();
        let store = create_test_store(dir.path());

        assert!(!store.folder_exists("INBOX"));
        store.ensure_folder("INBOX").unwrap();
        assert!(store.folder_exists("INBOX"));
    }

    #[test]
    fn folder_exists_returns_false_for_invalid_name() {
        let dir = tempfile::tempdir().unwrap();
        let store = create_test_store(dir.path());
        assert!(!store.folder_exists("../etc"));
    }

    #[test]
    fn ensure_folder_creates_nested_structure() {
        let dir = tempfile::tempdir().unwrap();
        let store = create_test_store(dir.path());

        let path = store.ensure_folder("Archive/2024/Q1").unwrap();
        assert!(path.join("cur").is_dir());
    }

    // --- Error cases ---

    #[test]
    fn store_message_rejects_traversal_folder() {
        let dir = tempfile::tempdir().unwrap();
        let store = create_test_store(dir.path());

        let result = store.store_message("../etc", b"evil");
        assert!(result.is_err());
    }

    #[test]
    fn move_message_rejects_traversal_folder() {
        let dir = tempfile::tempdir().unwrap();
        let store = create_test_store(dir.path());

        let original = store.store_message("INBOX", b"content").unwrap();
        let result = store.move_message(&original, "../etc");
        assert!(result.is_err());
    }

    // --- Fsync configuration ---

    #[test]
    fn store_with_fsync_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsMaildirStore::new(dir.path().to_path_buf(), true);

        let path = store.store_message("INBOX", b"content with fsync").unwrap();
        assert!(path.exists());
        assert_eq!(fs::read(&path).unwrap(), b"content with fsync");
    }

    // --- IMAP flag to Maildir info conversion ---

    #[test]
    fn flags_seen_produces_s() {
        let info = imap_flags_to_maildir_info(&["\\Seen".to_owned()]);
        assert_eq!(info, ":2,S");
    }

    #[test]
    fn flags_flagged_produces_f() {
        let info = imap_flags_to_maildir_info(&["\\Flagged".to_owned()]);
        assert_eq!(info, ":2,F");
    }

    #[test]
    fn flags_seen_and_flagged_sorted() {
        let info = imap_flags_to_maildir_info(&["\\Seen".to_owned(), "\\Flagged".to_owned()]);
        assert_eq!(info, ":2,FS");
    }

    #[test]
    fn flags_all_standard() {
        let info = imap_flags_to_maildir_info(&[
            "\\Seen".to_owned(),
            "\\Flagged".to_owned(),
            "\\Answered".to_owned(),
            "\\Draft".to_owned(),
            "\\Deleted".to_owned(),
        ]);
        assert_eq!(info, ":2,DFRST");
    }

    #[test]
    fn flags_empty_produces_empty_string() {
        let info = imap_flags_to_maildir_info(&[]);
        assert_eq!(info, "");
    }

    #[test]
    fn flags_recent_ignored() {
        let info = imap_flags_to_maildir_info(&["\\Recent".to_owned()]);
        assert_eq!(info, "");
    }

    #[test]
    fn flags_recent_with_seen() {
        let info = imap_flags_to_maildir_info(&["\\Recent".to_owned(), "\\Seen".to_owned()]);
        assert_eq!(info, ":2,S");
    }

    #[test]
    fn flags_deleted_produces_t() {
        let info = imap_flags_to_maildir_info(&["\\Deleted".to_owned()]);
        assert_eq!(info, ":2,T");
    }

    #[test]
    fn flags_unknown_ignored() {
        let info = imap_flags_to_maildir_info(&[
            "\\Seen".to_owned(),
            "$Junk".to_owned(),
            "custom-flag".to_owned(),
        ]);
        assert_eq!(info, ":2,S");
    }

    #[test]
    fn flags_case_insensitive() {
        let info = imap_flags_to_maildir_info(&["\\SEEN".to_owned(), "\\flagged".to_owned()]);
        assert_eq!(info, ":2,FS");
    }

    #[test]
    fn flags_duplicates_deduplicated() {
        let info = imap_flags_to_maildir_info(&["\\Seen".to_owned(), "\\Seen".to_owned()]);
        assert_eq!(info, ":2,S");
    }

    #[test]
    fn flags_answered_produces_r() {
        let info = imap_flags_to_maildir_info(&["\\Answered".to_owned()]);
        assert_eq!(info, ":2,R");
    }

    #[test]
    fn flags_draft_produces_d() {
        let info = imap_flags_to_maildir_info(&["\\Draft".to_owned()]);
        assert_eq!(info, ":2,D");
    }

    // --- store_message_with_flags ---

    #[test]
    fn store_with_flags_stores_in_cur_with_suffix() {
        let dir = tempfile::tempdir().unwrap();
        let store = create_test_store(dir.path());

        let path = store
            .store_message_with_flags(
                "INBOX",
                b"From: test\n\nHello",
                &["\\Seen".to_owned(), "\\Flagged".to_owned()],
            )
            .unwrap();

        assert!(path.exists());
        assert!(path.to_string_lossy().contains("/cur/"));
        assert!(path.to_string_lossy().ends_with(":2,FS"));
        assert_eq!(fs::read(&path).unwrap(), b"From: test\n\nHello");
    }

    #[test]
    fn store_with_no_flags_stores_in_new() {
        let dir = tempfile::tempdir().unwrap();
        let store = create_test_store(dir.path());

        let path = store
            .store_message_with_flags("INBOX", b"From: test\n\nHello", &[])
            .unwrap();

        assert!(path.exists());
        assert!(path.to_string_lossy().contains("/new/"));
    }

    #[test]
    fn store_with_only_recent_flag_stores_in_new() {
        let dir = tempfile::tempdir().unwrap();
        let store = create_test_store(dir.path());

        let path = store
            .store_message_with_flags("INBOX", b"From: test\n\nHello", &["\\Recent".to_owned()])
            .unwrap();

        assert!(path.exists());
        assert!(path.to_string_lossy().contains("/new/"));
    }

    #[test]
    fn store_with_replied_and_seen_flags() {
        let dir = tempfile::tempdir().unwrap();
        let store = create_test_store(dir.path());

        let path = store
            .store_message_with_flags(
                "INBOX",
                b"From: test\n\nHello",
                &["\\Answered".to_owned(), "\\Seen".to_owned()],
            )
            .unwrap();

        assert!(path.exists());
        assert!(path.to_string_lossy().contains("/cur/"));
        assert!(path.to_string_lossy().ends_with(":2,RS"));
    }
}
