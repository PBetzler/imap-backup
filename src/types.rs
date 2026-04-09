//! Shared domain types used across the email backup tool.
//!
//! These types represent the core data model: message metadata, folder
//! information, sync actions, and sync reports.

use std::path::PathBuf;
use std::time::Duration;

/// Metadata for a single MIME attachment extracted from IMAP `BODYSTRUCTURE`.
///
/// This metadata is used in fingerprint computation without downloading
/// the actual attachment content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentMeta {
    /// MIME type of the attachment (e.g., "application/pdf").
    pub mime_type: String,
    /// Original filename of the attachment, if provided by the sender.
    pub filename: Option<String>,
    /// Size of the attachment in bytes.
    pub size_bytes: u64,
}

/// Metadata for a single email message.
///
/// Computed from IMAP envelope and `BODYSTRUCTURE` data without downloading
/// the full message body. The composite `fingerprint` serves as the
/// authoritative identity for move detection and deduplication.
#[derive(Debug, Clone)]
pub struct MessageMetadata {
    /// RFC 2822 `Message-ID` header, if present.
    pub message_id: Option<String>,
    /// `Date` header value.
    pub date: String,
    /// `From` header value.
    pub from: String,
    /// `To` header value, if present.
    pub to: Option<String>,
    /// `Cc` header value, if present.
    pub cc: Option<String>,
    /// `Subject` header value.
    pub subject: String,
    /// Number of MIME attachments.
    pub attachment_count: u32,
    /// Metadata for each attachment.
    pub attachments: Vec<AttachmentMeta>,
    /// SHA-256 hash of the MIME body structure tree (part shapes and sizes).
    pub body_structure_hash: String,
    /// Composite fingerprint: the authoritative identity of this message.
    pub fingerprint: String,
}

/// Information about an IMAP folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderInfo {
    /// Full folder name (e.g., "INBOX", "Archive/2024").
    pub name: String,
    /// IMAP `UIDVALIDITY` value for this folder.
    pub uid_validity: u32,
    /// Total number of messages in the folder.
    pub message_count: u32,
}

/// Tracks where a specific message is stored locally and on the server.
#[derive(Debug, Clone)]
pub struct MessageLocation {
    /// Composite fingerprint identifying the message.
    pub fingerprint: String,
    /// IMAP folder name where the message resides.
    pub folder: String,
    /// Local filesystem path to the message file.
    pub local_path: PathBuf,
    /// IMAP UID of the message, if known.
    pub imap_uid: Option<u32>,
}

/// An action to be performed during a sync cycle.
///
/// These actions are computed by comparing server state against local state,
/// then executed (or logged in dry-run mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncAction {
    /// Download a new message from the server.
    Download {
        /// Composite fingerprint of the message.
        fingerprint: String,
        /// Folder to download from.
        folder: String,
        /// IMAP UID of the message.
        uid: u32,
        /// IMAP flags to preserve in the local Maildir storage.
        flags: Vec<String>,
    },
    /// Move a locally stored message to a different folder.
    Move {
        /// Composite fingerprint of the message.
        fingerprint: String,
        /// Original folder.
        from_folder: String,
        /// Destination folder.
        to_folder: String,
        /// Current local file path.
        local_path: PathBuf,
    },
    /// Copy a locally stored message to an additional folder.
    Copy {
        /// Composite fingerprint of the message.
        fingerprint: String,
        /// Source folder.
        from_folder: String,
        /// Destination folder.
        to_folder: String,
        /// Current local file path.
        local_path: PathBuf,
    },
    /// Skip a message (already backed up or filtered out).
    Skip {
        /// Composite fingerprint of the message.
        fingerprint: String,
        /// Reason for skipping.
        reason: String,
    },
    /// Archive a message that is no longer on the server.
    Archive {
        /// Composite fingerprint of the message.
        fingerprint: String,
        /// Folder where the message was last seen.
        folder: String,
    },
}

/// Summary report for a single folder's sync operation.
#[derive(Debug, Clone, Default)]
pub struct FolderSyncReport {
    /// Folder name.
    pub folder: String,
    /// Number of messages downloaded.
    pub downloaded: u64,
    /// Number of messages moved.
    pub moved: u64,
    /// Number of messages copied.
    pub copied: u64,
    /// Number of messages skipped (already backed up or filtered out).
    pub skipped: u64,
    /// Number of messages archived (kept locally after server deletion).
    pub archived: u64,
    /// Number of errors encountered.
    pub errors: u64,
}

/// Summary report for a single account's sync operation.
#[derive(Debug, Clone, Default)]
pub struct AccountSyncReport {
    /// Account name.
    pub account: String,
    /// Per-folder sync reports.
    pub folder_reports: Vec<FolderSyncReport>,
    /// Total messages downloaded across all folders.
    pub downloaded: u64,
    /// Total messages moved across all folders.
    pub moved: u64,
    /// Total messages copied across all folders.
    pub copied: u64,
    /// Total messages skipped across all folders.
    pub skipped: u64,
    /// Total messages archived across all folders.
    pub archived: u64,
    /// Total errors across all folders.
    pub errors: u64,
}

/// Summary report for an entire sync cycle across all accounts.
#[derive(Debug, Clone)]
pub struct SyncReport {
    /// Total messages downloaded.
    pub downloaded: u64,
    /// Total messages moved.
    pub moved: u64,
    /// Total messages copied.
    pub copied: u64,
    /// Total messages skipped.
    pub skipped: u64,
    /// Total messages archived.
    pub archived: u64,
    /// Total errors encountered.
    pub errors: u64,
    /// Wall-clock duration of the sync cycle.
    pub duration: Duration,
    /// Per-account sync reports.
    pub account_reports: Vec<AccountSyncReport>,
}
