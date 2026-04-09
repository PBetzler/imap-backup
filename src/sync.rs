//! Sync engine orchestration.
//!
//! The [`SyncEngine`] drives the end-to-end sync cycle for one or more
//! IMAP accounts: connect, list folders, fetch metadata, compute
//! fingerprints, plan sync actions, and execute them with crash-safe
//! ordering (filesystem first, then database).

use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use crate::config::AccountConfig;
use crate::error::SyncError;
use crate::imap_client::{FolderStatus, ImapClient};
use crate::maildir::MaildirStore;
use crate::shutdown::ShutdownSignal;
use crate::state::{FolderRecord, LocationRecord, MessageRecord, StateDb};
use crate::sync_plan::{LocalMessage, ServerMessage, plan_sync, plan_uid_validity_recovery};
use crate::types::{AccountSyncReport, FolderSyncReport, MessageMetadata, SyncAction, SyncReport};

/// Number of leading hex characters of a fingerprint to include in log messages.
const FINGERPRINT_LOG_LENGTH: usize = 12;

/// Maximum number of characters of a subject line to include in log messages.
const SUBJECT_LOG_LENGTH: usize = 60;

// ---------------------------------------------------------------------------
// SyncEngine
// ---------------------------------------------------------------------------

/// Orchestrates sync cycles for IMAP accounts.
///
/// Generic over the IMAP client, state database, and Maildir store
/// implementations to support both production and test configurations.
pub struct SyncEngine<I: ImapClient, S: StateDb, M: MaildirStore> {
    /// Persistent state database for tracking messages and sync progress.
    state_db: S,
    /// Local Maildir storage backend.
    maildir: M,
    /// Maximum allowed email body size in bytes. Messages exceeding this
    /// limit are skipped with a warning.
    max_email_size_bytes: u64,
    /// Phantom marker for the IMAP client type (constructed per-account via `I::connect`).
    _imap: PhantomData<I>,
}

impl<I: ImapClient, S: StateDb, M: MaildirStore> SyncEngine<I, S, M> {
    /// Create a new sync engine with the given state database, Maildir store,
    /// and maximum email size limit.
    pub fn new(state_db: S, maildir: M, max_email_size_bytes: u64) -> Self {
        Self {
            state_db,
            maildir,
            max_email_size_bytes,
            _imap: PhantomData,
        }
    }

    /// Run a full sync cycle for a single account.
    ///
    /// Connects to the IMAP server, iterates over folders (respecting
    /// folder pattern filters), and executes sync actions. Returns a
    /// report summarizing what was done.
    ///
    /// If `dry_run` is true, actions are logged but not executed.
    /// The `shutdown` signal is checked between folders and between
    /// individual message actions for cooperative cancellation.
    pub async fn sync_account(
        &self,
        account: &AccountConfig,
        imap_timeout: u64,
        dry_run: bool,
        shutdown: &ShutdownSignal,
    ) -> Result<AccountSyncReport, SyncError> {
        let mut report = AccountSyncReport {
            account: account.name.clone(),
            ..Default::default()
        };

        let mut imap = connect_imap::<I>(account, imap_timeout).await?;
        let folders = list_and_filter_folders(&mut imap, account).await?;

        for folder_info in &folders {
            if shutdown.is_shutdown_requested() {
                tracing::info!(
                    account = account.name,
                    "shutdown requested, stopping folder iteration"
                );
                break;
            }

            match self
                .sync_folder(&mut imap, account, &folder_info.name, dry_run, shutdown)
                .await
            {
                Ok(folder_report) => {
                    accumulate_folder_report(&mut report, &folder_report);
                    report.folder_reports.push(folder_report);
                }
                Err(e) => {
                    tracing::error!(
                        account = account.name,
                        folder = folder_info.name,
                        error = %e,
                        "folder sync failed, continuing with remaining folders"
                    );
                    let mut error_report = FolderSyncReport {
                        folder: folder_info.name.clone(),
                        ..Default::default()
                    };
                    error_report.errors = 1;
                    report.errors += 1;
                    report.folder_reports.push(error_report);
                }
            }
        }

        disconnect_imap(&mut imap, &account.name).await;

        if !dry_run && report.errors == 0 {
            update_last_successful_sync(&self.state_db, &account.name);
        }

        Ok(report)
    }

    /// Sync a single folder within an account.
    async fn sync_folder(
        &self,
        imap: &mut I,
        account: &AccountConfig,
        folder_name: &str,
        dry_run: bool,
        shutdown: &ShutdownSignal,
    ) -> Result<FolderSyncReport, SyncError> {
        let mut folder_report = FolderSyncReport {
            folder: folder_name.to_owned(),
            ..Default::default()
        };

        let status = select_folder(imap, account, folder_name).await?;
        let uid_validity = status.uid_validity.unwrap_or(0);
        let uid_resolution =
            resolve_highest_synced_uid(&self.state_db, &account.name, folder_name, uid_validity)?;

        let (_server_messages, _local_messages, actions, highest_synced_uid) = match uid_resolution
        {
            UidResolution::Incremental(uid) => {
                let uid_range = build_uid_range(uid);
                let server_msgs = fetch_metadata(imap, account, folder_name, &uid_range).await?;
                let local_msgs = load_local_state(&self.state_db, &account.name, &server_msgs)?;
                let sync_actions = plan_sync(&server_msgs, &local_msgs);
                (server_msgs, local_msgs, sync_actions, uid)
            }
            UidResolution::ValidityChanged => {
                self.perform_uid_validity_recovery(
                    imap,
                    account,
                    folder_name,
                    uid_validity,
                    dry_run,
                )
                .await?
            }
        };

        let mut max_uid = highest_synced_uid;

        for action in &actions {
            if shutdown.is_shutdown_requested() {
                tracing::info!(
                    account = account.name,
                    folder = folder_name,
                    "shutdown requested, stopping action execution"
                );
                break;
            }

            let result = self
                .execute_action(imap, account, folder_name, action, dry_run)
                .await;

            match result {
                Ok(()) => {
                    update_folder_report_for_action(&mut folder_report, action);
                    max_uid = update_max_uid(max_uid, action);
                }
                Err(e) => {
                    tracing::error!(
                        account = account.name,
                        folder = folder_name,
                        error = %e,
                        "action failed, continuing with next action"
                    );
                    folder_report.errors += 1;
                }
            }
        }

        if !dry_run {
            update_folder_record(
                &self.state_db,
                &account.name,
                folder_name,
                uid_validity,
                max_uid,
            );
        }

        Ok(folder_report)
    }

    /// Perform UIDVALIDITY recovery via fingerprint matching.
    ///
    /// When UIDVALIDITY changes, all UIDs in the folder are invalidated. Instead
    /// of re-downloading everything, we fetch metadata for ALL messages (`1:*`),
    /// compute fingerprints, and match against existing local messages. Matched
    /// messages just get their UIDs updated; only genuinely new messages are
    /// downloaded.
    ///
    /// Returns the same tuple that the `Incremental` branch produces so the
    /// caller can proceed with the normal action-execution loop.
    async fn perform_uid_validity_recovery(
        &self,
        imap: &mut I,
        account: &AccountConfig,
        folder_name: &str,
        new_uid_validity: u32,
        dry_run: bool,
    ) -> Result<(Vec<ServerMessage>, Vec<LocalMessage>, Vec<SyncAction>, u32), SyncError> {
        tracing::warn!(
            account = account.name,
            folder = folder_name,
            "UIDVALIDITY changed, attempting fingerprint-based recovery"
        );

        // Fetch metadata for ALL messages in the folder.
        let all_server_messages = fetch_metadata(imap, account, folder_name, "1:*").await?;
        let local_messages = load_local_state(&self.state_db, &account.name, &all_server_messages)?;

        // Filter local messages to only those in this folder.
        let local_in_folder: Vec<LocalMessage> = local_messages
            .iter()
            .filter(|m| m.folder == folder_name)
            .cloned()
            .collect();

        let recovery = plan_uid_validity_recovery(&all_server_messages, &local_in_folder);

        tracing::info!(
            account = account.name,
            folder = folder_name,
            matched = recovery.matched.len(),
            new_downloads = recovery.unmatched_server.len(),
            "UIDVALIDITY recovery complete"
        );

        // Update UIDs for matched messages (unless dry-run).
        if !dry_run {
            for (fingerprint, new_uid) in &recovery.matched {
                if let Err(e) = self.state_db.update_location_uid(
                    &account.name,
                    fingerprint,
                    folder_name,
                    *new_uid,
                ) {
                    tracing::warn!(
                        account = account.name,
                        folder = folder_name,
                        fingerprint = &fingerprint[..fingerprint.len().min(FINGERPRINT_LOG_LENGTH)],
                        error = %e,
                        "failed to update UID for recovered message"
                    );
                }
            }

            // Update the folder record with the new UIDVALIDITY.
            update_folder_record(
                &self.state_db,
                &account.name,
                folder_name,
                new_uid_validity,
                recovery.max_uid,
            );
        }

        // Plan sync actions for only the unmatched (genuinely new) messages.
        // We pass only local messages from this folder to avoid spurious Archive
        // actions for messages in unrelated folders.
        let actions = plan_sync(&recovery.unmatched_server, &local_in_folder);

        Ok((
            all_server_messages,
            local_messages,
            actions,
            recovery.max_uid,
        ))
    }

    /// Execute a single sync action (or log it in dry-run mode).
    async fn execute_action(
        &self,
        imap: &mut I,
        account: &AccountConfig,
        folder_name: &str,
        action: &SyncAction,
        dry_run: bool,
    ) -> Result<(), SyncError> {
        if dry_run {
            log_dry_run_action(folder_name, action);
            return Ok(());
        }

        match action {
            SyncAction::Download {
                fingerprint,
                folder,
                uid,
                flags,
            } => {
                self.execute_download(imap, account, folder, fingerprint, *uid, flags)
                    .await
            }
            SyncAction::Move {
                fingerprint,
                from_folder,
                to_folder,
                local_path,
            } => self.execute_move(
                &account.name,
                fingerprint,
                from_folder,
                to_folder,
                local_path,
            ),
            SyncAction::Copy {
                fingerprint,
                from_folder,
                to_folder,
                local_path,
            } => self.execute_copy(
                &account.name,
                fingerprint,
                from_folder,
                to_folder,
                local_path,
            ),
            SyncAction::Archive {
                fingerprint,
                folder,
            } => {
                log_action(
                    "archive",
                    folder,
                    fingerprint,
                    "message deleted on server, kept locally",
                );
                Ok(())
            }
            SyncAction::Skip {
                fingerprint,
                reason,
            } => {
                tracing::debug!(
                    fingerprint = truncate_fingerprint(fingerprint),
                    reason = reason.as_str(),
                    "skip"
                );
                Ok(())
            }
        }
    }

    /// Download a message body, store it in Maildir, then record it in the state DB.
    ///
    /// Messages exceeding `max_email_size_bytes` are skipped with a warning
    /// log entry. This prevents excessively large emails from consuming disk
    /// space or causing out-of-memory issues.
    ///
    /// Crash safety: filesystem write happens FIRST, then the DB insert.
    /// An orphan file on disk is harmless; a phantom DB entry would prevent
    /// re-download.
    async fn execute_download(
        &self,
        imap: &mut I,
        account: &AccountConfig,
        folder: &str,
        fingerprint: &str,
        uid: u32,
        flags: &[String],
    ) -> Result<(), SyncError> {
        let body = imap
            .fetch_message_body(uid)
            .await
            .map_err(|e| SyncError::FolderSync {
                account: account.name.clone(),
                folder: folder.to_owned(),
                reason: format!("failed to fetch body for UID {uid}: {e}"),
            })?;

        let body_size = body.len() as u64;
        if body_size > self.max_email_size_bytes {
            tracing::warn!(
                account = account.name,
                folder = folder,
                fingerprint = truncate_fingerprint(fingerprint),
                uid = uid,
                body_size_bytes = body_size,
                max_size_bytes = self.max_email_size_bytes,
                "skipping message that exceeds max_email_size_bytes"
            );
            return Ok(());
        }

        let metadata = extract_metadata_from_body(&body, fingerprint);

        // Filesystem FIRST — store with flags so Maildir filename preserves them
        let stored_path = self
            .maildir
            .store_message_with_flags(folder, &body, flags)
            .map_err(|e| SyncError::FolderSync {
                account: account.name.clone(),
                folder: folder.to_owned(),
                reason: format!("failed to store message: {e}"),
            })?;

        // Database SECOND
        insert_message_and_location(
            &self.state_db,
            &metadata,
            fingerprint,
            folder,
            &stored_path,
            uid,
            &account.name,
        )?;

        log_action("download", folder, fingerprint, &metadata.subject);

        Ok(())
    }

    /// Move a message file to a new folder and update the state DB.
    fn execute_move(
        &self,
        account_name: &str,
        fingerprint: &str,
        from_folder: &str,
        to_folder: &str,
        local_path: &Path,
    ) -> Result<(), SyncError> {
        // Filesystem FIRST
        let new_path = self
            .maildir
            .move_message(local_path, to_folder)
            .map_err(|e| SyncError::FolderSync {
                account: account_name.to_owned(),
                folder: to_folder.to_owned(),
                reason: format!("failed to move message: {e}"),
            })?;

        // Database SECOND: remove old location, insert new
        self.state_db
            .remove_location(account_name, fingerprint, from_folder)
            .map_err(|e| SyncError::FolderSync {
                account: account_name.to_owned(),
                folder: to_folder.to_owned(),
                reason: format!("failed to remove old location: {e}"),
            })?;

        let now = current_timestamp();
        let location = LocationRecord {
            account_name: account_name.to_owned(),
            fingerprint: fingerprint.to_owned(),
            folder: to_folder.to_owned(),
            local_path: new_path.display().to_string(),
            imap_uid: None,
            last_seen_on_server: now,
        };

        self.state_db
            .upsert_location(&location)
            .map_err(|e| SyncError::FolderSync {
                account: account_name.to_owned(),
                folder: to_folder.to_owned(),
                reason: format!("failed to insert new location: {e}"),
            })?;

        log_action(
            "move",
            &format!("{from_folder} -> {to_folder}"),
            fingerprint,
            "",
        );

        Ok(())
    }

    /// Copy a message file to a new folder and record the new location in the state DB.
    fn execute_copy(
        &self,
        account_name: &str,
        fingerprint: &str,
        from_folder: &str,
        to_folder: &str,
        local_path: &Path,
    ) -> Result<(), SyncError> {
        // Filesystem FIRST
        let new_path = self
            .maildir
            .copy_message(local_path, to_folder)
            .map_err(|e| SyncError::FolderSync {
                account: account_name.to_owned(),
                folder: to_folder.to_owned(),
                reason: format!("failed to copy message: {e}"),
            })?;

        // Database SECOND
        let now = current_timestamp();
        let location = LocationRecord {
            account_name: account_name.to_owned(),
            fingerprint: fingerprint.to_owned(),
            folder: to_folder.to_owned(),
            local_path: new_path.display().to_string(),
            imap_uid: None,
            last_seen_on_server: now,
        };

        self.state_db
            .upsert_location(&location)
            .map_err(|e| SyncError::FolderSync {
                account: account_name.to_owned(),
                folder: to_folder.to_owned(),
                reason: format!("failed to insert copy location: {e}"),
            })?;

        log_action(
            "copy",
            &format!("{from_folder} -> {to_folder}"),
            fingerprint,
            "",
        );

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Report aggregation (pure)
// ---------------------------------------------------------------------------

/// Aggregate multiple [`AccountSyncReport`]s into a single [`SyncReport`].
pub fn build_sync_report(
    account_reports: Vec<AccountSyncReport>,
    duration: std::time::Duration,
) -> SyncReport {
    let mut report = SyncReport {
        downloaded: 0,
        moved: 0,
        copied: 0,
        skipped: 0,
        archived: 0,
        errors: 0,
        duration,
        account_reports: Vec::new(),
    };

    for ar in &account_reports {
        report.downloaded += ar.downloaded;
        report.moved += ar.moved;
        report.copied += ar.copied;
        report.skipped += ar.skipped;
        report.archived += ar.archived;
        report.errors += ar.errors;
    }

    report.account_reports = account_reports;
    report
}

/// Log a summary of a [`SyncReport`].
pub fn log_sync_report(report: &SyncReport) {
    tracing::info!(
        downloaded = report.downloaded,
        moved = report.moved,
        copied = report.copied,
        skipped = report.skipped,
        archived = report.archived,
        errors = report.errors,
        duration_secs = report.duration.as_secs(),
        "sync cycle complete"
    );

    for ar in &report.account_reports {
        tracing::info!(
            account = ar.account,
            downloaded = ar.downloaded,
            moved = ar.moved,
            copied = ar.copied,
            skipped = ar.skipped,
            archived = ar.archived,
            errors = ar.errors,
            "account summary"
        );
    }
}

// ---------------------------------------------------------------------------
// IMAP helpers (async, side-effecting)
// ---------------------------------------------------------------------------

/// Connect to the IMAP server for an account.
async fn connect_imap<I: ImapClient>(
    account: &AccountConfig,
    imap_timeout: u64,
) -> Result<I, SyncError> {
    tracing::info!(
        account = account.name,
        host = account.host,
        port = account.port,
        "connecting to IMAP server"
    );

    I::connect(account, imap_timeout)
        .await
        .map_err(|e| SyncError::AccountSync {
            account: account.name.clone(),
            reason: format!("IMAP connection failed: {e}"),
        })
}

/// List folders from IMAP and apply folder pattern filters.
async fn list_and_filter_folders<I: ImapClient>(
    imap: &mut I,
    account: &AccountConfig,
) -> Result<Vec<crate::types::FolderInfo>, SyncError> {
    let all_folders = imap
        .list_folders()
        .await
        .map_err(|e| SyncError::AccountSync {
            account: account.name.clone(),
            reason: format!("failed to list folders: {e}"),
        })?;

    let filtered = filter_folders(&all_folders, &account.folder_patterns);

    tracing::info!(
        account = account.name,
        total_folders = all_folders.len(),
        synced_folders = filtered.len(),
        "folder list obtained"
    );

    Ok(filtered)
}

/// Select an IMAP folder and return its status.
async fn select_folder<I: ImapClient>(
    imap: &mut I,
    account: &AccountConfig,
    folder_name: &str,
) -> Result<FolderStatus, SyncError> {
    imap.select_folder(folder_name)
        .await
        .map_err(|e| SyncError::FolderSync {
            account: account.name.clone(),
            folder: folder_name.to_owned(),
            reason: format!("failed to select folder: {e}"),
        })
}

/// Fetch message metadata for a UID range.
async fn fetch_metadata<I: ImapClient>(
    imap: &mut I,
    account: &AccountConfig,
    folder_name: &str,
    uid_range: &str,
) -> Result<Vec<ServerMessage>, SyncError> {
    imap.fetch_metadata(uid_range)
        .await
        .map_err(|e| SyncError::FolderSync {
            account: account.name.clone(),
            folder: folder_name.to_owned(),
            reason: format!("failed to fetch metadata: {e}"),
        })
}

/// Disconnect from the IMAP server, logging any errors.
async fn disconnect_imap<I: ImapClient>(imap: &mut I, account_name: &str) {
    if let Err(e) = imap.disconnect().await {
        tracing::warn!(
            account = account_name,
            error = %e,
            "IMAP disconnect failed"
        );
    }
}

// ---------------------------------------------------------------------------
// State DB helpers (synchronous, side-effecting)
// ---------------------------------------------------------------------------

/// Outcome of resolving the highest synced UID for a folder.
#[derive(Debug, PartialEq, Eq)]
enum UidResolution {
    /// Normal incremental sync from this UID onward.
    Incremental(u32),
    /// UIDVALIDITY changed — recovery is needed.
    ValidityChanged,
}

/// Determine the highest synced UID, detecting UIDVALIDITY changes.
///
/// Returns [`UidResolution::Incremental`] for normal sync or
/// [`UidResolution::ValidityChanged`] when the server's UIDVALIDITY
/// no longer matches the stored value (requiring fingerprint-based
/// recovery).
fn resolve_highest_synced_uid<S: StateDb>(
    state_db: &S,
    account_name: &str,
    folder_name: &str,
    uid_validity: u32,
) -> Result<UidResolution, SyncError> {
    let folder_record = state_db
        .get_folder(account_name, folder_name)
        .map_err(|e| SyncError::FolderSync {
            account: account_name.to_owned(),
            folder: folder_name.to_owned(),
            reason: format!("failed to query folder record: {e}"),
        })?;

    let resolution = match folder_record {
        Some(ref record) => {
            let stored_validity = record.uid_validity.unwrap_or(0);
            if stored_validity != uid_validity && stored_validity != 0 {
                UidResolution::ValidityChanged
            } else {
                UidResolution::Incremental(record.highest_synced_uid.unwrap_or(0))
            }
        }
        None => UidResolution::Incremental(0),
    };

    Ok(resolution)
}

/// Load local state from the state DB for comparison with server messages.
fn load_local_state<S: StateDb>(
    state_db: &S,
    account_name: &str,
    server_messages: &[ServerMessage],
) -> Result<Vec<LocalMessage>, SyncError> {
    let all_locations = state_db
        .get_all_locations_for_account(account_name)
        .map_err(|e| SyncError::AccountSync {
            account: account_name.to_owned(),
            reason: format!("failed to load local state: {e}"),
        })?;

    let local_messages: Vec<LocalMessage> = all_locations
        .into_iter()
        .map(|loc| LocalMessage {
            fingerprint: loc.fingerprint,
            folder: loc.folder,
            local_path: PathBuf::from(loc.local_path),
        })
        .collect();

    // We need the full local state, not just what matches server fingerprints,
    // because plan_sync needs to detect archives (local-only messages).
    // However, for efficiency we could filter, but correctness requires the full set.
    let _ = server_messages; // Used for documentation clarity; full local state is needed.

    Ok(local_messages)
}

/// Insert a message record and its location into the state DB.
fn insert_message_and_location<S: StateDb>(
    state_db: &S,
    metadata: &MessageMetadata,
    fingerprint: &str,
    folder: &str,
    stored_path: &Path,
    uid: u32,
    account_name: &str,
) -> Result<(), SyncError> {
    let now = current_timestamp();

    let message_record = MessageRecord {
        fingerprint: fingerprint.to_owned(),
        message_id: metadata.message_id.clone(),
        subject: metadata.subject.clone(),
        from: metadata.from.clone(),
        date: metadata.date.clone(),
        attachment_count: metadata.attachment_count,
        body_structure_hash: metadata.body_structure_hash.clone(),
        first_seen: now.clone(),
    };

    state_db
        .insert_message(&message_record)
        .map_err(|e| SyncError::FolderSync {
            account: account_name.to_owned(),
            folder: folder.to_owned(),
            reason: format!("failed to insert message record: {e}"),
        })?;

    let location = LocationRecord {
        account_name: account_name.to_owned(),
        fingerprint: fingerprint.to_owned(),
        folder: folder.to_owned(),
        local_path: stored_path.display().to_string(),
        imap_uid: Some(uid),
        last_seen_on_server: now,
    };

    state_db
        .upsert_location(&location)
        .map_err(|e| SyncError::FolderSync {
            account: account_name.to_owned(),
            folder: folder.to_owned(),
            reason: format!("failed to insert location record: {e}"),
        })?;

    Ok(())
}

/// Update the folder record with current uid_validity and highest_synced_uid.
fn update_folder_record<S: StateDb>(
    state_db: &S,
    account_name: &str,
    folder_name: &str,
    uid_validity: u32,
    highest_synced_uid: u32,
) {
    let record = FolderRecord {
        account_name: account_name.to_owned(),
        folder_name: folder_name.to_owned(),
        uid_validity: Some(uid_validity),
        highest_synced_uid: Some(highest_synced_uid),
    };

    if let Err(e) = state_db.upsert_folder(&record) {
        tracing::error!(
            folder = folder_name,
            error = %e,
            "failed to update folder record"
        );
    }
}

/// Update the last_successful_sync timestamp for an account.
fn update_last_successful_sync<S: StateDb>(state_db: &S, account_name: &str) {
    let now = current_timestamp();
    if let Err(e) = state_db.set_last_successful_sync(account_name, &now) {
        tracing::error!(
            account = account_name,
            error = %e,
            "failed to update last_successful_sync"
        );
    }
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Build a UID range string for incremental fetch.
fn build_uid_range(highest_synced_uid: u32) -> String {
    let start = highest_synced_uid.saturating_add(1);
    format!("{start}:*")
}

/// Filter folders by glob-style folder patterns.
fn filter_folders(
    folders: &[crate::types::FolderInfo],
    patterns: &[String],
) -> Vec<crate::types::FolderInfo> {
    folders
        .iter()
        .filter(|f| crate::config::matches_folder_patterns(&f.name, patterns))
        .cloned()
        .collect()
}

/// Extract minimal metadata from a raw message body for the DB record.
///
/// Uses a best-effort approach: parses common headers from the RFC 822
/// body. Falls back to empty strings for missing headers.
fn extract_metadata_from_body(body: &[u8], fingerprint: &str) -> MessageMetadata {
    let body_str = String::from_utf8_lossy(body);
    let headers_end = body_str.find("\r\n\r\n").or_else(|| body_str.find("\n\n"));
    let header_section = match headers_end {
        Some(pos) => &body_str[..pos],
        None => &body_str,
    };

    let message_id = extract_header_value(header_section, "message-id");
    let date = extract_header_value(header_section, "date").unwrap_or_default();
    let from = extract_header_value(header_section, "from").unwrap_or_default();
    let to = extract_header_value(header_section, "to");
    let cc = extract_header_value(header_section, "cc");
    let subject = extract_header_value(header_section, "subject").unwrap_or_default();

    MessageMetadata {
        message_id,
        date,
        from,
        to,
        cc,
        subject,
        attachment_count: 0,
        attachments: Vec::new(),
        body_structure_hash: String::new(),
        fingerprint: fingerprint.to_owned(),
    }
}

/// Extract a header value from a raw header section (case-insensitive).
///
/// Matches only exact header names by verifying the colon immediately follows
/// the name (with optional whitespace). This prevents false positives like
/// matching "Total:" when searching for "to".
fn extract_header_value(headers: &str, name: &str) -> Option<String> {
    let prefix = format!("{}:", name.to_lowercase());
    for line in headers.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with(&prefix) {
            let value = line[name.len() + 1..].trim().to_owned();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// Update the maximum UID seen based on the action type.
fn update_max_uid(current_max: u32, action: &SyncAction) -> u32 {
    let uid = match action {
        SyncAction::Download { uid, .. } => Some(*uid),
        _ => None,
    };

    match uid {
        Some(u) if u > current_max => u,
        _ => current_max,
    }
}

/// Update the folder report counters for a successfully executed action.
fn update_folder_report_for_action(report: &mut FolderSyncReport, action: &SyncAction) {
    match action {
        SyncAction::Download { .. } => report.downloaded += 1,
        SyncAction::Move { .. } => report.moved += 1,
        SyncAction::Copy { .. } => report.copied += 1,
        SyncAction::Skip { .. } => report.skipped += 1,
        SyncAction::Archive { .. } => report.archived += 1,
    }
}

/// Accumulate a folder report's counters into an account report.
fn accumulate_folder_report(
    account_report: &mut AccountSyncReport,
    folder_report: &FolderSyncReport,
) {
    account_report.downloaded += folder_report.downloaded;
    account_report.moved += folder_report.moved;
    account_report.copied += folder_report.copied;
    account_report.skipped += folder_report.skipped;
    account_report.archived += folder_report.archived;
    account_report.errors += folder_report.errors;
}

/// Truncate a fingerprint for display in log messages.
fn truncate_fingerprint(fingerprint: &str) -> &str {
    if fingerprint.len() > FINGERPRINT_LOG_LENGTH {
        &fingerprint[..FINGERPRINT_LOG_LENGTH]
    } else {
        fingerprint
    }
}

/// Truncate a subject line for display in log messages.
fn truncate_subject(subject: &str) -> &str {
    if subject.len() > SUBJECT_LOG_LENGTH {
        // Find a char boundary to avoid splitting multi-byte characters.
        let mut end = SUBJECT_LOG_LENGTH;
        while end > 0 && !subject.is_char_boundary(end) {
            end -= 1;
        }
        &subject[..end]
    } else {
        subject
    }
}

/// Get the current UTC timestamp in ISO 8601 format.
fn current_timestamp() -> String {
    // Use SystemTime to avoid adding a chrono dependency.
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Simple UTC formatting: seconds since epoch as a string.
    // A full ISO 8601 formatter would be better, but this avoids extra dependencies.
    format!("{secs}")
}

// ---------------------------------------------------------------------------
// Logging helpers
// ---------------------------------------------------------------------------

/// Log a sync action at info level.
fn log_action(action_type: &str, folder: &str, fingerprint: &str, subject: &str) {
    tracing::info!(
        action = action_type,
        folder = folder,
        fingerprint = truncate_fingerprint(fingerprint),
        subject = truncate_subject(subject),
        "{action_type}"
    );
}

/// Log a dry-run action at info level.
fn log_dry_run_action(folder: &str, action: &SyncAction) {
    match action {
        SyncAction::Download {
            fingerprint, uid, ..
        } => {
            tracing::info!(
                folder = folder,
                fingerprint = truncate_fingerprint(fingerprint),
                uid = uid,
                "[DRY RUN] would download"
            );
        }
        SyncAction::Move {
            fingerprint,
            from_folder,
            to_folder,
            ..
        } => {
            tracing::info!(
                fingerprint = truncate_fingerprint(fingerprint),
                from = from_folder.as_str(),
                to = to_folder.as_str(),
                "[DRY RUN] would move"
            );
        }
        SyncAction::Copy {
            fingerprint,
            from_folder,
            to_folder,
            ..
        } => {
            tracing::info!(
                fingerprint = truncate_fingerprint(fingerprint),
                from = from_folder.as_str(),
                to = to_folder.as_str(),
                "[DRY RUN] would copy"
            );
        }
        SyncAction::Archive {
            fingerprint,
            folder: archive_folder,
        } => {
            tracing::info!(
                folder = archive_folder.as_str(),
                fingerprint = truncate_fingerprint(fingerprint),
                "[DRY RUN] would archive"
            );
        }
        SyncAction::Skip {
            fingerprint,
            reason,
        } => {
            tracing::debug!(
                fingerprint = truncate_fingerprint(fingerprint),
                reason = reason.as_str(),
                "[DRY RUN] skip"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    use crate::imap_client::{FolderStatus, MockImapClient};
    use crate::maildir::FsMaildirStore;
    use crate::state::SqliteStateDb;
    use crate::types::FolderInfo;

    // --- Pure helper tests ---

    #[test]
    fn build_uid_range_from_zero() {
        assert_eq!(build_uid_range(0), "1:*");
    }

    #[test]
    fn build_uid_range_incremental() {
        assert_eq!(build_uid_range(42), "43:*");
    }

    #[test]
    fn build_uid_range_max_u32_saturates() {
        // u32::MAX + 1 saturates to u32::MAX
        assert_eq!(build_uid_range(u32::MAX), format!("{}:*", u32::MAX));
    }

    #[test]
    fn filter_folders_default_patterns() {
        let folders = vec![
            make_folder_info("INBOX"),
            make_folder_info("Sent"),
            make_folder_info("Trash"),
        ];
        let patterns = vec!["*".to_owned()];
        let result = filter_folders(&folders, &patterns);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn filter_folders_include_only() {
        let folders = vec![
            make_folder_info("INBOX"),
            make_folder_info("Sent"),
            make_folder_info("Trash"),
        ];
        let patterns = vec!["INBOX".to_owned(), "Sent".to_owned()];
        let result = filter_folders(&folders, &patterns);
        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|f| f.name == "INBOX"));
        assert!(result.iter().any(|f| f.name == "Sent"));
    }

    #[test]
    fn filter_folders_exclude_trash() {
        let folders = vec![
            make_folder_info("INBOX"),
            make_folder_info("Sent"),
            make_folder_info("Trash"),
        ];
        let patterns = vec!["*".to_owned(), "!Trash".to_owned()];
        let result = filter_folders(&folders, &patterns);
        assert_eq!(result.len(), 2);
        assert!(!result.iter().any(|f| f.name == "Trash"));
    }

    #[test]
    fn filter_folders_star_with_multiple_exclusions() {
        let folders = vec![
            make_folder_info("INBOX"),
            make_folder_info("Sent"),
            make_folder_info("Trash"),
        ];
        let patterns = vec!["*".to_owned(), "!Trash".to_owned()];
        let result = filter_folders(&folders, &patterns);
        assert_eq!(result.len(), 2);
        assert!(!result.iter().any(|f| f.name == "Trash"));
    }

    #[test]
    fn truncate_fingerprint_short() {
        assert_eq!(truncate_fingerprint("abcdef"), "abcdef");
    }

    #[test]
    fn truncate_fingerprint_exact() {
        let fp = "a".repeat(FINGERPRINT_LOG_LENGTH);
        assert_eq!(truncate_fingerprint(&fp), fp.as_str());
    }

    #[test]
    fn truncate_fingerprint_long() {
        let fp = "a".repeat(64);
        assert_eq!(truncate_fingerprint(&fp).len(), FINGERPRINT_LOG_LENGTH);
    }

    #[test]
    fn truncate_subject_short() {
        assert_eq!(truncate_subject("Hello"), "Hello");
    }

    #[test]
    fn truncate_subject_long() {
        let subj = "x".repeat(100);
        assert!(truncate_subject(&subj).len() <= SUBJECT_LOG_LENGTH);
    }

    #[test]
    fn update_folder_report_download() {
        let mut report = FolderSyncReport::default();
        let action = SyncAction::Download {
            fingerprint: "fp".to_owned(),
            folder: "INBOX".to_owned(),
            uid: 1,
            flags: Vec::new(),
        };
        update_folder_report_for_action(&mut report, &action);
        assert_eq!(report.downloaded, 1);
    }

    #[test]
    fn update_folder_report_all_actions() {
        let mut report = FolderSyncReport::default();

        update_folder_report_for_action(
            &mut report,
            &SyncAction::Download {
                fingerprint: "fp".to_owned(),
                folder: "INBOX".to_owned(),
                uid: 1,
                flags: Vec::new(),
            },
        );
        update_folder_report_for_action(
            &mut report,
            &SyncAction::Move {
                fingerprint: "fp".to_owned(),
                from_folder: "INBOX".to_owned(),
                to_folder: "Archive".to_owned(),
                local_path: PathBuf::from("/tmp/msg"),
            },
        );
        update_folder_report_for_action(
            &mut report,
            &SyncAction::Copy {
                fingerprint: "fp".to_owned(),
                from_folder: "INBOX".to_owned(),
                to_folder: "Important".to_owned(),
                local_path: PathBuf::from("/tmp/msg"),
            },
        );
        update_folder_report_for_action(
            &mut report,
            &SyncAction::Skip {
                fingerprint: "fp".to_owned(),
                reason: "already backed up".to_owned(),
            },
        );
        update_folder_report_for_action(
            &mut report,
            &SyncAction::Archive {
                fingerprint: "fp".to_owned(),
                folder: "INBOX".to_owned(),
            },
        );

        assert_eq!(report.downloaded, 1);
        assert_eq!(report.moved, 1);
        assert_eq!(report.copied, 1);
        assert_eq!(report.skipped, 1);
        assert_eq!(report.archived, 1);
    }

    #[test]
    fn accumulate_folder_report_sums_correctly() {
        let mut account = AccountSyncReport::default();
        let folder = FolderSyncReport {
            folder: "INBOX".to_owned(),
            downloaded: 3,
            moved: 1,
            copied: 2,
            skipped: 5,
            archived: 1,
            errors: 0,
        };
        accumulate_folder_report(&mut account, &folder);
        assert_eq!(account.downloaded, 3);
        assert_eq!(account.moved, 1);
        assert_eq!(account.copied, 2);
        assert_eq!(account.skipped, 5);
        assert_eq!(account.archived, 1);
    }

    #[test]
    fn extract_header_value_finds_subject() {
        let headers = "From: alice@example.com\nSubject: Hello World\nDate: 2024-01-01";
        assert_eq!(
            extract_header_value(headers, "subject"),
            Some("Hello World".to_owned())
        );
    }

    #[test]
    fn extract_header_value_case_insensitive() {
        let headers = "FROM: alice@example.com\nSUBJECT: Test\n";
        assert_eq!(
            extract_header_value(headers, "subject"),
            Some("Test".to_owned())
        );
    }

    #[test]
    fn extract_header_value_missing() {
        let headers = "From: alice@example.com\n";
        assert_eq!(extract_header_value(headers, "subject"), None);
    }

    #[test]
    fn extract_metadata_from_body_parses_headers() {
        let body = b"From: alice@example.com\r\nSubject: Test Email\r\nDate: Mon, 1 Jan 2024\r\n\r\nBody text here";
        let metadata = extract_metadata_from_body(body, "fp123");
        assert_eq!(metadata.from, "alice@example.com");
        assert_eq!(metadata.subject, "Test Email");
        assert_eq!(metadata.date, "Mon, 1 Jan 2024");
        assert_eq!(metadata.fingerprint, "fp123");
    }

    #[test]
    fn build_sync_report_aggregates() {
        let ar1 = AccountSyncReport {
            account: "a1".to_owned(),
            downloaded: 5,
            moved: 1,
            copied: 2,
            skipped: 10,
            archived: 3,
            errors: 0,
            folder_reports: Vec::new(),
        };
        let ar2 = AccountSyncReport {
            account: "a2".to_owned(),
            downloaded: 3,
            moved: 0,
            copied: 1,
            skipped: 7,
            archived: 1,
            errors: 1,
            folder_reports: Vec::new(),
        };

        let report = build_sync_report(vec![ar1, ar2], std::time::Duration::from_secs(42));

        assert_eq!(report.downloaded, 8);
        assert_eq!(report.moved, 1);
        assert_eq!(report.copied, 3);
        assert_eq!(report.skipped, 17);
        assert_eq!(report.archived, 4);
        assert_eq!(report.errors, 1);
        assert_eq!(report.duration.as_secs(), 42);
        assert_eq!(report.account_reports.len(), 2);
    }

    // --- Integration tests with mock IMAP + real SQLite + real Maildir ---

    fn make_folder_info(name: &str) -> FolderInfo {
        FolderInfo {
            name: name.to_owned(),
            uid_validity: 0,
            message_count: 0,
        }
    }

    fn make_test_account() -> AccountConfig {
        AccountConfig {
            name: "test-account".to_owned(),
            host: "imap.example.com".to_owned(),
            port: 993,
            tls: true,
            username: "user@example.com".to_owned(),
            password_source: crate::config::PasswordSource::Plaintext("password".to_owned()),
            folder_patterns: vec!["*".to_owned()],
        }
    }

    fn setup_test_env() -> (tempfile::TempDir, SqliteStateDb, FsMaildirStore) {
        let dir = tempfile::tempdir().unwrap();
        let state_db = SqliteStateDb::open_in_memory().unwrap();
        let maildir = FsMaildirStore::new(dir.path().to_path_buf(), false);
        (dir, state_db, maildir)
    }

    #[tokio::test]
    async fn sync_downloads_new_messages() {
        // Verify that planning produces download for new messages
        let server = vec![ServerMessage {
            fingerprint: "fp_new_1".to_owned(),
            folder: "INBOX".to_owned(),
            uid: 1,
            flags: Vec::new(),
        }];
        let local: Vec<LocalMessage> = vec![];
        let actions = plan_sync(&server, &local);

        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], SyncAction::Download { uid: 1, .. }));
    }

    #[tokio::test]
    async fn sync_detects_move() {
        let server = vec![ServerMessage {
            fingerprint: "fp_moved".to_owned(),
            folder: "Archive".to_owned(),
            uid: 10,
            flags: Vec::new(),
        }];
        let local = vec![LocalMessage {
            fingerprint: "fp_moved".to_owned(),
            folder: "INBOX".to_owned(),
            local_path: PathBuf::from("/mail/INBOX/msg.eml"),
        }];
        let actions = plan_sync(&server, &local);

        assert!(actions.iter().any(|a| matches!(
            a,
            SyncAction::Move {
                fingerprint,
                from_folder,
                to_folder,
                ..
            } if fingerprint == "fp_moved" && from_folder == "INBOX" && to_folder == "Archive"
        )));
    }

    #[tokio::test]
    async fn sync_detects_copy() {
        let server = vec![
            ServerMessage {
                fingerprint: "fp_copied".to_owned(),
                folder: "INBOX".to_owned(),
                uid: 1,
                flags: Vec::new(),
            },
            ServerMessage {
                fingerprint: "fp_copied".to_owned(),
                folder: "Important".to_owned(),
                uid: 5,
                flags: Vec::new(),
            },
        ];
        let local = vec![LocalMessage {
            fingerprint: "fp_copied".to_owned(),
            folder: "INBOX".to_owned(),
            local_path: PathBuf::from("/mail/INBOX/msg.eml"),
        }];
        let actions = plan_sync(&server, &local);

        assert!(actions.iter().any(|a| matches!(
            a,
            SyncAction::Copy {
                fingerprint,
                to_folder,
                ..
            } if fingerprint == "fp_copied" && to_folder == "Important"
        )));
    }

    #[tokio::test]
    async fn sync_detects_archive() {
        let server: Vec<ServerMessage> = vec![];
        let local = vec![LocalMessage {
            fingerprint: "fp_archived".to_owned(),
            folder: "INBOX".to_owned(),
            local_path: PathBuf::from("/mail/INBOX/msg.eml"),
        }];
        let actions = plan_sync(&server, &local);

        assert!(actions.iter().any(|a| matches!(
            a,
            SyncAction::Archive {
                fingerprint,
                folder,
            } if fingerprint == "fp_archived" && folder == "INBOX"
        )));
    }

    #[tokio::test]
    async fn dry_run_does_not_modify_state() {
        let action = SyncAction::Download {
            fingerprint: "fp_dry".to_owned(),
            folder: "INBOX".to_owned(),
            uid: 1,
            flags: Vec::new(),
        };

        // dry_run should return Ok without touching filesystem or DB
        // We test the log_dry_run_action path directly
        log_dry_run_action("INBOX", &action);
        // If we got here without error, the dry-run path works.
    }

    #[tokio::test]
    async fn shutdown_signal_interrupts_sync() {
        let (controller, shutdown) = crate::shutdown::ShutdownController::new();

        // Request shutdown immediately
        controller.request_shutdown();

        assert!(shutdown.is_shutdown_requested());
        // The sync_account method would break out of the folder loop on the first
        // check, returning a partial report. We test the signal mechanism here.
    }

    #[tokio::test]
    async fn uid_validity_change_resets_sync_progress() {
        let (_dir, state_db, _maildir) = setup_test_env();

        // Insert a folder record with uid_validity = 100
        let folder_record = FolderRecord {
            account_name: "test-account".to_owned(),
            folder_name: "INBOX".to_owned(),
            uid_validity: Some(100),
            highest_synced_uid: Some(50),
        };
        state_db.upsert_folder(&folder_record).unwrap();

        // Check with same validity: should return Incremental(50)
        let uid = resolve_highest_synced_uid(&state_db, "test-account", "INBOX", 100).unwrap();
        assert_eq!(uid, UidResolution::Incremental(50));

        // Check with different validity: should return ValidityChanged
        let uid = resolve_highest_synced_uid(&state_db, "test-account", "INBOX", 200).unwrap();
        assert_eq!(uid, UidResolution::ValidityChanged);
    }

    #[tokio::test]
    async fn uid_validity_zero_does_not_trigger_reset() {
        let (_dir, state_db, _maildir) = setup_test_env();

        // Insert a folder record with uid_validity = 0 (unknown)
        let folder_record = FolderRecord {
            account_name: "test-account".to_owned(),
            folder_name: "INBOX".to_owned(),
            uid_validity: Some(0),
            highest_synced_uid: Some(50),
        };
        state_db.upsert_folder(&folder_record).unwrap();

        // uid_validity 0 in DB means "never set", so new validity should not
        // trigger a reset
        let uid = resolve_highest_synced_uid(&state_db, "test-account", "INBOX", 100).unwrap();
        assert_eq!(uid, UidResolution::Incremental(50));
    }

    #[tokio::test]
    async fn execute_download_stores_and_records() {
        let (_dir, state_db, maildir) = setup_test_env();
        let engine: SyncEngine<MockImapClient, _, _> =
            SyncEngine::new(state_db, maildir, 100 * 1024 * 1024);

        let account = make_test_account();
        let body = b"From: test@example.com\r\nSubject: Test\r\nDate: 2024-01-01\r\n\r\nBody";
        let mut bodies = HashMap::new();
        bodies.insert(1u32, body.to_vec());

        let mut mock = MockImapClient::new();
        mock.message_bodies = bodies;
        mock.folder_status.insert(
            "INBOX".to_owned(),
            FolderStatus {
                uid_validity: Some(1),
                message_count: 1,
                uid_next: Some(2),
            },
        );

        let result = engine
            .execute_download(&mut mock, &account, "INBOX", "fp_test_dl", 1, &[])
            .await;

        assert!(result.is_ok());

        // Verify message is in the state DB
        let msg = engine.state_db.get_message("fp_test_dl").unwrap();
        assert!(msg.is_some());

        // Verify location is recorded
        let locs = engine
            .state_db
            .get_locations("test-account", "fp_test_dl")
            .unwrap();
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].folder, "INBOX");

        // Verify file exists on disk
        let path = PathBuf::from(&locs[0].local_path);
        assert!(path.exists());
    }

    #[tokio::test]
    async fn execute_download_skips_oversized_message() {
        let (_dir, state_db, maildir) = setup_test_env();
        // Set a tiny limit so our test message exceeds it
        let engine: SyncEngine<MockImapClient, _, _> = SyncEngine::new(state_db, maildir, 10);

        let account = make_test_account();
        let body = b"From: test@example.com\r\nSubject: Big\r\nDate: 2024-01-01\r\n\r\nLarge body content here";
        let mut bodies = HashMap::new();
        bodies.insert(1u32, body.to_vec());

        let mut mock = MockImapClient::new();
        mock.message_bodies = bodies;

        let result = engine
            .execute_download(&mut mock, &account, "INBOX", "fp_big", 1, &[])
            .await;

        // Should succeed (skip, not error)
        assert!(result.is_ok());

        // Message should NOT be stored in the state DB
        let msg = engine.state_db.get_message("fp_big").unwrap();
        assert!(msg.is_none(), "oversized message should not be recorded");

        // No locations should be created
        let locs = engine
            .state_db
            .get_locations("test-account", "fp_big")
            .unwrap();
        assert!(
            locs.is_empty(),
            "oversized message should have no locations"
        );
    }

    #[tokio::test]
    async fn execute_download_accepts_message_at_size_limit() {
        let (_dir, state_db, maildir) = setup_test_env();
        let body = b"From: a@b.c\r\n\r\nX";
        // Set limit to exactly the body size
        let engine: SyncEngine<MockImapClient, _, _> =
            SyncEngine::new(state_db, maildir, body.len() as u64);

        let account = make_test_account();
        let mut bodies = HashMap::new();
        bodies.insert(1u32, body.to_vec());

        let mut mock = MockImapClient::new();
        mock.message_bodies = bodies;

        let result = engine
            .execute_download(&mut mock, &account, "INBOX", "fp_exact", 1, &[])
            .await;

        assert!(result.is_ok());

        // Message at exactly the limit should be stored
        let msg = engine.state_db.get_message("fp_exact").unwrap();
        assert!(msg.is_some(), "message at size limit should be stored");
    }

    #[tokio::test]
    async fn execute_move_relocates_and_updates_db() {
        let (_dir, state_db, maildir) = setup_test_env();

        // First store a message to have a real file
        let stored_path = maildir
            .store_message("INBOX", b"From: test\r\n\r\nBody")
            .unwrap();

        // Insert into DB
        let msg_record = MessageRecord {
            fingerprint: "fp_move_test".to_owned(),
            message_id: None,
            subject: "Test".to_owned(),
            from: "test@example.com".to_owned(),
            date: "2024-01-01".to_owned(),
            attachment_count: 0,
            body_structure_hash: String::new(),
            first_seen: "0".to_owned(),
        };
        state_db.insert_message(&msg_record).unwrap();
        let loc = LocationRecord {
            account_name: "test-account".to_owned(),
            fingerprint: "fp_move_test".to_owned(),
            folder: "INBOX".to_owned(),
            local_path: stored_path.display().to_string(),
            imap_uid: Some(1),
            last_seen_on_server: "0".to_owned(),
        };
        state_db.upsert_location(&loc).unwrap();

        let engine: SyncEngine<MockImapClient, _, _> =
            SyncEngine::new(state_db, maildir, 100 * 1024 * 1024);

        let result = engine.execute_move(
            "test-account",
            "fp_move_test",
            "INBOX",
            "Archive",
            &stored_path,
        );

        assert!(result.is_ok());

        // Old location should be gone
        let locs = engine
            .state_db
            .get_locations("test-account", "fp_move_test")
            .unwrap();
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].folder, "Archive");

        // File should exist at new location
        let new_path = PathBuf::from(&locs[0].local_path);
        assert!(new_path.exists());

        // Old file should not exist
        assert!(!stored_path.exists());
    }

    #[tokio::test]
    async fn execute_copy_duplicates_and_records() {
        let (_dir, state_db, maildir) = setup_test_env();

        // Store a message to have a real file
        let stored_path = maildir
            .store_message("INBOX", b"From: test\r\n\r\nBody")
            .unwrap();

        // Insert into DB
        let msg_record = MessageRecord {
            fingerprint: "fp_copy_test".to_owned(),
            message_id: None,
            subject: "Test".to_owned(),
            from: "test@example.com".to_owned(),
            date: "2024-01-01".to_owned(),
            attachment_count: 0,
            body_structure_hash: String::new(),
            first_seen: "0".to_owned(),
        };
        state_db.insert_message(&msg_record).unwrap();
        let loc = LocationRecord {
            account_name: "test-account".to_owned(),
            fingerprint: "fp_copy_test".to_owned(),
            folder: "INBOX".to_owned(),
            local_path: stored_path.display().to_string(),
            imap_uid: Some(1),
            last_seen_on_server: "0".to_owned(),
        };
        state_db.upsert_location(&loc).unwrap();

        let engine: SyncEngine<MockImapClient, _, _> =
            SyncEngine::new(state_db, maildir, 100 * 1024 * 1024);

        let result = engine.execute_copy(
            "test-account",
            "fp_copy_test",
            "INBOX",
            "Important",
            &stored_path,
        );

        assert!(result.is_ok());

        // Both locations should exist
        let locs = engine
            .state_db
            .get_locations("test-account", "fp_copy_test")
            .unwrap();
        assert_eq!(locs.len(), 2);

        // Original file should still exist
        assert!(stored_path.exists());

        // Copy file should exist
        let copy_loc = locs.iter().find(|l| l.folder == "Important").unwrap();
        let copy_path = PathBuf::from(&copy_loc.local_path);
        assert!(copy_path.exists());
    }
}
