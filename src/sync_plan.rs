//! Pure sync planning logic.
//!
//! Compares server-side IMAP state against locally stored messages and
//! produces a list of [`SyncAction`]s to bring the local state in sync.
//! All functions in this module are **pure** — no I/O, no side effects.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

use crate::types::SyncAction;

/// A message as seen on the IMAP server (from IMAP FETCH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerMessage {
    /// Composite fingerprint identifying the message.
    pub fingerprint: String,
    /// IMAP folder where the message resides.
    pub folder: String,
    /// IMAP UID of the message within the folder.
    pub uid: u32,
    /// IMAP flags on this message (e.g., `\Seen`, `\Flagged`, `\Answered`).
    pub flags: Vec<String>,
}

/// A message as stored locally (from the state database).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalMessage {
    /// Composite fingerprint identifying the message.
    pub fingerprint: String,
    /// Folder the message is filed under locally.
    pub folder: String,
    /// Local filesystem path to the message file.
    pub local_path: PathBuf,
}

/// Plan the sync actions needed to reconcile server state with local state.
///
/// Compares `server_state` (what the IMAP server currently has) against
/// `local_state` (what we have stored locally) and returns a list of
/// actions to execute:
///
/// - **Download** — message exists on the server but not locally
/// - **Move** — message moved to a different folder on the server
/// - **Copy** — message was copied to an additional folder on the server
/// - **Skip** — message is already in sync
/// - **Archive** — message was deleted from the server (kept locally)
pub fn plan_sync(server_state: &[ServerMessage], local_state: &[LocalMessage]) -> Vec<SyncAction> {
    let server_map = build_server_map(server_state);
    let local_map = build_local_map(local_state);

    let mut actions = Vec::new();

    plan_server_side_actions(&server_map, &local_map, &mut actions);
    plan_archive_actions(&server_map, &local_map, &mut actions);

    actions
}

/// Server-side view: fingerprint mapped to its folders and UIDs.
struct ServerEntry {
    /// Set of folders containing this fingerprint on the server.
    folders: BTreeSet<String>,
    /// Map from folder name to IMAP UID.
    uid_by_folder: HashMap<String, u32>,
    /// Map from folder name to IMAP flags.
    flags_by_folder: HashMap<String, Vec<String>>,
}

/// Local-side view: fingerprint mapped to its folders and paths.
struct LocalEntry {
    /// Set of folders containing this fingerprint locally.
    folders: BTreeSet<String>,
    /// Map from folder name to local file path.
    path_by_folder: HashMap<String, PathBuf>,
}

/// Build a map from fingerprint to server-side folder set and UIDs.
fn build_server_map(server_state: &[ServerMessage]) -> BTreeMap<String, ServerEntry> {
    let mut map: BTreeMap<String, ServerEntry> = BTreeMap::new();

    for msg in server_state {
        let entry = map
            .entry(msg.fingerprint.clone())
            .or_insert_with(|| ServerEntry {
                folders: BTreeSet::new(),
                uid_by_folder: HashMap::new(),
                flags_by_folder: HashMap::new(),
            });
        entry.folders.insert(msg.folder.clone());
        entry.uid_by_folder.insert(msg.folder.clone(), msg.uid);
        entry
            .flags_by_folder
            .insert(msg.folder.clone(), msg.flags.clone());
    }

    map
}

/// Build a map from fingerprint to local folder set and paths.
fn build_local_map(local_state: &[LocalMessage]) -> BTreeMap<String, LocalEntry> {
    let mut map: BTreeMap<String, LocalEntry> = BTreeMap::new();

    for msg in local_state {
        let entry = map
            .entry(msg.fingerprint.clone())
            .or_insert_with(|| LocalEntry {
                folders: BTreeSet::new(),
                path_by_folder: HashMap::new(),
            });
        entry.folders.insert(msg.folder.clone());
        entry
            .path_by_folder
            .insert(msg.folder.clone(), msg.local_path.clone());
    }

    map
}

/// Plan actions for messages present on the server.
fn plan_server_side_actions(
    server_map: &BTreeMap<String, ServerEntry>,
    local_map: &BTreeMap<String, LocalEntry>,
    actions: &mut Vec<SyncAction>,
) {
    for (fingerprint, server_entry) in server_map {
        match local_map.get(fingerprint) {
            None => plan_downloads(fingerprint, server_entry, actions),
            Some(local_entry) => {
                plan_sync_existing(fingerprint, server_entry, local_entry, actions);
            }
        }
    }
}

/// Plan download actions for a message not present locally at all.
fn plan_downloads(fingerprint: &str, server_entry: &ServerEntry, actions: &mut Vec<SyncAction>) {
    for folder in &server_entry.folders {
        let uid = server_entry.uid_by_folder.get(folder).copied().unwrap_or(0);
        let flags = server_entry
            .flags_by_folder
            .get(folder)
            .cloned()
            .unwrap_or_default();
        actions.push(SyncAction::Download {
            fingerprint: fingerprint.to_owned(),
            folder: folder.clone(),
            uid,
            flags,
        });
    }
}

/// Plan actions for a message that exists both on server and locally.
fn plan_sync_existing(
    fingerprint: &str,
    server_entry: &ServerEntry,
    local_entry: &LocalEntry,
    actions: &mut Vec<SyncAction>,
) {
    let server_folders = &server_entry.folders;
    let local_folders = &local_entry.folders;

    // Folders that are on the server but not locally — need to be added
    let new_folders: BTreeSet<&String> = server_folders.difference(local_folders).collect();

    // Folders that are both on server and locally — already in sync
    let common_folders: BTreeSet<&String> = server_folders.intersection(local_folders).collect();

    // Skip common folders
    for folder in &common_folders {
        actions.push(SyncAction::Skip {
            fingerprint: fingerprint.to_owned(),
            reason: format!("already backed up in folder '{folder}'"),
        });
    }

    if new_folders.is_empty() {
        return;
    }

    // Determine the source for copy/move operations
    let source = pick_source_folder(local_entry, &common_folders);

    // When we need to move (no common folders) to multiple targets, we
    // collect copies here and emit them before the final move.
    let mut pending_copies: Vec<SyncAction> = Vec::new();

    for new_folder in &new_folders {
        let uid = server_entry
            .uid_by_folder
            .get(*new_folder)
            .copied()
            .unwrap_or(0);

        match &source {
            Some((source_folder, source_path)) if !common_folders.is_empty() => {
                // Message still exists in at least one common folder — copy
                actions.push(SyncAction::Copy {
                    fingerprint: fingerprint.to_owned(),
                    from_folder: source_folder.clone(),
                    to_folder: (*new_folder).clone(),
                    local_path: source_path.clone(),
                });
            }
            Some((source_folder, source_path)) => {
                // Message only exists locally in folders NOT on the server.
                // We need to move it to one target and copy to the rest.
                // Copies are emitted first; the move is deferred to the end
                // so that the source file still exists for all copy operations.
                if new_folders.len() == 1 {
                    // Only one target — just move directly
                    actions.push(SyncAction::Move {
                        fingerprint: fingerprint.to_owned(),
                        from_folder: source_folder.clone(),
                        to_folder: (*new_folder).clone(),
                        local_path: source_path.clone(),
                    });
                } else {
                    pending_copies.push(SyncAction::Copy {
                        fingerprint: fingerprint.to_owned(),
                        from_folder: source_folder.clone(),
                        to_folder: (*new_folder).clone(),
                        local_path: source_path.clone(),
                    });
                }
            }
            None => {
                // No local source available (shouldn't happen since local_entry
                // must have at least one folder, but handle gracefully)
                let flags = server_entry
                    .flags_by_folder
                    .get(*new_folder)
                    .cloned()
                    .unwrap_or_default();
                actions.push(SyncAction::Download {
                    fingerprint: fingerprint.to_owned(),
                    folder: (*new_folder).clone(),
                    uid,
                    flags,
                });
            }
        }
    }

    // When there are no common folders and multiple new targets, convert the
    // last pending copy into a Move (so the source file is preserved for all
    // preceding copies) and append them all.
    if !pending_copies.is_empty() {
        if let Some(last) = pending_copies.pop() {
            // Emit all copies first (source still exists)
            actions.append(&mut pending_copies);
            // Convert the last copy into a move
            if let SyncAction::Copy {
                fingerprint: fp,
                from_folder,
                to_folder,
                local_path,
            } = last
            {
                actions.push(SyncAction::Move {
                    fingerprint: fp,
                    from_folder,
                    to_folder,
                    local_path,
                });
            }
        }
    }
}

/// Pick the best source folder and path from the local entry.
///
/// Prefers a folder that is also present on the server (common folder).
/// Falls back to the first local folder if no common folder exists.
fn pick_source_folder(
    local_entry: &LocalEntry,
    common_folders: &BTreeSet<&String>,
) -> Option<(String, PathBuf)> {
    // Prefer a common folder as source
    for folder in common_folders {
        if let Some(path) = local_entry.path_by_folder.get(*folder) {
            return Some(((*folder).clone(), path.clone()));
        }
    }

    // Fall back to the first local folder (BTreeSet iteration is sorted)
    for folder in &local_entry.folders {
        if let Some(path) = local_entry.path_by_folder.get(folder) {
            return Some((folder.clone(), path.clone()));
        }
    }

    None
}

/// Plan archive actions for messages that exist locally but not on the server.
fn plan_archive_actions(
    server_map: &BTreeMap<String, ServerEntry>,
    local_map: &BTreeMap<String, LocalEntry>,
    actions: &mut Vec<SyncAction>,
) {
    for (fingerprint, local_entry) in local_map {
        if !server_map.contains_key(fingerprint) {
            for folder in &local_entry.folders {
                actions.push(SyncAction::Archive {
                    fingerprint: fingerprint.clone(),
                    folder: folder.clone(),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// UIDVALIDITY recovery planning
// ---------------------------------------------------------------------------

/// Result of UIDVALIDITY recovery analysis.
///
/// Produced by [`plan_uid_validity_recovery`] to describe which server
/// messages can be matched to existing local messages (by fingerprint) and
/// which are genuinely new.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UidValidityRecovery {
    /// Messages that matched by fingerprint — update their UIDs.
    pub matched: Vec<(String, u32)>,
    /// Messages on server that have no local match — need downloading.
    pub unmatched_server: Vec<ServerMessage>,
    /// Highest UID seen in the server messages.
    pub max_uid: u32,
}

/// Compare server messages with local state to recover from a UIDVALIDITY change.
///
/// When UIDVALIDITY changes, all UIDs in a folder are invalidated. This
/// function matches server messages to existing local messages using their
/// composite fingerprints:
///
/// - **Matched**: the message already exists locally — only its UID needs
///   updating (no re-download).
/// - **Unmatched**: the message is genuinely new and must be downloaded.
///
/// Only local messages in the same folder as the server messages are
/// considered for matching.
pub fn plan_uid_validity_recovery(
    server_messages: &[ServerMessage],
    local_messages: &[LocalMessage],
) -> UidValidityRecovery {
    let local_fingerprints: std::collections::HashSet<&str> = local_messages
        .iter()
        .map(|m| m.fingerprint.as_str())
        .collect();

    let mut matched = Vec::new();
    let mut unmatched_server = Vec::new();
    let mut max_uid: u32 = 0;

    for msg in server_messages {
        if msg.uid > max_uid {
            max_uid = msg.uid;
        }

        if local_fingerprints.contains(msg.fingerprint.as_str()) {
            matched.push((msg.fingerprint.clone(), msg.uid));
        } else {
            unmatched_server.push(msg.clone());
        }
    }

    UidValidityRecovery {
        matched,
        unmatched_server,
        max_uid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_msg(fingerprint: &str, folder: &str, uid: u32) -> ServerMessage {
        ServerMessage {
            fingerprint: fingerprint.to_owned(),
            folder: folder.to_owned(),
            uid,
            flags: Vec::new(),
        }
    }

    fn local_msg(fingerprint: &str, folder: &str, path: &str) -> LocalMessage {
        LocalMessage {
            fingerprint: fingerprint.to_owned(),
            folder: folder.to_owned(),
            local_path: PathBuf::from(path),
        }
    }

    /// Count actions of a specific variant.
    fn count_actions(actions: &[SyncAction], variant: &str) -> usize {
        actions
            .iter()
            .filter(|a| match (a, variant) {
                (SyncAction::Download { .. }, "Download") => true,
                (SyncAction::Move { .. }, "Move") => true,
                (SyncAction::Copy { .. }, "Copy") => true,
                (SyncAction::Skip { .. }, "Skip") => true,
                (SyncAction::Archive { .. }, "Archive") => true,
                _ => false,
            })
            .count()
    }

    /// Find the first action matching a variant and fingerprint.
    fn find_action<'a>(
        actions: &'a [SyncAction],
        variant: &str,
        fingerprint: &str,
    ) -> Option<&'a SyncAction> {
        actions.iter().find(|a| match (a, variant) {
            (
                SyncAction::Download {
                    fingerprint: fp, ..
                },
                "Download",
            ) => fp == fingerprint,
            (
                SyncAction::Move {
                    fingerprint: fp, ..
                },
                "Move",
            ) => fp == fingerprint,
            (
                SyncAction::Copy {
                    fingerprint: fp, ..
                },
                "Copy",
            ) => fp == fingerprint,
            (
                SyncAction::Skip {
                    fingerprint: fp, ..
                },
                "Skip",
            ) => fp == fingerprint,
            (
                SyncAction::Archive {
                    fingerprint: fp, ..
                },
                "Archive",
            ) => fp == fingerprint,
            _ => false,
        })
    }

    // --- New message on server → Download ---

    #[test]
    fn new_message_on_server_produces_download() {
        let server = vec![server_msg("fp1", "INBOX", 1)];
        let local = vec![];

        let actions = plan_sync(&server, &local);

        assert_eq!(count_actions(&actions, "Download"), 1);
        let action = find_action(&actions, "Download", "fp1").unwrap();
        match action {
            SyncAction::Download { folder, uid, .. } => {
                assert_eq!(folder, "INBOX");
                assert_eq!(*uid, 1);
            }
            _ => panic!("expected Download"),
        }
    }

    // --- Message moved (A→B) → Move ---

    #[test]
    fn message_moved_produces_move() {
        let server = vec![server_msg("fp1", "Archive", 10)];
        let local = vec![local_msg("fp1", "INBOX", "/mail/INBOX/fp1.eml")];

        let actions = plan_sync(&server, &local);

        assert_eq!(count_actions(&actions, "Move"), 1);
        let action = find_action(&actions, "Move", "fp1").unwrap();
        match action {
            SyncAction::Move {
                from_folder,
                to_folder,
                local_path,
                ..
            } => {
                assert_eq!(from_folder, "INBOX");
                assert_eq!(to_folder, "Archive");
                assert_eq!(local_path, &PathBuf::from("/mail/INBOX/fp1.eml"));
            }
            _ => panic!("expected Move"),
        }
    }

    // --- Message copied (A→A+B) → Copy ---

    #[test]
    fn message_copied_produces_copy() {
        let server = vec![
            server_msg("fp1", "INBOX", 1),
            server_msg("fp1", "Important", 5),
        ];
        let local = vec![local_msg("fp1", "INBOX", "/mail/INBOX/fp1.eml")];

        let actions = plan_sync(&server, &local);

        assert_eq!(count_actions(&actions, "Skip"), 1);
        assert_eq!(count_actions(&actions, "Copy"), 1);
        let action = find_action(&actions, "Copy", "fp1").unwrap();
        match action {
            SyncAction::Copy {
                from_folder,
                to_folder,
                ..
            } => {
                assert_eq!(from_folder, "INBOX");
                assert_eq!(to_folder, "Important");
            }
            _ => panic!("expected Copy"),
        }
    }

    // --- Message deleted from server → Archive ---

    #[test]
    fn message_deleted_from_server_produces_archive() {
        let server = vec![];
        let local = vec![local_msg("fp1", "INBOX", "/mail/INBOX/fp1.eml")];

        let actions = plan_sync(&server, &local);

        assert_eq!(count_actions(&actions, "Archive"), 1);
        let action = find_action(&actions, "Archive", "fp1").unwrap();
        match action {
            SyncAction::Archive { folder, .. } => {
                assert_eq!(folder, "INBOX");
            }
            _ => panic!("expected Archive"),
        }
    }

    // --- Message in same place → Skip ---

    #[test]
    fn message_in_same_place_produces_skip() {
        let server = vec![server_msg("fp1", "INBOX", 1)];
        let local = vec![local_msg("fp1", "INBOX", "/mail/INBOX/fp1.eml")];

        let actions = plan_sync(&server, &local);

        assert_eq!(count_actions(&actions, "Skip"), 1);
        assert_eq!(count_actions(&actions, "Download"), 0);
        assert_eq!(count_actions(&actions, "Move"), 0);
        assert_eq!(count_actions(&actions, "Copy"), 0);
        assert_eq!(count_actions(&actions, "Archive"), 0);
    }

    // --- Message in 3+ folders on server, 1 locally ---

    #[test]
    fn message_in_three_server_folders_one_local() {
        let server = vec![
            server_msg("fp1", "INBOX", 1),
            server_msg("fp1", "Archive", 10),
            server_msg("fp1", "Important", 20),
        ];
        let local = vec![local_msg("fp1", "INBOX", "/mail/INBOX/fp1.eml")];

        let actions = plan_sync(&server, &local);

        // INBOX is common → Skip
        assert_eq!(count_actions(&actions, "Skip"), 1);
        // Archive and Important are new → Copy from INBOX
        assert_eq!(count_actions(&actions, "Copy"), 2);
        assert_eq!(count_actions(&actions, "Download"), 0);
        assert_eq!(count_actions(&actions, "Move"), 0);
    }

    // --- Empty server state → all local messages archived ---

    #[test]
    fn empty_server_state_archives_all_local() {
        let server = vec![];
        let local = vec![
            local_msg("fp1", "INBOX", "/mail/INBOX/fp1.eml"),
            local_msg("fp2", "Sent", "/mail/Sent/fp2.eml"),
        ];

        let actions = plan_sync(&server, &local);

        assert_eq!(count_actions(&actions, "Archive"), 2);
        assert_eq!(count_actions(&actions, "Download"), 0);
    }

    // --- Empty local state → all server messages downloaded ---

    #[test]
    fn empty_local_state_downloads_all_server() {
        let server = vec![server_msg("fp1", "INBOX", 1), server_msg("fp2", "Sent", 2)];
        let local = vec![];

        let actions = plan_sync(&server, &local);

        assert_eq!(count_actions(&actions, "Download"), 2);
        assert_eq!(count_actions(&actions, "Archive"), 0);
    }

    // --- No changes → empty plan (all skips) ---

    #[test]
    fn no_changes_produces_all_skips() {
        let server = vec![server_msg("fp1", "INBOX", 1), server_msg("fp2", "Sent", 2)];
        let local = vec![
            local_msg("fp1", "INBOX", "/mail/INBOX/fp1.eml"),
            local_msg("fp2", "Sent", "/mail/Sent/fp2.eml"),
        ];

        let actions = plan_sync(&server, &local);

        assert_eq!(count_actions(&actions, "Skip"), 2);
        assert_eq!(count_actions(&actions, "Download"), 0);
        assert_eq!(count_actions(&actions, "Move"), 0);
        assert_eq!(count_actions(&actions, "Copy"), 0);
        assert_eq!(count_actions(&actions, "Archive"), 0);
    }

    // --- Message moved to multiple new folders ---

    #[test]
    fn message_moved_to_multiple_new_folders() {
        // Local has fp1 in INBOX; server has fp1 in Archive and Important (not INBOX)
        let server = vec![
            server_msg("fp1", "Archive", 10),
            server_msg("fp1", "Important", 20),
        ];
        let local = vec![local_msg("fp1", "INBOX", "/mail/INBOX/fp1.eml")];

        let actions = plan_sync(&server, &local);

        // No common folders → copy to first new folder, move last
        assert_eq!(count_actions(&actions, "Copy"), 1);
        assert_eq!(count_actions(&actions, "Move"), 1);
        assert_eq!(count_actions(&actions, "Skip"), 0);

        // Copy comes before Move so the source file still exists
        let copy = find_action(&actions, "Copy", "fp1").unwrap();
        let move_action = find_action(&actions, "Move", "fp1").unwrap();

        // Both reference the original source folder (INBOX) where the file
        // actually exists at execution time
        assert_eq!(
            *copy,
            SyncAction::Copy {
                fingerprint: "fp1".to_owned(),
                from_folder: "INBOX".to_owned(),
                to_folder: "Archive".to_owned(),
                local_path: PathBuf::from("/mail/INBOX/fp1.eml"),
            }
        );
        assert_eq!(
            *move_action,
            SyncAction::Move {
                fingerprint: "fp1".to_owned(),
                from_folder: "INBOX".to_owned(),
                to_folder: "Important".to_owned(),
                local_path: PathBuf::from("/mail/INBOX/fp1.eml"),
            }
        );

        // Verify ordering: Copy appears before Move in the actions list
        let copy_idx = actions
            .iter()
            .position(|a| matches!(a, SyncAction::Copy { .. }))
            .unwrap();
        let move_idx = actions
            .iter()
            .position(|a| matches!(a, SyncAction::Move { .. }))
            .unwrap();
        assert!(
            copy_idx < move_idx,
            "Copy must precede Move so the source file still exists"
        );
    }

    // --- Both empty → no actions ---

    #[test]
    fn both_empty_produces_no_actions() {
        let actions = plan_sync(&[], &[]);
        assert!(actions.is_empty());
    }

    // --- Message in multiple local folders, subset on server ---

    #[test]
    fn message_in_multiple_local_folders_subset_on_server() {
        // Local has fp1 in INBOX and Sent; server only has fp1 in INBOX
        let server = vec![server_msg("fp1", "INBOX", 1)];
        let local = vec![
            local_msg("fp1", "INBOX", "/mail/INBOX/fp1.eml"),
            local_msg("fp1", "Sent", "/mail/Sent/fp1.eml"),
        ];

        let actions = plan_sync(&server, &local);

        // INBOX is common → Skip
        assert_eq!(count_actions(&actions, "Skip"), 1);
        // Sent is only locally → no archive because we only archive if
        // the fingerprint is completely absent from the server
        assert_eq!(count_actions(&actions, "Archive"), 0);
    }

    // --- Multiple distinct messages ---

    #[test]
    fn multiple_distinct_messages_correct_actions() {
        let server = vec![
            server_msg("fp1", "INBOX", 1),   // existing
            server_msg("fp2", "INBOX", 2),   // new
            server_msg("fp3", "Archive", 5), // moved from Sent
        ];
        let local = vec![
            local_msg("fp1", "INBOX", "/mail/INBOX/fp1.eml"),
            local_msg("fp3", "Sent", "/mail/Sent/fp3.eml"),
            local_msg("fp4", "INBOX", "/mail/INBOX/fp4.eml"), // deleted from server
        ];

        let actions = plan_sync(&server, &local);

        // fp1: INBOX → INBOX → Skip
        assert!(find_action(&actions, "Skip", "fp1").is_some());
        // fp2: new → Download
        assert!(find_action(&actions, "Download", "fp2").is_some());
        // fp3: Sent → Archive → Move
        assert!(find_action(&actions, "Move", "fp3").is_some());
        // fp4: local only → Archive
        assert!(find_action(&actions, "Archive", "fp4").is_some());
    }

    // --- Download includes correct UID ---

    #[test]
    fn download_includes_correct_uid() {
        let server = vec![server_msg("fp1", "INBOX", 42)];
        let local = vec![];

        let actions = plan_sync(&server, &local);

        match &actions[0] {
            SyncAction::Download { uid, .. } => assert_eq!(*uid, 42),
            _ => panic!("expected Download"),
        }
    }

    // --- New message in multiple server folders → multiple downloads ---

    #[test]
    fn new_message_in_multiple_server_folders_downloads_all() {
        let server = vec![
            server_msg("fp1", "INBOX", 1),
            server_msg("fp1", "Important", 5),
        ];
        let local = vec![];

        let actions = plan_sync(&server, &local);

        assert_eq!(count_actions(&actions, "Download"), 2);
    }

    // --- UIDVALIDITY recovery tests ---

    #[test]
    fn uid_validity_recovery_all_messages_match() {
        let server = vec![
            server_msg("fp1", "INBOX", 100),
            server_msg("fp2", "INBOX", 200),
            server_msg("fp3", "INBOX", 300),
        ];
        let local = vec![
            local_msg("fp1", "INBOX", "/mail/INBOX/fp1.eml"),
            local_msg("fp2", "INBOX", "/mail/INBOX/fp2.eml"),
            local_msg("fp3", "INBOX", "/mail/INBOX/fp3.eml"),
        ];

        let recovery = plan_uid_validity_recovery(&server, &local);

        assert_eq!(recovery.matched.len(), 3);
        assert!(recovery.unmatched_server.is_empty());
        assert_eq!(recovery.max_uid, 300);

        // Verify the matched UIDs are correct
        assert!(recovery.matched.contains(&("fp1".to_owned(), 100)));
        assert!(recovery.matched.contains(&("fp2".to_owned(), 200)));
        assert!(recovery.matched.contains(&("fp3".to_owned(), 300)));
    }

    #[test]
    fn uid_validity_recovery_some_matches_some_new() {
        let server = vec![
            server_msg("fp1", "INBOX", 100),
            server_msg("fp2", "INBOX", 200),
            server_msg("fp_new", "INBOX", 300),
        ];
        let local = vec![
            local_msg("fp1", "INBOX", "/mail/INBOX/fp1.eml"),
            local_msg("fp2", "INBOX", "/mail/INBOX/fp2.eml"),
        ];

        let recovery = plan_uid_validity_recovery(&server, &local);

        assert_eq!(recovery.matched.len(), 2);
        assert_eq!(recovery.unmatched_server.len(), 1);
        assert_eq!(recovery.unmatched_server[0].fingerprint, "fp_new");
        assert_eq!(recovery.unmatched_server[0].uid, 300);
        assert_eq!(recovery.max_uid, 300);
    }

    #[test]
    fn uid_validity_recovery_no_matches() {
        let server = vec![
            server_msg("fp_new1", "INBOX", 100),
            server_msg("fp_new2", "INBOX", 200),
        ];
        let local = vec![
            local_msg("fp_old1", "INBOX", "/mail/INBOX/fp_old1.eml"),
            local_msg("fp_old2", "INBOX", "/mail/INBOX/fp_old2.eml"),
        ];

        let recovery = plan_uid_validity_recovery(&server, &local);

        assert!(recovery.matched.is_empty());
        assert_eq!(recovery.unmatched_server.len(), 2);
        assert_eq!(recovery.max_uid, 200);
    }

    #[test]
    fn uid_validity_recovery_empty_server() {
        let server = vec![];
        let local = vec![
            local_msg("fp1", "INBOX", "/mail/INBOX/fp1.eml"),
            local_msg("fp2", "INBOX", "/mail/INBOX/fp2.eml"),
        ];

        let recovery = plan_uid_validity_recovery(&server, &local);

        assert!(recovery.matched.is_empty());
        assert!(recovery.unmatched_server.is_empty());
        assert_eq!(recovery.max_uid, 0);
    }

    #[test]
    fn uid_validity_recovery_empty_both() {
        let recovery = plan_uid_validity_recovery(&[], &[]);

        assert!(recovery.matched.is_empty());
        assert!(recovery.unmatched_server.is_empty());
        assert_eq!(recovery.max_uid, 0);
    }

    #[test]
    fn uid_validity_recovery_empty_local() {
        let server = vec![
            server_msg("fp1", "INBOX", 100),
            server_msg("fp2", "INBOX", 200),
        ];

        let recovery = plan_uid_validity_recovery(&server, &[]);

        assert!(recovery.matched.is_empty());
        assert_eq!(recovery.unmatched_server.len(), 2);
        assert_eq!(recovery.max_uid, 200);
    }
}
