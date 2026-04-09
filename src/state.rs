//! SQLite-backed state database for tracking message locations and sync progress.
//!
//! The [`StateDb`] trait defines the contract for all state persistence operations.
//! [`SqliteStateDb`] is the production implementation backed by a SQLite database
//! with WAL mode enabled for crash safety. All queries use parameterized statements
//! to prevent SQL injection.

use std::path::Path;

use rusqlite::{Connection, OpenFlags, params};

use crate::error::StateError;

// ---------------------------------------------------------------------------
// Record types
// ---------------------------------------------------------------------------

/// A stored message record keyed by composite fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRecord {
    /// Composite fingerprint (primary key).
    pub fingerprint: String,
    /// RFC 2822 `Message-ID` header, if present.
    pub message_id: Option<String>,
    /// `Subject` header value.
    pub subject: String,
    /// `From` header value.
    pub from: String,
    /// `Date` header value.
    pub date: String,
    /// Number of MIME attachments.
    pub attachment_count: u32,
    /// SHA-256 hash of the MIME body structure tree.
    pub body_structure_hash: String,
    /// ISO 8601 timestamp of when the message was first seen.
    pub first_seen: String,
}

/// A location record mapping a message to a folder and local file path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationRecord {
    /// Account name this location belongs to.
    pub account_name: String,
    /// Composite fingerprint identifying the message.
    pub fingerprint: String,
    /// IMAP folder name.
    pub folder: String,
    /// Local filesystem path to the message file.
    pub local_path: String,
    /// IMAP UID of the message, if known.
    pub imap_uid: Option<u32>,
    /// ISO 8601 timestamp of when the message was last seen on the server.
    pub last_seen_on_server: String,
}

/// A folder record tracking IMAP UID validity and sync progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderRecord {
    /// Account name this folder belongs to.
    pub account_name: String,
    /// Full folder name (e.g., "INBOX", "Archive/2024").
    pub folder_name: String,
    /// IMAP `UIDVALIDITY` value, if known.
    pub uid_validity: Option<u32>,
    /// Highest UID that has been fully synced.
    pub highest_synced_uid: Option<u32>,
}

// ---------------------------------------------------------------------------
// Trait definition
// ---------------------------------------------------------------------------

/// Contract for state persistence operations.
///
/// Implementations must ensure that all mutations are atomic and that
/// concurrent reads are safe. The sync engine depends only on this trait,
/// enabling in-memory test doubles.
pub trait StateDb {
    /// Retrieve a message record by its fingerprint.
    fn get_message(&self, fingerprint: &str) -> Result<Option<MessageRecord>, StateError>;

    /// Retrieve all location records for a given fingerprint within an account.
    fn get_locations(
        &self,
        account_name: &str,
        fingerprint: &str,
    ) -> Result<Vec<LocationRecord>, StateError>;

    /// Retrieve all location records for a given account.
    fn get_all_locations_for_account(
        &self,
        account_name: &str,
    ) -> Result<Vec<LocationRecord>, StateError>;

    /// Insert a new message record. Fails silently if the fingerprint already exists.
    fn insert_message(&self, record: &MessageRecord) -> Result<(), StateError>;

    /// Insert or update a location record (composite key: account_name + fingerprint + folder).
    fn upsert_location(&self, location: &LocationRecord) -> Result<(), StateError>;

    /// Update only the `imap_uid` for an existing location record.
    ///
    /// Used during UIDVALIDITY recovery to re-map a message to its new UID
    /// without re-downloading the content.
    fn update_location_uid(
        &self,
        account_name: &str,
        fingerprint: &str,
        folder: &str,
        new_uid: u32,
    ) -> Result<(), StateError>;

    /// Remove a location record for a given account, fingerprint, and folder.
    fn remove_location(
        &self,
        account_name: &str,
        fingerprint: &str,
        folder: &str,
    ) -> Result<(), StateError>;

    /// Update the local file path for an existing location record.
    fn update_location_path(
        &self,
        account_name: &str,
        fingerprint: &str,
        folder: &str,
        new_path: &str,
    ) -> Result<(), StateError>;

    /// Retrieve a folder record by account name and folder name.
    fn get_folder(
        &self,
        account_name: &str,
        folder_name: &str,
    ) -> Result<Option<FolderRecord>, StateError>;

    /// Insert or update a folder record.
    fn upsert_folder(&self, folder: &FolderRecord) -> Result<(), StateError>;

    /// Retrieve all folder records for a specific account.
    fn get_folders_for_account(&self, account_name: &str) -> Result<Vec<FolderRecord>, StateError>;

    /// Retrieve the timestamp of the last successful sync for an account.
    fn get_last_successful_sync(&self, account: &str) -> Result<Option<String>, StateError>;

    /// Record the timestamp of the last successful sync for an account.
    fn set_last_successful_sync(&self, account: &str, timestamp: &str) -> Result<(), StateError>;

    /// Execute a closure within a database transaction.
    ///
    /// All state mutations performed by the closure are committed atomically.
    /// If the closure returns an error, all mutations are rolled back.
    ///
    /// This method requires `Self: Sized` and cannot be called through trait
    /// objects. Callers that need dynamic dispatch should use concrete types.
    fn execute_in_transaction<F, T>(&self, f: F) -> Result<T, StateError>
    where
        Self: Sized,
        F: FnOnce(&Self) -> Result<T, StateError>;
}

// ---------------------------------------------------------------------------
// SQLite implementation
// ---------------------------------------------------------------------------

/// Production state database backed by SQLite with WAL mode.
pub struct SqliteStateDb {
    /// The underlying SQLite connection.
    conn: Connection,
}

impl SqliteStateDb {
    /// Open or create a SQLite state database at the given path.
    ///
    /// Enables WAL mode for crash safety, creates all tables if they do not
    /// exist, and sets the database file permissions to owner-only (0600)
    /// on Unix systems.
    pub fn open(path: &Path) -> Result<Self, StateError> {
        let conn = open_connection(path)?;
        configure_connection(&conn)?;
        create_schema(&conn)?;
        set_file_permissions(path)?;
        Ok(Self { conn })
    }

    /// Open an in-memory SQLite database (for testing).
    #[cfg(test)]
    pub(crate) fn open_in_memory() -> Result<Self, StateError> {
        let conn = Connection::open_in_memory().map_err(|e| StateError::Open {
            path: ":memory:".to_owned(),
            reason: e.to_string(),
        })?;
        configure_connection(&conn)?;
        create_schema(&conn)?;
        Ok(Self { conn })
    }

    /// Return a reference to the underlying connection (for recovery checks).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}

impl StateDb for SqliteStateDb {
    fn get_message(&self, fingerprint: &str) -> Result<Option<MessageRecord>, StateError> {
        query_message(&self.conn, fingerprint)
    }

    fn get_locations(
        &self,
        account_name: &str,
        fingerprint: &str,
    ) -> Result<Vec<LocationRecord>, StateError> {
        query_locations(&self.conn, account_name, fingerprint)
    }

    fn get_all_locations_for_account(
        &self,
        account_name: &str,
    ) -> Result<Vec<LocationRecord>, StateError> {
        query_all_locations_for_account(&self.conn, account_name)
    }

    fn insert_message(&self, record: &MessageRecord) -> Result<(), StateError> {
        execute_insert_message(&self.conn, record)
    }

    fn upsert_location(&self, location: &LocationRecord) -> Result<(), StateError> {
        execute_upsert_location(&self.conn, location)
    }

    fn update_location_uid(
        &self,
        account_name: &str,
        fingerprint: &str,
        folder: &str,
        new_uid: u32,
    ) -> Result<(), StateError> {
        execute_update_location_uid(&self.conn, account_name, fingerprint, folder, new_uid)
    }

    fn remove_location(
        &self,
        account_name: &str,
        fingerprint: &str,
        folder: &str,
    ) -> Result<(), StateError> {
        execute_remove_location(&self.conn, account_name, fingerprint, folder)
    }

    fn update_location_path(
        &self,
        account_name: &str,
        fingerprint: &str,
        folder: &str,
        new_path: &str,
    ) -> Result<(), StateError> {
        execute_update_location_path(&self.conn, account_name, fingerprint, folder, new_path)
    }

    fn get_folder(
        &self,
        account_name: &str,
        folder_name: &str,
    ) -> Result<Option<FolderRecord>, StateError> {
        query_folder(&self.conn, account_name, folder_name)
    }

    fn upsert_folder(&self, folder: &FolderRecord) -> Result<(), StateError> {
        execute_upsert_folder(&self.conn, folder)
    }

    fn get_folders_for_account(&self, account_name: &str) -> Result<Vec<FolderRecord>, StateError> {
        query_folders_for_account(&self.conn, account_name)
    }

    fn get_last_successful_sync(&self, account: &str) -> Result<Option<String>, StateError> {
        query_last_successful_sync(&self.conn, account)
    }

    fn set_last_successful_sync(&self, account: &str, timestamp: &str) -> Result<(), StateError> {
        execute_set_last_successful_sync(&self.conn, account, timestamp)
    }

    fn execute_in_transaction<F, T>(&self, f: F) -> Result<T, StateError>
    where
        F: FnOnce(&Self) -> Result<T, StateError>,
    {
        self.conn
            .execute_batch("BEGIN")
            .map_err(|e| StateError::Transaction {
                reason: format!("failed to begin transaction: {e}"),
            })?;

        match f(self) {
            Ok(value) => {
                self.conn
                    .execute_batch("COMMIT")
                    .map_err(|e| StateError::Transaction {
                        reason: format!("failed to commit transaction: {e}"),
                    })?;
                Ok(value)
            }
            Err(e) => {
                if let Err(rollback_err) = self.conn.execute_batch("ROLLBACK") {
                    return Err(StateError::Transaction {
                        reason: format!(
                            "failed to rollback transaction: {rollback_err} (original error: {e})"
                        ),
                    });
                }
                Err(e)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers — connection setup
// ---------------------------------------------------------------------------

/// Open a SQLite connection with restricted flags.
fn open_connection(path: &Path) -> Result<Connection, StateError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;

    Connection::open_with_flags(path, flags).map_err(|e| StateError::Open {
        path: path.display().to_string(),
        reason: e.to_string(),
    })
}

/// Enable WAL mode and set pragmas for crash safety.
fn configure_connection(conn: &Connection) -> Result<(), StateError> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;",
    )
    .map_err(|e| StateError::Migration {
        reason: format!("failed to configure connection: {e}"),
    })
}

/// Create all tables if they do not exist.
fn create_schema(conn: &Connection) -> Result<(), StateError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS messages (
            fingerprint        TEXT PRIMARY KEY NOT NULL,
            message_id         TEXT,
            subject            TEXT NOT NULL,
            from_addr          TEXT NOT NULL,
            date               TEXT NOT NULL,
            attachment_count   INTEGER NOT NULL,
            body_structure_hash TEXT NOT NULL,
            first_seen         TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_messages_message_id
            ON messages(message_id);

        CREATE TABLE IF NOT EXISTS locations (
            account_name       TEXT NOT NULL,
            fingerprint        TEXT NOT NULL,
            folder             TEXT NOT NULL,
            local_path         TEXT NOT NULL,
            imap_uid           INTEGER,
            last_seen_on_server TEXT NOT NULL,
            PRIMARY KEY (account_name, fingerprint, folder),
            FOREIGN KEY (fingerprint) REFERENCES messages(fingerprint)
        );

        CREATE TABLE IF NOT EXISTS folders (
            account_name       TEXT NOT NULL,
            folder_name        TEXT NOT NULL,
            uid_validity       INTEGER,
            highest_synced_uid INTEGER,
            PRIMARY KEY (account_name, folder_name)
        );

        CREATE TABLE IF NOT EXISTS sync_log (
            account_name       TEXT PRIMARY KEY NOT NULL,
            last_successful_sync TEXT NOT NULL
        );",
    )
    .map_err(|e| StateError::Migration {
        reason: format!("failed to create schema: {e}"),
    })
}

/// Set database file permissions to owner-only on Unix.
#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<(), StateError> {
    use std::os::unix::fs::PermissionsExt;

    /// File permission mode: owner read + write only (0600).
    const OWNER_READ_WRITE: u32 = 0o600;

    let metadata = std::fs::metadata(path).map_err(|e| StateError::Open {
        path: path.display().to_string(),
        reason: format!("failed to read metadata for permissions: {e}"),
    })?;

    let mut perms = metadata.permissions();
    perms.set_mode(OWNER_READ_WRITE);

    std::fs::set_permissions(path, perms).map_err(|e| StateError::Open {
        path: path.display().to_string(),
        reason: format!("failed to set file permissions: {e}"),
    })
}

/// No-op on non-Unix platforms.
#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> Result<(), StateError> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers — queries
// ---------------------------------------------------------------------------

/// Query a single message by fingerprint.
fn query_message(
    conn: &Connection,
    fingerprint: &str,
) -> Result<Option<MessageRecord>, StateError> {
    let mut stmt = conn
        .prepare(
            "SELECT fingerprint, message_id, subject, from_addr, date,
                    attachment_count, body_structure_hash, first_seen
             FROM messages WHERE fingerprint = ?1",
        )
        .map_err(|e| StateError::Query {
            reason: format!("failed to prepare get_message: {e}"),
        })?;

    let mut rows = stmt
        .query_map(params![fingerprint], row_to_message_record)
        .map_err(|e| StateError::Query {
            reason: format!("failed to execute get_message: {e}"),
        })?;

    match rows.next() {
        Some(row) => {
            let record = row.map_err(|e| StateError::Query {
                reason: format!("failed to read message row: {e}"),
            })?;
            Ok(Some(record))
        }
        None => Ok(None),
    }
}

/// Map a SQLite row to a `MessageRecord`.
fn row_to_message_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<MessageRecord> {
    Ok(MessageRecord {
        fingerprint: row.get(0)?,
        message_id: row.get(1)?,
        subject: row.get(2)?,
        from: row.get(3)?,
        date: row.get(4)?,
        attachment_count: row.get(5)?,
        body_structure_hash: row.get(6)?,
        first_seen: row.get(7)?,
    })
}

/// Query all location records for a fingerprint within an account.
fn query_locations(
    conn: &Connection,
    account_name: &str,
    fingerprint: &str,
) -> Result<Vec<LocationRecord>, StateError> {
    let mut stmt = conn
        .prepare(
            "SELECT account_name, fingerprint, folder, local_path, imap_uid, last_seen_on_server
             FROM locations WHERE account_name = ?1 AND fingerprint = ?2",
        )
        .map_err(|e| StateError::Query {
            reason: format!("failed to prepare get_locations: {e}"),
        })?;

    let rows = stmt
        .query_map(params![account_name, fingerprint], row_to_location_record)
        .map_err(|e| StateError::Query {
            reason: format!("failed to execute get_locations: {e}"),
        })?;

    collect_rows(rows, "get_locations")
}

/// Query all location records for a specific account.
fn query_all_locations_for_account(
    conn: &Connection,
    account_name: &str,
) -> Result<Vec<LocationRecord>, StateError> {
    let mut stmt = conn
        .prepare(
            "SELECT account_name, fingerprint, folder, local_path, imap_uid, last_seen_on_server
             FROM locations WHERE account_name = ?1",
        )
        .map_err(|e| StateError::Query {
            reason: format!("failed to prepare get_all_locations_for_account: {e}"),
        })?;

    let rows = stmt
        .query_map(params![account_name], row_to_location_record)
        .map_err(|e| StateError::Query {
            reason: format!("failed to execute get_all_locations_for_account: {e}"),
        })?;

    collect_rows(rows, "get_all_locations_for_account")
}

/// Map a SQLite row to a `LocationRecord`.
fn row_to_location_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<LocationRecord> {
    Ok(LocationRecord {
        account_name: row.get(0)?,
        fingerprint: row.get(1)?,
        folder: row.get(2)?,
        local_path: row.get(3)?,
        imap_uid: row.get(4)?,
        last_seen_on_server: row.get(5)?,
    })
}

/// Collect `rusqlite::Rows` into a `Vec`, converting errors.
fn collect_rows<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>>,
    context: &str,
) -> Result<Vec<T>, StateError> {
    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| StateError::Query {
            reason: format!("failed to read row in {context}: {e}"),
        })?);
    }
    Ok(result)
}

/// Query a folder record by account name and folder name.
fn query_folder(
    conn: &Connection,
    account_name: &str,
    folder_name: &str,
) -> Result<Option<FolderRecord>, StateError> {
    let mut stmt = conn
        .prepare(
            "SELECT account_name, folder_name, uid_validity, highest_synced_uid
             FROM folders WHERE account_name = ?1 AND folder_name = ?2",
        )
        .map_err(|e| StateError::Query {
            reason: format!("failed to prepare get_folder: {e}"),
        })?;

    let mut rows = stmt
        .query_map(params![account_name, folder_name], row_to_folder_record)
        .map_err(|e| StateError::Query {
            reason: format!("failed to execute get_folder: {e}"),
        })?;

    match rows.next() {
        Some(row) => {
            let record = row.map_err(|e| StateError::Query {
                reason: format!("failed to read folder row: {e}"),
            })?;
            Ok(Some(record))
        }
        None => Ok(None),
    }
}

/// Map a SQLite row to a `FolderRecord`.
fn row_to_folder_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<FolderRecord> {
    Ok(FolderRecord {
        account_name: row.get(0)?,
        folder_name: row.get(1)?,
        uid_validity: row.get(2)?,
        highest_synced_uid: row.get(3)?,
    })
}

/// Query all folder records for a specific account.
fn query_folders_for_account(
    conn: &Connection,
    account_name: &str,
) -> Result<Vec<FolderRecord>, StateError> {
    let mut stmt = conn
        .prepare(
            "SELECT account_name, folder_name, uid_validity, highest_synced_uid
             FROM folders WHERE account_name = ?1",
        )
        .map_err(|e| StateError::Query {
            reason: format!("failed to prepare get_folders_for_account: {e}"),
        })?;

    let rows = stmt
        .query_map(params![account_name], row_to_folder_record)
        .map_err(|e| StateError::Query {
            reason: format!("failed to execute get_folders_for_account: {e}"),
        })?;

    collect_rows(rows, "get_folders_for_account")
}

/// Query the last successful sync timestamp for an account.
fn query_last_successful_sync(
    conn: &Connection,
    account: &str,
) -> Result<Option<String>, StateError> {
    let mut stmt = conn
        .prepare("SELECT last_successful_sync FROM sync_log WHERE account_name = ?1")
        .map_err(|e| StateError::Query {
            reason: format!("failed to prepare get_last_successful_sync: {e}"),
        })?;

    let mut rows = stmt
        .query_map(params![account], |row| row.get::<_, String>(0))
        .map_err(|e| StateError::Query {
            reason: format!("failed to execute get_last_successful_sync: {e}"),
        })?;

    match rows.next() {
        Some(row) => {
            let ts = row.map_err(|e| StateError::Query {
                reason: format!("failed to read sync_log row: {e}"),
            })?;
            Ok(Some(ts))
        }
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Private helpers — mutations
// ---------------------------------------------------------------------------

/// Insert a message record, ignoring conflicts on the primary key.
fn execute_insert_message(conn: &Connection, record: &MessageRecord) -> Result<(), StateError> {
    conn.execute(
        "INSERT OR IGNORE INTO messages
            (fingerprint, message_id, subject, from_addr, date,
             attachment_count, body_structure_hash, first_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            record.fingerprint,
            record.message_id,
            record.subject,
            record.from,
            record.date,
            record.attachment_count,
            record.body_structure_hash,
            record.first_seen,
        ],
    )
    .map_err(|e| StateError::Query {
        reason: format!("failed to insert message: {e}"),
    })?;
    Ok(())
}

/// Insert or update a location record.
fn execute_upsert_location(conn: &Connection, loc: &LocationRecord) -> Result<(), StateError> {
    conn.execute(
        "INSERT INTO locations
            (account_name, fingerprint, folder, local_path, imap_uid, last_seen_on_server)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(account_name, fingerprint, folder) DO UPDATE SET
            local_path = excluded.local_path,
            imap_uid = excluded.imap_uid,
            last_seen_on_server = excluded.last_seen_on_server",
        params![
            loc.account_name,
            loc.fingerprint,
            loc.folder,
            loc.local_path,
            loc.imap_uid,
            loc.last_seen_on_server,
        ],
    )
    .map_err(|e| StateError::Query {
        reason: format!("failed to upsert location: {e}"),
    })?;
    Ok(())
}

/// Remove a location record.
fn execute_remove_location(
    conn: &Connection,
    account_name: &str,
    fingerprint: &str,
    folder: &str,
) -> Result<(), StateError> {
    conn.execute(
        "DELETE FROM locations WHERE account_name = ?1 AND fingerprint = ?2 AND folder = ?3",
        params![account_name, fingerprint, folder],
    )
    .map_err(|e| StateError::Query {
        reason: format!("failed to remove location: {e}"),
    })?;
    Ok(())
}

/// Update only the IMAP UID for a location record.
fn execute_update_location_uid(
    conn: &Connection,
    account_name: &str,
    fingerprint: &str,
    folder: &str,
    new_uid: u32,
) -> Result<(), StateError> {
    conn.execute(
        "UPDATE locations SET imap_uid = ?1
         WHERE account_name = ?2 AND fingerprint = ?3 AND folder = ?4",
        params![new_uid, account_name, fingerprint, folder],
    )
    .map_err(|e| StateError::Query {
        reason: format!("failed to update location UID: {e}"),
    })?;
    Ok(())
}

/// Update the local path for a location record.
fn execute_update_location_path(
    conn: &Connection,
    account_name: &str,
    fingerprint: &str,
    folder: &str,
    new_path: &str,
) -> Result<(), StateError> {
    conn.execute(
        "UPDATE locations SET local_path = ?1
         WHERE account_name = ?2 AND fingerprint = ?3 AND folder = ?4",
        params![new_path, account_name, fingerprint, folder],
    )
    .map_err(|e| StateError::Query {
        reason: format!("failed to update location path: {e}"),
    })?;
    Ok(())
}

/// Insert or update a folder record.
fn execute_upsert_folder(conn: &Connection, folder: &FolderRecord) -> Result<(), StateError> {
    conn.execute(
        "INSERT INTO folders (account_name, folder_name, uid_validity, highest_synced_uid)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(account_name, folder_name) DO UPDATE SET
            uid_validity = excluded.uid_validity,
            highest_synced_uid = excluded.highest_synced_uid",
        params![
            folder.account_name,
            folder.folder_name,
            folder.uid_validity,
            folder.highest_synced_uid
        ],
    )
    .map_err(|e| StateError::Query {
        reason: format!("failed to upsert folder: {e}"),
    })?;
    Ok(())
}

/// Insert or update the last successful sync timestamp.
fn execute_set_last_successful_sync(
    conn: &Connection,
    account: &str,
    timestamp: &str,
) -> Result<(), StateError> {
    conn.execute(
        "INSERT INTO sync_log (account_name, last_successful_sync)
         VALUES (?1, ?2)
         ON CONFLICT(account_name) DO UPDATE SET
            last_successful_sync = excluded.last_successful_sync",
        params![account, timestamp],
    )
    .map_err(|e| StateError::Query {
        reason: format!("failed to set last successful sync: {e}"),
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_db() -> SqliteStateDb {
        SqliteStateDb::open_in_memory().unwrap()
    }

    fn sample_message(fingerprint: &str) -> MessageRecord {
        MessageRecord {
            fingerprint: fingerprint.to_owned(),
            message_id: Some("<test@example.com>".to_owned()),
            subject: "Test Subject".to_owned(),
            from: "alice@example.com".to_owned(),
            date: "2024-01-15T10:30:00Z".to_owned(),
            attachment_count: 0,
            body_structure_hash: "abc123".to_owned(),
            first_seen: "2024-01-15T10:30:00Z".to_owned(),
        }
    }

    /// Default test account name used across state tests.
    const TEST_ACCOUNT: &str = "test-account";

    fn sample_location(fingerprint: &str, folder: &str) -> LocationRecord {
        LocationRecord {
            account_name: TEST_ACCOUNT.to_owned(),
            fingerprint: fingerprint.to_owned(),
            folder: folder.to_owned(),
            local_path: format!("/mail/{folder}/{fingerprint}.eml"),
            imap_uid: Some(42),
            last_seen_on_server: "2024-01-15T10:30:00Z".to_owned(),
        }
    }

    fn sample_folder(name: &str) -> FolderRecord {
        FolderRecord {
            account_name: TEST_ACCOUNT.to_owned(),
            folder_name: name.to_owned(),
            uid_validity: Some(12345),
            highest_synced_uid: Some(100),
        }
    }

    // --- Message CRUD ---

    #[test]
    fn insert_and_retrieve_message() {
        let db = open_test_db();
        let msg = sample_message("fp1");
        db.insert_message(&msg).unwrap();

        let retrieved = db.get_message("fp1").unwrap().unwrap();
        assert_eq!(retrieved, msg);
    }

    #[test]
    fn get_nonexistent_message_returns_none() {
        let db = open_test_db();
        let result = db.get_message("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn insert_duplicate_message_is_ignored() {
        let db = open_test_db();
        let msg = sample_message("fp1");
        db.insert_message(&msg).unwrap();

        let mut msg2 = sample_message("fp1");
        msg2.subject = "Different Subject".to_owned();
        db.insert_message(&msg2).unwrap();

        let retrieved = db.get_message("fp1").unwrap().unwrap();
        assert_eq!(retrieved.subject, "Test Subject");
    }

    #[test]
    fn insert_message_with_null_message_id() {
        let db = open_test_db();
        let mut msg = sample_message("fp_null_mid");
        msg.message_id = None;
        db.insert_message(&msg).unwrap();

        let retrieved = db.get_message("fp_null_mid").unwrap().unwrap();
        assert!(retrieved.message_id.is_none());
    }

    // --- Location CRUD ---

    #[test]
    fn upsert_and_retrieve_location() {
        let db = open_test_db();
        db.insert_message(&sample_message("fp1")).unwrap();

        let loc = sample_location("fp1", "INBOX");
        db.upsert_location(&loc).unwrap();

        let locations = db.get_locations(TEST_ACCOUNT, "fp1").unwrap();
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0], loc);
    }

    #[test]
    fn upsert_location_updates_existing() {
        let db = open_test_db();
        db.insert_message(&sample_message("fp1")).unwrap();

        let loc = sample_location("fp1", "INBOX");
        db.upsert_location(&loc).unwrap();

        let mut updated = loc.clone();
        updated.local_path = "/mail/INBOX/fp1_moved.eml".to_owned();
        updated.imap_uid = Some(99);
        db.upsert_location(&updated).unwrap();

        let locations = db.get_locations(TEST_ACCOUNT, "fp1").unwrap();
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].local_path, "/mail/INBOX/fp1_moved.eml");
        assert_eq!(locations[0].imap_uid, Some(99));
    }

    #[test]
    fn multiple_locations_for_same_fingerprint() {
        let db = open_test_db();
        db.insert_message(&sample_message("fp1")).unwrap();

        db.upsert_location(&sample_location("fp1", "INBOX"))
            .unwrap();
        db.upsert_location(&sample_location("fp1", "Archive"))
            .unwrap();

        let locations = db.get_locations(TEST_ACCOUNT, "fp1").unwrap();
        assert_eq!(locations.len(), 2);
    }

    #[test]
    fn get_all_locations_returns_all() {
        let db = open_test_db();
        db.insert_message(&sample_message("fp1")).unwrap();
        db.insert_message(&sample_message("fp2")).unwrap();

        db.upsert_location(&sample_location("fp1", "INBOX"))
            .unwrap();
        db.upsert_location(&sample_location("fp2", "Sent")).unwrap();

        let all = db.get_all_locations_for_account(TEST_ACCOUNT).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn remove_location() {
        let db = open_test_db();
        db.insert_message(&sample_message("fp1")).unwrap();
        db.upsert_location(&sample_location("fp1", "INBOX"))
            .unwrap();

        db.remove_location(TEST_ACCOUNT, "fp1", "INBOX").unwrap();

        let locations = db.get_locations(TEST_ACCOUNT, "fp1").unwrap();
        assert!(locations.is_empty());
    }

    #[test]
    fn remove_nonexistent_location_is_noop() {
        let db = open_test_db();
        db.remove_location(TEST_ACCOUNT, "nonexistent", "INBOX")
            .unwrap();
    }

    #[test]
    fn update_location_uid() {
        let db = open_test_db();
        db.insert_message(&sample_message("fp1")).unwrap();
        db.upsert_location(&sample_location("fp1", "INBOX"))
            .unwrap();

        db.update_location_uid(TEST_ACCOUNT, "fp1", "INBOX", 999)
            .unwrap();

        let locations = db.get_locations(TEST_ACCOUNT, "fp1").unwrap();
        assert_eq!(locations[0].imap_uid, Some(999));
    }

    #[test]
    fn update_location_uid_nonexistent_is_noop() {
        let db = open_test_db();
        // No error for updating a location that does not exist
        db.update_location_uid(TEST_ACCOUNT, "nonexistent", "INBOX", 123)
            .unwrap();
    }

    #[test]
    fn update_location_path() {
        let db = open_test_db();
        db.insert_message(&sample_message("fp1")).unwrap();
        db.upsert_location(&sample_location("fp1", "INBOX"))
            .unwrap();

        db.update_location_path(TEST_ACCOUNT, "fp1", "INBOX", "/new/path/fp1.eml")
            .unwrap();

        let locations = db.get_locations(TEST_ACCOUNT, "fp1").unwrap();
        assert_eq!(locations[0].local_path, "/new/path/fp1.eml");
    }

    // --- Folder CRUD ---

    #[test]
    fn upsert_and_retrieve_folder() {
        let db = open_test_db();
        let folder = sample_folder("INBOX");
        db.upsert_folder(&folder).unwrap();

        let retrieved = db.get_folder(TEST_ACCOUNT, "INBOX").unwrap().unwrap();
        assert_eq!(retrieved, folder);
    }

    #[test]
    fn get_nonexistent_folder_returns_none() {
        let db = open_test_db();
        let result = db.get_folder(TEST_ACCOUNT, "nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn upsert_folder_updates_existing() {
        let db = open_test_db();
        db.upsert_folder(&sample_folder("INBOX")).unwrap();

        let updated = FolderRecord {
            account_name: TEST_ACCOUNT.to_owned(),
            folder_name: "INBOX".to_owned(),
            uid_validity: Some(99999),
            highest_synced_uid: Some(500),
        };
        db.upsert_folder(&updated).unwrap();

        let retrieved = db.get_folder(TEST_ACCOUNT, "INBOX").unwrap().unwrap();
        assert_eq!(retrieved.uid_validity, Some(99999));
        assert_eq!(retrieved.highest_synced_uid, Some(500));
    }

    #[test]
    fn get_all_folders() {
        let db = open_test_db();
        db.upsert_folder(&sample_folder("INBOX")).unwrap();
        db.upsert_folder(&sample_folder("Sent")).unwrap();
        db.upsert_folder(&sample_folder("Archive")).unwrap();

        let all = db.get_folders_for_account(TEST_ACCOUNT).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn folder_with_null_uid_fields() {
        let db = open_test_db();
        let folder = FolderRecord {
            account_name: TEST_ACCOUNT.to_owned(),
            folder_name: "Drafts".to_owned(),
            uid_validity: None,
            highest_synced_uid: None,
        };
        db.upsert_folder(&folder).unwrap();

        let retrieved = db.get_folder(TEST_ACCOUNT, "Drafts").unwrap().unwrap();
        assert!(retrieved.uid_validity.is_none());
        assert!(retrieved.highest_synced_uid.is_none());
    }

    // --- Account scoping ---

    #[test]
    fn folders_are_scoped_to_account() {
        let db = open_test_db();

        let folder_a = FolderRecord {
            account_name: "account-a".to_owned(),
            folder_name: "INBOX".to_owned(),
            uid_validity: Some(100),
            highest_synced_uid: Some(50),
        };
        let folder_b = FolderRecord {
            account_name: "account-b".to_owned(),
            folder_name: "INBOX".to_owned(),
            uid_validity: Some(200),
            highest_synced_uid: Some(75),
        };

        db.upsert_folder(&folder_a).unwrap();
        db.upsert_folder(&folder_b).unwrap();

        let retrieved_a = db.get_folder("account-a", "INBOX").unwrap().unwrap();
        let retrieved_b = db.get_folder("account-b", "INBOX").unwrap().unwrap();

        assert_eq!(retrieved_a.uid_validity, Some(100));
        assert_eq!(retrieved_b.uid_validity, Some(200));

        let all_a = db.get_folders_for_account("account-a").unwrap();
        assert_eq!(all_a.len(), 1);

        let all_b = db.get_folders_for_account("account-b").unwrap();
        assert_eq!(all_b.len(), 1);
    }

    #[test]
    fn locations_are_scoped_to_account() {
        let db = open_test_db();
        db.insert_message(&sample_message("fp_shared")).unwrap();

        let loc_a = LocationRecord {
            account_name: "account-a".to_owned(),
            fingerprint: "fp_shared".to_owned(),
            folder: "INBOX".to_owned(),
            local_path: "/mail/a/INBOX/fp_shared.eml".to_owned(),
            imap_uid: Some(1),
            last_seen_on_server: "0".to_owned(),
        };
        let loc_b = LocationRecord {
            account_name: "account-b".to_owned(),
            fingerprint: "fp_shared".to_owned(),
            folder: "INBOX".to_owned(),
            local_path: "/mail/b/INBOX/fp_shared.eml".to_owned(),
            imap_uid: Some(2),
            last_seen_on_server: "0".to_owned(),
        };

        db.upsert_location(&loc_a).unwrap();
        db.upsert_location(&loc_b).unwrap();

        let locs_a = db.get_locations("account-a", "fp_shared").unwrap();
        assert_eq!(locs_a.len(), 1);
        assert_eq!(locs_a[0].local_path, "/mail/a/INBOX/fp_shared.eml");

        let locs_b = db.get_locations("account-b", "fp_shared").unwrap();
        assert_eq!(locs_b.len(), 1);
        assert_eq!(locs_b[0].local_path, "/mail/b/INBOX/fp_shared.eml");

        let all_a = db.get_all_locations_for_account("account-a").unwrap();
        assert_eq!(all_a.len(), 1);

        let all_b = db.get_all_locations_for_account("account-b").unwrap();
        assert_eq!(all_b.len(), 1);
    }

    // --- Sync log ---

    #[test]
    fn set_and_get_last_successful_sync() {
        let db = open_test_db();
        db.set_last_successful_sync("personal", "2024-01-15T10:30:00Z")
            .unwrap();

        let ts = db.get_last_successful_sync("personal").unwrap().unwrap();
        assert_eq!(ts, "2024-01-15T10:30:00Z");
    }

    #[test]
    fn get_nonexistent_sync_log_returns_none() {
        let db = open_test_db();
        let result = db.get_last_successful_sync("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn set_sync_log_updates_existing() {
        let db = open_test_db();
        db.set_last_successful_sync("personal", "2024-01-01T00:00:00Z")
            .unwrap();
        db.set_last_successful_sync("personal", "2024-06-15T12:00:00Z")
            .unwrap();

        let ts = db.get_last_successful_sync("personal").unwrap().unwrap();
        assert_eq!(ts, "2024-06-15T12:00:00Z");
    }

    // --- File-based database ---

    #[test]
    fn open_creates_file_database() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test_state.db");

        let db = SqliteStateDb::open(&db_path).unwrap();
        db.insert_message(&sample_message("fp1")).unwrap();

        let retrieved = db.get_message("fp1").unwrap();
        assert!(retrieved.is_some());
        assert!(db_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn database_file_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("perms_test.db");

        let _db = SqliteStateDb::open(&db_path).unwrap();

        let mode = std::fs::metadata(&db_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "database file should have mode 0600");
    }

    // --- Transactions ---

    #[test]
    fn transaction_commits_on_success() {
        let db = open_test_db();
        db.execute_in_transaction(|tx| {
            tx.insert_message(&sample_message("fp_tx"))?;
            tx.upsert_location(&sample_location("fp_tx", "INBOX"))?;
            tx.upsert_folder(&sample_folder("INBOX"))?;
            Ok(())
        })
        .unwrap();

        assert!(db.get_message("fp_tx").unwrap().is_some());
        assert_eq!(db.get_locations(TEST_ACCOUNT, "fp_tx").unwrap().len(), 1);
        assert!(db.get_folder(TEST_ACCOUNT, "INBOX").unwrap().is_some());
    }

    #[test]
    fn transaction_rolls_back_on_error() {
        let db = open_test_db();
        let result: Result<(), StateError> = db.execute_in_transaction(|tx| {
            tx.insert_message(&sample_message("fp_rollback"))?;
            Err(StateError::Query {
                reason: "intentional failure".to_owned(),
            })
        });

        assert!(result.is_err());
        assert!(
            db.get_message("fp_rollback").unwrap().is_none(),
            "message should not exist after rollback"
        );
    }

    #[test]
    fn transaction_returns_value_on_success() {
        let db = open_test_db();
        let value = db
            .execute_in_transaction(|tx| {
                tx.insert_message(&sample_message("fp_ret"))?;
                Ok(42_u64)
            })
            .unwrap();

        assert_eq!(value, 42);
    }
}
