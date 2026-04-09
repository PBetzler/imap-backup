//! Central error types for the email backup tool.
//!
//! All error variants use `thiserror` for ergonomic `Display` and `Error`
//! implementations. Each variant preserves context about where and why the
//! failure occurred.

/// Top-level application error that wraps all domain-specific error types.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Configuration file parsing or validation failure.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// IMAP connection, authentication, or fetch failure.
    #[error(transparent)]
    Imap(#[from] ImapError),

    /// SQLite state database operation failure.
    #[error(transparent)]
    State(#[from] StateError),

    /// Maildir filesystem operation failure.
    #[error(transparent)]
    Storage(#[from] StorageError),

    /// Sync orchestration failure.
    #[error(transparent)]
    Sync(#[from] SyncError),

    /// Fingerprint computation failure.
    #[error(transparent)]
    Fingerprint(#[from] FingerprintError),

    /// Startup recovery failure.
    #[error(transparent)]
    Recovery(#[from] RecoveryError),

    /// Logging subsystem initialization failure.
    #[error("failed to initialize logging: {reason}")]
    LogInit {
        /// Description of the initialization failure.
        reason: String,
    },
}

/// Errors related to configuration file parsing and validation.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The configuration file could not be read from disk.
    #[error("failed to read config file '{path}': {source}")]
    ReadFile {
        /// Path to the configuration file.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// The configuration file contains invalid TOML syntax.
    #[error("failed to parse config file '{path}': {source}")]
    ParseToml {
        /// Path to the configuration file.
        path: String,
        /// Underlying TOML parse error.
        source: toml::de::Error,
    },

    /// A required configuration field is missing.
    #[error("missing required config field: {field}")]
    MissingField {
        /// Name of the missing field.
        field: String,
    },

    /// A configuration value is invalid.
    #[error("invalid config value for '{field}': {reason}")]
    InvalidValue {
        /// Name of the field with the invalid value.
        field: String,
        /// Explanation of why the value is invalid.
        reason: String,
    },

    /// Duplicate account names were found in the configuration.
    #[error("duplicate account name: '{name}'")]
    DuplicateAccount {
        /// The duplicated account name.
        name: String,
    },

    /// Password retrieval failed for an account.
    #[error("failed to resolve password for account '{account}': {reason}")]
    PasswordResolution {
        /// Account name.
        account: String,
        /// Explanation of the failure.
        reason: String,
    },

    /// Password command execution failed.
    #[error("password command failed for account '{account}': {source}")]
    PasswordCommand {
        /// Account name.
        account: String,
        /// Underlying I/O error from command execution.
        source: std::io::Error,
    },

    /// Password file could not be read.
    #[error("failed to read password file '{path}' for account '{account}': {source}")]
    PasswordFile {
        /// Account name.
        account: String,
        /// Path to the password file.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// A configured path does not exist or is not accessible.
    #[error("path validation failed for '{field}': {reason}")]
    PathValidation {
        /// Name of the configuration field containing the path.
        field: String,
        /// Explanation of the validation failure.
        reason: String,
    },
}

/// Errors related to IMAP operations.
#[derive(Debug, thiserror::Error)]
pub enum ImapError {
    /// Failed to establish a TCP connection to the IMAP server.
    #[error("failed to connect to IMAP server '{host}:{port}': {reason}")]
    Connection {
        /// IMAP server hostname.
        host: String,
        /// IMAP server port.
        port: u16,
        /// Description of the connection failure.
        reason: String,
    },

    /// TLS handshake failed.
    #[error("TLS handshake failed for '{host}': {reason}")]
    Tls {
        /// IMAP server hostname.
        host: String,
        /// Description of the TLS failure.
        reason: String,
    },

    /// IMAP authentication failed.
    #[error("authentication failed for '{username}' on '{host}': {reason}")]
    Authentication {
        /// IMAP server hostname.
        host: String,
        /// Username used for authentication.
        username: String,
        /// Description of the authentication failure.
        reason: String,
    },

    /// Failed to list folders on the IMAP server.
    #[error("failed to list folders on '{host}': {reason}")]
    ListFolders {
        /// IMAP server hostname.
        host: String,
        /// Description of the failure.
        reason: String,
    },

    /// Failed to select a folder.
    #[error("failed to select folder '{folder}' on '{host}': {reason}")]
    SelectFolder {
        /// IMAP server hostname.
        host: String,
        /// Folder name.
        folder: String,
        /// Description of the failure.
        reason: String,
    },

    /// Failed to fetch message metadata or body.
    #[error("failed to fetch messages from '{folder}' on '{host}': {reason}")]
    Fetch {
        /// IMAP server hostname.
        host: String,
        /// Folder name.
        folder: String,
        /// Description of the failure.
        reason: String,
    },

    /// IMAP operation timed out.
    #[error("IMAP operation timed out after {timeout_seconds}s on '{host}'")]
    Timeout {
        /// IMAP server hostname.
        host: String,
        /// Timeout duration in seconds.
        timeout_seconds: u64,
    },
}

/// Errors related to the SQLite state database.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// Failed to open or create the SQLite database.
    #[error("failed to open state database '{path}': {reason}")]
    Open {
        /// Path to the database file.
        path: String,
        /// Description of the failure.
        reason: String,
    },

    /// A database query or command failed.
    #[error("state database query failed: {reason}")]
    Query {
        /// Description of the failure.
        reason: String,
    },

    /// A database migration or schema update failed.
    #[error("state database migration failed: {reason}")]
    Migration {
        /// Description of the failure.
        reason: String,
    },

    /// A database transaction failed.
    #[error("state database transaction failed: {reason}")]
    Transaction {
        /// Description of the failure.
        reason: String,
    },
}

/// Errors related to Maildir filesystem operations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Failed to create a directory.
    #[error("failed to create directory '{path}': {source}")]
    CreateDir {
        /// Path to the directory.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Failed to write a message file.
    #[error("failed to write message to '{path}': {source}")]
    WriteFile {
        /// Path to the file.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Failed to move a message file.
    #[error("failed to move message from '{from}' to '{to}': {source}")]
    MoveFile {
        /// Source path.
        from: String,
        /// Destination path.
        to: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Failed to copy a message file.
    #[error("failed to copy message from '{from}' to '{to}': {source}")]
    CopyFile {
        /// Source path.
        from: String,
        /// Destination path.
        to: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Failed to read a message file.
    #[error("failed to read message from '{path}': {source}")]
    ReadFile {
        /// Path to the file.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// The folder name is invalid (contains path traversal or null bytes).
    #[error("invalid folder name '{name}': {reason}")]
    InvalidFolderName {
        /// The invalid folder name.
        name: String,
        /// Explanation of why the name is invalid.
        reason: String,
    },

    /// Failed to sync file to disk.
    #[error("failed to fsync '{path}': {source}")]
    Fsync {
        /// Path to the file.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

/// Errors related to sync orchestration.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// A sync cycle for a specific account failed.
    #[error("sync failed for account '{account}': {reason}")]
    AccountSync {
        /// Account name.
        account: String,
        /// Description of the failure.
        reason: String,
    },

    /// A sync cycle for a specific folder failed.
    #[error("sync failed for folder '{folder}' in account '{account}': {reason}")]
    FolderSync {
        /// Account name.
        account: String,
        /// Folder name.
        folder: String,
        /// Description of the failure.
        reason: String,
    },

    /// The requested account was not found in the configuration.
    #[error("account '{name}' not found in configuration")]
    AccountNotFound {
        /// Account name.
        name: String,
    },
}

/// Errors related to fingerprint computation.
#[derive(Debug, thiserror::Error)]
pub enum FingerprintError {
    /// A required field for fingerprint computation is missing.
    #[error("missing required field '{field}' for fingerprint computation")]
    MissingField {
        /// Name of the missing field.
        field: String,
    },

    /// The fingerprint input data is invalid.
    #[error("invalid fingerprint input for field '{field}': {reason}")]
    InvalidInput {
        /// Name of the field with invalid data.
        field: String,
        /// Explanation of why the data is invalid.
        reason: String,
    },
}

/// Errors related to startup recovery after interrupted operations.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// Failed to recover from an interrupted sync.
    #[error("recovery failed: {reason}")]
    SyncRecovery {
        /// Description of the recovery failure.
        reason: String,
    },

    /// Failed to repair the state database.
    #[error("database repair failed: {reason}")]
    DatabaseRepair {
        /// Description of the repair failure.
        reason: String,
    },

    /// Failed to clean up temporary files.
    #[error("temporary file cleanup failed in '{path}': {source}")]
    TempCleanup {
        /// Path to the directory containing temporary files.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Failed to check or remove a stale lock file.
    #[error("lock file check failed for '{path}': {reason}")]
    LockFile {
        /// Path to the lock file.
        path: String,
        /// Description of the failure.
        reason: String,
    },

    /// Database integrity check failed.
    #[error("database integrity check failed: {reason}")]
    IntegrityCheck {
        /// Description of the integrity failure.
        reason: String,
    },
}
