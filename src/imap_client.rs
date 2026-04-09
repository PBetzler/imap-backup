//! IMAP client trait and production implementation.
//!
//! Defines [`ImapClient`], an async trait for IMAP operations, and
//! [`AsyncImapClient`], its production implementation using `async-imap`
//! with TLS via `tokio-rustls` and system certificates.

use std::sync::Arc;
use std::time::Duration;

use async_imap::imap_proto::types as imap_types;
use async_imap::types::{Fetch, Flag};
use futures::TryStreamExt;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

use crate::config::{AccountConfig, resolve_password};
use crate::error::ImapError;
use crate::sync_plan::ServerMessage;
use crate::types::{AttachmentMeta, FolderInfo};

/// Maximum allowed size in bytes for a single IMAP response payload.
///
/// Protects against malicious or malformed servers sending excessively large
/// responses that could exhaust memory.
const MAX_RESPONSE_SIZE_BYTES: usize = 256 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// Status information returned after selecting an IMAP folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderStatus {
    /// IMAP `UIDVALIDITY` value, if provided by the server.
    pub uid_validity: Option<u32>,
    /// Total number of messages in the folder.
    pub message_count: u32,
    /// Next UID the server will assign, if provided.
    pub uid_next: Option<u32>,
}

// ---------------------------------------------------------------------------
// Trait definition
// ---------------------------------------------------------------------------

/// Async trait for IMAP operations.
///
/// Defines the contract that both the production client and test mocks must
/// satisfy. All operations return [`ImapError`] on failure.
#[async_trait::async_trait]
pub trait ImapClient: Send {
    /// Connect to an IMAP server using the account configuration.
    ///
    /// The `timeout_seconds` parameter controls the maximum duration for each
    /// individual network operation (TCP connect, TLS handshake, login).
    async fn connect(account: &AccountConfig, timeout_seconds: u64) -> Result<Self, ImapError>
    where
        Self: Sized;

    /// List all folders/mailboxes on the server.
    async fn list_folders(&mut self) -> Result<Vec<FolderInfo>, ImapError>;

    /// Select a folder and return its status.
    async fn select_folder(&mut self, name: &str) -> Result<FolderStatus, ImapError>;

    /// Fetch message metadata for a range of UIDs (no body download).
    async fn fetch_metadata(&mut self, uid_range: &str) -> Result<Vec<ServerMessage>, ImapError>;

    /// Download the full RFC 822 body of a message by UID.
    async fn fetch_message_body(&mut self, uid: u32) -> Result<Vec<u8>, ImapError>;

    /// Disconnect cleanly (IMAP LOGOUT).
    async fn disconnect(&mut self) -> Result<(), ImapError>;
}

// ---------------------------------------------------------------------------
// Production implementation
// ---------------------------------------------------------------------------

/// Stream type alias for the TLS-wrapped TCP connection used by async-imap.
type ImapSession = async_imap::Session<TlsStream<TcpStream>>;

/// Production IMAP client backed by `async-imap` with TLS.
///
/// Connects using `tokio-rustls` with the system certificate store loaded
/// via `rustls-native-certs`. Passwords are held in `Zeroizing<String>` and
/// dropped as soon as authentication completes.
pub struct AsyncImapClient {
    /// The authenticated IMAP session.
    session: ImapSession,
    /// Server hostname (stored for error context).
    host: String,
    /// Currently selected folder name, if any.
    current_folder: Option<String>,
    /// Timeout duration for individual IMAP network operations.
    timeout_duration: Duration,
}

#[async_trait::async_trait]
impl ImapClient for AsyncImapClient {
    async fn connect(account: &AccountConfig, timeout_seconds: u64) -> Result<Self, ImapError> {
        let host = &account.host;
        let port = account.port;
        let timeout = Duration::from_secs(timeout_seconds);

        let tcp_stream = with_timeout(
            timeout,
            establish_tcp_connection(host, port),
            host,
            timeout_seconds,
        )
        .await??;

        let tls_stream = with_timeout(
            timeout,
            perform_tls_handshake(tcp_stream, host),
            host,
            timeout_seconds,
        )
        .await??;

        let session = with_timeout(
            timeout,
            perform_login(tls_stream, host, account),
            host,
            timeout_seconds,
        )
        .await??;

        Ok(Self {
            session,
            host: host.clone(),
            current_folder: None,
            timeout_duration: timeout,
        })
    }

    async fn list_folders(&mut self) -> Result<Vec<FolderInfo>, ImapError> {
        let timeout = self.timeout_duration;
        let timeout_secs = timeout.as_secs();
        let host = self.host.clone();

        let names_stream = with_timeout(
            timeout,
            self.session.list(None, Some("*")),
            &host,
            timeout_secs,
        )
        .await?
        .map_err(|e| ImapError::ListFolders {
            host: host.clone(),
            reason: e.to_string(),
        })?;

        let names: Vec<_> = with_timeout(timeout, names_stream.try_collect(), &host, timeout_secs)
            .await?
            .map_err(|e| ImapError::ListFolders {
                host: host.clone(),
                reason: e.to_string(),
            })?;

        let folders = names
            .iter()
            .map(|name| FolderInfo {
                name: name.name().to_owned(),
                uid_validity: 0,
                message_count: 0,
            })
            .collect();

        Ok(folders)
    }

    async fn select_folder(&mut self, name: &str) -> Result<FolderStatus, ImapError> {
        let timeout = self.timeout_duration;
        let timeout_secs = timeout.as_secs();

        let mailbox = with_timeout(timeout, self.session.select(name), &self.host, timeout_secs)
            .await?
            .map_err(|e| ImapError::SelectFolder {
                host: self.host.clone(),
                folder: name.to_owned(),
                reason: e.to_string(),
            })?;

        self.current_folder = Some(name.to_owned());

        Ok(FolderStatus {
            uid_validity: mailbox.uid_validity,
            message_count: mailbox.exists,
            uid_next: mailbox.uid_next,
        })
    }

    async fn fetch_metadata(&mut self, uid_range: &str) -> Result<Vec<ServerMessage>, ImapError> {
        let folder = self
            .current_folder
            .clone()
            .unwrap_or_else(|| "UNKNOWN".to_owned());
        let timeout = self.timeout_duration;
        let timeout_secs = timeout.as_secs();

        let fetch_query =
            "(UID FLAGS ENVELOPE BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)] BODYSTRUCTURE)";

        let fetches_stream = with_timeout(
            timeout,
            self.session.uid_fetch(uid_range, fetch_query),
            &self.host,
            timeout_secs,
        )
        .await?
        .map_err(|e| ImapError::Fetch {
            host: self.host.clone(),
            folder: folder.clone(),
            reason: e.to_string(),
        })?;

        let fetches: Vec<Fetch> = with_timeout(
            timeout,
            fetches_stream.try_collect(),
            &self.host,
            timeout_secs,
        )
        .await?
        .map_err(|e| ImapError::Fetch {
            host: self.host.clone(),
            folder: folder.clone(),
            reason: e.to_string(),
        })?;

        let mut messages = Vec::with_capacity(fetches.len());

        for fetch in &fetches {
            let uid = match fetch.uid {
                Some(uid) => uid,
                None => continue,
            };

            let envelope = fetch.envelope();
            let bodystructure = fetch.bodystructure();

            let date = extract_envelope_date(envelope);
            let from = extract_envelope_from(envelope);
            let subject = extract_envelope_subject(envelope);
            let to = extract_envelope_to(envelope);
            let cc = extract_envelope_cc(envelope);
            let message_id = extract_message_id_from_header(fetch);
            let attachments = bodystructure.map(extract_attachments).unwrap_or_default();

            let body_structure_hash = crate::fingerprint::compute_body_structure_hash(&attachments);

            let metadata = crate::types::MessageMetadata {
                message_id,
                date,
                from,
                to,
                cc,
                subject,
                attachment_count: attachments.len() as u32,
                attachments,
                body_structure_hash,
                fingerprint: String::new(),
            };

            let fingerprint = crate::fingerprint::compute_fingerprint(&metadata).map_err(|e| {
                ImapError::Fetch {
                    host: self.host.clone(),
                    folder: folder.clone(),
                    reason: format!("fingerprint computation failed: {e}"),
                }
            })?;

            let flags = extract_flags(fetch);

            messages.push(ServerMessage {
                fingerprint,
                folder: folder.clone(),
                uid,
                flags,
            });
        }

        Ok(messages)
    }

    async fn fetch_message_body(&mut self, uid: u32) -> Result<Vec<u8>, ImapError> {
        let folder = self
            .current_folder
            .clone()
            .unwrap_or_else(|| "UNKNOWN".to_owned());
        let timeout = self.timeout_duration;
        let timeout_secs = timeout.as_secs();

        let uid_str = uid.to_string();
        let fetches_stream = with_timeout(
            timeout,
            self.session.uid_fetch(&uid_str, "BODY.PEEK[]"),
            &self.host,
            timeout_secs,
        )
        .await?
        .map_err(|e| ImapError::Fetch {
            host: self.host.clone(),
            folder: folder.clone(),
            reason: e.to_string(),
        })?;

        let fetches: Vec<Fetch> = with_timeout(
            timeout,
            fetches_stream.try_collect(),
            &self.host,
            timeout_secs,
        )
        .await?
        .map_err(|e| ImapError::Fetch {
            host: self.host.clone(),
            folder: folder.clone(),
            reason: e.to_string(),
        })?;

        let fetch = fetches.first().ok_or_else(|| ImapError::Fetch {
            host: self.host.clone(),
            folder: folder.clone(),
            reason: format!("no response for UID {uid}"),
        })?;

        let body = fetch.body().ok_or_else(|| ImapError::Fetch {
            host: self.host.clone(),
            folder: folder.clone(),
            reason: format!("UID {uid} has no body"),
        })?;

        validate_response_size(body.len(), &self.host)?;

        Ok(body.to_vec())
    }

    async fn disconnect(&mut self) -> Result<(), ImapError> {
        let timeout = self.timeout_duration;
        let timeout_secs = timeout.as_secs();

        with_timeout(timeout, self.session.logout(), &self.host, timeout_secs)
            .await?
            .map_err(|e| ImapError::Connection {
                host: self.host.clone(),
                port: 0,
                reason: format!("logout failed: {e}"),
            })?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Timeout helper
// ---------------------------------------------------------------------------

/// Wrap a future in a timeout, returning `ImapError::Timeout` on expiry.
async fn with_timeout<F, T>(
    duration: Duration,
    future: F,
    host: &str,
    timeout_seconds: u64,
) -> Result<T, ImapError>
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(duration, future)
        .await
        .map_err(|_| ImapError::Timeout {
            host: host.to_owned(),
            timeout_seconds,
        })
}

// ---------------------------------------------------------------------------
// Connection helpers
// ---------------------------------------------------------------------------

/// Establish a raw TCP connection to the IMAP server.
async fn establish_tcp_connection(host: &str, port: u16) -> Result<TcpStream, ImapError> {
    let addr = format!("{host}:{port}");
    TcpStream::connect(&addr)
        .await
        .map_err(|e| ImapError::Connection {
            host: host.to_owned(),
            port,
            reason: e.to_string(),
        })
}

/// Perform TLS handshake over an established TCP connection.
async fn perform_tls_handshake(
    tcp_stream: TcpStream,
    host: &str,
) -> Result<TlsStream<TcpStream>, ImapError> {
    let tls_config = build_tls_config(host)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    let server_name =
        rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|e| ImapError::Tls {
            host: host.to_owned(),
            reason: format!("invalid server name: {e}"),
        })?;

    connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| ImapError::Tls {
            host: host.to_owned(),
            reason: e.to_string(),
        })
}

/// Build a rustls `ClientConfig` using the system certificate store.
fn build_tls_config(host: &str) -> Result<rustls::ClientConfig, ImapError> {
    let mut root_store = rustls::RootCertStore::empty();

    let cert_result = rustls_native_certs::load_native_certs();

    if cert_result.certs.is_empty() {
        let error_summary = cert_result
            .errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(ImapError::Tls {
            host: host.to_owned(),
            reason: format!("no system certificates loaded: {error_summary}"),
        });
    }

    for cert in cert_result.certs {
        // Ignore individual cert parse errors (some system certs may be unparseable)
        let _ = root_store.add(cert);
    }

    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth())
}

/// Perform IMAP LOGIN using credentials from the account configuration.
///
/// The password is resolved from the account's configured source, wrapped in
/// `Zeroizing<String>`, and dropped immediately after the login call completes.
async fn perform_login(
    tls_stream: TlsStream<TcpStream>,
    host: &str,
    account: &AccountConfig,
) -> Result<ImapSession, ImapError> {
    let mut client = async_imap::Client::new(tls_stream);

    // Read the server greeting
    let _greeting = client
        .read_response()
        .await
        .map_err(|e| ImapError::Connection {
            host: host.to_owned(),
            port: account.port,
            reason: format!("failed to read server greeting: {e}"),
        })?;

    let password: Zeroizing<String> = resolve_password(&account.name, &account.password_source)
        .map_err(|e| ImapError::Authentication {
            host: host.to_owned(),
            username: account.username.clone(),
            reason: format!("password resolution failed: {e}"),
        })?;

    let session = client
        .login(&account.username, password.as_str())
        .await
        .map_err(|(e, _client)| ImapError::Authentication {
            host: host.to_owned(),
            username: account.username.clone(),
            reason: e.to_string(),
        })?;

    // password is dropped here (Zeroizing zeroes memory on drop)

    Ok(session)
}

// ---------------------------------------------------------------------------
// Flag extraction (pure functions)
// ---------------------------------------------------------------------------

/// Extract IMAP flags from a FETCH response as string representations.
///
/// Converts each [`Flag`] variant to its standard IMAP string form
/// (e.g., `\Seen`, `\Flagged`). Unknown custom flags are included as-is.
fn extract_flags(fetch: &Fetch) -> Vec<String> {
    fetch.flags().map(flag_to_string).collect()
}

/// Convert an async-imap [`Flag`] to its standard IMAP string representation.
fn flag_to_string(flag: Flag<'_>) -> String {
    match flag {
        Flag::Seen => "\\Seen".to_owned(),
        Flag::Answered => "\\Answered".to_owned(),
        Flag::Flagged => "\\Flagged".to_owned(),
        Flag::Deleted => "\\Deleted".to_owned(),
        Flag::Draft => "\\Draft".to_owned(),
        Flag::Recent => "\\Recent".to_owned(),
        Flag::MayCreate => "\\*".to_owned(),
        Flag::Custom(name) => name.into_owned(),
    }
}

// ---------------------------------------------------------------------------
// Envelope/BODYSTRUCTURE parsing (pure functions)
// ---------------------------------------------------------------------------

/// Extract the Date field from an IMAP envelope.
fn extract_envelope_date(envelope: Option<&imap_types::Envelope<'_>>) -> String {
    envelope
        .and_then(|env| env.date.as_ref())
        .and_then(|d| std::str::from_utf8(d).ok())
        .unwrap_or("")
        .to_owned()
}

/// Extract the first From address from an IMAP envelope as a formatted string.
fn extract_envelope_from(envelope: Option<&imap_types::Envelope<'_>>) -> String {
    envelope
        .and_then(|env| env.from.as_ref())
        .and_then(|addrs| addrs.first())
        .map(format_address)
        .unwrap_or_default()
}

/// Extract the Subject field from an IMAP envelope.
fn extract_envelope_subject(envelope: Option<&imap_types::Envelope<'_>>) -> String {
    envelope
        .and_then(|env| env.subject.as_ref())
        .and_then(|s| std::str::from_utf8(s).ok())
        .unwrap_or("")
        .to_owned()
}

/// Extract the To addresses from an IMAP envelope as a comma-separated string.
fn extract_envelope_to(envelope: Option<&imap_types::Envelope<'_>>) -> Option<String> {
    envelope
        .and_then(|env| env.to.as_ref())
        .map(|addrs| format_address_list(addrs))
}

/// Extract the Cc addresses from an IMAP envelope as a comma-separated string.
fn extract_envelope_cc(envelope: Option<&imap_types::Envelope<'_>>) -> Option<String> {
    envelope
        .and_then(|env| env.cc.as_ref())
        .map(|addrs| format_address_list(addrs))
}

/// Format a list of IMAP addresses as a comma-separated string.
fn format_address_list(addresses: &[imap_types::Address<'_>]) -> String {
    addresses
        .iter()
        .map(format_address)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Format a single IMAP address as `"name <mailbox@host>"` or `"mailbox@host"`.
fn format_address(addr: &imap_types::Address<'_>) -> String {
    let mailbox = addr
        .mailbox
        .as_ref()
        .and_then(|m| std::str::from_utf8(m).ok())
        .unwrap_or("");
    let host = addr
        .host
        .as_ref()
        .and_then(|h| std::str::from_utf8(h).ok())
        .unwrap_or("");

    let email = if mailbox.is_empty() && host.is_empty() {
        String::new()
    } else {
        format!("{mailbox}@{host}")
    };

    match addr.name.as_ref().and_then(|n| std::str::from_utf8(n).ok()) {
        Some(name) if !name.is_empty() => format!("{name} <{email}>"),
        _ => email,
    }
}

/// Extract the Message-ID header from the raw header bytes in a FETCH response.
///
/// Parses the `BODY[HEADER.FIELDS (MESSAGE-ID)]` section, looking for a line
/// that starts with `Message-ID:` (case-insensitive).
fn extract_message_id_from_header(fetch: &Fetch) -> Option<String> {
    // The BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)] response comes back as a
    // BodySection with a specific section path. We need to iterate through
    // all body sections and find the header fields data.
    let header_bytes = extract_header_fields_bytes(fetch)?;

    parse_message_id_from_header_bytes(header_bytes)
}

/// Extract the raw bytes of the HEADER.FIELDS body section from a Fetch response.
///
/// This looks at the underlying `imap_proto` response data to find the
/// `BodySection` attribute that contains the header fields.
fn extract_header_fields_bytes(fetch: &Fetch) -> Option<&[u8]> {
    // The Fetch type provides .header() but that only matches BODY[HEADER]
    // (the full header). For BODY[HEADER.FIELDS (MESSAGE-ID)] we need to
    // look at the raw body section data. Since the Fetch API doesn't expose
    // a dedicated method for partial header fields, we iterate over body
    // sections using the body() method or examine the raw attributes.
    //
    // However, the Fetch type's .header() only matches Full(Header), not
    // HEADER.FIELDS. We need to use the section() method or access raw data.
    //
    // The section data for HEADER.FIELDS comes as a BodySection with
    // section = Some(Part([], Some(Header))) in some implementations,
    // or the data may simply be available as a body section.
    //
    // A practical approach: we use the `header()` method first, and if that
    // doesn't work, try the raw body section that was fetched.
    fetch.header()
}

/// Parse a `Message-ID` value from raw RFC 2822 header bytes.
///
/// Handles continuation lines (folded headers) and extracts the angle-bracket
/// delimited message ID.
fn parse_message_id_from_header_bytes(header_bytes: &[u8]) -> Option<String> {
    let header_str = std::str::from_utf8(header_bytes).ok()?;

    for line in header_str.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("Message-ID:") {
            return Some(value.trim().to_owned());
        }
        if let Some(value) = trimmed.strip_prefix("Message-Id:") {
            return Some(value.trim().to_owned());
        }
        if let Some(value) = trimmed.strip_prefix("message-id:") {
            return Some(value.trim().to_owned());
        }
    }

    // Case-insensitive fallback
    for line in header_str.lines() {
        let trimmed = line.trim();
        if let Some(colon_pos) = trimmed.find(':') {
            let key = &trimmed[..colon_pos];
            if key.eq_ignore_ascii_case("Message-ID") {
                return Some(trimmed[colon_pos + 1..].trim().to_owned());
            }
        }
    }

    None
}

/// Extract attachment metadata from an IMAP `BODYSTRUCTURE` response.
///
/// Recursively walks the MIME tree and collects non-text/non-inline parts
/// that represent attachments.
fn extract_attachments(bodystructure: &imap_types::BodyStructure<'_>) -> Vec<AttachmentMeta> {
    let mut attachments = Vec::new();
    collect_attachments(bodystructure, &mut attachments);
    attachments
}

/// Recursively collect attachment metadata from a BODYSTRUCTURE tree.
fn collect_attachments(bs: &imap_types::BodyStructure<'_>, result: &mut Vec<AttachmentMeta>) {
    match bs {
        imap_types::BodyStructure::Basic { common, other, .. } => {
            if is_attachment(common) {
                result.push(build_attachment_meta(common, other.octets));
            }
        }
        imap_types::BodyStructure::Text { common, other, .. } => {
            // Text parts with a Content-Disposition of "attachment" are attachments
            if is_attachment(common) {
                result.push(build_attachment_meta(common, other.octets));
            }
        }
        imap_types::BodyStructure::Message {
            common,
            other,
            body,
            ..
        } => {
            if is_attachment(common) {
                result.push(build_attachment_meta(common, other.octets));
            }
            // Also recurse into the nested message body
            collect_attachments(body, result);
        }
        imap_types::BodyStructure::Multipart { bodies, .. } => {
            for body in bodies {
                collect_attachments(body, result);
            }
        }
    }
}

/// Determine whether a MIME part is an attachment based on Content-Disposition.
///
/// A part is considered an attachment if:
/// - It has `Content-Disposition: attachment`, OR
/// - It is a non-text, non-multipart type (e.g., `application/*`, `image/*`)
fn is_attachment(common: &imap_types::BodyContentCommon<'_>) -> bool {
    // Explicit attachment disposition
    if let Some(ref disp) = common.disposition {
        if disp.ty.eq_ignore_ascii_case("attachment") {
            return true;
        }
    }

    // Non-text types without inline disposition are treated as attachments
    let mime_type = &common.ty.ty;
    let is_text = mime_type.eq_ignore_ascii_case("text");
    let is_multipart = mime_type.eq_ignore_ascii_case("multipart");

    if is_text || is_multipart {
        return false;
    }

    true
}

/// Build an `AttachmentMeta` from BODYSTRUCTURE common fields.
fn build_attachment_meta(
    common: &imap_types::BodyContentCommon<'_>,
    octets: u32,
) -> AttachmentMeta {
    let mime_type = format!(
        "{}/{}",
        common.ty.ty.to_lowercase(),
        common.ty.subtype.to_lowercase()
    );

    let filename = extract_filename_from_params(common);

    AttachmentMeta {
        mime_type,
        filename,
        size_bytes: u64::from(octets),
    }
}

/// Extract the filename from Content-Disposition or Content-Type parameters.
fn extract_filename_from_params(common: &imap_types::BodyContentCommon<'_>) -> Option<String> {
    // Try Content-Disposition params first (more reliable)
    if let Some(ref disp) = common.disposition {
        if let Some(ref params) = disp.params {
            for (key, value) in params {
                if key.eq_ignore_ascii_case("filename") {
                    return Some(value.to_string());
                }
            }
        }
    }

    // Fall back to Content-Type "name" parameter
    if let Some(ref params) = common.ty.params {
        for (key, value) in params {
            if key.eq_ignore_ascii_case("name") {
                return Some(value.to_string());
            }
        }
    }

    None
}

/// Validate that a response payload does not exceed the maximum allowed size.
fn validate_response_size(size: usize, host: &str) -> Result<(), ImapError> {
    if size > MAX_RESPONSE_SIZE_BYTES {
        return Err(ImapError::Fetch {
            host: host.to_owned(),
            folder: String::new(),
            reason: format!(
                "response size {size} bytes exceeds maximum allowed {MAX_RESPONSE_SIZE_BYTES} bytes"
            ),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Mock implementation (test only)
// ---------------------------------------------------------------------------

#[cfg(test)]
use std::collections::HashMap;

#[cfg(test)]
pub struct MockImapClient {
    /// Pre-configured folder list to return from `list_folders`.
    pub folders: Vec<FolderInfo>,
    /// Pre-configured folder status to return from `select_folder`.
    pub folder_status: HashMap<String, FolderStatus>,
    /// Pre-configured messages to return from `fetch_metadata`, keyed by folder name.
    pub messages: HashMap<String, Vec<ServerMessage>>,
    /// Pre-configured message bodies to return from `fetch_message_body`, keyed by UID.
    pub message_bodies: HashMap<u32, Vec<u8>>,
    /// Currently selected folder.
    current_folder: Option<String>,
    /// Whether disconnect has been called.
    disconnected: bool,
}

#[cfg(test)]
impl MockImapClient {
    /// Create a new mock client with empty defaults.
    pub fn new() -> Self {
        Self {
            folders: Vec::new(),
            folder_status: HashMap::new(),
            messages: HashMap::new(),
            message_bodies: HashMap::new(),
            current_folder: None,
            disconnected: false,
        }
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl ImapClient for MockImapClient {
    async fn connect(_account: &AccountConfig, _timeout_seconds: u64) -> Result<Self, ImapError> {
        Ok(Self::new())
    }

    async fn list_folders(&mut self) -> Result<Vec<FolderInfo>, ImapError> {
        Ok(self.folders.clone())
    }

    async fn select_folder(&mut self, name: &str) -> Result<FolderStatus, ImapError> {
        self.current_folder = Some(name.to_owned());

        self.folder_status
            .get(name)
            .cloned()
            .ok_or_else(|| ImapError::SelectFolder {
                host: "mock".to_owned(),
                folder: name.to_owned(),
                reason: "folder not found in mock".to_owned(),
            })
    }

    async fn fetch_metadata(&mut self, _uid_range: &str) -> Result<Vec<ServerMessage>, ImapError> {
        let folder = self
            .current_folder
            .clone()
            .unwrap_or_else(|| "UNKNOWN".to_owned());

        Ok(self.messages.get(&folder).cloned().unwrap_or_default())
    }

    async fn fetch_message_body(&mut self, uid: u32) -> Result<Vec<u8>, ImapError> {
        self.message_bodies
            .get(&uid)
            .cloned()
            .ok_or_else(|| ImapError::Fetch {
                host: "mock".to_owned(),
                folder: self
                    .current_folder
                    .clone()
                    .unwrap_or_else(|| "UNKNOWN".to_owned()),
                reason: format!("UID {uid} not found in mock"),
            })
    }

    async fn disconnect(&mut self) -> Result<(), ImapError> {
        self.disconnected = true;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    use imap_types::{
        Address, BodyContentCommon, BodyContentSinglePart, BodyStructure, ContentDisposition,
        ContentEncoding, ContentType, Envelope,
    };

    // --- Message-ID parsing ---

    #[test]
    fn parse_message_id_standard_header() {
        let header = b"Message-ID: <abc@example.com>\r\n";
        let result = parse_message_id_from_header_bytes(header);
        assert_eq!(result, Some("<abc@example.com>".to_owned()));
    }

    #[test]
    fn parse_message_id_case_insensitive() {
        let header = b"message-id: <def@example.com>\r\n";
        let result = parse_message_id_from_header_bytes(header);
        assert_eq!(result, Some("<def@example.com>".to_owned()));
    }

    #[test]
    fn parse_message_id_mixed_case() {
        let header = b"Message-Id: <ghi@example.com>\r\n";
        let result = parse_message_id_from_header_bytes(header);
        assert_eq!(result, Some("<ghi@example.com>".to_owned()));
    }

    #[test]
    fn parse_message_id_missing() {
        let header = b"Subject: Test\r\n";
        let result = parse_message_id_from_header_bytes(header);
        assert_eq!(result, None);
    }

    #[test]
    fn parse_message_id_empty_header() {
        let header = b"";
        let result = parse_message_id_from_header_bytes(header);
        assert_eq!(result, None);
    }

    #[test]
    fn parse_message_id_with_extra_whitespace() {
        let header = b"Message-ID:   <spaced@example.com>  \r\n";
        let result = parse_message_id_from_header_bytes(header);
        assert_eq!(result, Some("<spaced@example.com>".to_owned()));
    }

    // --- Address formatting ---

    #[test]
    fn format_address_with_name_and_email() {
        let addr = Address {
            name: Some(Cow::Borrowed(b"Alice")),
            adl: None,
            mailbox: Some(Cow::Borrowed(b"alice")),
            host: Some(Cow::Borrowed(b"example.com")),
        };
        assert_eq!(format_address(&addr), "Alice <alice@example.com>");
    }

    #[test]
    fn format_address_without_name() {
        let addr = Address {
            name: None,
            adl: None,
            mailbox: Some(Cow::Borrowed(b"bob")),
            host: Some(Cow::Borrowed(b"example.com")),
        };
        assert_eq!(format_address(&addr), "bob@example.com");
    }

    #[test]
    fn format_address_empty_name() {
        let addr = Address {
            name: Some(Cow::Borrowed(b"")),
            adl: None,
            mailbox: Some(Cow::Borrowed(b"carol")),
            host: Some(Cow::Borrowed(b"example.com")),
        };
        assert_eq!(format_address(&addr), "carol@example.com");
    }

    #[test]
    fn format_address_no_mailbox_or_host() {
        let addr = Address {
            name: Some(Cow::Borrowed(b"Nobody")),
            adl: None,
            mailbox: None,
            host: None,
        };
        assert_eq!(format_address(&addr), "Nobody <>");
    }

    #[test]
    fn format_address_list_multiple() {
        let addrs = vec![
            Address {
                name: Some(Cow::Borrowed(b"Alice")),
                adl: None,
                mailbox: Some(Cow::Borrowed(b"alice")),
                host: Some(Cow::Borrowed(b"example.com")),
            },
            Address {
                name: None,
                adl: None,
                mailbox: Some(Cow::Borrowed(b"bob")),
                host: Some(Cow::Borrowed(b"example.com")),
            },
        ];
        assert_eq!(
            format_address_list(&addrs),
            "Alice <alice@example.com>, bob@example.com"
        );
    }

    // --- Envelope extraction ---

    fn make_envelope<'a>(
        date: Option<&'a [u8]>,
        subject: Option<&'a [u8]>,
        from: Option<Vec<Address<'a>>>,
        to: Option<Vec<Address<'a>>>,
        cc: Option<Vec<Address<'a>>>,
    ) -> Envelope<'a> {
        Envelope {
            date: date.map(Cow::Borrowed),
            subject: subject.map(Cow::Borrowed),
            from,
            sender: None,
            reply_to: None,
            to,
            cc,
            bcc: None,
            in_reply_to: None,
            message_id: None,
        }
    }

    #[test]
    fn extract_date_from_envelope() {
        let env = make_envelope(
            Some(b"Mon, 1 Jan 2024 00:00:00 +0000"),
            None,
            None,
            None,
            None,
        );
        assert_eq!(
            extract_envelope_date(Some(&env)),
            "Mon, 1 Jan 2024 00:00:00 +0000"
        );
    }

    #[test]
    fn extract_date_from_none_envelope() {
        assert_eq!(extract_envelope_date(None), "");
    }

    #[test]
    fn extract_date_from_envelope_missing_date() {
        let env = make_envelope(None, None, None, None, None);
        assert_eq!(extract_envelope_date(Some(&env)), "");
    }

    #[test]
    fn extract_from_with_name() {
        let env = make_envelope(
            None,
            None,
            Some(vec![Address {
                name: Some(Cow::Borrowed(b"Alice")),
                adl: None,
                mailbox: Some(Cow::Borrowed(b"alice")),
                host: Some(Cow::Borrowed(b"example.com")),
            }]),
            None,
            None,
        );
        assert_eq!(
            extract_envelope_from(Some(&env)),
            "Alice <alice@example.com>"
        );
    }

    #[test]
    fn extract_subject_from_envelope() {
        let env = make_envelope(None, Some(b"Hello World"), None, None, None);
        assert_eq!(extract_envelope_subject(Some(&env)), "Hello World");
    }

    #[test]
    fn extract_to_from_envelope() {
        let env = make_envelope(
            None,
            None,
            None,
            Some(vec![Address {
                name: None,
                adl: None,
                mailbox: Some(Cow::Borrowed(b"bob")),
                host: Some(Cow::Borrowed(b"example.com")),
            }]),
            None,
        );
        assert_eq!(
            extract_envelope_to(Some(&env)),
            Some("bob@example.com".to_owned())
        );
    }

    #[test]
    fn extract_cc_from_envelope() {
        let env = make_envelope(
            None,
            None,
            None,
            None,
            Some(vec![Address {
                name: None,
                adl: None,
                mailbox: Some(Cow::Borrowed(b"cc")),
                host: Some(Cow::Borrowed(b"example.com")),
            }]),
        );
        assert_eq!(
            extract_envelope_cc(Some(&env)),
            Some("cc@example.com".to_owned())
        );
    }

    #[test]
    fn extract_to_returns_none_when_absent() {
        let env = make_envelope(None, None, None, None, None);
        assert_eq!(extract_envelope_to(Some(&env)), None);
    }

    // --- BODYSTRUCTURE attachment extraction ---

    fn make_content_type<'a>(ty: &'a str, subtype: &'a str) -> ContentType<'a> {
        ContentType {
            ty: Cow::Borrowed(ty),
            subtype: Cow::Borrowed(subtype),
            params: None,
        }
    }

    fn make_common<'a>(
        ty: &'a str,
        subtype: &'a str,
        disposition: Option<ContentDisposition<'a>>,
    ) -> BodyContentCommon<'a> {
        BodyContentCommon {
            ty: make_content_type(ty, subtype),
            disposition,
            language: None,
            location: None,
        }
    }

    fn make_single_part(octets: u32) -> BodyContentSinglePart<'static> {
        BodyContentSinglePart {
            id: None,
            md5: None,
            description: None,
            transfer_encoding: ContentEncoding::SevenBit,
            octets,
        }
    }

    fn attachment_disposition<'a>(filename: &'a str) -> ContentDisposition<'a> {
        ContentDisposition {
            ty: Cow::Borrowed("attachment"),
            params: Some(vec![(Cow::Borrowed("filename"), Cow::Borrowed(filename))]),
        }
    }

    #[test]
    fn extract_attachments_simple_text_plain() {
        let bs = BodyStructure::Text {
            common: make_common("text", "plain", None),
            other: make_single_part(100),
            lines: 10,
            extension: None,
        };
        let attachments = extract_attachments(&bs);
        assert!(
            attachments.is_empty(),
            "text/plain without attachment disposition should not be an attachment"
        );
    }

    #[test]
    fn extract_attachments_single_pdf() {
        let bs = BodyStructure::Basic {
            common: make_common(
                "application",
                "pdf",
                Some(attachment_disposition("doc.pdf")),
            ),
            other: make_single_part(5000),
            extension: None,
        };
        let attachments = extract_attachments(&bs);
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].mime_type, "application/pdf");
        assert_eq!(attachments[0].filename, Some("doc.pdf".to_owned()));
        assert_eq!(attachments[0].size_bytes, 5000);
    }

    #[test]
    fn extract_attachments_multipart_mixed_with_pdf() {
        // multipart/mixed containing text/plain + application/pdf
        let bs = BodyStructure::Multipart {
            common: make_common("multipart", "mixed", None),
            bodies: vec![
                BodyStructure::Text {
                    common: make_common("text", "plain", None),
                    other: make_single_part(200),
                    lines: 5,
                    extension: None,
                },
                BodyStructure::Basic {
                    common: make_common(
                        "application",
                        "pdf",
                        Some(attachment_disposition("report.pdf")),
                    ),
                    other: make_single_part(10000),
                    extension: None,
                },
            ],
            extension: None,
        };
        let attachments = extract_attachments(&bs);
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].mime_type, "application/pdf");
        assert_eq!(attachments[0].filename, Some("report.pdf".to_owned()));
        assert_eq!(attachments[0].size_bytes, 10000);
    }

    #[test]
    fn extract_attachments_multipart_with_image_no_disposition() {
        // An image/* part without explicit disposition is still treated as attachment
        let bs = BodyStructure::Multipart {
            common: make_common("multipart", "mixed", None),
            bodies: vec![
                BodyStructure::Text {
                    common: make_common("text", "plain", None),
                    other: make_single_part(100),
                    lines: 3,
                    extension: None,
                },
                BodyStructure::Basic {
                    common: make_common("image", "png", None),
                    other: make_single_part(3000),
                    extension: None,
                },
            ],
            extension: None,
        };
        let attachments = extract_attachments(&bs);
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].mime_type, "image/png");
        assert_eq!(attachments[0].filename, None);
        assert_eq!(attachments[0].size_bytes, 3000);
    }

    #[test]
    fn extract_attachments_gmail_style_multipart() {
        // Gmail-style: multipart/mixed [ multipart/alternative [ text/plain, text/html ], application/pdf ]
        let bs = BodyStructure::Multipart {
            common: make_common("multipart", "mixed", None),
            bodies: vec![
                BodyStructure::Multipart {
                    common: make_common("multipart", "alternative", None),
                    bodies: vec![
                        BodyStructure::Text {
                            common: make_common("text", "plain", None),
                            other: make_single_part(150),
                            lines: 5,
                            extension: None,
                        },
                        BodyStructure::Text {
                            common: make_common("text", "html", None),
                            other: make_single_part(300),
                            lines: 10,
                            extension: None,
                        },
                    ],
                    extension: None,
                },
                BodyStructure::Basic {
                    common: make_common(
                        "application",
                        "pdf",
                        Some(attachment_disposition("invoice.pdf")),
                    ),
                    other: make_single_part(25000),
                    extension: None,
                },
            ],
            extension: None,
        };
        let attachments = extract_attachments(&bs);
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].mime_type, "application/pdf");
        assert_eq!(attachments[0].filename, Some("invoice.pdf".to_owned()));
    }

    #[test]
    fn extract_attachments_multiple_attachments() {
        let bs = BodyStructure::Multipart {
            common: make_common("multipart", "mixed", None),
            bodies: vec![
                BodyStructure::Text {
                    common: make_common("text", "plain", None),
                    other: make_single_part(100),
                    lines: 3,
                    extension: None,
                },
                BodyStructure::Basic {
                    common: make_common(
                        "application",
                        "pdf",
                        Some(attachment_disposition("doc.pdf")),
                    ),
                    other: make_single_part(5000),
                    extension: None,
                },
                BodyStructure::Basic {
                    common: make_common("image", "jpeg", Some(attachment_disposition("photo.jpg"))),
                    other: make_single_part(8000),
                    extension: None,
                },
            ],
            extension: None,
        };
        let attachments = extract_attachments(&bs);
        assert_eq!(attachments.len(), 2);
        assert_eq!(attachments[0].mime_type, "application/pdf");
        assert_eq!(attachments[1].mime_type, "image/jpeg");
    }

    #[test]
    fn extract_attachments_text_attachment() {
        // A text/plain part with Content-Disposition: attachment should be treated as attachment
        let bs = BodyStructure::Text {
            common: make_common("text", "plain", Some(attachment_disposition("readme.txt"))),
            other: make_single_part(500),
            lines: 20,
            extension: None,
        };
        let attachments = extract_attachments(&bs);
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].mime_type, "text/plain");
        assert_eq!(attachments[0].filename, Some("readme.txt".to_owned()));
    }

    #[test]
    fn extract_attachments_filename_from_content_type_name() {
        // Filename can come from Content-Type "name" param when no disposition params
        let common = BodyContentCommon {
            ty: ContentType {
                ty: Cow::Borrowed("application"),
                subtype: Cow::Borrowed("octet-stream"),
                params: Some(vec![(Cow::Borrowed("name"), Cow::Borrowed("data.bin"))]),
            },
            disposition: Some(ContentDisposition {
                ty: Cow::Borrowed("attachment"),
                params: None,
            }),
            language: None,
            location: None,
        };
        let bs = BodyStructure::Basic {
            common,
            other: make_single_part(1024),
            extension: None,
        };
        let attachments = extract_attachments(&bs);
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].filename, Some("data.bin".to_owned()));
    }

    // --- is_attachment ---

    #[test]
    fn text_plain_is_not_attachment() {
        let common = make_common("text", "plain", None);
        assert!(!is_attachment(&common));
    }

    #[test]
    fn text_html_is_not_attachment() {
        let common = make_common("text", "html", None);
        assert!(!is_attachment(&common));
    }

    #[test]
    fn multipart_is_not_attachment() {
        let common = make_common("multipart", "mixed", None);
        assert!(!is_attachment(&common));
    }

    #[test]
    fn application_pdf_is_attachment() {
        let common = make_common("application", "pdf", None);
        assert!(is_attachment(&common));
    }

    #[test]
    fn image_jpeg_is_attachment() {
        let common = make_common("image", "jpeg", None);
        assert!(is_attachment(&common));
    }

    #[test]
    fn text_with_attachment_disposition_is_attachment() {
        let common = make_common("text", "plain", Some(attachment_disposition("readme.txt")));
        assert!(is_attachment(&common));
    }

    // --- Response size validation ---

    #[test]
    fn validate_response_size_accepts_normal_size() {
        let result = validate_response_size(1024, "test.example.com");
        assert!(result.is_ok());
    }

    #[test]
    fn validate_response_size_rejects_oversized() {
        let result = validate_response_size(MAX_RESPONSE_SIZE_BYTES + 1, "test.example.com");
        assert!(result.is_err());
    }

    #[test]
    fn validate_response_size_accepts_exactly_max() {
        let result = validate_response_size(MAX_RESPONSE_SIZE_BYTES, "test.example.com");
        assert!(result.is_ok());
    }

    // --- MockImapClient tests ---

    #[tokio::test]
    async fn mock_list_folders_returns_configured_folders() {
        let mut mock = MockImapClient::new();
        mock.folders = vec![
            FolderInfo {
                name: "INBOX".to_owned(),
                uid_validity: 1,
                message_count: 10,
            },
            FolderInfo {
                name: "Sent".to_owned(),
                uid_validity: 2,
                message_count: 5,
            },
        ];

        let folders = mock.list_folders().await.unwrap();
        assert_eq!(folders.len(), 2);
        assert_eq!(folders[0].name, "INBOX");
        assert_eq!(folders[1].name, "Sent");
    }

    #[tokio::test]
    async fn mock_select_folder_returns_status() {
        let mut mock = MockImapClient::new();
        mock.folder_status.insert(
            "INBOX".to_owned(),
            FolderStatus {
                uid_validity: Some(12345),
                message_count: 42,
                uid_next: Some(100),
            },
        );

        let status = mock.select_folder("INBOX").await.unwrap();
        assert_eq!(status.uid_validity, Some(12345));
        assert_eq!(status.message_count, 42);
        assert_eq!(status.uid_next, Some(100));
    }

    #[tokio::test]
    async fn mock_select_folder_returns_error_for_unknown() {
        let mut mock = MockImapClient::new();
        let result = mock.select_folder("NoSuchFolder").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mock_fetch_metadata_returns_configured_messages() {
        let mut mock = MockImapClient::new();
        mock.folder_status.insert(
            "INBOX".to_owned(),
            FolderStatus {
                uid_validity: Some(1),
                message_count: 1,
                uid_next: Some(2),
            },
        );
        mock.messages.insert(
            "INBOX".to_owned(),
            vec![ServerMessage {
                fingerprint: "fp1".to_owned(),
                folder: "INBOX".to_owned(),
                uid: 1,
                flags: vec!["\\Seen".to_owned()],
            }],
        );

        mock.select_folder("INBOX").await.unwrap();
        let messages = mock.fetch_metadata("1:*").await.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].fingerprint, "fp1");
        assert_eq!(messages[0].uid, 1);
    }

    #[tokio::test]
    async fn mock_fetch_body_returns_configured_body() {
        let mut mock = MockImapClient::new();
        mock.message_bodies
            .insert(42, b"From: test\r\n\r\nHello".to_vec());

        let body = mock.fetch_message_body(42).await.unwrap();
        assert_eq!(body, b"From: test\r\n\r\nHello");
    }

    #[tokio::test]
    async fn mock_fetch_body_returns_error_for_unknown_uid() {
        let mut mock = MockImapClient::new();
        let result = mock.fetch_message_body(999).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mock_disconnect_succeeds() {
        let mut mock = MockImapClient::new();
        let result = mock.disconnect().await;
        assert!(result.is_ok());
        assert!(mock.disconnected);
    }

    #[tokio::test]
    async fn mock_fetch_metadata_returns_empty_for_unset_folder() {
        let mut mock = MockImapClient::new();
        mock.folder_status.insert(
            "INBOX".to_owned(),
            FolderStatus {
                uid_validity: Some(1),
                message_count: 0,
                uid_next: Some(1),
            },
        );

        mock.select_folder("INBOX").await.unwrap();
        let messages = mock.fetch_metadata("1:*").await.unwrap();
        assert!(messages.is_empty());
    }

    // --- FolderStatus ---

    #[test]
    fn folder_status_equality() {
        let a = FolderStatus {
            uid_validity: Some(1),
            message_count: 10,
            uid_next: Some(11),
        };
        let b = FolderStatus {
            uid_validity: Some(1),
            message_count: 10,
            uid_next: Some(11),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn folder_status_debug_format() {
        let status = FolderStatus {
            uid_validity: Some(42),
            message_count: 100,
            uid_next: None,
        };
        let debug = format!("{status:?}");
        assert!(debug.contains("42"));
        assert!(debug.contains("100"));
    }
}
