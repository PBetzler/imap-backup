//! Composite fingerprint computation for email message identity.
//!
//! All functions in this module are **pure** — no I/O, no side effects.
//! The fingerprint is a hex-encoded SHA-256 hash of normalized message
//! metadata, used to detect moves and deduplication across IMAP folders.

use std::fmt::Write;

use sha2::{Digest, Sha256};

use crate::error::FingerprintError;
use crate::types::{AttachmentMeta, MessageMetadata};

/// Null byte used as a field delimiter in hash input to prevent collisions
/// between adjacent fields (e.g., "ab" || "cd" vs "a" || "bcd").
const FIELD_SEPARATOR: &[u8] = b"\x00";

/// Number of hex characters in a SHA-256 digest (32 bytes × 2 hex chars).
const SHA256_HEX_LEN: usize = 64;

/// Compute a composite fingerprint for the given message metadata.
///
/// Returns a hex-encoded SHA-256 hash string. The hash input depends on
/// whether a `Message-ID` header is present:
///
/// - **With `Message-ID`:** `message_id || date || from || subject || attachment_count || attachment_metadata || body_structure_hash`
/// - **Without `Message-ID`:** `from || to || cc || date || subject || attachment_metadata || body_structure_hash`
///
/// All header values are normalized (trimmed, lowercased) before hashing.
pub fn compute_fingerprint(metadata: &MessageMetadata) -> Result<String, FingerprintError> {
    let body_structure_hash = compute_body_structure_hash(&metadata.attachments);

    let hash = match &metadata.message_id {
        Some(message_id) => {
            compute_fingerprint_with_message_id(metadata, message_id, &body_structure_hash)
        }
        None => compute_fingerprint_without_message_id(metadata, &body_structure_hash),
    };

    Ok(hash)
}

/// Compute the fingerprint when a `Message-ID` header is present.
fn compute_fingerprint_with_message_id(
    metadata: &MessageMetadata,
    message_id: &str,
    body_structure_hash: &str,
) -> String {
    let mut hasher = Sha256::new();

    hasher.update(normalize_header(message_id).as_bytes());
    hasher.update(FIELD_SEPARATOR);
    hasher.update(normalize_header(&metadata.date).as_bytes());
    hasher.update(FIELD_SEPARATOR);
    hasher.update(normalize_email_address(&metadata.from).as_bytes());
    hasher.update(FIELD_SEPARATOR);
    hasher.update(normalize_header(&metadata.subject).as_bytes());
    hasher.update(FIELD_SEPARATOR);
    hasher.update(metadata.attachment_count.to_string().as_bytes());
    hasher.update(FIELD_SEPARATOR);
    hasher.update(compute_attachment_metadata_string(&metadata.attachments).as_bytes());
    hasher.update(FIELD_SEPARATOR);
    hasher.update(body_structure_hash.as_bytes());

    hex_encode_sha256(hasher)
}

/// Compute the fingerprint when no `Message-ID` header is present (fallback).
fn compute_fingerprint_without_message_id(
    metadata: &MessageMetadata,
    body_structure_hash: &str,
) -> String {
    let mut hasher = Sha256::new();

    hasher.update(normalize_email_address(&metadata.from).as_bytes());
    hasher.update(FIELD_SEPARATOR);
    hasher.update(normalize_header(optional_str(&metadata.to)).as_bytes());
    hasher.update(FIELD_SEPARATOR);
    hasher.update(normalize_header(optional_str(&metadata.cc)).as_bytes());
    hasher.update(FIELD_SEPARATOR);
    hasher.update(normalize_header(&metadata.date).as_bytes());
    hasher.update(FIELD_SEPARATOR);
    hasher.update(normalize_header(&metadata.subject).as_bytes());
    hasher.update(FIELD_SEPARATOR);
    hasher.update(compute_attachment_metadata_string(&metadata.attachments).as_bytes());
    hasher.update(FIELD_SEPARATOR);
    hasher.update(body_structure_hash.as_bytes());

    hex_encode_sha256(hasher)
}

/// Encode a SHA-256 digest as a lowercase hex string.
fn hex_encode_sha256(hasher: Sha256) -> String {
    let result = hasher.finalize();
    let mut hex = String::with_capacity(SHA256_HEX_LEN);
    for byte in result.iter() {
        // write! to a String is infallible, but we use let _ to satisfy
        // the lint that denies unused Results while avoiding unwrap().
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Extract the inner string from an `Option<String>`, returning an empty
/// string when `None`.
fn optional_str(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("")
}

/// Normalize a header value by trimming whitespace and converting to lowercase.
pub fn normalize_header(value: &str) -> String {
    value.trim().to_lowercase()
}

/// Normalize an email address by extracting the address portion from an
/// RFC 5322 display-name + angle-addr format and lowercasing it.
///
/// Examples:
/// - `"Alice <ALICE@Example.COM>"` → `"alice@example.com"`
/// - `"bob@example.com"` → `"bob@example.com"`
/// - `""` → `""`
pub fn normalize_email_address(addr: &str) -> String {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // Try to extract angle-bracket address: "Display Name <addr>"
    if let Some(start) = trimmed.rfind('<') {
        if let Some(end) = trimmed[start..].find('>') {
            let extracted = &trimmed[start + 1..start + end];
            return extracted.trim().to_lowercase();
        }
    }

    // No angle brackets — treat the whole string as the address
    trimmed.to_lowercase()
}

/// Compute a SHA-256 hash of the MIME body structure shape.
///
/// The hash is computed from the sorted attachment metadata (mime_type,
/// filename, size) to ensure order-independence and determinism.
pub fn compute_body_structure_hash(attachments: &[AttachmentMeta]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(compute_attachment_metadata_string(attachments).as_bytes());
    hex_encode_sha256(hasher)
}

/// Build a deterministic string representation of attachment metadata.
///
/// Attachments are sorted by (mime_type, filename, size) before
/// serialization to ensure order-independence.
fn compute_attachment_metadata_string(attachments: &[AttachmentMeta]) -> String {
    if attachments.is_empty() {
        return String::new();
    }

    let mut sorted: Vec<&AttachmentMeta> = attachments.iter().collect();
    sorted.sort_by(|a, b| {
        a.mime_type
            .cmp(&b.mime_type)
            .then_with(|| a.filename.cmp(&b.filename))
            .then_with(|| a.size_bytes.cmp(&b.size_bytes))
    });

    sorted
        .iter()
        .map(|a| {
            format!(
                "{}|{}|{}",
                a.mime_type,
                a.filename.as_deref().unwrap_or(""),
                a.size_bytes,
            )
        })
        .collect::<Vec<_>>()
        .join("\x00")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a `MessageMetadata` with sensible defaults.
    fn make_metadata(
        message_id: Option<&str>,
        from: &str,
        to: Option<&str>,
        cc: Option<&str>,
        date: &str,
        subject: &str,
        attachments: Vec<AttachmentMeta>,
    ) -> MessageMetadata {
        MessageMetadata {
            message_id: message_id.map(String::from),
            date: date.to_owned(),
            from: from.to_owned(),
            to: to.map(String::from),
            cc: cc.map(String::from),
            subject: subject.to_owned(),
            attachment_count: attachments.len() as u32,
            attachments,
            body_structure_hash: String::new(),
            fingerprint: String::new(),
        }
    }

    fn make_attachment(mime_type: &str, filename: Option<&str>, size: u64) -> AttachmentMeta {
        AttachmentMeta {
            mime_type: mime_type.to_owned(),
            filename: filename.map(String::from),
            size_bytes: size,
        }
    }

    // --- Determinism ---

    #[test]
    fn same_email_produces_same_fingerprint() {
        let m1 = make_metadata(
            Some("<abc@example.com>"),
            "Alice <alice@example.com>",
            Some("bob@example.com"),
            None,
            "Mon, 1 Jan 2024 00:00:00 +0000",
            "Hello World",
            vec![],
        );
        let m2 = make_metadata(
            Some("<abc@example.com>"),
            "Alice <alice@example.com>",
            Some("bob@example.com"),
            None,
            "Mon, 1 Jan 2024 00:00:00 +0000",
            "Hello World",
            vec![],
        );

        let f1 = compute_fingerprint(&m1).unwrap();
        let f2 = compute_fingerprint(&m2).unwrap();
        assert_eq!(f1, f2);
    }

    #[test]
    fn fingerprint_is_64_hex_chars() {
        let m = make_metadata(
            Some("<test@example.com>"),
            "test@example.com",
            None,
            None,
            "2024-01-01",
            "Test",
            vec![],
        );
        let fp = compute_fingerprint(&m).unwrap();
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // --- Uniqueness ---

    #[test]
    fn different_emails_produce_different_fingerprints() {
        let m1 = make_metadata(
            Some("<abc@example.com>"),
            "alice@example.com",
            None,
            None,
            "2024-01-01",
            "Subject A",
            vec![],
        );
        let m2 = make_metadata(
            Some("<def@example.com>"),
            "alice@example.com",
            None,
            None,
            "2024-01-01",
            "Subject B",
            vec![],
        );

        let f1 = compute_fingerprint(&m1).unwrap();
        let f2 = compute_fingerprint(&m2).unwrap();
        assert_ne!(f1, f2);
    }

    #[test]
    fn different_subjects_produce_different_fingerprints() {
        let m1 = make_metadata(
            Some("<same@example.com>"),
            "alice@example.com",
            None,
            None,
            "2024-01-01",
            "Subject A",
            vec![],
        );
        let m2 = make_metadata(
            Some("<same@example.com>"),
            "alice@example.com",
            None,
            None,
            "2024-01-01",
            "Subject B",
            vec![],
        );

        let f1 = compute_fingerprint(&m1).unwrap();
        let f2 = compute_fingerprint(&m2).unwrap();
        assert_ne!(f1, f2);
    }

    // --- Missing Message-ID fallback ---

    #[test]
    fn missing_message_id_fallback_works() {
        let m = make_metadata(
            None,
            "alice@example.com",
            Some("bob@example.com"),
            Some("carol@example.com"),
            "2024-01-01",
            "No Message-ID",
            vec![],
        );
        let fp = compute_fingerprint(&m).unwrap();
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn with_and_without_message_id_produce_different_fingerprints() {
        let m1 = make_metadata(
            Some("<id@example.com>"),
            "alice@example.com",
            Some("bob@example.com"),
            None,
            "2024-01-01",
            "Same Subject",
            vec![],
        );
        let m2 = make_metadata(
            None,
            "alice@example.com",
            Some("bob@example.com"),
            None,
            "2024-01-01",
            "Same Subject",
            vec![],
        );

        let f1 = compute_fingerprint(&m1).unwrap();
        let f2 = compute_fingerprint(&m2).unwrap();
        assert_ne!(f1, f2);
    }

    // --- Normalization ---

    #[test]
    fn whitespace_normalization_is_consistent() {
        let m1 = make_metadata(
            Some("  <abc@example.com>  "),
            "  Alice <alice@example.com>  ",
            None,
            None,
            "  2024-01-01  ",
            "  Hello World  ",
            vec![],
        );
        let m2 = make_metadata(
            Some("<abc@example.com>"),
            "Alice <alice@example.com>",
            None,
            None,
            "2024-01-01",
            "Hello World",
            vec![],
        );

        let f1 = compute_fingerprint(&m1).unwrap();
        let f2 = compute_fingerprint(&m2).unwrap();
        assert_eq!(f1, f2);
    }

    #[test]
    fn case_normalization_is_consistent() {
        let m1 = make_metadata(
            Some("<ABC@EXAMPLE.COM>"),
            "ALICE@EXAMPLE.COM",
            None,
            None,
            "2024-01-01",
            "HELLO WORLD",
            vec![],
        );
        let m2 = make_metadata(
            Some("<abc@example.com>"),
            "alice@example.com",
            None,
            None,
            "2024-01-01",
            "hello world",
            vec![],
        );

        let f1 = compute_fingerprint(&m1).unwrap();
        let f2 = compute_fingerprint(&m2).unwrap();
        assert_eq!(f1, f2);
    }

    // --- Email address normalization ---

    #[test]
    fn normalize_email_extracts_angle_bracket_address() {
        assert_eq!(
            normalize_email_address("Alice <ALICE@Example.COM>"),
            "alice@example.com"
        );
    }

    #[test]
    fn normalize_email_handles_plain_address() {
        assert_eq!(
            normalize_email_address("BOB@Example.COM"),
            "bob@example.com"
        );
    }

    #[test]
    fn normalize_email_handles_empty_string() {
        assert_eq!(normalize_email_address(""), "");
    }

    #[test]
    fn normalize_email_handles_whitespace_only() {
        assert_eq!(normalize_email_address("   "), "");
    }

    #[test]
    fn normalize_email_handles_nested_angle_brackets() {
        // Malformed input: rfind('<') finds the innermost '<', then find('>')
        // from there finds the first '>', extracting "user@example.com".
        assert_eq!(
            normalize_email_address("Name <<user@example.com>>"),
            "user@example.com"
        );
    }

    // --- Attachments ---

    #[test]
    fn attachment_order_does_not_affect_fingerprint() {
        let a1 = make_attachment("application/pdf", Some("doc.pdf"), 1000);
        let a2 = make_attachment("image/png", Some("photo.png"), 2000);

        let m1 = make_metadata(
            Some("<id@example.com>"),
            "alice@example.com",
            None,
            None,
            "2024-01-01",
            "Test",
            vec![a1.clone(), a2.clone()],
        );
        let m2 = make_metadata(
            Some("<id@example.com>"),
            "alice@example.com",
            None,
            None,
            "2024-01-01",
            "Test",
            vec![a2, a1],
        );

        let f1 = compute_fingerprint(&m1).unwrap();
        let f2 = compute_fingerprint(&m2).unwrap();
        assert_eq!(f1, f2);
    }

    #[test]
    fn empty_attachments_list_works() {
        let m = make_metadata(
            Some("<id@example.com>"),
            "alice@example.com",
            None,
            None,
            "2024-01-01",
            "Test",
            vec![],
        );
        let fp = compute_fingerprint(&m).unwrap();
        assert_eq!(fp.len(), 64);
    }

    #[test]
    fn different_attachments_produce_different_fingerprints() {
        let m1 = make_metadata(
            Some("<id@example.com>"),
            "alice@example.com",
            None,
            None,
            "2024-01-01",
            "Test",
            vec![make_attachment("application/pdf", Some("a.pdf"), 100)],
        );
        let m2 = make_metadata(
            Some("<id@example.com>"),
            "alice@example.com",
            None,
            None,
            "2024-01-01",
            "Test",
            vec![make_attachment("image/png", Some("a.png"), 200)],
        );

        let f1 = compute_fingerprint(&m1).unwrap();
        let f2 = compute_fingerprint(&m2).unwrap();
        assert_ne!(f1, f2);
    }

    // --- All-empty metadata ---

    #[test]
    fn all_empty_metadata_produces_valid_fingerprint() {
        let m = make_metadata(None, "", None, None, "", "", vec![]);
        let fp = compute_fingerprint(&m).unwrap();
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn all_empty_with_message_id_produces_valid_fingerprint() {
        let m = make_metadata(Some(""), "", None, None, "", "", vec![]);
        let fp = compute_fingerprint(&m).unwrap();
        assert_eq!(fp.len(), 64);
    }

    // --- Unicode ---

    #[test]
    fn unicode_normalization_works() {
        let m1 = make_metadata(
            Some("<uni@example.com>"),
            "Ünïcödé User <user@example.com>",
            None,
            None,
            "2024-01-01",
            "Ünïcödé Subject 日本語",
            vec![],
        );
        let m2 = make_metadata(
            Some("<uni@example.com>"),
            "Ünïcödé User <user@example.com>",
            None,
            None,
            "2024-01-01",
            "Ünïcödé Subject 日本語",
            vec![],
        );

        let f1 = compute_fingerprint(&m1).unwrap();
        let f2 = compute_fingerprint(&m2).unwrap();
        assert_eq!(f1, f2);
        assert_eq!(f1.len(), 64);
    }

    #[test]
    fn unicode_case_folding_in_headers() {
        // Lowercase of "Ü" is "ü" — verify normalization handles it
        assert_eq!(normalize_header("  ÜBER  "), "über");
    }

    // --- Header normalization ---

    #[test]
    fn normalize_header_trims_and_lowercases() {
        assert_eq!(normalize_header("  Hello WORLD  "), "hello world");
    }

    #[test]
    fn normalize_header_empty_string() {
        assert_eq!(normalize_header(""), "");
    }

    // --- Body structure hash ---

    #[test]
    fn body_structure_hash_is_deterministic() {
        let attachments = vec![
            make_attachment("text/plain", Some("readme.txt"), 500),
            make_attachment("image/jpeg", Some("photo.jpg"), 3000),
        ];
        let h1 = compute_body_structure_hash(&attachments);
        let h2 = compute_body_structure_hash(&attachments);
        assert_eq!(h1, h2);
    }

    #[test]
    fn body_structure_hash_order_independent() {
        let a1 = make_attachment("text/plain", Some("readme.txt"), 500);
        let a2 = make_attachment("image/jpeg", Some("photo.jpg"), 3000);

        let h1 = compute_body_structure_hash(&[a1.clone(), a2.clone()]);
        let h2 = compute_body_structure_hash(&[a2, a1]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn body_structure_hash_empty_attachments() {
        let h = compute_body_structure_hash(&[]);
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn body_structure_hash_attachment_without_filename() {
        let a = make_attachment("application/octet-stream", None, 1024);
        let h = compute_body_structure_hash(&[a]);
        assert_eq!(h.len(), 64);
    }

    // --- Field separator prevents collision ---

    #[test]
    fn field_separator_prevents_collision() {
        // "ab" + "cd" should differ from "a" + "bcd" due to \x00 separator
        let m1 = make_metadata(
            Some("<ab>"),
            "cd@example.com",
            None,
            None,
            "2024-01-01",
            "subject",
            vec![],
        );
        let m2 = make_metadata(
            Some("<a>"),
            "bcd@example.com",
            None,
            None,
            "2024-01-01",
            "subject",
            vec![],
        );

        let f1 = compute_fingerprint(&m1).unwrap();
        let f2 = compute_fingerprint(&m2).unwrap();
        assert_ne!(f1, f2);
    }

    // --- Fallback uniqueness ---

    #[test]
    fn fallback_different_to_produces_different_fingerprints() {
        let m1 = make_metadata(
            None,
            "alice@example.com",
            Some("bob@example.com"),
            None,
            "2024-01-01",
            "Same",
            vec![],
        );
        let m2 = make_metadata(
            None,
            "alice@example.com",
            Some("carol@example.com"),
            None,
            "2024-01-01",
            "Same",
            vec![],
        );

        let f1 = compute_fingerprint(&m1).unwrap();
        let f2 = compute_fingerprint(&m2).unwrap();
        assert_ne!(f1, f2);
    }

    #[test]
    fn fallback_different_cc_produces_different_fingerprints() {
        let m1 = make_metadata(
            None,
            "alice@example.com",
            Some("bob@example.com"),
            Some("dave@example.com"),
            "2024-01-01",
            "Same",
            vec![],
        );
        let m2 = make_metadata(
            None,
            "alice@example.com",
            Some("bob@example.com"),
            Some("eve@example.com"),
            "2024-01-01",
            "Same",
            vec![],
        );

        let f1 = compute_fingerprint(&m1).unwrap();
        let f2 = compute_fingerprint(&m2).unwrap();
        assert_ne!(f1, f2);
    }
}
