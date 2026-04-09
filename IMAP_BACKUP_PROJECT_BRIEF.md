# Project Brief: IMAP Email Backup Tool

## First Step — Before Writing Any Code

**Ask the user where to find the coding guidelines and style rules for this project.** Do not generate any code, scaffolding, or file structure until you have received and read the coding guidelines.

---

## Overview

Build a command-line IMAP backup tool in **Rust**. The tool connects to one or more IMAP accounts, downloads all emails into a local directory structure, and maintains an ongoing backup with the following key behaviors:

1. **New emails** on the server are downloaded to the corresponding local folder.
2. **Moved emails** (email disappears from folder A, appears in folder B on the server) are detected and the local copy is moved accordingly — not re-downloaded.
3. **Deleted emails** (email disappears from the server entirely) are **kept locally** — they are never removed from the backup.
4. **New folders** on the server are created locally.
5. **Deleted folders** on the server are kept locally (archival behavior).

## Core Design Requirement: Move Detection

IMAP has no native "move" event. A move is a copy-to-new-folder followed by a delete-from-old-folder. The tool must detect this pattern by matching emails across folders using a **composite fingerprint** — not just a single header field, since subjects can be identical across different emails and `Message-ID` headers can be missing or duplicated in the wild.

### Message Identification Strategy

Identify each email by computing a **composite fingerprint** from multiple properties. This fingerprint is the key used for move detection, deduplication, and "have I already downloaded this?" checks.

**Primary identifier: `Message-ID` header + envelope metadata**

When a `Message-ID` header is present, combine it with:
- `Date` header
- `From` header
- `Subject` header

This combination prevents false matches when different emails happen to share the same `Message-ID` (it happens with broken mail software) or the same subject line.

**Attachment metadata as additional differentiator:**

Two emails can have identical subject, sender, and date but differ in their attachments. Include attachment metadata in the fingerprint:
- Number of MIME parts / attachments
- For each attachment: filename (if present), MIME type, and size in bytes

Do **not** download full attachment bodies just for identification — use only the metadata available from IMAP `BODYSTRUCTURE` (RFC 3501), which provides MIME type, size, filename, and encoding without fetching the actual content. This keeps identification fast and bandwidth-efficient.

**Fallback: content hash**

For emails that lack a `Message-ID` entirely (e.g. drafts, some auto-generated messages), compute a SHA-256 hash over:
- `From`, `To`, `Cc`, `Date`, `Subject` headers (normalized: trimmed, lowercased)
- Attachment metadata (as above)
- Body structure fingerprint (MIME tree shape, part sizes)

**Final composite fingerprint:**

```
fingerprint = SHA-256(
    message_id || date || from || subject ||
    attachment_count ||
    for each attachment: (mime_type || filename || size) ||
    body_structure_hash
)
```

Store both the raw `Message-ID` (for quick lookups) and the full composite fingerprint (for definitive matching) in the state database.

### Sync Logic (per run)

1. Connect to the IMAP server, list all folders.
2. For each folder, fetch the list of messages with: UID, `Message-ID`, envelope (`Date`, `From`, `Subject`), and `BODYSTRUCTURE` (for attachment metadata). All of this is available via IMAP `FETCH` without downloading message bodies.
3. Compute the composite fingerprint for each server-side message.
4. Compare with the local state database:
   - **Fingerprint present on server, absent locally** → download and store.
   - **Fingerprint present on server in folder B, locally only in folder A** → move the local file from A to B.
   - **Fingerprint present on server in folders A and B, locally only in A** → copy local file to B.
   - **Fingerprint absent from server entirely, present locally** → keep local copy (archived, do nothing).
5. Update the local state database.

### State Database

Maintain a local SQLite database with at minimum:

- **messages table**: `fingerprint` (primary key), `message_id` (nullable, indexed for fast lookups), `subject`, `from`, `date`, `attachment_count`, `body_structure_hash`, `first_seen timestamp`
- **locations table**: `fingerprint` (FK), `folder`, `local_path`, `imap_uid` (nullable), `last_seen_on_server timestamp`
- **folders table**: `folder_name`, `uid_validity`, `highest_synced_uid` (for efficient incremental sync using IMAP UID ranges)

The fingerprint is the authoritative identity of a message across the entire backup. The `message_id` column serves as a fast-path index for the common case but is never trusted alone.

## Local Storage Format

Use **Maildir** format (one file per email, folder hierarchy mirrors the IMAP hierarchy). This is a well-understood standard, works with many mail clients (Thunderbird via import, mutt, neomutt, etc.), and avoids corruption risks of mbox.

## Configuration

TOML configuration file, supporting multiple accounts. Example structure:

```toml
[general]
backup_dir = "/srv/mail-backup"
state_db = "/srv/mail-backup/state.db"
log_level = "info"

[[account]]
name = "personal"
host = "imap.example.com"
port = 993
tls = true
username = "user@example.com"
# Password retrieval: support at least one of these
password_command = "pass show email/personal"  # shell command that prints password to stdout
# password_file = "/run/secrets/email-password"
# password = "plaintext-fallback-not-recommended"

# Optional: glob-style folder patterns (default: ["*"] = sync all)
# folder_patterns = ["*", "!Trash", "!Spam"]
```

## Non-Functional Requirements

- **Security**: This tool handles untrusted data from the network. Rust's memory safety is a key reason for this language choice. Use well-maintained crates for IMAP and TLS. Validate and sanitize all server responses. No `unsafe` blocks without explicit justification.
- **Reliability**: Crash-safe — interrupted syncs must not corrupt the state database or local mail store. Use SQLite transactions. Write new Maildir files atomically (write to tmp, then rename).
- **Performance**: Support IMAP pipelining where possible. Avoid re-downloading emails that are already present locally. Use UID ranges for incremental sync.
- **Logging**: Structured logging with configurable verbosity. Log every significant action (download, move, skip, error) so the user can audit what happened.
- **Dry-run mode**: A `--dry-run` flag that logs what would happen without making any changes.
- **Testability**: Design for testability — trait-based abstractions over IMAP connections to allow mock-based unit testing without a real server.

## Suggested Crate Ecosystem (verify current state before use)

- `imap` or `async-imap` — IMAP client
- `native-tls` or `rustls` — TLS
- `rusqlite` — SQLite
- `toml` + `serde` — config parsing
- `clap` — CLI argument parsing
- `tracing` or `env_logger` — logging
- `sha2` — content hashing fallback
- `maildir` — Maildir operations (or implement manually, it is a simple format)

**Verify that these crates are actively maintained and have no known security issues before committing to them.**

## Out of Scope (for now)

- Sending email / SMTP
- Two-way sync (local changes pushed to server)
- Web UI or GUI
- Full-text search indexing
- OAuth2 (can be added later; start with password-based auth)

## Summary

The goal is a focused, security-conscious, single-purpose tool: pull-only IMAP backup with move detection and archival retention. Written in Rust for memory safety when handling untrusted network data. The key differentiator over existing tools (mbsync, OfflineIMAP, imap-backup) is native move detection via Message-ID tracking combined with a strict "never delete locally" policy.
