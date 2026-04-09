# src/

Source code for the IMAP email backup tool.

## Modules

| File | Purpose |
|---|---|
| `main.rs` | CLI entry point, argument parsing (clap), logging setup, top-level orchestration |
| `error.rs` | Central error types using `thiserror` — one enum per domain (config, IMAP, state, storage, sync, fingerprint, recovery) |
| `types.rs` | Shared domain types — message metadata, folder info, sync actions, sync reports |
| `config.rs` | TOML configuration loading, parsing, validation, and password resolution |
| `fingerprint.rs` | Pure functions for composite fingerprint computation (SHA-256 of normalized message metadata) |
| `sync_plan.rs` | Pure sync planning logic — compares server state vs local state and produces sync actions |
| `state.rs` | SQLite state database — `StateDb` trait and `SqliteStateDb` implementation for tracking messages, locations, folders, and sync progress |
| `imap_client.rs` | IMAP client — `ImapClient` async trait and `AsyncImapClient` production implementation with TLS, BODYSTRUCTURE/ENVELOPE parsing, and `MockImapClient` for testing |
| `maildir.rs` | Maildir storage — `MaildirStore` trait and `FsMaildirStore` implementation with atomic writes and folder name sanitization |
| `recovery.rs` | Startup recovery — orphaned tmp cleanup, database integrity checks, stale lock file detection |
| `shutdown.rs` | Graceful shutdown signaling — `ShutdownController`/`ShutdownSignal` pair using `tokio::sync::watch`, SIGTERM/SIGINT handler registration |
| `sync.rs` | Sync engine orchestration — `SyncEngine` drives per-account sync cycles: IMAP connect, folder iteration, action execution with crash-safe ordering (filesystem first, then DB) |

## When to modify

- **Adding a new CLI flag or subcommand** — modify `main.rs`
- **Adding a new error variant** — modify `error.rs`
- **Adding or changing a domain type** — modify `types.rs`
- **Changing configuration options or validation** — modify `config.rs`
- **Changing fingerprint algorithm or normalization** — modify `fingerprint.rs`
- **Changing sync planning logic (move/copy/download/archive decisions)** — modify `sync_plan.rs`
- **Changing state persistence (messages, locations, folders, sync log)** — modify `state.rs`
- **Changing IMAP connection, authentication, or metadata parsing** — modify `imap_client.rs`
- **Changing local email storage (Maildir operations, folder sanitization)** — modify `maildir.rs`
- **Changing startup recovery (tmp cleanup, integrity checks, lock files)** — modify `recovery.rs`
- **Changing shutdown signal handling or cooperative cancellation** — modify `shutdown.rs`
- **Changing sync orchestration (per-account flow, folder iteration, action execution, crash safety)** — modify `sync.rs`
- **Changing one-shot/daemon mode behavior, lock file management, or stale backup detection** — modify `main.rs`
- **Adding a new module** — create the file here and register it in `main.rs` with `mod`; update this README
