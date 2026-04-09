# email-backups

Pull-only IMAP email backup tool with move detection and archival retention. Written in Rust for memory safety when handling untrusted network data.

Connects to one or more IMAP accounts, downloads all emails into a local Maildir structure, detects server-side moves via composite fingerprinting, and never deletes emails locally — even when they are removed from the server.

## Quick start

1. Copy and edit the example configuration:

   ```bash
   cp config/config.example.toml config/config.toml
   # Edit config/config.toml with your IMAP account details
   ```

2. Start the backup daemon:

   ```bash
   docker compose up -d
   ```

3. Check the logs:

   ```bash
   docker compose logs -f
   ```

## Features

- **Multi-account support** — back up any number of IMAP accounts from a single configuration file
- **Move detection** — detects when emails are moved between folders on the server and mirrors the move locally instead of re-downloading
- **Archival retention** — emails deleted on the server are never removed from the local backup
- **Composite fingerprinting** — identifies emails using a SHA-256 hash of Message-ID, envelope metadata, and MIME structure, preventing false matches from duplicate Message-IDs or identical subjects
- **Crash-safe sync** — atomic Maildir writes (write to tmp, then rename) and ordered operations (filesystem first, then database) ensure interrupted syncs never corrupt data
- **Startup recovery** — automatically cleans up orphaned temp files and stale lock files from previous crashes
- **Daemon mode** — runs continuously with configurable polling intervals, or run a single sync cycle with `--once`
- **Dry-run mode** — logs what would happen without making any changes
- **Structured logging** — human-readable or JSON log output for monitoring and alerting
- **Flexible password management** — retrieve passwords from shell commands (pass, gpg, 1Password CLI), files (Docker secrets), or plaintext fallback
- **Folder filtering** — glob-style patterns to include or exclude IMAP folders per account
- **Stale backup warnings** — alerts when no successful sync has occurred within a configurable threshold
- **Graceful shutdown** — responds to SIGTERM/SIGINT and finishes the current operation before exiting
- **Maildir format** — standard one-file-per-email format compatible with mutt, neomutt, Thunderbird (via import), and other mail clients

## Configuration reference

### `[general]` section

| Field | Type | Default | Description |
|---|---|---|---|
| `maildir_path` | string | **required** | Root directory for Maildir storage |
| `state_db` | string | **required** | Path to the SQLite state database |
| `log_level` | string | `"info"` | Log verbosity: `trace`, `debug`, `info`, `warn`, `error` |
| `sync_interval_seconds` | integer | `300` | Polling interval for daemon mode (minimum: 60) |
| `stale_threshold_days` | integer | `7` | Warn after this many days without a successful sync |
| `max_email_size_bytes` | integer | `104857600` | Skip emails larger than this (default: 100 MB) |
| `imap_timeout_seconds` | integer | `60` | Timeout for IMAP operations |
| `fsync_on_write` | boolean | `true` | Fsync Maildir writes for crash safety |

### `[[account]]` section

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | string | **required** | Unique account name (used as Maildir subdirectory) |
| `host` | string | **required** | IMAP server hostname |
| `port` | integer | `993` | IMAP server port |
| `tls` | boolean | `true` | Use TLS (required, plaintext connections are rejected) |
| `username` | string | **required** | IMAP username |
| `password_command` | string | | Shell command that prints the password to stdout |
| `password_file` | string | | Path to a file containing the password |
| `password_env` | string | | Name of an environment variable containing the password |
| `password` | string | | Plaintext password (not recommended) |
| `folder_patterns` | string[] | `["*"]` | Glob-style patterns controlling which folders to sync (see below) |

Exactly one of `password_command`, `password_file`, `password_env`, or `password` must be set per account. Priority order: `password_command` > `password_file` > `password_env` > `password`.

### Folder patterns

The `folder_patterns` field controls which IMAP folders are synced. Patterns are evaluated in order and the last matching pattern wins. Prefix a pattern with `!` to exclude matching folders. Wildcards `*` (any characters) and `?` (single character) are supported.

| Pattern | Effect |
|---|---|
| `["*"]` | Sync all folders (default) |
| `["*", "!Trash", "!Spam"]` | Sync everything except Trash and Spam |
| `["INBOX", "Sent"]` | Sync only INBOX and Sent |
| `["*", "!Draft*"]` | Exclude Drafts and any Draft subfolders |
| `["Archive/*"]` | Sync only Archive subfolders |

If no patterns match a folder, the folder is excluded. An empty list excludes all folders.

See [`config/config.example.toml`](config/config.example.toml) for a fully commented example.

## Deployment

### Docker Compose (recommended)

The default `docker-compose.yml` uses named volumes for data persistence:

```bash
cp config/config.example.toml config/config.toml
# Edit config/config.toml
docker compose up -d
```

The container runs as a non-root `mailbackup` user and starts in daemon mode with JSON logging by default.

#### Container credential strategies

For containers, use `password_file` or `password_env` instead of `password_command`. The container image only includes `ca-certificates` — tools like `pass` or `gpg` are not available. If you need `password_command`, the command's dependencies must be installed in a custom image.

**Using `password_env` with docker-compose environment variables:**

```yaml
# docker-compose.yml
services:
  email-backup:
    environment:
      - IMAP_PASSWORD_PERSONAL=your-password-here
```

```toml
# config.toml
[[account]]
name = "personal"
host = "imap.example.com"
username = "user@example.com"
password_env = "IMAP_PASSWORD_PERSONAL"
```

**Using `password_file` with mounted secret files:**

```yaml
# docker-compose.yml
services:
  email-backup:
    secrets:
      - email_password
secrets:
  email_password:
    file: ./secrets/email-password.txt
```

```toml
# config.toml
[[account]]
name = "personal"
host = "imap.example.com"
username = "user@example.com"
password_file = "/run/secrets/email_password"
```

### Synology NAS

See [`examples/synology/`](examples/synology/) for a Docker Compose override with Synology volume paths and a detailed setup guide.

### Bare metal with systemd

Build the binary and create a systemd service:

```bash
cargo build --release
sudo cp target/release/email-backups /usr/local/bin/

sudo tee /etc/systemd/system/email-backups.service > /dev/null << 'EOF'
[Unit]
Description=IMAP email backup daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mailbackup
ExecStart=/usr/local/bin/email-backups --config /etc/email-backups/config.toml --daemon
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now email-backups
```

### Bare metal with cron

For periodic sync without a persistent daemon:

```bash
# Run every 5 minutes
*/5 * * * * /usr/local/bin/email-backups --config /etc/email-backups/config.toml --once
```

## How it works

### Sync logic

Each sync cycle performs these steps per account:

1. Connect to the IMAP server via TLS and authenticate.
2. List all folders (applying folder pattern filters).
3. For each folder, fetch message metadata (envelope, BODYSTRUCTURE) without downloading message bodies.
4. Compute a composite fingerprint for each message using its envelope metadata and MIME structure.
5. Compare server state against the local state database to produce sync actions:
   - **Download** — fingerprint exists on server but not locally.
   - **Move** — fingerprint exists on server in folder B, locally only in folder A.
   - **Copy** — fingerprint exists on server in folders A and B, locally only in A.
   - **Archive** — fingerprint absent from server, present locally (kept as-is).
   - **Skip** — fingerprint already backed up in the correct location.
6. Execute actions in crash-safe order: filesystem writes first, then database updates.
7. Update folder sync progress (highest synced UID) for incremental sync on the next run.

### Composite fingerprinting

Emails are identified by a SHA-256 hash of normalized metadata:

- **With Message-ID**: `Message-ID + Date + From + Subject + attachment metadata + body structure hash`
- **Without Message-ID** (fallback): `From + To + Cc + Date + Subject + attachment metadata + body structure hash`

Attachment metadata (MIME type, filename, size) is extracted from IMAP BODYSTRUCTURE without downloading attachment content, keeping identification fast and bandwidth-efficient.

This composite approach prevents false matches from duplicate Message-IDs (common with broken mail software) or identical subjects.

### Move detection

When a message disappears from one folder and appears in another on the server, the fingerprint remains the same. The sync planner detects this pattern and moves the local file instead of re-downloading it, saving bandwidth and preserving the file's modification time.

## Recovery

### Hard shutdown recovery

If the process is killed (power failure, OOM, SIGKILL), the next startup automatically:

1. Cleans up orphaned temp files in Maildir `tmp/` directories.
2. Checks database integrity.
3. Detects and removes stale lock files from dead processes.

No manual intervention is required. The crash-safe write ordering (filesystem first, database second) means the worst case is a downloaded email that is not yet recorded in the database — it will be re-detected and skipped on the next sync.

### Verifying backup integrity

The state database records every known message fingerprint and its local file path. To verify that all recorded messages exist on disk, inspect the state database directly:

```bash
sqlite3 /path/to/state.db "SELECT fingerprint, local_path FROM locations WHERE local_path NOT NULL" | while IFS='|' read -r fp path; do
  [ -f "$path" ] || echo "MISSING: $fp -> $path"
done
```

## CLI reference

```
email-backups [OPTIONS] --config <PATH>
```

| Flag | Description |
|---|---|
| `--config <PATH>` | Path to the TOML configuration file (required) |
| `--once` | Run a single sync cycle and exit (default behavior) |
| `--daemon` | Run continuously, polling at the configured interval |
| `--dry-run` | Log what would happen without making changes |
| `--account <NAME>` | Sync only the named account |
| `-v, --verbose` | Increase log verbosity (`-v` = debug, `-vv` = trace) |
| `--log-format <FORMAT>` | Log output format: `human` (default) or `json` |
| `--version` | Print version information |
| `--help` | Print help |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | All accounts synced successfully |
| `1` | All accounts failed |
| `2` | Partial failure (some accounts succeeded, some failed) |

## Building from source

### Prerequisites

- Rust 1.85 or later (edition 2024)
- A C compiler (for SQLite bundled build via rusqlite)

### Build

```bash
cargo build --release
```

The binary is at `target/release/email-backups`.

### Test

```bash
cargo test
```

### Lint and format

```bash
cargo fmt --check
cargo clippy
```

## License

TBD
