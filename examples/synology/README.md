# Synology NAS Deployment

This guide covers deploying email-backups on a Synology NAS using Docker (Container Manager).

## Prerequisites

- Synology DSM 7.0 or later
- Container Manager package installed (or Docker package on older DSM versions)
- SSH access to the NAS (for initial setup)

## Setup

### 1. Create directories

SSH into your NAS and create the required directories:

```bash
sudo mkdir -p /volume1/docker/email-backups/config
sudo mkdir -p /volume1/docker/email-backups/state
sudo mkdir -p /volume1/mail-backup/maildir
```

Set ownership to your NAS user. Replace `1026` with your actual UID (find it with `id -u <username>`):

```bash
sudo chown -R 1026:100 /volume1/docker/email-backups
sudo chown -R 1026:100 /volume1/mail-backup
```

### 2. Create the configuration file

Copy the example configuration:

```bash
cp config.example.toml /volume1/docker/email-backups/config/config.toml
```

Edit the config file. The paths inside the container are:

| Host path | Container path | Purpose |
|---|---|---|
| `/volume1/mail-backup/maildir` | `/data/maildir` | Maildir email storage |
| `/volume1/docker/email-backups/state` | `/data/state` | SQLite state database |
| `/volume1/docker/email-backups/config` | `/config` | Configuration file |

Your `config.toml` should use the **container paths** (i.e., `/data/maildir` and `/data/state/state.db`), not the host paths.

### 3. Configure password retrieval

On a Synology NAS, the simplest approach is to use a password file:

```bash
# Create a password file with restrictive permissions
echo -n "your-imap-password" > /volume1/docker/email-backups/config/password.txt
chmod 600 /volume1/docker/email-backups/config/password.txt
```

In your `config.toml`, use:

```toml
password_file = "/config/password.txt"
```

Since the config directory is mounted read-only into the container, the password file is not writable by the application.

### 4. Find your UID and GID

The `docker-compose.yml` in this directory uses `user: "1026:100"` by default. You need to replace this with your actual UID:

```bash
id -u your-username    # Typically 1026, 1027, etc.
id -g your-username    # Typically 100 (users group)
```

Edit `docker-compose.yml` and update the `user:` line.

### 5. Build and start

Copy the project files to your NAS, then:

```bash
cd /path/to/email-backups
docker compose -f examples/synology/docker-compose.yml up -d
```

Alternatively, build the image once and use it:

```bash
docker build -t email-backups:latest .
docker compose -f examples/synology/docker-compose.yml up -d
```

### 6. Verify

Check the logs:

```bash
docker compose -f examples/synology/docker-compose.yml logs -f
```

You should see the daemon starting and performing its first sync cycle.

## Hyper Backup integration

The Maildir data at `/volume1/mail-backup/` is a standard directory of files. You can include it in a Hyper Backup task for off-site backup to Synology C2, an external drive, or another NAS.

The state database at `/volume1/docker/email-backups/state/` should also be included in backups — it tracks sync progress and avoids re-downloading emails after a restore.

## Performance tuning

On NAS devices, consider setting `fsync_on_write = false` in your config to reduce disk I/O. This is acceptable when the NAS has a UPS or battery backup. Without fsync, a power failure during a write could leave a partially-written email file, but startup recovery will clean up orphaned temp files on the next run.

## Updating

To update to a new version:

```bash
cd /path/to/email-backups
git pull
docker compose -f examples/synology/docker-compose.yml build
docker compose -f examples/synology/docker-compose.yml up -d
```

## Troubleshooting

**Permission denied errors**: Verify the `user:` line in `docker-compose.yml` matches your NAS user's UID:GID, and that the host directories are owned by that user.

**Cannot connect to IMAP server**: Verify the NAS can reach the IMAP server. Some Synology firewall rules may block outbound connections on port 993. Check Control Panel > Security > Firewall.

**State database locked**: Only one instance of email-backups can run at a time. Check that no other container is using the same state directory. The tool detects stale lock files from crashed instances and recovers automatically.
