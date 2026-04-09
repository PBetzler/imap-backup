# Stage 1: Builder
FROM rust:latest AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

# Stage 2: Runtime (minimal)
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="email-backups" \
      org.opencontainers.image.description="IMAP email backup tool with move detection and archival retention" \
      org.opencontainers.image.version="0.1.0"

# Install CA certificates (required for TLS/rustls-native-certs).
# Note: Only ca-certificates is installed to keep the image small. For container
# deployments, use password_file (with Docker secrets or mounted files) or
# password_env (with environment variables) instead of password_command. If you
# need password_command, the command's dependencies (e.g. pass, gpg) must be
# installed manually in this image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r mailbackup && useradd -r -g mailbackup -d /data mailbackup

# Copy binary
COPY --from=builder /app/target/release/email-backups /usr/local/bin/email-backups

# Create data directories
RUN mkdir -p /data/maildir /data/state /config \
    && chown -R mailbackup:mailbackup /data

USER mailbackup

ENTRYPOINT ["email-backups"]
CMD ["--config", "/config/config.toml", "--daemon", "--log-format", "json"]
