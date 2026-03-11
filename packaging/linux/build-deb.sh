#!/usr/bin/env bash
# build-deb.sh — Build the Cyberbox Agent .deb package
#
# Prerequisites:
#   - Rust toolchain with musl target: rustup target add x86_64-unknown-linux-musl
#   - dpkg-deb (installed on Debian/Ubuntu by default)
#
# Usage:
#   ./packaging/linux/build-deb.sh [version]
#
# Output:
#   packaging/linux/cyberbox-agent_<version>_amd64.deb

set -euo pipefail

VERSION="${1:-0.1.0}"
ARCH="amd64"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PKG_NAME="cyberbox-agent"
PKG_DIR="$ROOT/packaging/linux/pkg-staging"
DEB_OUT="$ROOT/packaging/linux/${PKG_NAME}_${VERSION}_${ARCH}.deb"

echo "=== Building Cyberbox Agent .deb v${VERSION} ==="

# Step 1: Build static binary
echo "Building release binary (musl)..."
cd "$ROOT"
cargo build --release -p cyberbox-agent --target x86_64-unknown-linux-musl
BINARY="$ROOT/target/x86_64-unknown-linux-musl/release/cyberbox-agent"

if [ ! -f "$BINARY" ]; then
    echo "WARN: musl binary not found, trying default release build..."
    cargo build --release -p cyberbox-agent
    BINARY="$ROOT/target/release/cyberbox-agent"
fi

# Step 2: Create package structure
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/etc/cyberbox"
mkdir -p "$PKG_DIR/var/lib/cyberbox"
mkdir -p "$PKG_DIR/usr/lib/systemd/system"
mkdir -p "$PKG_DIR/usr/share/doc/cyberbox-agent"
mkdir -p "$PKG_DIR/usr/share/icons/hicolor/256x256/apps"

# Binary
cp "$BINARY" "$PKG_DIR/usr/bin/cyberbox-agent"
chmod 755 "$PKG_DIR/usr/bin/cyberbox-agent"
strip "$PKG_DIR/usr/bin/cyberbox-agent" 2>/dev/null || true

# Default config (conffile — dpkg won't overwrite user edits)
cp "$ROOT/apps/cyberbox-agent/agent.example.toml" "$PKG_DIR/etc/cyberbox/agent.toml"
chmod 644 "$PKG_DIR/etc/cyberbox/agent.toml"

# Logo / icon
if [ -f "$ROOT/web/cyberbox-ui/public/cyberboxlogo.png" ]; then
    cp "$ROOT/web/cyberbox-ui/public/cyberboxlogo.png" \
       "$PKG_DIR/usr/share/icons/hicolor/256x256/apps/cyberbox-agent.png"
fi

# Systemd unit
cat > "$PKG_DIR/usr/lib/systemd/system/cyberbox-agent.service" << 'UNIT'
[Unit]
Description=Cyberbox SIEM Agent
Documentation=https://github.com/cyberboxsiem/CyberboxSIEM
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/cyberbox-agent run --config /etc/cyberbox/agent.toml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/cyberbox
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT

# DEBIAN/control
cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: Cyberbox Security <security@cyberbox.dev>
Description: Cyberbox SIEM Agent — lightweight log-forwarding agent
 Collects system logs (file tail, journald, /proc monitoring, FIM)
 and forwards them to a CyberboxSIEM collector or API endpoint.
 .
 Features:
  - File tail with persistent bookmarks
  - systemd journal source
  - Linux process monitor (/proc polling)
  - File integrity monitoring (SHA-256)
  - Crash-safe disk-backed event queue (sled)
  - TLS output with custom CA pinning
  - Live config reload via API heartbeat
  - Self-update from GitHub Releases
Section: admin
Priority: optional
Homepage: https://github.com/cyberboxsiem/CyberboxSIEM
EOF

# DEBIAN/conffiles — mark config as user-editable
cat > "$PKG_DIR/DEBIAN/conffiles" << 'EOF'
/etc/cyberbox/agent.toml
EOF

# DEBIAN/postinst
cat > "$PKG_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/sh
set -e

# Create data directory
mkdir -p /var/lib/cyberbox/queue
chown root:root /var/lib/cyberbox

# Enable and start the service
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable cyberbox-agent.service
    systemctl start cyberbox-agent.service || true
    echo ""
    echo "Cyberbox Agent installed and started."
    echo "  Config:  /etc/cyberbox/agent.toml"
    echo "  Status:  systemctl status cyberbox-agent"
    echo "  Logs:    journalctl -u cyberbox-agent -f"
    echo ""
fi
EOF
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# DEBIAN/prerm
cat > "$PKG_DIR/DEBIAN/prerm" << 'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop cyberbox-agent.service || true
    systemctl disable cyberbox-agent.service || true
fi
EOF
chmod 755 "$PKG_DIR/DEBIAN/prerm"

# DEBIAN/postrm
cat > "$PKG_DIR/DEBIAN/postrm" << 'EOF'
#!/bin/sh
set -e
if [ "$1" = "purge" ]; then
    rm -rf /var/lib/cyberbox
    rm -rf /etc/cyberbox
fi
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
EOF
chmod 755 "$PKG_DIR/DEBIAN/postrm"

# Copyright
cat > "$PKG_DIR/usr/share/doc/cyberbox-agent/copyright" << EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: CyberboxSIEM
Source: https://github.com/cyberboxsiem/CyberboxSIEM

Files: *
Copyright: $(date +%Y) Cyberbox Security
License: Apache-2.0
EOF

# Step 3: Build .deb
echo "Building .deb package..."
dpkg-deb --build --root-owner-group "$PKG_DIR" "$DEB_OUT"

# Cleanup
rm -rf "$PKG_DIR"

SIZE=$(du -h "$DEB_OUT" | cut -f1)
echo ""
echo "=== .deb built successfully ==="
echo "  Output: $DEB_OUT"
echo "  Size:   $SIZE"
echo ""
echo "Install:   sudo dpkg -i $DEB_OUT"
echo "Uninstall: sudo dpkg -r cyberbox-agent"
echo "Purge:     sudo dpkg --purge cyberbox-agent"
