#!/bin/bash

# ==================================================================================== #
# Ocserv v1.5.0 Builder Script for Ubuntu 22.04                                        #
#                                                                                      #
# This script compiles ocserv from source but does NOT install it on the host system.  #
# Its sole purpose is to produce a self-contained tar.gz package containing all        #
# compiled artifacts (binaries, libraries, man pages, systemd service file, etc.).     #
#                                                                                      #
# This package can then be transferred to other compatible servers and extracted       #
# at the root directory ('/') to deploy ocserv without needing to recompile.           #
#                                                                                      #
# Usage: Run this script as root or via sudo.                                          #
# ==================================================================================== #

# Exit immediately if a command exits with a non-zero status.
set -euo pipefail

# Ensure the script is run as root.
if [[ $(id -u) -ne 0 ]]; then
  echo "Please run this script as root or using sudo." >&2
  exit 1
fi

# --- STEP 1: Install Build Dependencies ---
echo "Updating package lists and installing build dependencies..."
apt-get update
apt-get install -y \
  build-essential git pkg-config meson ninja-build \
  libgnutls28-dev libev-dev liblz4-dev libseccomp-dev \
  libreadline-dev libnl-route-3-dev libkrb5-dev libradcli-dev \
  libpam0g-dev libpam-radius-auth libcurl4-gnutls-dev libcjose-dev \
  libjansson-dev libprotobuf-c-dev libtalloc-dev \
  libhttp-parser-dev protobuf-c-compiler gperf \
  gawk gnutls-bin iproute2 yajl-tools tcpdump ipcalc

# --- STEP 2: Download and Prepare Source Code ---
echo "Creating a working directory in /usr/local/src..."
mkdir -p /usr/local/src
cd /usr/local/src

# Download (or re-download if tarball is missing/corrupt) the 1.5.0 release tarball.
TARBALL="ocserv-1.5.0.tar.xz"
TARBALL_URL="https://www.infradead.org/ocserv/download/${TARBALL}"

if [[ -f "$TARBALL" ]]; then
  echo "Verifying existing tarball..."
  if ! tar -tf "$TARBALL" > /dev/null 2>&1; then
    echo "Tarball is corrupt. Re-downloading..."
    rm -f "$TARBALL"
  fi
fi

if [[ ! -f "$TARBALL" ]]; then
  echo "Downloading ocserv 1.5.0 source tarball..."
  wget -O "$TARBALL" "$TARBALL_URL"
fi

echo "Detecting source directory inside tarball..."
# Temporarily disable pipefail: when 'head -1' exits after reading one line,
# tar receives SIGPIPE and exits non-zero, which would cause pipefail to abort the script.
set +o pipefail
SRC_DIR=$(tar -tf "$TARBALL" 2>/dev/null | head -1 | cut -d/ -f1)
set -o pipefail

if [[ -z "$SRC_DIR" ]]; then
  echo "ERROR: Could not determine source directory from tarball. The file may be corrupt." >&2
  rm -f "$TARBALL"
  exit 1
fi
echo "Source directory: ${SRC_DIR}"

echo "Extracting source code..."
rm -rf "$SRC_DIR"
tar -xf "$TARBALL"
cd "$SRC_DIR"

echo "--- STEP 3: Compile the Software (Meson build system) ---"

BUILD_DIR="builddir"
rm -rf "$BUILD_DIR"

echo "Configuring the build with Meson (prefix=/usr/local)..."
meson setup "$BUILD_DIR" --prefix=/usr/local --buildtype=release

echo "Building ocserv using all available CPU cores..."
ninja -C "$BUILD_DIR" -j"$(nproc)"

# --- STEP 4: Package the Compiled Artifacts ---
echo "Packaging all compiled files into a tar.gz archive..."
PKG_STAGE_DIR="/tmp/ocserv-package"
rm -rf "$PKG_STAGE_DIR"
mkdir -p "$PKG_STAGE_DIR"

# Use 'ninja install' with DESTDIR to populate the staging directory.
DESTDIR="$PKG_STAGE_DIR" ninja -C "$BUILD_DIR" install

# ocserv 1.5.0 (Meson build) does not install a systemd service file automatically.
# We generate a correct, production-ready service file and place it at the standard
# system path (/etc/systemd/system/) so systemctl can find it without extra configuration.
echo "Generating and injecting systemd service file into the package..."
SERVICE_INSTALL_DIR="$PKG_STAGE_DIR/etc/systemd/system"
mkdir -p "$SERVICE_INSTALL_DIR"
cat > "$SERVICE_INSTALL_DIR/ocserv.service" << 'EOF'
[Unit]
Description=OpenConnect SSL VPN server
Documentation=man:ocserv(8)
After=network-online.target
Wants=network-online.target
ConditionPathExists=/etc/ocserv/ocserv.conf

[Service]
Type=forking
PIDFile=/run/ocserv.pid
ExecStart=/usr/local/sbin/ocserv --config /etc/ocserv/ocserv.conf --pid-file /run/ocserv.pid --foreground
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

# Security hardening
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/run /etc/ocserv /var/lib/ocserv /var/log

[Install]
WantedBy=multi-user.target
EOF
echo "Service file written to: ${SERVICE_INSTALL_DIR}/ocserv.service"

# Meson installs the firewall script as 'ocserv-fw-nftables'; rename it to 'ocserv-fw'
# to match the expected binary name used by the install script.
FW_SRC="$PKG_STAGE_DIR/usr/local/libexec/ocserv-fw-nftables"
FW_DST="$PKG_STAGE_DIR/usr/local/libexec/ocserv-fw"
if [[ -f "$FW_SRC" ]]; then
  mv "$FW_SRC" "$FW_DST"
  echo "Renamed ocserv-fw-nftables → ocserv-fw"
fi

# Define the final package path and name.
PACKAGE_TAR="/root/ocserv-1.5.0-local.tar.gz"

# Create the final tarball. The -C flag ensures paths are relative inside the archive
# (e.g., 'usr/local/sbin/ocserv' instead of an absolute path).
tar -C "$PKG_STAGE_DIR" -czf "$PACKAGE_TAR" .

# Clean up the temporary staging directory.
rm -rf "$PKG_STAGE_DIR"

# --- COMPLETE ---
GREEN=$(tput setaf 2)
RESET=$(tput sgr0)

echo "============================================================="
echo "Build and packaging complete!"
echo ""
echo "Package created at: ${GREEN}${PACKAGE_TAR}${RESET}"
echo ""
echo "Installation command: ${GREEN}curl -sSL https://raw.githubusercontent.com/ArashAfkandeh/Ocserv-Installer/main/install_ocserv.sh | sudo bash${RESET}"
echo "============================================================="
