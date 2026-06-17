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

set -euo pipefail

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
set +o pipefail
SRC_DIR=$(tar -tf "$TARBALL" 2>/dev/null | head -1 | cut -d/ -f1)
set -o pipefail

if [[ -z "$SRC_DIR" ]]; then
  echo "ERROR: Could not determine source directory from tarball." >&2
  rm -f "$TARBALL"
  exit 1
fi
echo "Source directory: ${SRC_DIR}"

echo "Extracting source code..."
rm -rf "$SRC_DIR"
tar -xf "$TARBALL"
cd "$SRC_DIR"

# --- STEP 3: Compile ---
echo "--- STEP 3: Compile the Software (Meson) ---"
BUILD_DIR="builddir"
rm -rf "$BUILD_DIR"

echo "Configuring with Meson..."
meson setup "$BUILD_DIR" --prefix=/usr/local --buildtype=release

echo "Building..."
ninja -C "$BUILD_DIR" -j"$(nproc)"

# --- STEP 4: Package with Custom Structure ---
echo "Packaging all compiled files into a tar.gz archive with custom structure..."
PKG_STAGE_DIR="/tmp/ocserv-package"
rm -rf "$PKG_STAGE_DIR"
mkdir -p "$PKG_STAGE_DIR"

# Install normally first
DESTDIR="$PKG_STAGE_DIR" ninja -C "$BUILD_DIR" install

# === فایل سرویس دقیقاً مثل v1.3.0 ===
echo "Installing and patching systemd service file (exactly like v1.3.0)..."
SERVICE_FILE_PATH="$PKG_STAGE_DIR/usr/local/lib/systemd/system/ocserv.service"
mkdir -p "$(dirname "$SERVICE_FILE_PATH")"

cat > "$SERVICE_FILE_PATH" << 'EOF'
[Unit]
Description=OpenConnect SSL VPN server
Documentation=man:ocserv(8)
After=network-online.target

[Service]
PrivateTmp=true
PIDFile=/run/ocserv.pid
Type=simple
ExecStart=/usr/sbin/ocserv --log-stderr --foreground --pid-file /run/ocserv.pid --config /etc/ocserv/ocserv.conf
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
EOF

# اعمال پچ مسیر
sed -i 's#ExecStart=/usr/sbin/ocserv#ExecStart=/usr/local/sbin/ocserv#g' "$SERVICE_FILE_PATH"

# Rename firewall script
FW_SRC="$PKG_STAGE_DIR/usr/local/libexec/ocserv-fw-nftables"
FW_DST="$PKG_STAGE_DIR/usr/local/libexec/ocserv-fw"
if [[ -f "$FW_SRC" ]]; then
  mv "$FW_SRC" "$FW_DST"
  echo "Renamed ocserv-fw-nftables → ocserv-fw"
fi

# === ساختار درخواستی: lib → etc و در کنار usr ===
echo "Restructuring package: moving 'lib' contents to 'etc' at root level..."

# Move everything under usr/local/lib to a new top-level etc/
if [[ -d "$PKG_STAGE_DIR/usr/local/lib" ]]; then
  mkdir -p "$PKG_STAGE_DIR/etc"
  mv "$PKG_STAGE_DIR/usr/local/lib"/* "$PKG_STAGE_DIR/etc/" 2>/dev/null || true
  rmdir "$PKG_STAGE_DIR/usr/local/lib" 2>/dev/null || true
  echo "Moved lib contents to top-level etc/"
fi

# Also ensure systemd service is in the right place inside etc
if [[ -f "$PKG_STAGE_DIR/etc/systemd/system/ocserv.service" ]]; then
  mkdir -p "$PKG_STAGE_DIR/etc/systemd/system"
  # Already handled above
  :
fi

# Final package
PACKAGE_TAR="/root/ocserv-1.5.0-local.tar.gz"
tar -C "$PKG_STAGE_DIR" -czf "$PACKAGE_TAR" .

rm -rf "$PKG_STAGE_DIR"

# --- COMPLETE ---
GREEN=$(tput setaf 2)
RESET=$(tput sgr0)
echo "============================================================="
echo "Build and packaging complete!"
echo ""
echo "Package created at: ${GREEN}${PACKAGE_TAR}${RESET}"
echo "Structure inside tar.gz: usr/ and etc/ (side by side)"
echo "============================================================="
