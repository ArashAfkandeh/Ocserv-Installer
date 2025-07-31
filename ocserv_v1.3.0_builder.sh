#!/bin/bash

# ==================================================================================== #
# Ocserv v1.3.0 Builder Script for Ubuntu 22.04                                        #
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
  build-essential git pkg-config autoconf automake libtool \
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

# Download the 1.3.0 release tarball if it doesn't exist.
TARBALL="ocserv-1.3.0.tar.xz"
if [[ ! -f "$TARBALL" ]]; then
  wget -O "$TARBALL" "https://www.infradead.org/ocserv/download/${TARBALL}"
fi

echo "Extracting source code..."
rm -rf ocserv-1.3.0
tar -xf "$TARBALL"
cd ocserv-1.3.0

# --- STEP 3: Compile the Software ---
echo "Generating the configure script..."
autoreconf -fvi

echo "Configuring the build..."
# The default install prefix (/usr/local) will be used inside the package.
./configure

echo "Building ocserv using all available CPU cores..."
make -j"$(nproc)"

# --- STEP 4: Package the Compiled Artifacts ---
# Instead of a system-wide 'make install', we install all files into a temporary
# staging directory. This allows us to package everything reliably.

echo "Packaging all compiled files into a tar.gz archive..."
PKG_STAGE_DIR="/tmp/ocserv-package"
rm -rf "$PKG_STAGE_DIR"
mkdir -p "$PKG_STAGE_DIR"

# Use 'make install' with DESTDIR to populate the staging directory.
# This installs all files (including ocserv-worker) into the temp dir, not the host system.
make install DESTDIR="$PKG_STAGE_DIR"

# The systemd service file installed into the staging directory has the default,
# incorrect path. We must patch it *inside the package* to point to our binary.
SERVICE_FILE_PATH="$PKG_STAGE_DIR/usr/local/lib/systemd/system/ocserv.service"
if [[ -f "$SERVICE_FILE_PATH" ]]; then
  echo "Patching systemd service file inside the package..."
  sed -i 's#ExecStart=/usr/sbin/ocserv#ExecStart=/usr/local/sbin/ocserv#g' "$SERVICE_FILE_PATH"
else
  echo "Warning: Systemd service file not found at the expected path. The package may not work correctly."
fi

# Define the final package path and name.
PACKAGE_TAR="/root/ocserv-1.3.0.tar.gz"

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
echo "============================================================="
