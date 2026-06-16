#!/bin/bash

# --- Strict Mode & Logging ---
set -eE -o pipefail
exec > >(tee -i /var/log/ocserv_installer.log) 2>&1

# This script installs ocserv from a pre-compiled package, configures Dual-Stack Networking,
# and downloads the management panel from GitHub.
# Usage: sudo ./install_ocserv.sh [PORT] [DOMAIN] [RADIUS_IP] [RADIUS_SECRET] [DNS_CHOICE]

# --- UI Color Definitions ---
C_OFF='\033[0m'; C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m'; C_BLUE='\033[0;34m'; C_PURPLE='\033[0;35m'; C_CYAN='\033[0;36m'; C_BOLD='\033[1m';

# --- Helper Functions ---
print_header() { echo -e "\n${C_PURPLE}${C_BOLD}====== $1 ======${C_OFF}"; }
print_success() { echo -e "${C_GREEN}✔ ${1}${C_OFF}"; }
print_error() { echo -e "${C_RED}✖ ${1}${C_OFF}" >&2; }
print_warning() { echo -e "${C_YELLOW}⚠ ${1}${C_OFF}"; }

# --- Pre-execution Checks ---
if [[ $(id -u) -ne 0 ]]; then print_error "Please run this script using sudo or as root."; exit 1; fi

# --- GitHub Package Download ---
GITHUB_REPO="ArashAfkandeh/Ocserv-Installer"

download_package() {
    echo "Finding the latest release..." >&2
    if ! command -v curl &>/dev/null; then
        apt-get update >/dev/null
        apt-get install -y curl >/dev/null
    fi

    LATEST_RELEASE_URL=$(curl -s "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep "browser_download_url" | cut -d '"' -f 4 || true)

    if [ -z "$LATEST_RELEASE_URL" ]; then
        print_error "Could not find the latest release."
        exit 1
    fi

    PACKAGE_NAME=$(basename "$LATEST_RELEASE_URL")
    
    echo "Downloading latest release: $PACKAGE_NAME" >&2
    
    TMP_DIR=$(mktemp -d)
    if ! curl -sSL "$LATEST_RELEASE_URL" -o "${TMP_DIR}/${PACKAGE_NAME}"; then
        print_error "Failed to download package from GitHub"
        rm -rf "$TMP_DIR" || true
        exit 1
    fi
    echo "$TMP_DIR/${PACKAGE_NAME}"
}

# --- Welcome Banner ---
clear; echo -e "${C_CYAN}${C_BOLD}"; echo "    +--------------------------------------------------+"; echo "    |        Ocserv Advanced Installer & Panel         |"; echo "    +--------------------------------------------------+"; echo -e "${C_OFF}"

# --- Pre-Installation Check ---
print_header "Checking for Existing Ocserv"

if command -v ocserv >/dev/null || [ -d "/etc/ocserv" ] || systemctl list-unit-files | grep -q '^ocserv\.service' 2>/dev/null; then
    print_warning "An existing ocserv installation was detected."
    read -u 1 -p "  Do you want to remove it and continue with a fresh installation? [y/N]: " -n 1 -r REPLY
    echo

    if [[ "$REPLY" =~ ^[Yy]$ ]]; then
        print_success "Proceeding with removal of the existing version..."
        echo "  Stopping any existing ocserv service..."
        if systemctl list-unit-files | grep -q '^ocserv\.service' 2>/dev/null; then
            systemctl stop ocserv >/dev/null 2>&1 || true
            systemctl disable ocserv >/dev/null 2>&1 || true
        fi
        killall -q -9 ocserv ocserv-main ocserv-worker || true

        OCSERV_BINARY="/usr/local/sbin/ocserv"
        timeout=20
        while pgrep -f "$OCSERV_BINARY" >/dev/null && [ "$timeout" -gt 0 ]; do
            sleep 0.5
            ((timeout--))
        done

        if pgrep -f "$OCSERV_BINARY" >/dev/null; then
            print_error "Ocserv processes could not be terminated. Please remove manually."
            exit 1
        fi

        echo "  Removing old packages and configurations..."
        apt-get remove --purge -y ocserv >/dev/null 2>&1 || true
        rm -rf /etc/ocserv /usr/local/sbin/ocserv /usr/local/bin/occtl /usr/local/sbin/ocpasswd /usr/local/bin/ocpasswd /etc/systemd/system/ocserv.service || true
        apt-get autoremove -y >/dev/null 2>&1 || true
        systemctl daemon-reload
        print_success "Old packages and configurations removed."
        echo
    else
        print_error "Installation aborted by the user."
        exit 1
    fi
else
    print_success "No existing ocserv installation found. Proceeding..."
fi

# --- Helper Function to Get DNS Settings ---
get_dns_config_lines() {
    local choice="$1"
    case $choice in
        1) echo -e "${C_GREEN}✔ Using System default...${C_OFF}" >&2; grep -v '^#' /etc/resolv.conf | grep 'nameserver' | awk '{print "dns = " $2}' || true;;
        2) echo -e "${C_GREEN}✔ Setting DNS to Google...${C_OFF}" >&2; echo -e "dns = 8.8.8.8\ndns = 8.8.4.4";;
        3) echo -e "${C_GREEN}✔ Setting DNS to Cloudflare...${C_OFF}" >&2; echo -e "dns = 1.1.1.1\ndns = 1.0.0.1";;
        4) echo -e "${C_GREEN}✔ Setting DNS to OpenDNS...${C_OFF}" >&2; echo -e "dns = 208.67.222.222\ndns = 208.67.220.220";;
        5) echo -e "${C_GREEN}✔ Setting DNS to Local Caching (dnsmasq)...${C_OFF}" >&2; echo -e "dns = 10.10.10.1";;
        *) print_warning "Invalid DNS choice. Defaulting to Google DNS." >&2; echo -e "dns = 8.8.8.8\ndns = 8.8.4.4";;
    esac
}

# --- User Input & Port Check ---
print_header "Step 1: Initial Configuration"

LOCAL_PACKAGE_PATH="/root/ocserv-1.3.0-user.tar.gz"
PACKAGE_PATH=""

if [ -f "$LOCAL_PACKAGE_PATH" ]; then
    echo
    echo -e "  A local ocserv package was found."
    echo -e "  Please choose an installation source:"
    echo -e "     ${C_CYAN}1)${C_OFF} Download the latest version from GitHub"
    echo -e "     ${C_CYAN}2)${C_OFF} Use the local package (${LOCAL_PACKAGE_PATH})"
    
    while true; do
        read -u 1 -p "  Your choice [1-2]: " PACKAGE_CHOICE
        case "$PACKAGE_CHOICE" in
            1) PACKAGE_PATH=$(download_package); break ;;
            2) print_success "Using local package: $LOCAL_PACKAGE_PATH"; PACKAGE_PATH="$LOCAL_PACKAGE_PATH"; break ;;
            *) print_warning "Invalid choice. Please enter 1 or 2." ;;
        esac
    done
else
    PACKAGE_PATH=$(download_package)
fi

if [[ ! -f "$PACKAGE_PATH" ]]; then print_error "Failed to obtain package file."; exit 1; fi

if [[ -z "${1:-}" ]]; then read -u 1 -p "  Enter port number for ocserv: " PORT; else PORT="$1"; fi
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then print_error "Invalid port number."; exit 1; fi

# Port Availability Check
if ss -tuln | grep -qE "(0\.0\.0\.0|\[::\]):${PORT}\b"; then
    print_error "Port ${PORT} is already in use by another service. Please abort or choose a different port."
    exit 1
fi
print_success "Port ${PORT} is available."

if [[ -z "${2:-}" ]]; then read -u 1 -p "  Enter default domain: " DOMAIN; else DOMAIN="$2"; fi
if [[ -z "$DOMAIN" ]]; then print_error "Domain cannot be empty."; exit 1; fi
if [[ -z "${3:-}" ]]; then read -u 1 -p "  Enter RADIUS server IP: " RADIUS_SERVER_IP; else RADIUS_SERVER_IP="$3"; fi
if [[ -z "${4:-}" ]]; then read -u 1 -s -p "  Enter shared secret for RADIUS server: " SHARED_SECRET; echo; else SHARED_SECRET="$4"; fi
if [[ -z "$SHARED_SECRET" ]]; then print_error "Shared secret cannot be empty."; exit 1; fi

DNS_CHOICE="${5:-}"
if [[ -z "$DNS_CHOICE" ]]; then 
    echo; echo -e "  Please choose DNS resolvers:"
    echo -e "     ${C_CYAN}1)${C_OFF} System default"
    echo -e "     ${C_CYAN}2)${C_OFF} Google"
    echo -e "     ${C_CYAN}3)${C_OFF} Cloudflare"
    echo -e "     ${C_CYAN}4)${C_OFF} OpenDNS"
    echo -e "     ${C_CYAN}5)${C_OFF} Local Caching DNS (dnsmasq - High Speed)"
    read -u 1 -p "  Your choice [1-5]: " DNS_CHOICE
fi
DNS_CONFIG_LINES=$(get_dns_config_lines "$DNS_CHOICE")

# --- System Preparation ---
print_header "Step 2: System Preparation"
echo "  Installing dependencies..."
apt-get update >/dev/null
sudo sed -i 's/^#\$nrconf{restart} = .*/\$nrconf{restart} = "a";/' /etc/needrestart/needrestart.conf 2>/dev/null || true
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
apt-get install -y psmisc apt-utils dialog libev4 libgnutls30 liblz4-1 libseccomp2 libreadline8 libnl-route-3-200 libkrb5-3 libradcli4 libpam0g libpam-radius-auth libcurl4-gnutls-dev libcjose0 libjansson4 libprotobuf-c1 libtalloc2 libhttp-parser2.9 gss-ntlmssp iptables-persistent socat dnsmasq curl >/dev/null
print_success "Dependencies installed."

# --- Installation ---
print_header "Step 3: Installing Ocserv Package"
echo "  Extracting ocserv package..."
if ! tar -C / -xzf "$PACKAGE_PATH"; then
    print_error "Failed to extract package."
    rm -rf "$(dirname "$PACKAGE_PATH")" || true
    exit 1
fi
rm -rf "$(dirname "$PACKAGE_PATH")" || true
systemctl daemon-reload
print_success "Ocserv installed."

# --- Configuration ---
print_header "Step 4: Final Configuration"
mkdir -p /etc/ocserv/ssl; SSL_DIR="/etc/ocserv/ssl"
if [[ ! -f "$SSL_DIR/server.crt" || ! -f "$SSL_DIR/server.key" ]]; then
  echo "  Generating self-signed SSL certificates..."; openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=$DOMAIN" -keyout "$SSL_DIR/server.key" -out "$SSL_DIR/server.crt" >/dev/null 2>&1
  chmod 600 "$SSL_DIR/server.key" && chmod 644 "$SSL_DIR/server.crt"; print_success "SSL certificates generated."
else print_success "Existing SSL certificates found."; fi

echo "  Creating ocserv.conf with Dual-Stack (IPv4/IPv6) support..."
cat > /etc/ocserv/ocserv.conf <<EOF
auth = "radius[config=/etc/radcli/radiusclient.conf,groupconfig=true]"
acct = "radius[config=/etc/radcli/radiusclient.conf,groupconfig=true]"
tcp-port = ${PORT}
udp-port = ${PORT}
run-as-user = nobody
run-as-group = daemon
socket-file = /run/ocserv.socket
server-cert = /etc/ocserv/ssl/server.crt
server-key = /etc/ocserv/ssl/server.key
isolate-workers = true
max-same-clients = 2
keepalive = 30
dpd = 60
mobile-dpd = 300
mtu = 1350
try-mtu-discovery = true
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
pid-file = /run/ocserv.pid
device = vpns
default-domain = ${DOMAIN}
# IPv4 Subnet
ipv4-network = 10.10.10.0
ipv4-netmask = 255.255.255.0
# IPv6 Subnet for Leak Protection and Dual-Stack
ipv6-network = fd00:10:10::
ipv6-subnet-prefix = 64
tunnel-all-dns = true
${DNS_CONFIG_LINES}
cisco-client-compat = true
dtls-legacy = true
no-route = ${RADIUS_SERVER_IP}/32
EOF
chmod 640 /etc/ocserv/ocserv.conf; print_success "ocserv.conf created."

echo "  Configuring RADIUS client..."
RADCLI_DIR="/etc/radcli"; mkdir -p "$RADCLI_DIR"
cat > "$RADCLI_DIR/radiusclient.conf" <<EOF
authserver ${RADIUS_SERVER_IP}:1812
acctserver ${RADIUS_SERVER_IP}:1813
servers /etc/radcli/servers
dictionary /etc/radcli/dictionary
radius_timeout 3
radius_retries 1
bindaddr *
EOF
chmod 640 "$RADCLI_DIR/radiusclient.conf"
cat > "$RADCLI_DIR/servers" <<EOF
${RADIUS_SERVER_IP}  ${SHARED_SECRET}
EOF
chmod 600 "$RADCLI_DIR/servers"; chown root:root "$RADCLI_DIR/servers"
print_success "RADIUS client configured."

if [ "$DNS_CHOICE" == "5" ]; then
    echo "  Configuring Local Caching DNS (dnsmasq)..."
    cat > /etc/dnsmasq.d/ocserv-vpn.conf <<EOF
listen-address=10.10.10.1,127.0.0.1
server=8.8.8.8
server=1.1.1.1
cache-size=2000
EOF
    systemctl restart dnsmasq || true
    systemctl enable dnsmasq >/dev/null 2>&1 || true
    print_success "Local Caching DNS active."
fi

# --- PRO NAT, BBR & Dual-Stack Network ---
echo "  Configuring networking (BBR, NAT IPv4 & IPv6)..."

if command -v ufw &> /dev/null; then 
    ufw allow "$PORT"/tcp >/dev/null || true
    ufw allow "$PORT"/udp >/dev/null || true
fi

# Permanent Sysctl configs (IP Forwarding IPv4/IPv6, BBR)
cat > /etc/sysctl.d/99-ocserv-network.conf <<EOF
# IP Forwarding for Dual-Stack
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
# TCP BBR for Performance
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
sysctl --system >/dev/null

OUTGOING_IFACE=$(ip route show default | awk '/default/ {print $5}' | head -n 1 || true)
VPN_SUBNET="10.10.10.0/24"
VPN_IP6_SUBNET="fd00:10:10::/64"

if [ -n "$OUTGOING_IFACE" ]; then
    # IPv4 NAT & Forwarding
    iptables -t nat -D POSTROUTING -s "$VPN_SUBNET" -o "$OUTGOING_IFACE" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -s "$VPN_SUBNET" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -d "$VPN_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

    iptables -t nat -A POSTROUTING -s "$VPN_SUBNET" -o "$OUTGOING_IFACE" -j MASQUERADE
    iptables -A FORWARD -s "$VPN_SUBNET" -j ACCEPT
    iptables -A FORWARD -d "$VPN_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT

    # IPv6 NAT & Forwarding (with || true fallback for non-IPv6 kernels)
    ip6tables -t nat -D POSTROUTING -s "$VPN_IP6_SUBNET" -o "$OUTGOING_IFACE" -j MASQUERADE 2>/dev/null || true
    ip6tables -D FORWARD -s "$VPN_IP6_SUBNET" -j ACCEPT 2>/dev/null || true
    ip6tables -D FORWARD -d "$VPN_IP6_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

    ip6tables -t nat -A POSTROUTING -s "$VPN_IP6_SUBNET" -o "$OUTGOING_IFACE" -j MASQUERADE 2>/dev/null || true
    ip6tables -A FORWARD -s "$VPN_IP6_SUBNET" -j ACCEPT 2>/dev/null || true
    ip6tables -A FORWARD -d "$VPN_IP6_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true

    if command -v ufw &> /dev/null; then
        sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw 2>/dev/null || true
        ufw reload >/dev/null 2>&1 || true
    fi
    print_success "Network (Dual-Stack IPv4/IPv6, BBR, NAT) configured permanently."
else
    print_error "Could not determine outgoing interface. NAT rules not applied."
fi

# --- Modular Management Panel Download ---
print_header "Step 5: Downloading Management Panel"

PANEL_URL="https://raw.githubusercontent.com/ArashAfkandeh/Ocserv-Installer/main/management_panel.sh"
echo "  Fetching panel from GitHub..."

if curl -sSL "$PANEL_URL" -o /usr/local/bin/oc-p; then
    chmod +x /usr/local/bin/oc-p
    print_success "Management panel downloaded and installed as 'oc-p'."
else
    print_error "Failed to download the management panel from GitHub."
    print_warning "You can manually install it later by running:"
    echo "  curl -sSL $PANEL_URL -o /usr/local/bin/oc-p && chmod +x /usr/local/bin/oc-p"
fi

# --- Finalization ---
print_header "Step 6: Starting Service"
echo "  Enabling and starting ocserv service..."
systemctl enable --now ocserv >/dev/null 2>&1 || true
sleep 2; clear

if systemctl is-active --quiet ocserv; then
    echo -e "${C_GREEN}${C_BOLD}"; echo "    +--------------------------------------------------+"; echo "    |        Installation Completed Successfully!      |"; echo "    +--------------------------------------------------+"; echo -e "${C_OFF}"
    echo -e "    ${C_GREEN}✔${C_OFF} The ocserv service is now active and running."; echo
    echo -e "    Connection Address: ${C_GREEN}${DOMAIN}:${PORT}${C_OFF}"
    echo -e "    Command to management panel: ${C_GREEN}oc-p${C_OFF}"
    echo -e "    Installation Logs: ${C_CYAN}/var/log/ocserv_installer.log${C_OFF}"; echo
else
    print_error "Ocserv service failed to start. Please check the logs using:"; echo -e "    ${C_YELLOW}journalctl -u ocserv${C_OFF}"
fi
