#!/bin/bash

# This script installs ocserv from a pre-compiled package, configures it,
# and installs a final, professionally designed management panel.
# Usage (interactive): sudo ./install_ocserv_from_package.sh [PORT] [DOMAIN] [RADIUS_IP] [RADIUS_SECRET]
# Usage (non-interactive): sudo ./install_ocserv_from_package.sh [PORT] [DOMAIN] [RADIUS_IP] [RADIUS_SECRET] [DNS_CHOICE]

# --- UI Color Definitions ---
C_OFF='\033[0m'; C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m'; C_BLUE='\033[0;34m'; C_PURPLE='\033[0;35m'; C_CYAN='\033[0;36m'; C_BOLD='\033[1m'; C_BLINK_RED='\033[5;31m'

# --- Helper Functions ---
print_header() { echo -e "\n${C_PURPLE}${C_BOLD}====== $1 ======${C_OFF}"; }
print_success() { echo -e "${C_GREEN}✔ ${1}${C_OFF}"; }
print_error() { echo -e "${C_RED}✖ ${1}${C_OFF}" >&2; }
print_warning() { echo -e "${C_YELLOW}⚠ ${1}${C_OFF}"; }

# --- Pre-execution Checks ---
if [[ $(id -u) -ne 0 ]]; then print_error "Please run this script using sudo or as root."; exit 1; fi

# --- GitHub Package Download ---
GITHUB_URL="https://raw.githubusercontent.com/ArashAfkandeh/Ocserv-Installer/main"
PACKAGE_NAME="ocserv-1.3.0.tar.gz"

download_package() {
    echo "Downloading package from GitHub..." >&2
    if ! command -v curl &>/dev/null; then
        apt-get update >/dev/null
        apt-get install -y curl >/dev/null
    fi
    
    TMP_DIR=$(mktemp -d)
    if ! curl -sSL "${GITHUB_URL}/${PACKAGE_NAME}" -o "${TMP_DIR}/${PACKAGE_NAME}"; then
        print_error "Failed to download package from GitHub"
        rm -rf "$TMP_DIR"
        exit 1
    fi
    echo "$TMP_DIR/${PACKAGE_NAME}"
}

# --- Welcome Banner ---
clear; echo -e "${C_CYAN}${C_BOLD}"; echo "    +--------------------------------------------------+"; echo "    |        Ocserv Advanced Installer & Panel         |"; echo "    +--------------------------------------------------+"; echo -e "${C_OFF}"

# --- Helper Function to Get DNS Settings ---
get_dns_config_lines() {
    local choice="$1"
    case $choice in
        1) echo -e "${C_GREEN}✔ Using current system resolvers...${C_OFF}" >&2; grep -v '^#' /etc/resolv.conf | grep 'nameserver' | awk '{print "dns = " $2}';;
        2) echo -e "${C_GREEN}✔ Setting DNS to Google...${C_OFF}" >&2; echo -e "dns = 8.8.8.8\ndns = 8.8.4.4";;
        3) echo -e "${C_GREEN}✔ Setting DNS to Cloudflare...${C_OFF}" >&2; echo -e "dns = 1.1.1.1\ndns = 1.0.0.1";;
        4) echo -e "${C_GREEN}✔ Setting DNS to OpenDNS...${C_OFF}" >&2; echo -e "dns = 208.67.222.222\ndns = 208.67.220.220";;
        *) print_warning "Invalid DNS choice. Defaulting to Google DNS." >&2; echo -e "dns = 8.8.8.8\ndns = 8.8.4.4";;
    esac
}

# --- User Input ---
print_header "Step 1: Initial Configuration"
PACKAGE_PATH=$(download_package)
if [[ ! -f "$PACKAGE_PATH" ]]; then print_error "Failed to download package file"; exit 1; fi
if [[ -z "${1:-}" ]]; then read -u 1 -p "  Enter port number for ocserv: " PORT; else PORT="$1"; fi
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then print_error "Invalid port number."; exit 1; fi
if [[ -z "${2:-}" ]]; then read -u 1 -p "  Enter default domain: " DOMAIN; else DOMAIN="$2"; fi
if [[ -z "$DOMAIN" ]]; then print_error "Domain cannot be empty."; exit 1; fi
if [[ -z "${3:-}" ]]; then read -u 1 -p "  Enter RADIUS server IP: " RADIUS_SERVER_IP; else RADIUS_SERVER_IP="$3"; fi
if ! [[ "$RADIUS_SERVER_IP" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then print_error "Invalid IP format."; exit 1; fi
if [[ -z "${4:-}" ]]; then read -u 1 -p "  Enter shared secret for RADIUS server: " SHARED_SECRET; else SHARED_SECRET="$4"; fi
if [[ -z "$SHARED_SECRET" ]]; then print_error "Shared secret cannot be empty."; exit 1; fi
DNS_CHOICE="${5:-}"; if [[ -z "$DNS_CHOICE" ]]; then echo; echo "  Please choose DNS resolvers:"; echo "     ${C_CYAN}1)${C_OFF} System"; echo "     ${C_CYAN}2)${C_OFF} Google"; echo "     ${C_CYAN}3)${C_OFF} Cloudflare"; echo "     ${C_CYAN}4)${C_OFF} OpenDNS"; read -u 1 -p "  Your choice [1-4]: " DNS_CHOICE; fi
DNS_CONFIG_LINES=$(get_dns_config_lines "$DNS_CHOICE")

# --- System Preparation ---
print_header "Step 2: System Preparation"
echo "  Installing dependencies..."; apt-get update >/dev/null; echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections; echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
apt-get install -y psmisc apt-utils dialog libev4 libgnutls30 liblz4-1 libseccomp2 libreadline8 libnl-route-3-200 libkrb5-3 libradcli4 libpam0g libpam-radius-auth libcurl4-gnutls-dev libcjose0 libjansson4 libprotobuf-c1 libtalloc2 libhttp-parser2.9 gss-ntlmssp iptables-persistent socat >/dev/null
print_success "Dependencies installed."
echo "  Stopping any existing ocserv service..."; if systemctl list-unit-files | grep -q '^ocserv\.service'; then systemctl stop ocserv || true; systemctl disable ocserv || true; fi; killall -q -9 ocserv ocserv-main ocserv-worker || true
OCSERV_BINARY="/usr/local/sbin/ocserv"; timeout=20; while pgrep -f "$OCSERV_BINARY" >/dev/null && [ "$timeout" -gt 0 ]; do sleep 0.5; ((timeout--)); done
if pgrep -f "$OCSERV_BINARY" >/dev/null; then print_error "Ocserv processes could not be terminated."; exit 1; fi
print_success "All ocserv processes terminated."
echo "  Removing old packages..."; apt-get remove -y ocserv >/dev/null 2>&1 || true; apt-get autoremove -y >/dev/null 2>&1; print_success "Old packages removed."

# --- Installation ---
print_header "Step 3: Installing Ocserv"
TMP_DIR=$(mktemp -d); trap 'rm -rf "$TMP_DIR"' EXIT; echo "  Extracting package..."; tar -xzf "$PACKAGE_PATH" -C "$TMP_DIR"
echo "  Copying files..."; if [ -d "$TMP_DIR/usr" ]; then cp -a "$TMP_DIR/usr/." /usr/; fi; if [ -d "$TMP_DIR/etc" ]; then cp -a "$TMP_DIR/etc/." /etc/; fi; if [ -d "$TMP_DIR/lib" ]; then cp -a "$TMP_DIR/lib/." /lib/; fi
echo "  Setting permissions..."; chmod 755 /usr/local/sbin/ocserv /usr/local/bin/occtl
if [ -f /usr/local/sbin/ocpasswd ]; then chmod 755 /usr/local/sbin/ocpasswd; fi; if [ -f /usr/local/bin/ocpasswd ]; then chmod 755 /usr/local/bin/ocpasswd; fi
systemctl daemon-reload; print_success "Ocserv installed successfully."

# --- Configuration ---
print_header "Step 4: Final Configuration"
mkdir -p /etc/ocserv/ssl; SSL_DIR="/etc/ocserv/ssl"
if [[ ! -f "$SSL_DIR/server.crt" || ! -f "$SSL_DIR/server.key" ]]; then
  echo "  Generating self-signed SSL certificates..."; openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=$DOMAIN" -keyout "$SSL_DIR/server.key" -out "$SSL_DIR/server.crt" >/dev/null 2>&1
  chmod 600 "$SSL_DIR/server.key" && chmod 644 "$SSL_DIR/server.crt"; print_success "SSL certificates generated."
else print_success "Existing SSL certificates found."; fi
echo "  Creating ocserv.conf..."; cat > /etc/ocserv/ocserv.conf <<EOF
auth = "radius[config=/etc/radcli/radiusclient.conf]"
acct = "radius[config=/etc/radcli/radiusclient.conf]"
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
try-mtu-discovery = true
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
pid-file = /run/ocserv.pid
device = vpns
default-domain = ${DOMAIN}
ipv4-network = 10.10.10.0
ipv4-netmask = 255.255.255.0
tunnel-all-dns = true
${DNS_CONFIG_LINES}
cisco-client-compat = true
dtls-legacy = true
no-route = ${RADIUS_SERVER_IP}/32
EOF
chmod 640 /etc/ocserv/ocserv.conf; print_success "ocserv.conf created."
echo "  Configuring RADIUS client..."; RADCLI_DIR="/etc/radcli"; mkdir -p "$RADCLI_DIR"; cat > "$RADCLI_DIR/radiusclient.conf" <<EOF
authserver ${RADIUS_SERVER_IP}:1812
acctserver ${RADIUS_SERVER_IP}:1813
servers /etc/radcli/servers
dictionary /etc/radcli/dictionary
radius_timeout 3
radius_retries 1
bindaddr *
EOF
chmod 640 "$RADCLI_DIR/radiusclient.conf"; cat > "$RADCLI_DIR/servers" <<EOF
${RADIUS_SERVER_IP}  ${SHARED_SECRET}
EOF
chmod 640 "$RADCLI_DIR/servers"; print_success "RADIUS client configured."
echo "  Configuring networking..."; if command -v ufw &> /dev/null; then ufw allow "$PORT"/tcp >/dev/null && ufw allow "$PORT"/udp >/dev/null; fi; sed -i '/net.ipv4.ip_forward=1/s/^#//' /etc/sysctl.conf
sysctl -p >/dev/null; OUTGOING_IFACE=$(ip route show default | awk '/default/ {print $5}' | head -n 1); if [ -n "$OUTGOING_IFACE" ]; then iptables -t nat -A POSTROUTING -o "$OUTGOING_IFACE" -j MASQUERADE; iptables-save > /etc/iptables/rules.v4; fi
print_success "Network configured."

# --- Management Panel Installation ---
print_header "Step 5: Installing Management Panel"
cat > /usr/local/bin/oc-p <<'EOF'
#!/bin/bash
# Ocserv Advanced Management Panel v4.6 (SSL Email Fix)

# --- UI Definitions ---
C_OFF='\033[0m'; C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m';
C_BLUE='\033[0;34m'; C_PURPLE='\033[0;35m'; C_CYAN='\033[0;36m'; C_BOLD='\033[1m';
C_BLINK_RED='\033[5;31m'

# --- Config Paths ---
OCSERV_CONF="/etc/ocserv/ocserv.conf"
RADCLI_SERVERS="/etc/radcli/servers"

# --- Core Functions ---
get_value() { grep "^$1" "$2" | awk '{print $3}'; }
get_dns_values() { grep "^dns =" "$OCSERV_CONF" | awk '{print $3}' | tr '\n' ',' | sed 's/,$//'; }
pause_for_error() { echo -e "\n    ${C_RED}✖ $1 Press any key to continue...${C_OFF}"; read -n 1 -s; }
pause_for_success() { echo -e "\n    ${C_GREEN}✔ $1${C_OFF}"; sleep 2; }
restart_ocserv() { if systemctl restart ocserv; then return 0; else return 1; fi; }

# --- Validation Functions ---
is_valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
is_valid_ip() { [[ "$1" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; }
is_valid_email() { [[ "$1" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; }

# --- Get SSL Certificate Function ---
get_ssl_cert() {
    clear
    echo -e "${C_YELLOW}--- Let's Encrypt SSL Certificate ---${C_OFF}"
    if ! command -v socat &>/dev/null || ! command -v curl &>/dev/null; then
        echo "  -> Installing dependencies (socat, curl)..."
        apt-get update >/dev/null && apt-get install -y socat curl >/dev/null
    fi
    local current_domain=$(get_value "default-domain =" "$OCSERV_CONF")
    read -p "  -> Enter domain for SSL cert [${current_domain}]: " HOST
    HOST=${HOST:-$current_domain}
    
    local EMAIL=""
    while true; do
        read -p "  -> Enter a valid email (required for Let's Encrypt): " EMAIL
        if is_valid_email "$EMAIL"; then
            break
        else
            echo -e "  -> ${C_RED}Invalid email format. Please try again.${C_OFF}"
        fi
    done
    
    local UFW_WD_PID=""
    start_ufw_watchdog() { (while true; do ufw disable &>/dev/null; sleep 5; done) & UFW_WD_PID=$!; }
    stop_ufw_watchdog() {
        if [[ -n "$UFW_WD_PID" ]] && kill -0 "$UFW_WD_PID" 2>/dev/null; then kill "$UFW_WD_PID"; wait "$UFW_WD_PID" 2>/dev/null; fi
        echo -e "  -> Re-enabling UFW and restarting Ocserv..."
        ufw enable >/dev/null
        systemctl restart ocserv || true
    }
    
    echo "  -> Temporarily stopping ocserv and managing UFW..."
    systemctl stop ocserv
    trap stop_ufw_watchdog RETURN EXIT INT TERM
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then start_ufw_watchdog; fi
    if [ ! -d "$HOME/.acme.sh" ]; then echo "  -> Installing acme.sh..."; curl -s https://get.acme.sh | sh >/dev/null; fi
    
    "$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null
    
    echo "  -> Issuing certificate for ${HOST} (this may take a minute)..."
    if ! "$HOME"/.acme.sh/acme.sh --issue --standalone -d "$HOST" --accountemail "$EMAIL"; then
        pause_for_error "Certificate issuance failed. Check logs."; return 1
    fi
    
    local CERT_DIR="/etc/ocserv/ssl/${HOST}"; mkdir -p "$CERT_DIR"
    local KEY_FILE="$CERT_DIR/privkey.pem"; local CHAIN_FILE="$CERT_DIR/fullchain.pem"
    echo "  -> Installing certificate to ${CERT_DIR}..."
    if ! "$HOME"/.acme.sh/acme.sh --install-cert -d "$HOST" --key-file "$KEY_FILE" --fullchain-file "$CHAIN_FILE" >/dev/null; then
        pause_for_error "Certificate installation failed."; return 1
    fi
    
    echo -e "\n${C_GREEN}✔ SSL certificate for ${HOST} was successfully obtained.${C_OFF}"
    
    read -p "  -> Do you want to activate this certificate for ocserv? (This will update the domain and cert paths in ocserv.conf) [y/N]: " -n 1 -r REPLY
    echo
    if [[ "$REPLY" =~ ^[Yy]$ ]]; then
        echo "  -> Updating ocserv.conf to use the new certificate..."
        sed -i "s#^default-domain = .*#default-domain = ${HOST}#" "$OCSERV_CONF"
        sed -i "s#^server-cert = .*#server-cert = ${CHAIN_FILE}#" "$OCSERV_CONF"
        sed -i "s#^server-key = .*#server-key = ${KEY_FILE}#" "$OCSERV_CONF"
        (crontab -l 2>/dev/null; echo "0 0 * * 0 \"$HOME/.acme.sh/acme.sh\" --cron --home \"$HOME/.acme.sh\" > /dev/null") | sort -u | crontab -
        "$HOME"/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null
        pause_for_success "Configuration updated and auto-renewal is set."
    else
        echo -e "${C_YELLOW}  -> Ocserv configuration not modified. The new certificate is available but not active.${C_OFF}"; sleep 3
    fi
}

# --- DANGEROUS FUNCTION: Uninstall ---
uninstall_ocserv() {
    clear; echo -e "\n${C_RED}+================== ${C_BOLD}DANGER ZONE${C_OFF}${C_RED} ==================+${C_OFF}";
    echo -e "${C_YELLOW}| This will ${C_BOLD}COMPLETELY REMOVE${C_OFF}${C_YELLOW} ocserv and all its  |"; echo -e "| configurations. This action is ${C_RED}${C_BOLD}IRREVERSIBLE${C_OFF}. |"; echo -e "${C_RED}+==================================================+${C_OFF}"; echo;
    read -p "  To confirm, please type 'UNINSTALL': " confirmation
    if [[ "$confirmation" != "UNINSTALL" ]]; then echo -e "\n${C_GREEN}✔ Uninstall cancelled.${C_OFF}"; sleep 2; return; fi
    echo -e "\n${C_YELLOW}Uninstalling ocserv...${C_OFF}"; systemctl stop ocserv || true; systemctl disable ocserv || true; killall -q -9 ocserv ocserv-main ocserv-worker || true
    rm -f /usr/local/sbin/ocserv /usr/local/sbin/ocpasswd /usr/local/bin/ocpasswd /usr/local/bin/occtl; rm -rf /etc/ocserv /etc/radcli; rm -f /etc/systemd/system/ocserv.service
    rm -f /usr/local/bin/oc-p; systemctl daemon-reload; echo -e "\n${C_GREEN}✔ Ocserv has been completely uninstalled.${C_OFF}"; exit 0
}

# --- Menu and Main Loop ---
while true; do
    clear
    if systemctl is-active --quiet ocserv; then status_display="${C_GREEN}[RUNNING]${C_OFF}"; else status_display="${C_RED}[STOPPED]${C_OFF}"; fi
    port=$(get_value "tcp-port =" "$OCSERV_CONF"); domain=$(get_value "default-domain =" "$OCSERV_CONF");
    radius_ip=$(awk '{print $1}' "$RADCLI_SERVERS" 2>/dev/null); dns=$(get_dns_values)
    
    echo -e "${C_BOLD}${C_CYAN}+--- Ocserv Management Panel v4.6 ---+${C_OFF}"
    echo
    echo -e "${C_BLUE}|---[ Information ]----------------------------------+${C_OFF}"
    echo
    printf "  %-14s : %b\n" "Service Status" "$status_display"; printf "  %-14s : %b\n" "Port" "${C_CYAN}${port}${C_OFF}";
    printf "  %-14s : %b\n" "Domain" "${C_CYAN}${domain}${C_OFF}"; printf "  %-14s : %b\n" "RADIUS IP" "${C_CYAN}${radius_ip:-N/A}${C_OFF}";
    printf "  %-14s : %b\n" "DNS Servers" "${C_CYAN}${dns:-N/A}${C_OFF}";
    echo
    echo -e "${C_PURPLE}|---[ Configuration ]--------------------------------+${C_OFF}"
    echo
    echo -e "  ${C_CYAN}1)${C_OFF} Edit Port"
    echo -e "  ${C_CYAN}2)${C_OFF} Edit Domain"
    echo -e "  ${C_CYAN}3)${C_OFF} Edit RADIUS IP"
    echo -e "  ${C_CYAN}4)${C_OFF} Edit RADIUS Secret"
    echo -e "  ${C_CYAN}5)${C_OFF} Change DNS Servers"
    echo -e "  ${C_BOLD}${C_CYAN}6)${C_OFF} Get Let's Encrypt SSL"
    echo
    echo -e "${C_PURPLE}|---[ Management ]-----------------------------------+${C_OFF}"
    echo
    echo -e "  ${C_CYAN}7)${C_OFF} Restart Service"
    echo -e "  ${C_CYAN}8)${C_OFF} ${C_BLINK_RED}UNINSTALL Ocserv${C_OFF}"
    echo
    echo -e "${C_PURPLE}+----------------------------------------------------+${C_OFF}"
    
    read -p "  Enter your choice [1-8, q for quit]: " choice
    case $choice in
        1) read -p " -> Enter new Port: " val; if ! is_valid_port "$val"; then pause_for_error "Invalid port."; continue; fi; sed -i "s/^tcp-port = .*/tcp-port = $val/; s/^udp-port = .*/udp-port = $val/" "$OCSERV_CONF"; if restart_ocserv; then pause_for_success "Port updated."; else pause_for_error "Service failed to restart."; fi;;
        2) read -p " -> Enter new Domain: " val; if [[ -z "$val" ]]; then pause_for_error "Domain cannot be empty."; continue; fi; sed -i "s/^default-domain = .*/default-domain = $val/" "$OCSERV_CONF"; if restart_ocserv; then pause_for_success "Domain updated."; else pause_for_error "Service failed to restart."; fi;;
        3) read -p " -> Enter new RADIUS IP: " val; if ! is_valid_ip "$val"; then pause_for_error "Invalid IP format."; continue; fi; secret=$(awk '{print $2}' "$RADCLI_SERVERS"); echo "$val  $secret" > "$RADCLI_SERVERS"; sed -i "s/authserver .*/authserver ${val}:1812/; s/acctserver .*/acctserver ${val}:1813/; s/^no-route = .*/no-route = ${val}\/32/" "$OCSERV_CONF"; if restart_ocserv; then pause_for_success "RADIUS IP updated."; else pause_for_error "Service failed to restart."; fi;;
        4) read -p " -> Enter new RADIUS Secret: " val; if [[ -z "$val" ]]; then pause_for_error "Secret cannot be empty."; continue; fi; ip=$(awk '{print $1}' "$RADCLI_SERVERS"); echo "$ip  $val" > "$RADCLI_SERVERS"; if restart_ocserv; then pause_for_success "RADIUS Secret updated."; else pause_for_error "Service failed to restart."; fi;;
        5) clear; echo; echo -e "  ${C_CYAN}1)${C_OFF} System  ${C_CYAN}2)${C_OFF} Google  ${C_CYAN}3)${C_OFF} Cloudflare  ${C_CYAN}4)${C_OFF} OpenDNS"; read -p " -> Enter DNS choice: " val; sed -i '/^dns =/d' "$OCSERV_CONF"; case $val in 1) grep -v '^#' /etc/resolv.conf|grep 'nameserver'|awk '{print "dns = " $2}' >> "$OCSERV_CONF";; 2) echo "dns = 8.8.8.8" >> "$OCSERV_CONF"; echo "dns = 8.8.4.4" >> "$OCSERV_CONF";; 3) echo "dns = 1.1.1.1" >> "$OCSERV_CONF"; echo "dns = 1.0.0.1" >> "$OCSERV_CONF";; 4) echo "dns = 208.67.222.222" >> "$OCSERV_CONF"; echo "dns = 208.67.220.220" >> "$OCSERV_CONF";; *) pause_for_error "Invalid choice."; continue;; esac; if restart_ocserv; then pause_for_success "DNS servers updated."; else pause_for_error "Service failed to restart."; fi;;
        6) get_ssl_cert;;
        7) if restart_ocserv; then pause_for_success "Service restarted."; else pause_for_error "Service failed to restart."; fi;;
        8) uninstall_ocserv;;
        q|Q) echo -e "\n    ${C_CYAN}Exiting panel. Goodbye!${C_OFF}"; break;;
        *) pause_for_error "Invalid option.";;
    esac
done
EOF

chmod +x /usr/local/bin/oc-p; print_success "Management panel installed as 'oc-p'."

# --- Finalization ---
print_header "Step 6: Starting Service"
echo "  Enabling and starting ocserv service..."; systemctl enable --now ocserv >/dev/null 2>&1; sleep 2; clear
if systemctl is-active --quiet ocserv; then
    echo -e "${C_GREEN}${C_BOLD}"; echo "    +--------------------------------------------------+"; echo "    |        Installation Completed Successfully!      |"; echo "    +--------------------------------------------------+"; echo -e "${C_OFF}"
    echo -e "    ${C_GREEN}✔${C_OFF} The ocserv service is now active and running."; echo
    echo -e "    ${C_BLUE}${C_BOLD}For future management, use the command:${C_OFF}"; echo -e "    ${C_CYAN}sudo oc-p${C_OFF}"; echo
else
    print_error "Ocserv service failed to start. Please check the logs using:"; echo -e "    ${C_YELLOW}journalctl -u ocserv${C_OFF}"
fi
