#!/bin/bash
# Ocserv Advanced Management Panel
# Repository: https://github.com/ArashAfkandeh/Ocserv-Installer

# --- UI Definitions ---
C_OFF='\033[0m'; C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m';
C_BLUE='\033[0;34m'; C_PURPLE='\033[0;35m'; C_CYAN='\033[0;36m'; C_BOLD='\033[1m';
C_BLINK_GREEN='\033[5;32m'

# --- Pre-execution Check ---
if [[ $(id -u) -ne 0 ]]; then
    echo -e "${C_RED}✖ Please run this script as root (sudo oc-p).${C_OFF}"
    exit 1
fi

OCSERV_CONF="/etc/ocserv/ocserv.conf"
RADCLI_SERVERS="/etc/radcli/servers"
RADCLI_CONF="/etc/radcli/radiusclient.conf"

get_value() { grep "^$1" "$2" 2>/dev/null | awk '{print $3}'; }
get_dns_values() { grep "^dns =" "$OCSERV_CONF" 2>/dev/null | awk '{print $3}' | tr '\n' ',' | sed 's/,$//'; }
pause_for_error() { echo -e "\n    ${C_RED}✖ $1 Press any key to continue...${C_OFF}"; read -n 1 -s; }
pause_for_success() { echo -e "\n    ${C_GREEN}✔ $1${C_OFF}"; sleep 2; }
restart_ocserv() { if systemctl restart ocserv; then return 0; else return 1; fi; }

is_valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
is_valid_email() { [[ "$1" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; }

get_ssl_cert() {
    clear; echo -e "${C_YELLOW}--- Let's Encrypt SSL Certificate ---${C_OFF}"
    if ! command -v socat &>/dev/null || ! command -v curl &>/dev/null; then 
        echo -e "  -> Installing dependencies..."
        apt-get update >/dev/null && apt-get install -y socat curl >/dev/null
    fi
    local current_domain=$(get_value "default-domain =" "$OCSERV_CONF")
    read -p "  -> Enter domain for SSL cert [${current_domain}]: " HOST
    HOST=${HOST:-$current_domain}
    
    local EMAIL=""
    while true; do 
        read -p "  -> Enter a valid email: " EMAIL
        if is_valid_email "$EMAIL"; then break; else echo -e "  -> ${C_RED}Invalid email.${C_OFF}"; fi
    done
    
    local UFW_WD_PID=""
    start_ufw_watchdog() { (while true; do ufw disable &>/dev/null; sleep 5; done) & UFW_WD_PID=$!; }
    stop_ufw_watchdog() { 
        if [[ -n "$UFW_WD_PID" ]] && kill -0 "$UFW_WD_PID" 2>/dev/null; then kill "$UFW_WD_PID"; wait "$UFW_WD_PID" 2>/dev/null; fi
        ufw enable >/dev/null 2>&1 || true
        systemctl restart ocserv || true 
    }
    
    echo "  -> Managing UFW and issuing cert..."
    systemctl stop ocserv
    trap stop_ufw_watchdog RETURN EXIT INT TERM
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then start_ufw_watchdog; fi
    
    if [ ! -d "$HOME/.acme.sh" ]; then curl -s https://get.acme.sh | sh >/dev/null; fi
    "$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null
    
    if ! "$HOME"/.acme.sh/acme.sh --issue --standalone -d "$HOST" --accountemail "$EMAIL"; then 
        pause_for_error "Cert issuance failed."
        return 1
    fi
    
    local CERT_DIR="/etc/ocserv/ssl/${HOST}"
    mkdir -p "$CERT_DIR"
    local KEY_FILE="$CERT_DIR/privkey.pem"
    local CHAIN_FILE="$CERT_DIR/fullchain.pem"
    
    if ! "$HOME"/.acme.sh/acme.sh --install-cert -d "$HOST" --key-file "$KEY_FILE" --fullchain-file "$CHAIN_FILE" >/dev/null; then 
        pause_for_error "Install failed."
        return 1
    fi
    
    echo -e "\n${C_GREEN}✔ SSL certificate for ${HOST} obtained.${C_OFF}"
    read -p "  -> Activate this certificate in ocserv.conf? [y/N]: " -n 1 -r REPLY; echo
    if [[ "$REPLY" =~ ^[Yy]$ ]]; then
        sed -i "s#^default-domain = .*#default-domain = ${HOST}#" "$OCSERV_CONF"
        sed -i "s#^server-cert = .*#server-cert = ${CHAIN_FILE}#" "$OCSERV_CONF"
        sed -i "s#^server-key = .*#server-key = ${KEY_FILE}#" "$OCSERV_CONF"
        
        (crontab -l 2>/dev/null; echo "0 0 * * 0 \"$HOME/.acme.sh/acme.sh\" --cron --home \"$HOME/.acme.sh\" > /dev/null") | sort -u | crontab -
        "$HOME"/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null
        pause_for_success "Configuration updated."
    else
        echo -e "${C_YELLOW}  -> Config not modified.${C_OFF}"; sleep 2
    fi
}

uninstall_ocserv() {
    clear; echo -e "\n${C_RED}+================== ${C_BOLD}DANGER ZONE${C_OFF}${C_RED} ==================+${C_OFF}"
    echo -e "${C_YELLOW}| This will ${C_BOLD}COMPLETELY REMOVE${C_OFF}${C_YELLOW} ocserv.             |"; 
    echo -e "| This action is ${C_RED}${C_BOLD}IRREVERSIBLE${C_OFF}.                 |"; 
    echo -e "${C_RED}+==================================================+${C_OFF}\n"
    read -p "  Type 'UNINSTALL' to confirm: " confirmation
    if [[ "$confirmation" != "UNINSTALL" ]]; then echo -e "\n${C_GREEN}✔ Cancelled.${C_OFF}"; sleep 2; return; fi
    
    echo -e "\n${C_YELLOW}Uninstalling...${C_OFF}"
    systemctl stop ocserv || true
    systemctl disable ocserv || true
    killall -q -9 ocserv ocserv-main ocserv-worker || true
    
    rm -f /usr/local/sbin/ocserv /usr/local/sbin/ocpasswd /usr/local/bin/ocpasswd /usr/local/bin/occtl /usr/local/bin/oc-p /etc/systemd/system/ocserv.service
    rm -rf /etc/ocserv
    apt-get purge -y libradcli4 >/dev/null 2>&1 || true
    apt-get autoremove -y >/dev/null 2>&1 || true
    systemctl daemon-reload
    
    echo -e "\n${C_GREEN}✔ Completely uninstalled.${C_OFF}"; exit 0
}

# --- Main Menu Loop ---
while true; do
    clear
    if systemctl is-active --quiet ocserv 2>/dev/null; then status_display="${C_BLINK_GREEN}RUNNING${C_OFF}"; else status_display="${C_RED}[STOPPED]${C_OFF}"; fi
    
    port=$(get_value "tcp-port =" "$OCSERV_CONF")
    domain=$(get_value "default-domain =" "$OCSERV_CONF")
    radius_ip=$(awk '{print $1}' "$RADCLI_SERVERS" 2>/dev/null)
    dns=$(get_dns_values)
    
    echo -e "${C_BOLD}${C_CYAN}+--- Ocserv Management Panel ---+${C_OFF}\n${C_BLUE}|---[ Information ]----------------------------------+${C_OFF}\n"
    printf "  %-14s : %b\n" "Service Status" "$status_display"
    printf "  %-14s : %b\n" "Port" "${C_CYAN}${port:-N/A}${C_OFF}"
    printf "  %-14s : %b\n" "Domain" "${C_CYAN}${domain:-N/A}${C_OFF}"
    printf "  %-14s : %b\n" "RADIUS IP" "${C_CYAN}${radius_ip:-N/A}${C_OFF}"
    printf "  %-14s : %b\n" "DNS Servers" "${C_CYAN}${dns:-N/A}${C_OFF}"
    echo
    
    echo -e "${C_PURPLE}|---[ Configuration ]--------------------------------+${C_OFF}\n"
    echo -e "  ${C_CYAN}1)${C_OFF} Edit Port       ${C_CYAN}2)${C_OFF} Edit Domain"
    echo -e "  ${C_CYAN}3)${C_OFF} Edit RADIUS IP  ${C_CYAN}4)${C_OFF} Edit RADIUS Secret"
    echo -e "  ${C_CYAN}5)${C_OFF} Change DNS      ${C_BOLD}${C_CYAN}6)${C_OFF} Get Let's Encrypt SSL\n"
    
    echo -e "${C_PURPLE}|---[ Management ]-----------------------------------+${C_OFF}\n"
    echo -e "  ${C_CYAN}7)${C_OFF} View Live Logs"
    echo -e "  ${C_CYAN}8)${C_OFF} Restart Service"
    echo -e "  ${C_CYAN}9)${C_OFF} Update Panel from GitHub"
    echo -e "  ${C_CYAN}10)${C_OFF} ${C_RED}Uninstall Ocserv${C_OFF}\n"
    echo -e "${C_PURPLE}+----------------------------------------------------+${C_OFF}"
    
    read -p "  Enter your choice [1-10, q for quit]: " choice
    case $choice in
        1) 
            read -p " -> Enter new Port: " val
            if ! is_valid_port "$val"; then pause_for_error "Invalid port."; continue; fi
            sed -i "s/^tcp-port = .*/tcp-port = $val/; s/^udp-port = .*/udp-port = $val/" "$OCSERV_CONF"
            if restart_ocserv; then pause_for_success "Port updated."; else pause_for_error "Failed to restart."; fi
            ;;
        2) 
            read -p " -> Enter new Domain: " val
            if [[ -z "$val" ]]; then pause_for_error "Empty domain."; continue; fi
            sed -i "s/^default-domain = .*/default-domain = $val/" "$OCSERV_CONF"
            if restart_ocserv; then pause_for_success "Domain updated."; else pause_for_error "Failed to restart."; fi
            ;;
        3) 
            read -p " -> Enter new RADIUS IP: " val
            secret=$(awk '{print $2}' "$RADCLI_SERVERS" 2>/dev/null)
            echo "$val  $secret" > "$RADCLI_SERVERS"
            sed -i "s/^no-route = .*/no-route = ${val}\/32/" "$OCSERV_CONF"
            sed -i "s/^authserver .*/authserver ${val}:1812/; s/^acctserver .*/acctserver ${val}:1813/" "$RADCLI_CONF"
            if restart_ocserv; then pause_for_success "IP updated."; else pause_for_error "Failed to restart."; fi
            ;;
        4) 
            read -p " -> Enter new RADIUS Secret: " val
            if [[ -z "$val" ]]; then pause_for_error "Empty secret."; continue; fi
            ip=$(awk '{print $1}' "$RADCLI_SERVERS" 2>/dev/null)
            echo "$ip  $val" > "$RADCLI_SERVERS"
            if restart_ocserv; then pause_for_success "Secret updated."; else pause_for_error "Failed to restart."; fi
            ;;
        5) 
            clear; echo -e "\n  ${C_CYAN}1)${C_OFF} System default  ${C_CYAN}2)${C_OFF} Google  ${C_CYAN}3)${C_OFF} Cloudflare  ${C_CYAN}4)${C_OFF} OpenDNS  ${C_CYAN}5)${C_OFF} Local Caching (dnsmasq)"
            read -p " -> Enter DNS choice: " val
            sed -i '/^dns =/d' "$OCSERV_CONF"
            case $val in 
                1) grep -v '^#' /etc/resolv.conf | grep 'nameserver' | awk '{print "dns = " $2}' >> "$OCSERV_CONF" ;; 
                2) echo -e "dns = 8.8.8.8\ndns = 8.8.4.4" >> "$OCSERV_CONF" ;; 
                3) echo -e "dns = 1.1.1.1\ndns = 1.0.0.1" >> "$OCSERV_CONF" ;; 
                4) echo -e "dns = 208.67.222.222\ndns = 208.67.220.220" >> "$OCSERV_CONF" ;; 
                5) echo "dns = 10.10.10.1" >> "$OCSERV_CONF"; systemctl restart dnsmasq || true ;; 
                *) pause_for_error "Invalid."; continue ;; 
            esac
            if restart_ocserv; then pause_for_success "DNS updated."; else pause_for_error "Failed to restart."; fi
            ;;
        6) get_ssl_cert ;;
        7) 
            clear; echo -e "${C_YELLOW}--- Live Logs (Press Ctrl+C to exit) ---${C_OFF}\n"
            journalctl -u ocserv -f --output=cat
            echo
            ;;
        8) 
            if restart_ocserv; then pause_for_success "Service restarted."; else pause_for_error "Failed to restart."; fi
            ;;
        9)
            echo "  -> Fetching latest panel from GitHub..."
            PANEL_URL="https://raw.githubusercontent.com/ArashAfkandeh/Ocserv-Installer/main/management_panel.sh"
            if curl -sSL "$PANEL_URL" -o /usr/local/bin/oc-p; then
                chmod +x /usr/local/bin/oc-p
                pause_for_success "Panel successfully updated! Restarting panel..."
                exec /usr/local/bin/oc-p # Reload the panel immediately
            else
                pause_for_error "Failed to download update."
            fi
            ;;
        10) uninstall_ocserv ;;
        q|Q) echo -e "\n    ${C_CYAN}Exiting panel. Goodbye!${C_OFF}"; break ;;
        *) pause_for_error "Invalid option." ;;
    esac
done
