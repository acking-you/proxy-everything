#!/bin/bash
#
# Proxy Server Manager - Interactive systemd service management
#

set -e

SERVICE_NAME="proxy-server"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
BINARY_PATH="/root/http-proxy-server"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════╗"
    echo "║     Proxy Server Manager           ║"
    echo "╚════════════════════════════════════╝"
    echo -e "${NC}"
}

print_menu() {
    echo ""
    echo "1) Install/Configure"
    echo "2) Start"
    echo "3) Stop"
    echo "4) Restart"
    echo "5) Status"
    echo "6) View Logs"
    echo "7) Monitor Resources"
    echo "8) Uninstall"
    echo "0) Exit"
    echo ""
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: Please run as root${NC}"
        exit 1
    fi
}

check_binary() {
    if [ ! -f "$BINARY_PATH" ]; then
        echo -e "${RED}Error: Binary not found at $BINARY_PATH${NC}"
        echo "Please download http-proxy-server from:"
        echo "https://github.com/acking-you/proxy-everything/releases"
        echo "and place it at $BINARY_PATH"
        return 1
    fi
    chmod +x "$BINARY_PATH"
    return 0
}

do_install() {
    echo -e "${YELLOW}=== Install/Configure ===${NC}"

    if ! check_binary; then
        return
    fi

    # Get SECRET_KEY
    echo -n "Enter SECRET_KEY (32 characters, required): "
    read -r SECRET_KEY
    if [ ${#SECRET_KEY} -ne 32 ]; then
        echo -e "${RED}Error: SECRET_KEY must be exactly 32 characters${NC}"
        return
    fi

    # Get PORT
    echo -n "Enter PORT [1081]: "
    read -r PORT
    PORT=${PORT:-1081}

    # Get UPSTREAM (optional)
    echo -n "Enter upstream proxy for chain mode (leave empty for direct mode): "
    read -r UPSTREAM

    # Get CONTROL_SESSION_KEY (optional)
    echo -n "Enter CONTROL_SESSION_KEY for encrypted control (32 chars, optional): "
    read -r CONTROL_SESSION_KEY

    # Get LOG_LEVEL
    echo -n "Enter log level [info]: "
    read -r LOG_LEVEL
    LOG_LEVEL=${LOG_LEVEL:-info}

    # Build Environment lines
    ENV_LINES="Environment=\"SECRET_KEY=${SECRET_KEY}\""
    ENV_LINES="${ENV_LINES}\nEnvironment=\"RUST_LOG=${LOG_LEVEL}\""
    if [ -n "$UPSTREAM" ]; then
        ENV_LINES="${ENV_LINES}\nEnvironment=\"TURELY_PROXY_SERVER=${UPSTREAM}\""
    fi
    if [ -n "$CONTROL_SESSION_KEY" ]; then
        ENV_LINES="${ENV_LINES}\nEnvironment=\"CONTROL_SESSION_KEY=${CONTROL_SESSION_KEY}\""
    fi

    # Generate service file
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Proxy Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
$(echo -e "$ENV_LINES")
ExecStart=/bin/sh -c 'ulimit -n 65535 && exec ${BINARY_PATH} -p ${PORT}'
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"

    echo -e "${GREEN}Service installed successfully!${NC}"
    echo "Configuration:"
    echo "  - Port: $PORT"
    echo "  - Mode: $([ -n "$UPSTREAM" ] && echo "chain -> $UPSTREAM" || echo "direct")"
    echo "  - Control encryption: $([ -n "$CONTROL_SESSION_KEY" ] && echo "enabled" || echo "disabled")"
    echo "  - Log level: $LOG_LEVEL"
    echo "  - Data dir: ~/.proxy-everything/ (nodes.json, relay.json)"
    echo ""
    echo "Run option 2 to start the service."
}

do_start() {
    echo -e "${YELLOW}Starting service...${NC}"
    systemctl start "$SERVICE_NAME"
    echo -e "${GREEN}Service started${NC}"
}

do_stop() {
    echo -e "${YELLOW}Stopping service...${NC}"
    systemctl stop "$SERVICE_NAME"
    echo -e "${GREEN}Service stopped${NC}"
}

do_restart() {
    echo -e "${YELLOW}Restarting service...${NC}"
    systemctl restart "$SERVICE_NAME"
    echo -e "${GREEN}Service restarted${NC}"
}

do_status() {
    echo -e "${YELLOW}=== Service Status ===${NC}"
    systemctl status "$SERVICE_NAME" --no-pager || true
}

do_logs() {
    echo -e "${YELLOW}=== Log Options ===${NC}"
    echo "1) Last 50 lines"
    echo "2) Last 100 lines"
    echo "3) Follow logs (Ctrl+C to exit)"
    echo -n "Choose: "
    read -r choice

    case $choice in
        1) journalctl -u "$SERVICE_NAME" -n 50 --no-pager ;;
        2) journalctl -u "$SERVICE_NAME" -n 100 --no-pager ;;
        3) journalctl -u "$SERVICE_NAME" -f ;;
        *) echo "Invalid choice" ;;
    esac
}

do_monitor() {
    echo -e "${YELLOW}=== Resource Monitor ===${NC}"

    PID=$(pgrep -f "http-proxy-server" || true)
    if [ -z "$PID" ]; then
        echo -e "${RED}Service is not running${NC}"
        return
    fi

    echo "1) One-time snapshot"
    echo "2) Live monitor (Ctrl+C to exit)"
    echo -n "Choose: "
    read -r choice

    case $choice in
        1)
            echo ""
            echo -e "${GREEN}Process Info:${NC}"
            ps -p "$PID" -o pid,user,%cpu,%mem,vsz,rss,stat,start,time,command --no-headers
            echo ""
            echo -e "${GREEN}Memory Details:${NC}"
            cat /proc/"$PID"/status | grep -E "^(VmSize|VmRSS|VmPeak|Threads):"
            ;;
        2)
            top -p "$PID"
            ;;
        *) echo "Invalid choice" ;;
    esac
}

do_uninstall() {
    echo -e "${YELLOW}=== Uninstall ===${NC}"
    echo -n "Are you sure? (y/N): "
    read -r confirm

    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "Cancelled"
        return
    fi

    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload

    echo -n "Delete binary at $BINARY_PATH? (y/N): "
    read -r del_binary
    if [ "$del_binary" = "y" ] || [ "$del_binary" = "Y" ]; then
        rm -f "$BINARY_PATH"
        echo "Binary deleted"
    fi

    echo -e "${GREEN}Uninstall complete${NC}"
}

main() {
    check_root

    while true; do
        print_header
        print_menu
        echo -n "Choose an option: "
        read -r choice

        case $choice in
            1) do_install ;;
            2) do_start ;;
            3) do_stop ;;
            4) do_restart ;;
            5) do_status ;;
            6) do_logs ;;
            7) do_monitor ;;
            8) do_uninstall ;;
            0) echo "Bye!"; exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}" ;;
        esac

        echo ""
        echo -n "Press Enter to continue..."
        read -r
    done
}

main
