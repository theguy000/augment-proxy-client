#!/bin/bash
#
# Augment Proxy - One-Line Installer for macOS and Linux
# Usage: curl -fsSL https://raw.githubusercontent.com/USER/augment-proxy-client/main/install.sh | bash -s <username> <password>
#

set -euo pipefail

# Configuration
PROXY_USERNAME="${1:-}"
PROXY_PASSWORD="${2:-}"
PROXY_HOST="${PROXY_HOST:-proxy.ai-proxy.space}"
PROXY_PORT="${PROXY_PORT:-6969}"
GITHUB_REPO="${GITHUB_REPO:-theguy000/augment-proxy-client}"
GITHUB_RAW="https://raw.githubusercontent.com/${GITHUB_REPO}/main"
GITHUB_RELEASES="https://github.com/${GITHUB_REPO}/releases/download"
VERSION="0.92.3"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up temporary files..."
    rm -f /tmp/cntlm* /tmp/mitmproxy-ca-cert.pem 2>/dev/null || true
}

# Rollback function
rollback() {
    log_error "Installation failed. Rolling back..."
    
    # Stop and remove CNTLM service
    if [[ "$OS" == "macos" ]]; then
        sudo launchctl unload /Library/LaunchDaemons/com.cntlm.plist 2>/dev/null || true
        sudo rm -f /Library/LaunchDaemons/com.cntlm.plist
    elif [[ "$OS" == "linux" ]]; then
        sudo systemctl stop cntlm 2>/dev/null || true
        sudo systemctl disable cntlm 2>/dev/null || true
        sudo rm -f /etc/systemd/system/cntlm.service
        sudo systemctl daemon-reload
    fi
    
    # Remove CNTLM binary and config
    sudo rm -f /usr/local/bin/cntlm /etc/cntlm.conf
    
    # Restore VS Code settings backup
    if [[ -f "${VSCODE_SETTINGS}.backup" ]]; then
        mv "${VSCODE_SETTINGS}.backup" "$VSCODE_SETTINGS"
    fi
    
    cleanup
    exit 1
}

# Set trap for errors
trap rollback ERR

# Validate arguments
if [[ -z "$PROXY_USERNAME" ]] || [[ -z "$PROXY_PASSWORD" ]]; then
    log_error "Missing credentials"
    echo ""
    echo "Usage: bash install.sh <username> <password>"
    echo ""
    echo "Example:"
    echo "  bash install.sh user_d99cfdfd NUqvdSuFzztEBPQC"
    echo ""
    exit 1
fi

# Detect platform
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case "$OS" in
        darwin) OS="macos" ;;
        linux) OS="linux" ;;
        *) 
            log_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
    
    case "$ARCH" in
        x86_64|amd64) ARCH="x64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        i386|i686) ARCH="x86" ;;
        *) 
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    
    PLATFORM="${OS}-${ARCH}"
    log_info "Detected platform: $PLATFORM"
}

# Check for required commands
check_requirements() {
    local missing_cmds=()
    
    for cmd in curl sudo; do
        if ! command -v $cmd &> /dev/null; then
            missing_cmds+=($cmd)
        fi
    done
    
    if [[ ${#missing_cmds[@]} -gt 0 ]]; then
        log_error "Missing required commands: ${missing_cmds[*]}"
        exit 1
    fi
}

# Download and install CNTLM
install_cntlm() {
    log_info "Downloading CNTLM for ${PLATFORM}..."
    
    # Determine binary URL based on platform
    if [[ "$OS" == "macos" ]]; then
        BINARY_URL="${GITHUB_RELEASES}/v${VERSION}/cntlm-${VERSION}-${ARCH}-macos"
    elif [[ "$OS" == "linux" ]]; then
        BINARY_URL="${GITHUB_RELEASES}/v${VERSION}/cntlm-${VERSION}-${ARCH}-linux"
    fi
    
    # Download binary
    if ! curl -fsSL "$BINARY_URL" -o /tmp/cntlm; then
        log_error "Failed to download CNTLM binary"
        log_info "Trying alternative installation method..."
        
        # Fallback: try to install via package manager
        if [[ "$OS" == "macos" ]]; then
            if command -v brew &> /dev/null; then
                log_info "Installing CNTLM via Homebrew..."
                brew install cntlm
                return 0
            fi
        elif [[ "$OS" == "linux" ]]; then
            if command -v apt-get &> /dev/null; then
                log_info "Installing CNTLM via apt..."
                sudo apt-get update
                sudo apt-get install -y cntlm
                return 0
            elif command -v yum &> /dev/null; then
                log_info "Installing CNTLM via yum..."
                sudo yum install -y cntlm
                return 0
            fi
        fi
        
        log_error "Could not install CNTLM"
        exit 1
    fi
    
    # Make binary executable
    chmod +x /tmp/cntlm
    
    # Install to system location
    log_info "Installing CNTLM to /usr/local/bin..."
    sudo install -m 755 /tmp/cntlm /usr/local/bin/cntlm
    
    log_success "CNTLM installed successfully"
}

# Install mitmproxy certificate
install_certificate() {
    log_info "Downloading mitmproxy certificate..."
    
    CERT_URL="${GITHUB_RAW}/certs/mitmproxy-ca-cert.pem"
    
    if ! curl -fsSL "$CERT_URL" -o /tmp/mitmproxy-ca-cert.pem; then
        log_error "Failed to download certificate"
        exit 1
    fi
    
    log_info "Installing certificate to system trust store..."
    
    if [[ "$OS" == "macos" ]]; then
        # macOS: Install to system keychain
        sudo security add-trusted-cert -d -r trustRoot \
            -k /Library/Keychains/System.keychain \
            /tmp/mitmproxy-ca-cert.pem
        log_success "Certificate installed to macOS keychain"
        
    elif [[ "$OS" == "linux" ]]; then
        # Linux: Install based on distribution
        if [[ -d "/usr/local/share/ca-certificates" ]]; then
            # Debian/Ubuntu
            sudo cp /tmp/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
            sudo chmod 644 /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
            sudo update-ca-certificates
            log_success "Certificate installed (Debian/Ubuntu)"
            
        elif [[ -d "/etc/pki/ca-trust/source/anchors" ]]; then
            # RedHat/Fedora/CentOS
            sudo cp /tmp/mitmproxy-ca-cert.pem /etc/pki/ca-trust/source/anchors/mitmproxy-ca-cert.pem
            sudo chmod 644 /etc/pki/ca-trust/source/anchors/mitmproxy-ca-cert.pem
            sudo update-ca-trust
            log_success "Certificate installed (RedHat/Fedora/CentOS)"
        else
            log_warn "Could not determine certificate installation method"
            log_warn "Please install /tmp/mitmproxy-ca-cert.pem manually"
        fi
    fi
}

# Generate CNTLM configuration
generate_config() {
    log_info "Generating CNTLM configuration..."
    
    # Download template
    TEMPLATE_URL="${GITHUB_RAW}/templates/cntlm.conf.template"
    
    if curl -fsSL "$TEMPLATE_URL" -o /tmp/cntlm.conf.template 2>/dev/null; then
        # Use template
        sed "s/{{PROXY_USERNAME}}/${PROXY_USERNAME}/g" /tmp/cntlm.conf.template | \
        sed "s/{{PROXY_PASSWORD}}/${PROXY_PASSWORD}/g" | \
        sed "s/{{PROXY_HOST}}/${PROXY_HOST}/g" | \
        sed "s/{{PROXY_PORT}}/${PROXY_PORT}/g" | \
        sudo tee /etc/cntlm.conf > /dev/null
    else
        # Fallback: create config directly
        log_warn "Could not download template, creating config directly..."
        sudo tee /etc/cntlm.conf > /dev/null <<EOF
# CNTLM Configuration for Augment Proxy
Listen 3128
Proxy ${PROXY_HOST}:${PROXY_PORT}
Username ${PROXY_USERNAME}
Password ${PROXY_PASSWORD}
Domain
Auth Basic
Allow 127.0.0.1
Allow localhost
Deny 0/0
NoProxy localhost, 127.0.0.1, .local
ConnectTimeout 3600
SocketTimeout 3600
LogLevel 2
EOF
    fi
    
    # Secure the config file (contains password)
    sudo chmod 600 /etc/cntlm.conf
    
    log_success "CNTLM configuration created"
}

# Start CNTLM service
start_cntlm() {
    log_info "Starting CNTLM service..."
    
    if [[ "$OS" == "macos" ]]; then
        # Create launchd plist
        sudo tee /Library/LaunchDaemons/com.cntlm.plist > /dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.cntlm</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/cntlm</string>
        <string>-c</string>
        <string>/etc/cntlm.conf</string>
        <string>-f</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/cntlm.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/cntlm.error.log</string>
</dict>
</plist>
EOF
        sudo launchctl load /Library/LaunchDaemons/com.cntlm.plist
        sleep 2
        log_success "CNTLM service started (launchd)"
        
    elif [[ "$OS" == "linux" ]]; then
        # Create systemd service
        sudo tee /etc/systemd/system/cntlm.service > /dev/null <<EOF
[Unit]
Description=CNTLM Authentication Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cntlm -c /etc/cntlm.conf -f
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        sudo systemctl daemon-reload
        sudo systemctl enable cntlm
        sudo systemctl start cntlm
        sleep 2
        log_success "CNTLM service started (systemd)"
    fi
    
    # Verify service is running
    if [[ "$OS" == "macos" ]]; then
        if ! sudo launchctl list | grep -q com.cntlm; then
            log_error "CNTLM service failed to start"
            exit 1
        fi
    elif [[ "$OS" == "linux" ]]; then
        if ! sudo systemctl is-active --quiet cntlm; then
            log_error "CNTLM service failed to start"
            sudo systemctl status cntlm
            exit 1
        fi
    fi
}

# Configure VS Code
configure_vscode() {
    log_info "Configuring VS Code..."
    
    # Determine VS Code settings location
    if [[ "$OS" == "macos" ]]; then
        VSCODE_SETTINGS="$HOME/Library/Application Support/Code/User/settings.json"
    elif [[ "$OS" == "linux" ]]; then
        VSCODE_SETTINGS="$HOME/.config/Code/User/settings.json"
    fi
    
    if [[ ! -f "$VSCODE_SETTINGS" ]]; then
        log_warn "VS Code settings file not found at: $VSCODE_SETTINGS"
        log_warn "Please manually configure VS Code with:"
        echo '  "http.proxy": "http://localhost:3128"'
        echo '  "http.proxyStrictSSL": false'
        return 0
    fi
    
    # Backup original settings
    cp "$VSCODE_SETTINGS" "${VSCODE_SETTINGS}.backup"
    
    # Update settings using jq if available
    if command -v jq &> /dev/null; then
        jq '.["http.proxy"] = "http://localhost:3128" | .["http.proxyStrictSSL"] = false' \
            "$VSCODE_SETTINGS" > "${VSCODE_SETTINGS}.tmp"
        mv "${VSCODE_SETTINGS}.tmp" "$VSCODE_SETTINGS"
        log_success "VS Code configured (backup saved to ${VSCODE_SETTINGS}.backup)"
    else
        log_warn "jq not found. Please manually add to VS Code settings:"
        echo '  "http.proxy": "http://localhost:3128"'
        echo '  "http.proxyStrictSSL": false'
    fi
}

# Main installation flow
main() {
    echo ""
    echo -e "${CYAN}=========================================${NC}"
    echo -e "${CYAN}Augment Proxy - One-Line Installer${NC}"
    echo -e "${CYAN}=========================================${NC}"
    echo ""
    
    detect_platform
    check_requirements
    install_cntlm
    install_certificate
    generate_config
    start_cntlm
    configure_vscode
    cleanup
    
    echo ""
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}✓ Installation Complete!${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo ""
    echo -e "${CYAN}Next steps:${NC}"
    echo "1. Restart VS Code"
    echo "2. The Augment extension will now work through the proxy"
    echo ""
    echo -e "${CYAN}Configuration:${NC}"
    echo "  CNTLM running on: localhost:3128"
    echo "  Proxy server: ${PROXY_HOST}:${PROXY_PORT}"
    echo "  Username: ${PROXY_USERNAME}"
    echo ""
    echo -e "${CYAN}Troubleshooting:${NC}"
    if [[ "$OS" == "macos" ]]; then
        echo "  Check CNTLM status: sudo launchctl list | grep cntlm"
        echo "  View logs: tail -f /var/log/cntlm.log"
        echo "  Restart CNTLM: sudo launchctl unload /Library/LaunchDaemons/com.cntlm.plist && sudo launchctl load /Library/LaunchDaemons/com.cntlm.plist"
    elif [[ "$OS" == "linux" ]]; then
        echo "  Check CNTLM status: sudo systemctl status cntlm"
        echo "  View logs: sudo journalctl -u cntlm -f"
        echo "  Restart CNTLM: sudo systemctl restart cntlm"
    fi
    echo ""
}

main

