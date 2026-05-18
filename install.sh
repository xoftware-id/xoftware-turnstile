#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

info() {
    echo -e "${BLUE}${BOLD}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}${BOLD}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}${BOLD}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}${BOLD}[ERROR]${NC} $1"
}

GO_VERSION="1.25.0"
APP_DIR="$(pwd)"
BINARY_NAME="xoftware-turnstile"
SERVICE_NAME="xoftware-turnstile"
SYSTEMD_SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

echo -e "${BLUE}${BOLD}>>> Initiating system setup and deployment...${NC}"

if [ "$EUID" -ne 0 ]; then
    error "Execution requires root privileges. Please run as root or prefix with sudo."
    exit 1
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME=$ID
    OS_VERSION=$VERSION_ID
else
    OS_NAME=$(uname -s | tr '[:upper:]' '[:lower:]')
    OS_VERSION="unknown"
fi

if [[ "$OS_NAME" != "ubuntu" && "$OS_NAME" != "debian" ]]; then
    warning "Platform mismatch. Continuing installation on $OS_NAME $OS_VERSION..."
else
    info "Target OS verified: $OS_NAME $OS_VERSION"
fi

info "Updating system packages and installing dependencies..."
apt-get update -y
apt-get install -y curl tar git build-essential tzdata jq

install_go() {
    info "Retrieving Go package version ${GO_VERSION}..."
    ARCH=$(dpkg --print-architecture)
    if [ "$ARCH" = "amd64" ]; then
        GO_ARCH="amd64"
    elif [ "$ARCH" = "arm64" ]; then
        GO_ARCH="arm64"
    else
        GO_ARCH="386"
    fi
    
    GO_TAR="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    DOWNLOAD_URL="https://go.dev/dl/${GO_TAR}"
    
    curl -L -o /tmp/${GO_TAR} "${DOWNLOAD_URL}"
    
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/${GO_TAR}
    rm -f /tmp/${GO_TAR}
    
    if [ ! -f /etc/profile.d/golang.sh ]; then
        echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/golang.sh
        echo 'export GOPATH=$HOME/go' >> /etc/profile.d/golang.sh
        echo 'export PATH=$PATH:$GOPATH/bin' >> /etc/profile.d/golang.sh
    fi
    
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
}

if command -v go >/dev/null 2>&1; then
    CURRENT_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    if [ "$(printf '%s\n' "$GO_VERSION" "$CURRENT_GO_VERSION" | sort -V | head -n1)" != "$GO_VERSION" ]; then
        info "Upgrading Go to version ${GO_VERSION}..."
        install_go
    else
        info "Golang is up to date (version ${CURRENT_GO_VERSION})"
    fi
else
    info "Golang is missing. Installing Go ${GO_VERSION}..."
    install_go
fi

if [ -f /etc/profile.d/golang.sh ]; then
    . /etc/profile.d/golang.sh
fi

if [ ! -f "${APP_DIR}/go.mod" ]; then
    error "go.mod file not found in ${APP_DIR}. Execution aborted."
    exit 1
fi

info "Synchronizing module dependencies..."
go mod tidy

info "Compiling project binary..."
go build -ldflags="-s -w" -o "${APP_DIR}/${BINARY_NAME}" "${APP_DIR}/main.go"

cat <<EOF > "${SYSTEMD_SERVICE_PATH}"
[Unit]
Description=Go Xoftware Turnstile Daemon Service
After=network.target mysql.service postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/${BINARY_NAME}
Restart=always
RestartSec=5s
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

sleep 2

SERVICE_STATUS=$(systemctl is-active "${SERVICE_NAME}" || true)

if [ "$SERVICE_STATUS" = "active" ]; then
    success "Deployment completed. The service is active and running."
else
    error "Service startup failure. Status: ${SERVICE_STATUS}"
    journalctl -u "${SERVICE_NAME}" -n 20 --no-pager
    exit 1
fi
