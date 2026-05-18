#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

info() {
    echo -e "${BLUE}${BOLD}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}${BOLD}[SUCCESS]${NC} $1"
}

error() {
    echo -e "${RED}${BOLD}[ERROR]${NC} $1"
}

APP_DIR="$(pwd)"
BINARY_NAME="xoftware-turnstile"
SERVICE_NAME="xoftware-turnstile"

info "Checking remote repository for updates..."

git fetch -q

LOCAL=$(git rev-parse @)
REMOTE=$(git rev-parse @{u})
BASE=$(git merge-base @ @{u})

if [ "$LOCAL" = "$REMOTE" ]; then
    success "System is up to date."
elif [ "$LOCAL" = "$BASE" ]; then
    info "New update detected on GitHub upstream. Initiating pull..."
    
    git pull
    
    info "Recompiling application binary..."
    go build -ldflags="-s -w" -o "${APP_DIR}/${BINARY_NAME}" "${APP_DIR}/main.go"
    
    info "Restarting daemon service..."
    if [ "$EUID" -ne 0 ]; then
        sudo systemctl restart "${SERVICE_NAME}"
    else
        systemctl restart "${SERVICE_NAME}"
    fi
    
    success "Update deployed successfully."
elif [ "$REMOTE" = "$BASE" ]; then
    info "Local branch is ahead of remote. No action required."
else
    error "Local and remote branches have diverged. Manual intervention required."
fi
