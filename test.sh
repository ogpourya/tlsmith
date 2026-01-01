#!/bin/bash
set -e

CA_CERT="$HOME/.config/tlsmith/ca.crt"
LOG_FILE="/tmp/tlsmith.log"

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    if [ ! -z "$PID" ]; then
        sudo kill $PID || true
    fi
    if [ -f /etc/hosts.bak ]; then
        sudo mv /etc/hosts.bak /etc/hosts
    fi
    # Reset tlsmith state for clean next run
    uv run tlsmith.py --reset > /dev/null 2>&1 || true
}
trap cleanup EXIT

# Reset before starting to ensure clean state for test
uv run tlsmith.py --reset

echo "Installing dependencies..."
uv sync

echo "Starting tlsmith with CLI args..."
# Note: tlsmith handles /etc/hosts injection.
# We use hooks.py to enable the Date header modification for testing
uv run tlsmith.py --script hooks.py example.com > "$LOG_FILE" 2>&1 &
PID=$!

echo "Waiting for server to start (10s)..."
sleep 10

if [ -f "$LOG_FILE" ]; then
    echo "--- tlsmith.log content ---"
    cat "$LOG_FILE"
    echo "---------------------------"
else
    echo "Log file not found!"
fi

if ! ps -p $PID > /dev/null; then
    echo "Server failed to start."
    exit 1
fi

echo "Backing up /etc/hosts (safety check)..."
sudo cp /etc/hosts /etc/hosts.bak

# Verify /etc/hosts was updated by tlsmith
echo "Checking /etc/hosts for injection..."
if grep -q "example.com" /etc/hosts && grep -q "# tlsmith" /etc/hosts; then
    echo "SUCCESS: /etc/hosts injected correctly."
else
    echo "FAILURE: example.com not found in /etc/hosts or missing marker."
    cat /etc/hosts
    exit 1
fi

# Unset proxy to ensure we hit our local server
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY

echo "Waiting for CA generation..."
sleep 2

if [ ! -f "$CA_CERT" ]; then
    echo "Error: $CA_CERT not found!"
    exit 1
fi

# --- Test 1: HTTPS ---
echo "----------------------------------------------------------------"
echo "Running HTTPS test..."
OUTPUT_HTTPS=$(curl -v --cacert "$CA_CERT" https://example.com 2>&1) || echo "CURL FAILED: $?"
echo "$OUTPUT_HTTPS"

if echo "$OUTPUT_HTTPS" | grep -q "Date: Sat, 01 Jan 2099 00:00:00 GMT"; then
    echo "SUCCESS: HTTPS Date header modification verified!"
else
    echo "FAILURE: HTTPS Date header not found or incorrect."
    exit 1
fi

# --- Test 2: HTTP ---
echo "----------------------------------------------------------------"
echo "Running HTTP test..."
OUTPUT_HTTP=$(curl -v http://example.com 2>&1)
echo "$OUTPUT_HTTP"

if echo "$OUTPUT_HTTP" | grep -q "Date: Sat, 01 Jan 2099 00:00:00 GMT"; then
    echo "SUCCESS: HTTP Date header modification verified!"
else
    echo "FAILURE: HTTP Date header not found or incorrect."
    exit 1
fi

echo "----------------------------------------------------------------"
echo "All tests passed!"
