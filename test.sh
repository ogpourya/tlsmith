#!/bin/bash
set -e

CA_CERT="$HOME/.config/tlsmith/ca.crt"
LOG_FILE="/tmp/tlsmith.log"

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    if [ ! -z "$PID" ]; then
        kill $PID || true
    fi
    if [ ! -z "$PROXY_PID" ]; then
        kill $PROXY_PID || true
    fi
    if [ -f /etc/hosts.bak ]; then
        sudo mv /etc/hosts.bak /etc/hosts
    fi
    # Reset tlsmith state for a clean next run
    uv run tlsmith.py --reset > /dev/null 2>&1 || true
}
trap cleanup EXIT

# Reset before starting to ensure clean state for test
uv run tlsmith.py --reset

echo "Installing dependencies..."
uv sync

echo "Assuming proxy is already running at http://localhost:3333"
# Do not start a new proxy, just check if something is listening
if ! nc -z localhost 3333; then
    echo "WARNING: No proxy detected at localhost:3333. Tests may fail!"
fi

echo "Starting tlsmith with CLI args..."
# tlsmith handles /etc/hosts injection and uses hooks.py for Date header modification
uv run tlsmith.py icanhazip.com --proxy http://localhost:3333 --script hooks.py  -v > "$LOG_FILE" 2>&1 &
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
if grep -q "icanhazip.com" /etc/hosts && grep -q "# tlsmith" /etc/hosts; then
    echo "SUCCESS: /etc/hosts injected correctly."
else
    echo "FAILURE: icanhazip.com not found in /etc/hosts or missing marker."
    cat /etc/hosts
    exit 1
fi

# Unset proxy to ensure we hit our local server directly
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
# Get initial IP without proxy for comparison
DIRECT_IP=$(curl -s https://icanhazip.com || echo "DIRECT_FAILED")
echo "Direct IP: $DIRECT_IP"

OUTPUT_HTTPS=$(curl -v --connect-to icanhazip.com:443:127.0.0.1:10443 --cacert "$CA_CERT" https://icanhazip.com 2>&1) || echo "CURL FAILED: $?"
PROXY_IP_HTTPS=$(echo "$OUTPUT_HTTPS" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || echo "FAILED_TO_GET_IP")
echo "Returned IP (HTTPS): $PROXY_IP_HTTPS"
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
OUTPUT_HTTP=$(curl -v --connect-to icanhazip.com:80:127.0.0.1:10080 http://icanhazip.com 2>&1)
PROXY_IP_HTTP=$(echo "$OUTPUT_HTTP" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || echo "FAILED_TO_GET_IP")
echo "Returned IP (HTTP): $PROXY_IP_HTTP"
echo "$OUTPUT_HTTP"

if echo "$OUTPUT_HTTP" | grep -q "Date: Sat, 01 Jan 2099 00:00:00 GMT"; then
    echo "SUCCESS: HTTP Date header modification verified!"
else
    echo "FAILURE: HTTP Date header not found or incorrect."
    exit 1
fi

if [ "$DIRECT_IP" == "$PROXY_IP_HTTPS" ] || [ "$DIRECT_IP" == "$PROXY_IP_HTTP" ]; then
    echo "FAILURE: Returned IP is the same as direct IP. Proxy might not be working."
    exit 1
else
    echo "SUCCESS: Proxy IP ($PROXY_IP_HTTPS) differs from direct IP ($DIRECT_IP)."
fi

echo "----------------------------------------------------------------"
echo "All tests passed!"

echo "----------------------------------------------------------------"
echo "Verifying Proxy Usage..."
if grep -q "Using upstream proxy: http://localhost:3333" "$LOG_FILE"; then
    echo "SUCCESS: Proxy usage logged in tlsmith.log"
else
    echo "FAILURE: Proxy usage NOT found in tlsmith.log"
    exit 1
fi
