#!/bin/bash
set -e

CA_CERT="$HOME/.config/tlsmith/ca.crt"
LOG_FILE="/tmp/tlsmith_ip.log"
TEST_IP="1.1.1.1"

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    if [ ! -z "$PID" ]; then
        sudo kill $PID || true
    fi
    # Reset tlsmith state for a clean next run (removes IP addresses from lo)
    uv run tlsmith.py --reset > /dev/null 2>&1 || true
}
trap cleanup EXIT

# Reset before starting to ensure clean state for test
uv run tlsmith.py --reset

echo "Installing dependencies..."
uv sync

echo "Starting tlsmith for IP $TEST_IP..."
# Run as sudo to allow port 80/443 binding and ip addr modification
sudo "$PWD/.venv/bin/python" tlsmith.py "$TEST_IP" example.com --script hooks.py -v > "$LOG_FILE" 2>&1 &
PID=$!

echo "Waiting for server to start (10s)..."
sleep 10

if [ -f "$LOG_FILE" ]; then
    echo "--- tlsmith.log content ---"
    cat "$LOG_FILE"
    echo "---------------------------"
fi

if ! sudo ps -p $PID > /dev/null; then
    echo "Server failed to start."
    exit 1
fi

# Verify IP was added to lo
echo "Verifying $TEST_IP on lo interface..."
if ip addr show dev lo | grep -q "$TEST_IP"; then
    echo "SUCCESS: $TEST_IP found on lo."
else
    echo "FAILURE: $TEST_IP not found on lo."
    exit 1
fi

# Ignore any system proxy environment variables
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY

echo "Waiting for CA generation..."
sleep 2

# --- Test 1: HTTPS ---
echo "----------------------------------------------------------------"
echo "Running HTTPS IP Interception test..."

OUTPUT_HTTPS=$(curl -v -s --cacert "$CA_CERT" --noproxy "*" "https://$TEST_IP" 2>&1) || echo "CURL FAILED"
echo "$OUTPUT_HTTPS"

if echo "$OUTPUT_HTTPS" | grep -qiE "subjectAltName: host \"$TEST_IP\" matched cert's (IP address!|IP Address: $TEST_IP)"; then
    echo "SUCCESS: IP SAN matched correctly."
else
    echo "FAILURE: IP SAN mismatch or SSL error."
    exit 1
fi

if echo "$OUTPUT_HTTPS" | grep -q "Date: Sat, 01 Jan 2099 00:00:00 GMT"; then
    echo "SUCCESS: HTTPS Date header modification verified!"
else
    echo "FAILURE: HTTPS Date header not modified."
    exit 1
fi

# --- Test 2: HTTP ---
echo "----------------------------------------------------------------"
echo "Running HTTP IP Interception test..."
OUTPUT_HTTP=$(curl -v -s --noproxy "*" "http://$TEST_IP" 2>&1)
echo "$OUTPUT_HTTP"

if echo "$OUTPUT_HTTP" | grep -q "Date: Sat, 01 Jan 2099 00:00:00 GMT"; then
    echo "SUCCESS: HTTP Date header modification verified!"
else
    echo "FAILURE: HTTP Date header not modified."
    exit 1
fi

echo "----------------------------------------------------------------"
echo "All IP Interception tests passed!"
