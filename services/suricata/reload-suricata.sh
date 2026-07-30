#!/bin/bash

# reload-suricata.sh - Reload Suricata IDS and IPS with new rule configurations
# This script restarts both IDS and IPS instances to apply updated rules from the admin dashboard

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Reloading Suricata IDS/IPS Configurations ==="
echo "$(date): Starting Suricata reload process..."

# Check if Suricata is installed
if ! command -v suricata &> /dev/null; then
    echo "ERROR: Suricata is not installed or not in PATH"
    exit 1
fi

# Check if we can use sudo (test with a simple command)
if ! sudo -n true 2>/dev/null; then
    echo "ERROR: sudo access required but not available (passwordless sudo needed)"
    exit 1
fi

# Function to check if Suricata is running
check_suricata_running() {
    local config_name=$1
    local pid_file="/var/run/suricata-${config_name}.pid"
    
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            return 0  # Process is running
        fi
    fi
    return 1  # Process is not running
}

# Function to stop Suricata instance
stop_suricata() {
    local config_name=$1
    local pid_file="/var/run/suricata-${config_name}.pid"
    
    echo "$(date): Stopping Suricata $config_name..."
    
    if check_suricata_running "$config_name"; then
        local pid=$(cat "$pid_file")
        echo "$(date): Sending TERM signal to Suricata $config_name (PID: $pid)"
        
        # Send SIGTERM
        sudo kill -TERM "$pid" 2>/dev/null || true
        
        # Wait for graceful shutdown (max 5 seconds - reduced from 10)
        for i in {1..5}; do
            if ! check_suricata_running "$config_name"; then
                echo "$(date): Suricata $config_name stopped gracefully"
                return 0
            fi
            sleep 1
        done
        
        # Force kill if still running
        if check_suricata_running "$config_name"; then
            echo "$(date): Force killing Suricata $config_name"
            sudo kill -KILL "$pid" 2>/dev/null || true
            sleep 1
        fi
    else
        echo "$(date): Suricata $config_name was not running"
    fi
    
    # Clean up PID file
    sudo rm -f "$pid_file"
}

# Function to start Suricata instance
start_suricata() {
    local config_name=$1
    local config_file=$2
    local interface=$3
    local extra_args=$4
    
    echo "$(date): Starting Suricata $config_name..."
    
    # Validate config before starting
    echo "$(date): Validating $config_file..."
    if ! sudo suricata -T -c "$config_file" >/dev/null 2>&1; then
        echo "ERROR: Configuration validation failed for $config_file"
        return 1
    fi
    
    # Start Suricata (let YAML config specify which rule files to load)
    # IPS/NFQUEUE mode (-q) and pcap/interface mode (-i) are mutually exclusive run modes
    local cmd
    if echo "$extra_args" | grep -q '\-q'; then
        cmd="sudo suricata -c $config_file -D --pidfile /var/run/suricata-${config_name}.pid $extra_args"
    else
        cmd="sudo suricata -c $config_file -i $interface -D --pidfile /var/run/suricata-${config_name}.pid $extra_args"
    fi
    echo "$(date): Executing: $cmd"
    
    if eval "$cmd"; then
        echo "$(date): Suricata $config_name started successfully"
        
        # Wait a moment and verify it's still running
        sleep 1
        if check_suricata_running "$config_name"; then
            echo "$(date): Confirmed Suricata $config_name is running"
            return 0
        else
            echo "ERROR: Suricata $config_name failed to start properly"
            return 1
        fi
    else
        echo "ERROR: Failed to start Suricata $config_name"
        return 1
    fi
}

# Main reload process
echo "$(date): Current Suricata processes:"
ps aux | grep '[s]uricata' || echo "No Suricata processes found"

# Stop existing instances
if check_suricata_running "ids"; then
    stop_suricata "ids"
fi

if check_suricata_running "ips"; then
    stop_suricata "ips"
fi

# Always remove stale PID files — Suricata refuses to start if they exist
# even when the process they reference is already dead.
sudo rm -f /var/run/suricata-ids.pid /var/run/suricata-ips.pid
echo "$(date): Stale PID files cleared."

# Kill any orphaned Suricata processes not caught by the PID check
sudo pkill -x suricata 2>/dev/null || true
sleep 1

# Wait a moment for complete shutdown
sleep 2

# Remove old NFQUEUE rules from all chains (cleanup any previous formats)
echo "$(date): Cleaning up old NFQUEUE rules..."
# Clean old mangle INPUT/OUTPUT rules
sudo iptables -t mangle -D INPUT -p tcp --dport 8080 -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
sudo iptables -t mangle -D OUTPUT -p tcp --sport 8080 -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
sudo iptables -t mangle -D INPUT -p tcp --dport 8080 -m mark ! --mark 1 -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
sudo iptables -t mangle -D OUTPUT -p tcp --sport 8080 -m mark ! --mark 1 -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
# Clean old FORWARD rules
sudo iptables -D FORWARD -s 192.168.35.132 -j ACCEPT 2>/dev/null || true
sudo iptables -D FORWARD -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true

# Ensure log directories exist for both IDS and IPS eve.json outputs
sudo mkdir -p /var/log/suricata/ids
sudo mkdir -p /var/log/suricata/ips

# Start IDS instance
echo ""
echo "$(date): === Starting Suricata IDS ==="
if start_suricata "ids" "suricata.yaml" "eth0" ""; then
    echo "$(date): ✓ Suricata IDS started successfully"
else
    echo "$(date): ✗ Failed to start Suricata IDS"
    exit 1
fi

sleep 1

# Start IPS instance  
echo ""
echo "$(date): === Starting Suricata IPS ==="
if start_suricata "ips" "suricata-ips.yaml" "eth0" "-q 0"; then
    echo "$(date): ✓ Suricata IPS started successfully"
else
    echo "$(date): ✗ Failed to start Suricata IPS"
    exit 1
fi

# Add FORWARD chain rules for IPS inline mode
# Rule 1: Allow trusted IP (192.168.35.132) to bypass NFQUEUE
# Rule 2: All other FORWARD traffic goes through NFQUEUE with fail-open
echo "$(date): Adding FORWARD chain NFQUEUE rules (trusted IP: 192.168.35.132)..."
sudo iptables -I FORWARD 1 -s 192.168.35.132 -j ACCEPT
sudo iptables -I FORWARD 2 -j NFQUEUE --queue-num 0 --queue-bypass
echo "$(date): FORWARD rules added: trusted .132 bypasses, rest goes through NFQUEUE."

if [ "${1}" = "--disable-ips" ]; then
    echo "$(date): --disable-ips flag: removing FORWARD NFQUEUE rules (IDS-only mode)..."
    sudo iptables -D FORWARD -s 192.168.35.132 -j ACCEPT 2>/dev/null || true
    sudo iptables -D FORWARD -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
    echo "$(date): FORWARD rules removed. Running in IDS-only mode."
fi

# Final status check
echo ""
echo "$(date): === Final Status Check ==="
echo "$(date): Active Suricata processes:"
ps aux | grep '[s]uricata' || echo "WARNING: No Suricata processes found"

echo "$(date): Active FORWARD rules:"
sudo iptables -L FORWARD -n --line-numbers | head -10 || echo "No FORWARD rules"

echo ""
echo "$(date): ✓ Suricata reload completed successfully!"
echo "$(date): IDS (passive detection) + IPS (inline blocking on port 8080) are both active."