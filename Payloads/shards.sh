#!/bin/bash

echo "[+] Starting shard scan..."
SHARD_REGEX='[a-f0-9]{32}'
FOUND=0

check_path() {
    local path=$1
    echo "[*] Scanning: $path"
    grep -rEo "$SHARD_REGEX" "$path" 2>/dev/null | while read -r shard; do
        echo "[✓] Shard Found: $shard"
        FOUND=$((FOUND + 1))
    done
}

# --- Persistence Backdoor Locations ---
check_path ~/.bashrc
check_path ~/.zshrc
check_path ~/.profile
check_path ~/.ssh
check_path ~/.config/systemd/user/
check_path ~/.gitconfig
check_path /etc/systemd/system/
check_path /etc/network/if-*.d/
check_path /etc/update-motd.d/
check_path /etc/udev/rules.d/
check_path /etc/apt/apt.conf.d/
check_path ~/.config/autostart/
check_path ~/  # catch hidden .aliases, .functions, or .hidden backdoors

# --- Git Hooks (repo-specific) ---
echo "[*] Searching Git hook folders..."
find ~ -type f -path '*/.git/hooks/*' -exec grep -Eo "$SHARD_REGEX" {} + 2>/dev/null | while read -r shard; do
    echo "[✓] Git Hook Shard Found: $shard"
    FOUND=$((FOUND + 1))
done

# --- Check for Aliases ---
echo "[*] Checking for aliased shard commands..."
alias | grep -Eo "$SHARD_REGEX" | while read -r shard; do
    echo "[✓] Alias Shard Found: $shard"
    FOUND=$((FOUND + 1))
done

# --- Check for Functions ---
echo "[*] Checking for declared bash functions..."
declare -f | grep -Eo "$SHARD_REGEX" | while read -r shard; do
    echo "[✓] Function Shard Found: $shard"
    FOUND=$((FOUND + 1))
done

# --- Final Summary ---
if [ "$FOUND" -eq 0 ]; then
    echo "[-] No new shards found. Try looking into obfuscated or encoded payloads."
else
    echo "[+] Total shards found: $FOUND"
fi
