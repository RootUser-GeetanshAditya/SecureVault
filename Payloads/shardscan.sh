#!/bin/bash

echo "[+] Starting deep shard scan..."

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Where to look
DIRS=(
    "$HOME"
    "/etc"
    "/opt"
    "/srv"
    "/var"
    "/usr/local/bin"
    "/usr/bin"
    "/bin"
    "/boot"
    "/root"
    "/tmp"
    "/lib"
    "/lib64"
)

# Pattern to look for (like MD5)
PATTERN='\b[a-fA-F0-9]{32}\b'

# Output
OUTFILE="/tmp/found_shards_$(date +%s).txt"
touch "$OUTFILE"

scan_dir() {
    local dir="$1"
    echo -e "${YELLOW}[*] Scanning: $dir${NC}"
    sudo grep -IroE "$PATTERN" "$dir" --exclude-dir={proc,sys,dev,run,cache} 2>/dev/null | sort -u >> "$OUTFILE"
}

for d in "${DIRS[@]}"; do
    scan_dir "$d"
done

echo -e "\n${GREEN}[✓] Unique shards found: $(wc -l < "$OUTFILE")${NC}"
echo -e "[+] Output saved to: $OUTFILE"

# Optionally send somewhere
read -p "[?] Submit all to observer.lab/validate ? (y/N): " confirm
if [[ "$confirm" =~ ^[Yy]$ ]]; then
    while read -r shard; do
        if [[ "$shard" =~ $PATTERN ]]; then
            echo -e "${YELLOW}[*] Submitting: $shard${NC}"
            curl -s -X POST -d "$shard" http://observer.lab/validate
            echo ""
        fi
    done < "$OUTFILE"
fi

echo -e "${GREEN}[+] Done.${NC}"
