#!/bin/bash

echo "[+] Starting deep shard scan..."

PATTERN='\b[a-fA-F0-9]{32}\b'
OUTFILE="/tmp/found_shards_clean.txt"
TMP_RAW="/tmp/found_shards_raw.txt"

# Directories to search
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

# Raw scan
> "$TMP_RAW"
for dir in "${DIRS[@]}"; do
    echo "[*] Scanning: $dir"
    sudo grep -IroE "$PATTERN" "$dir" --exclude-dir={proc,sys,dev,run,cache} 2>/dev/null >> "$TMP_RAW"
done

# Clean up
echo "[*] Cleaning and validating..."
cut -d: -f2 "$TMP_RAW" | grep -oE "$PATTERN" | sort -u > "$OUTFILE"

echo "[✓] Clean unique shards: $(wc -l < "$OUTFILE")"
echo "[+] Saved to: $OUTFILE"

# Submit
read -p "[?] Submit all to observer.lab/validate ? (y/N): " confirm
if [[ "$confirm" =~ ^[Yy]$ ]]; then
    i=0
    while read -r shard; do
        if [[ "$shard" =~ ^[a-fA-F0-9]{32}$ ]]; then
            ((i++))
            echo "[#${i}] → Submitting: $shard"
            curl -s -X POST -d "$shard" http://observer.lab/validate
            echo
        fi
    done < "$OUTFILE"
fi

echo "[+] Done."
