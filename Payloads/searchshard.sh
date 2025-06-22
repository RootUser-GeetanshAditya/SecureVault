#!/bin/bash

OUTPUT_FILE="shards1.txt"
TEMP_FILE=$(mktemp)

# Clear previous results
> "$OUTPUT_FILE"

# Function to search files/directories for shard pattern
search_locations() {
    local locations=("$@")
    for location in "${locations[@]}"; do
        if [ -e "$location" ]; then
            grep -rIhEo --color=never '[a-f0-9]{32}' "$location" 2>/dev/null
        fi
    done
}

# Function to check crontabs
check_crontabs() {
    { crontab -l 2>/dev/null
      sudo crontab -l 2>/dev/null
    } | grep -Eo '[a-f0-9]{32}'
}

# Function to check loaded kernel modules
check_kernel_modules() {
    while read -r module; do
        modinfo -F filename "$module" 2>/dev/null | xargs sudo strings 2>/dev/null
    done < <(lsmod | awk 'NR>1 {print $1}') | grep -Eo '[a-f0-9]{32}'
}

# User-level persistence locations
USER_LOCATIONS=(
    ~/.bashrc
    ~/.profile
    ~/.zshrc
    ~/.config/autostart
    ~/.ssh/authorized_keys
    ~/.local/share/applications
    ~/.config/systemd/user
)

# System-level persistence locations (require sudo)
SYSTEM_LOCATIONS=(
    /etc/systemd/system
    /etc/init.d
    /etc/rc.local
    /etc/cron.d
    /etc/cron.hourly
    /etc/cron.daily
    /etc/cron.weekly
    /etc/cron.monthly
    /etc/profile
    /etc/bash.bashrc
    /etc/zsh/zshrc
    /etc/ld.so.preload
    /root/.ssh/authorized_keys
    /etc/profile.d
    /etc/xdg/autostart
    /etc/network/if-up.d
    /etc/network/if-down.d
    /etc/update-motd.d
    /etc/pam.d
    /etc/sudoers.d
    /etc/rc?.d
    /etc/udev/rules.d
    /etc/crontab
    /var/spool/cron
    /lib/systemd/system
    /usr/lib/systemd/system
)

# 1. Search user locations
search_locations "${USER_LOCATIONS[@]}" >> "$TEMP_FILE"

# 2. Search system locations with sudo
sudo bash -c "$(declare -f search_locations); locations=($(printf "'%s' " "${SYSTEM_LOCATIONS[@]}")); search_locations \"\${locations[@]}\"" >> "$TEMP_FILE"

# 3. Check user and root crontabs
check_crontabs >> "$TEMP_FILE"

# 4. Check kernel modules
check_kernel_modules >> "$TEMP_FILE"

# 5. Check critical binaries
CRITICAL_BINARIES=(
    /sbin/init
    /usr/sbin/sshd
    /bin/bash
    /usr/bin/sudo
    /usr/bin/cron
)
for bin in "${CRITICAL_BINARIES[@]}"; do
    if [ -f "$bin" ]; then
        sudo strings "$bin" 2>/dev/null | grep -Eo '[a-f0-9]{32}' >> "$TEMP_FILE"
    fi
done

# 6. Check bootloader configs
BOOT_CONFIGS=(
    /boot/grub/grub.cfg
    /etc/default/grub
)
search_locations "${BOOT_CONFIGS[@]}" >> "$TEMP_FILE"

# 7. Check kernel command line
if [ -f "/proc/cmdline" ]; then
    grep -Eo '[a-f0-9]{32}' /proc/cmdline >> "$TEMP_FILE"
fi

# 8. Check for open ports/listeners (Lateral movement)
sudo netstat -tulnpe | awk '{print $7}' | cut -d/ -f1 | sort -u | while read -r pid; do
    [ -n "$pid" ] && sudo strings /proc/"$pid"/exe 2>/dev/null
done | grep -Eo '[a-f0-9]{32}' >> "$TEMP_FILE"

# Process and deduplicate results
sort -u "$TEMP_FILE" | while read -r shard; do
    # Validate MD5 pattern before saving
    if [[ $shard =~ ^[a-f0-9]{32}$ ]]; then
        echo "$shard"
    fi
done > "$OUTPUT_FILE"

# Cleanup
rm -f "$TEMP_FILE"

echo "Found $(wc -l < "$OUTPUT_FILE") persistence shards in $OUTPUT_FILE"