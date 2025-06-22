#!/usr/bin/env python3
import os
import re
import base64
import hashlib
import subprocess
import tempfile
import mmap
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
SCAN_DIRS = [
    '/etc', '/home', '/root', '/tmp', '/var', '/usr/local/bin',
    '/usr/local/sbin', '/opt', '/boot', '/lib', '/lib64', '/bin',
    '/sbin', '/usr/bin', '/usr/sbin', '/dev/shm'
]
PERSISTENCE_PATHS = [
    '/etc/systemd/system', '/etc/init.d', '/etc/rc.local', '/etc/cron*',
    '/etc/profile*', '/root/.ssh', '/etc/ld.so.preload', '/etc/profile.d',
    '/etc/xdg/autostart', '/etc/network/*.d', '/etc/pam.d', '/etc/sudoers.d',
    '/etc/udev/rules.d', '/var/spool/cron', '/lib/systemd/system',
    '/usr/lib/systemd/system', '~/.config/autostart', '~/.ssh',
    '~/.local/share/applications', '~/.config/systemd/user'
]
SUSPICIOUS_PATTERNS = [
    r'eval\s*\(.*base64',
    r'openssl\s+enc\s+-d',
    r'xxd\s+-r\s+-p',
    r'exec\s+.*\&\s*>\s*\/dev',
    r'socat\s+.*exec:',
    r'nc\s+-e\s+\/bin\/[a-z]+',
    r'bash\s+-c\s+\$'
]

def get_common_persistence_paths():
    """Expand and deduplicate persistence paths"""
    paths = set()
    for path in PERSISTENCE_PATHS:
        if path.startswith('~'):
            path = os.path.expanduser(path)
        expanded = glob.glob(path)
        if expanded:
            for p in expanded:
                if os.path.exists(p):
                    paths.add(p)
        elif os.path.exists(path):
            paths.add(path)
    return list(paths)

def find_shards_in_content(content):
    """Find shards using multiple analysis techniques"""
    shards = set()
    
    # Direct MD5 pattern
    direct_matches = re.findall(r'\b[a-f0-9]{32}\b', content, re.IGNORECASE)
    shards.update(m.lower() for m in direct_matches)
    
    # Base64 decoding
    base64_matches = re.findall(r'[A-Za-z0-9+/=]{40,}', content)
    for match in base64_matches:
        try:
            decoded = base64.b64decode(match).decode('ascii', 'ignore')
            decoded_matches = re.findall(r'\b[a-f0-9]{32}\b', decoded)
            shards.update(m.lower() for m in decoded_matches)
        except:
            pass
    
    # Hex decoding
    hex_matches = re.findall(r'[0-9a-fA-F]{64}', content)
    for match in hex_matches:
        try:
            decoded = bytes.fromhex(match).decode('ascii', 'ignore')
            decoded_matches = re.findall(r'\b[a-f0-9]{32}\b', decoded)
            shards.update(m.lower() for m in decoded_matches)
        except:
            pass
    
    # XOR patterns (common malware technique)
    xor_patterns = re.findall(r'\\x[a-f0-9]{2}', content, re.IGNORECASE)
    if xor_patterns:
        try:
            clean_hex = re.sub(r'[^a-f0-9]', '', ''.join(xor_patterns))
            if len(clean_hex) % 2 == 0:
                decoded = bytes.fromhex(clean_hex).decode('ascii', 'ignore')
                decoded_matches = re.findall(r'\b[a-f0-9]{32}\b', decoded)
                shards.update(m.lower() for m in decoded_matches)
        except:
            pass
    
    return shards

def analyze_file(filepath):
    """Analyze a file for hidden shards using multiple methods"""
    shards = set()
    
    try:
        file_size = os.path.getsize(filepath)
        if file_size == 0 or file_size > MAX_FILE_SIZE:
            return shards

        # Method 1: Direct content scanning
        with open(filepath, 'rb') as f:
            if file_size > 0:
                try:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        content = mm.read().decode('utf-8', 'ignore')
                        shards.update(find_shards_in_content(content))
                except:
                    pass

        # Method 2: Strings extraction (for binaries)
        if not shards:
            try:
                strings = subprocess.check_output(
                    ['strings', filepath], 
                    stderr=subprocess.DEVNULL,
                    timeout=5
                ).decode('utf-8', 'ignore')
                shards.update(find_shards_in_content(strings))
            except:
                pass

        # Method 3: Suspicious pattern detection
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read(10000)  # Only read first 10KB for pattern matching
            
            # Check for suspicious commands
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, content):
                    # Found suspicious pattern - do deeper analysis
                    all_shards = find_shards_in_content(content)
                    shards.update(all_shards)
                    
                    # Dynamic analysis for complex scripts
                    if filepath.endswith(('.sh', '.py', '.pl')):
                        try:
                            with tempfile.NamedTemporaryFile(delete=True) as tmp:
                                tmp.write(content.encode())
                                tmp.flush()
                                
                                # Execute in safe environment with timeout
                                result = subprocess.run(
                                    ['timeout', '10s', 'bash', tmp.name],
                                    capture_output=True,
                                    text=True,
                                    timeout=15
                                )
                                
                                # Analyze output
                                output_shards = find_shards_in_content(
                                    result.stdout + result.stderr
                                )
                                shards.update(output_shards)
                        except:
                            pass
                    break

    except Exception as e:
        pass  # Skip permission errors and unreadable files

    return shards

def analyze_process(pid):
    """Analyze running process for shards in memory"""
    shards = set()
    try:
        # Check process memory
        mem_file = f"/proc/{pid}/mem"
        if os.path.exists(mem_file):
            maps_file = f"/proc/{pid}/maps"
            with open(maps_file, 'r') as maps:
                for line in maps:
                    if 'r-xp' in line:  # Executable memory regions
                        addr_range = line.split()[0]
                        start, end = [int(x, 16) for x in addr_range.split('-')]
                        length = end - start
                        
                        try:
                            with open(mem_file, 'rb') as mem:
                                mem.seek(start)
                                content = mem.read(min(length, 1024000))  # Read up to 1MB
                                decoded = content.decode('utf-8', 'ignore')
                                shards.update(find_shards_in_content(decoded))
                        except:
                            pass
    except:
        pass
    return shards

def analyze_network_connections():
    """Check network connections for suspicious traffic patterns"""
    shards = set()
    try:
        # Get all network connections
        netstat = subprocess.check_output(
            ['sudo', 'netstat', '-tunape'],
            stderr=subprocess.DEVNULL,
            text=True
        )
        
        # Find suspicious connections
        suspicious_conns = []
        for line in netstat.splitlines():
            if 'ESTABLISHED' in line and any(p in line for p in ['/bash', '/sh', '/python', '/perl']):
                suspicious_conns.append(line)
        
        # Analyze suspicious processes
        pids = set()
        for conn in suspicious_conns:
            parts = conn.split()
            pid = parts[-1].split('/')[0]
            if pid.isdigit():
                pids.add(pid)
        
        # Analyze each suspicious process
        for pid in pids:
            shards.update(analyze_process(pid))
            
    except:
        pass
    return shards

def main():
    # Collect all scan targets
    scan_targets = []
    
    # 1. System directories
    for path in SCAN_DIRS:
        if os.path.exists(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    scan_targets.append(os.path.join(root, file))
    
    # 2. Persistence locations
    for path in get_common_persistence_paths():
        if os.path.isfile(path):
            scan_targets.append(path)
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    scan_targets.append(os.path.join(root, file))
    
    # 3. Running processes
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    
    # 4. Network connections
    scan_targets.append('NETWORK')
    
    print(f"[*] Scanning {len(scan_targets)} files, {len(pids)} processes, and network connections...")
    
    # Multi-threaded analysis
    all_shards = set()
    
    with ThreadPoolExecutor(max_workers=8) as executor:
        # File analysis
        future_to_file = {
            executor.submit(analyze_file, f): f 
            for f in scan_targets if isinstance(f, str)
        }
        
        # Process analysis
        future_to_pid = {
            executor.submit(analyze_process, pid): pid 
            for pid in pids
        }
        
        # Network analysis
        future_to_net = {
            executor.submit(analyze_network_connections): 'NET'
        }
        
        # Collect results
        for future in as_completed(
            list(future_to_file) + 
            list(future_to_pid) + 
            list(future_to_net)
        ):
            try:
                shards = future.result()
                all_shards.update(shards)
            except:
                pass
    
    # Write results
    with open('shards1.txt', 'w') as f:
        for shard in all_shards:
            f.write(f"{shard}\n")
    
    print(f"[+] Found {len(all_shards)} shards in shards1.txt")

if __name__ == '__main__':
    main()