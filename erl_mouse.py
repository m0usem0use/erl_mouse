#!/usr/bin/env python3
"""
erl_mouse.py

Hello, my fellow Makers + Breakers... this is a...

Terminal UI for "ERL MOUSE": scanning and detecting vulnerable Erlang/OTP SSH servers.
Produces both CSV and JSON lists of vulnerable hosts and prints results to terminal.

Note: It has been very dfficult to find a vulnerable host but so far not impossible!

Please Add to this as much as you can and share it!

Usage:
  python3 erl_mouse.py (using Masscan as the workhorse)

  (follow the on-screen menu to choose CIDRs or fetch AWS ranges)
"""

import sys, subprocess, json, socket, re, time, random
from packaging import version
from concurrent.futures import ThreadPoolExecutor
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("erl_mouse.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("erl_mouse")

# ─── Configuration (verified April 2025) ───────────────────────────────────
COUNTRY_CIDRS = {
    'USA': ['138.68.0.0/16', '139.162.0.0/16', '52.0.0.0/8', '54.0.0.0/8', '35.0.0.0/8'],  # DigitalOcean, Linode, AWS
    'Germany': ['88.198.0.0/16', '136.243.0.0/16', '5.9.0.0/16'],         # Hetzner, etc
    'France': ['51.91.0.0/16', '195.154.0.0/16', '212.83.0.0/16'],        # OVH, Online.net
    'Netherlands': ['185.14.0.0/16', '46.182.0.0/16', '94.229.0.0/16'],   # TransIP, LeaseWeb
    'UK': ['176.58.0.0/16', '109.74.0.0/16', '79.170.0.0/16'],            # Linode UK, Memset
}
TYPE_CIDRS = {
    'Cloud': ['138.68.0.0/16', '139.162.0.0/16', '52.0.0.0/8', '54.0.0.0/8'],
    'Telecom': ['62.0.0.0/8', '82.0.0.0/8', '89.0.0.0/8'],
    'IoT': ['192.168.0.0/16', '10.0.0.0/8'],  # Note: Private IP ranges for local testing
    'Custom': [],
}

# Erlang/OTP SSH banner regex & vulnerability thresholds - EXPANDED regex pattern
OTP_BANNER_RE = re.compile(
    rb'^SSH-2\.0-(?:OTP-SSH|Erlang|Erlang/OTP)[_\- ]?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)',
    re.IGNORECASE  # Added case insensitivity
)

# Updated with more permissive version handling
VULN_THRESHOLDS = {
    25: version.parse('25.3.2.19'),
    26: version.parse('26.2.5.10'),
    27: version.parse('27.3.2'),
}

# Static ASCII banner
def default_banner():
    return '''
__, __, _,    _, _ _  _,_  _, __,
|_  |_) |     |\/|/ \ | | (_  |_ 
|   | \ | ,   |  |\ / | | , ) |  
~~~ ~ ~ ~~~   ~  ~ ~  `~'  ~  ~~~
                         ____    .-.
                     .-"`    `",( __\_
      .-==:;-._    .'         .-.     `'.
    .'      `"-:'-/          (  \} -=a  .)
   /            \/       \,== `-  __..-'`
'-'              |       |   |  .'\ `;
                  \    _/---'\ (   `"`
                 /.`._ )      \ `;
                 \`-/.'        `"`
                  `"\`-.
                     `"`   m0usem0use says hi
'''

# ─── Utility functions ─────────────────────────────────────────────────────

def parse_version(vstr):
    """Parse version string with more flexible handling for Erlang version formats."""
    try:
        # Handle cases where version might be just "X.Y" instead of "X.Y.Z"
        parts = vstr.split('.')
        if len(parts) == 2:
            vstr = f"{vstr}.0"
        return version.parse(vstr)
    except Exception as e:
        logger.warning(f"Failed to parse version string '{vstr}': {e}")
        return None

def is_vulnerable(vstr):
    """Check if the given version string indicates a vulnerable Erlang/OTP version."""
    v = parse_version(vstr)
    if not v:
        return False
        
    # Get threshold for this major version
    thr = VULN_THRESHOLDS.get(v.major)
    if not thr:
        return False
        
    # Check if version is vulnerable (at or below threshold)
    return v <= thr

def fetch_aws_cidrs(region):
    """Fetch AWS IP ranges for the specified region."""
    try:
        logger.info(f"Fetching AWS IP ranges for region {region}...")
        data = json.loads(subprocess.check_output([
            'curl', '-s', 'https://ip-ranges.amazonaws.com/ip-ranges.json'
        ]))
        cidrs = [p['ip_prefix'] for p in data.get('prefixes', [])
                if p['region'] == region and p['service'] == 'EC2']
        logger.info(f"Found {len(cidrs)} CIDR blocks for AWS {region}")
        return cidrs
    except Exception as e:
        logger.error(f"Error fetching AWS CIDRs: {e}")
        return []

def run_masscan(cidrs, rate=10000, out='masscan.json'):
    """Run masscan on the specified CIDR ranges."""
    try:
        logger.info(f"Running masscan on {len(cidrs)} CIDR blocks at rate {rate}...")
        cmd = ['masscan', '-p22'] + cidrs + ['--rate', str(rate), '-oJ', out]
        logger.debug(f"Masscan command: {' '.join(cmd)}")
        subprocess.check_call(cmd)
        logger.info(f"Masscan completed successfully, output saved to {out}")
        return out
    except subprocess.CalledProcessError as e:
        logger.error(f"Masscan failed with exit code {e.returncode}")
        return out
    except Exception as e:
        logger.error(f"Error running masscan: {e}")
        return out

def grab_banner(ip, timeout=3, retries=2):
    """Connect to an SSH server and grab its banner, with retries."""
    for attempt in range(retries + 1):
        try:
            # Add jitter to avoid overwhelming targets
            if attempt > 0:
                time.sleep(random.uniform(0.1, 1.0))
                
            with socket.create_connection((ip, 22), timeout=timeout) as s:
                s.settimeout(timeout)  # Ensure recv also has a timeout
                banner = s.recv(1024)
                if banner:
                    logger.debug(f"Banner from {ip}: {banner[:50]}")
                    return banner
        except socket.timeout:
            logger.debug(f"Connection to {ip} timed out (attempt {attempt+1}/{retries+1})")
        except ConnectionRefusedError:
            logger.debug(f"Connection to {ip} refused")
            break  # No need to retry if connection is actively refused
        except Exception as e:
            logger.debug(f"Error connecting to {ip} (attempt {attempt+1}/{retries+1}): {e}")
    
    return b''

def check_host(ip):
    """Check if a host is running a vulnerable version of Erlang/OTP SSH."""
    banner = grab_banner(ip)
    if not banner:
        return None
        
    # Try to match the Erlang/OTP SSH banner pattern
    m = OTP_BANNER_RE.match(banner)
    if not m:
        # If we got a banner but it doesn't match our pattern, log it for debugging
        logger.debug(f"Non-matching banner from {ip}: {banner[:50]}")
        return None
        
    # Extract and check the version
    v = m.group(1).decode()
    logger.debug(f"Found Erlang/OTP SSH on {ip}, version {v}")
    
    if is_vulnerable(v):
        logger.info(f"Vulnerable Erlang/OTP SSH found on {ip}, version {v}")
        return (ip, v)
    else:
        logger.debug(f"Non-vulnerable Erlang/OTP SSH on {ip}, version {v}")
        return None

# ─── TUI Menus ──────────────────────────────────────────────────────────────

def menu_title(txt):
    print('\n' + default_banner())
    print(f"\n{txt}\n{'='*len(txt)}")

def choose_scan_rate():
    """Let the user choose a scan rate for masscan."""
    menu_title("Select scan rate")
    print(" 1) Slow (1,000 packets/sec) - Less likely to trigger IDS/IPS")
    print(" 2) Medium (10,000 packets/sec) - Default")
    print(" 3) Fast (100,000 packets/sec) - May trigger IDS/IPS")
    print(" 4) Custom rate")
    
    choice = input("Choose [1-4, default=2]: ").strip() or "2"
    
    if choice == "1":
        return 1000
    elif choice == "2":
        return 10000
    elif choice == "3":
        return 100000
    elif choice == "4":
        try:
            rate = int(input("Enter custom rate (packets/sec): ").strip())
            return max(100, rate)  # Ensure minimum reasonable rate
        except:
            print("Invalid rate, using default (10,000)")
            return 10000
    else:
        print("Invalid choice, using default (10,000)")
        return 10000

def choose_cidrs():
    """Interactive menu for selecting CIDR blocks to scan."""
    while True:
        menu_title("Select target selection mode for erl mouse")
        print(" 1) Explicit CIDR(s)")
        print(" 2) By country (and add custom)")
        print(" 3) By type (and custom)")
        print(" 4) AWS region")
        print(" 5) Shodan import (if you have shodan results)")
        choice = input("Choose [1–5]: ").strip()

        if choice == '1':
            raw = input("Enter CIDRs (comma-separated): ").strip()
            cidrs = [c.strip() for c in raw.split(',') if c.strip()]

        elif choice == '2':
            menu_title("Countries and CIDR lists")
            for i, (ct, lst) in enumerate(COUNTRY_CIDRS.items(), 1):
                print(f" {i}) {ct}: {len(lst)} CIDR blocks")
            print(f" {len(COUNTRY_CIDRS)+1}) Custom country list")
            
            try:
                sel = int(input("Choose: "))-1
                if sel == len(COUNTRY_CIDRS):
                    name = input("Custom country name: ").strip()
                    raw = input("Enter CIDRs: ").strip()
                    cidrs = [c.strip() for c in raw.split(',') if c.strip()]
                    COUNTRY_CIDRS[name] = cidrs
                else:
                    country = list(COUNTRY_CIDRS)[sel]
                    cidrs = COUNTRY_CIDRS[country]
            except (ValueError, IndexError):
                print("Invalid choice, try again.")
                continue

        elif choice == '3':
            menu_title("Types and CIDR lists")
            for i,(tp,lst) in enumerate(TYPE_CIDRS.items(),1):
                desc = f"{len(lst)} CIDR blocks" if lst else '<custom>'
                print(f" {i}) {tp}: {desc}")
            
            try:
                sel = int(input("Choose: "))-1
                t = list(TYPE_CIDRS)[sel]
                if TYPE_CIDRS[t]:
                    cidrs = TYPE_CIDRS[t]
                else:
                    raw = input(f"Enter CIDRs for '{t}': ").strip()
                    cidrs = [c.strip() for c in raw.split(',') if c.strip()]
                    TYPE_CIDRS[t] = cidrs
            except (ValueError, IndexError):
                print("Invalid choice, try again.")
                continue

        elif choice == '4':
            region = input("Enter AWS region (e.g. us-west-2): ").strip()
            cidrs = fetch_aws_cidrs(region)
            if not cidrs:
                print("No CIDRs found for that region, try again.")
                continue
            print(f"[+] Fetched {len(cidrs)} EC2 prefixes for {region}")

        elif choice == '5':
            filename = input("Enter Shodan results file (JSON format): ").strip()
            try:
                with open(filename, 'r') as f:
                    data = json.load(f)
                # Extract IPs from Shodan format - adjust based on actual format
                if isinstance(data, list):
                    ips = [item.get('ip_str') for item in data if 'ip_str' in item]
                else:
                    ips = [data.get('ip_str')] if 'ip_str' in data else []
                
                if not ips:
                    print("No IP addresses found in Shodan results.")
                    continue
                    
                # Convert single IPs to CIDR notation with /32
                cidrs = [f"{ip}/32" for ip in ips if ip]
                print(f"[+] Loaded {len(cidrs)} IPs from Shodan results")
            except Exception as e:
                print(f"Error loading Shodan results: {e}")
                continue
                
        else:
            print("Invalid choice, try again.")
            continue

        if not cidrs:
            print("No CIDRs selected, try again.")
            continue
            
        return cidrs

# ─── Main Flow ──────────────────────────────────────────────────────────────

def main():
    """Main execution flow for erl_mouse."""
    print(f"\n{default_banner()}\n")
    logger.info("Starting erl_mouse.py")

    # Get target CIDRs and scan rate from user
    cidrs = choose_cidrs()
    rate = choose_scan_rate()

    # Run masscan
    logger.info(f"Scanning {len(cidrs)} CIDR(s) with Masscan at {rate} packets/sec...")
    mj = run_masscan(cidrs, rate=rate)

    # Parse masscan results
    logger.info("Parsing Masscan JSON...")
    try:
        with open(mj, 'r') as f:
            entries = json.load(f)
        ips = []
        for e in entries:
            if 'ip' in e and 'ports' in e:
                for p in e['ports']:
                    if p.get('port') == 22 and p.get('status') == 'open':
                        ips.append(e['ip'])
                        break
        
        logger.info(f"Found {len(ips)} hosts with port 22 open")
    except Exception as e:
        logger.error(f"Error parsing masscan results: {e}")
        print(f"Error parsing masscan results: {e}")
        return

    if not ips:
        logger.warning("No hosts with SSH (port 22) found in scan results")
        print("[!] No hosts with SSH (port 22) found in scan results")
        return

    # Allow user to limit number of hosts to check
    if len(ips) > 1000:
        print(f"\nFound {len(ips)} hosts with port 22 open.")
        limit = input("How many hosts to check? (Enter a number or 'all', default=1000): ").strip()
        if limit.lower() != 'all':
            try:
                limit = int(limit or 1000)
                random.shuffle(ips)  # Randomize to get a good sample
                ips = ips[:limit]
                logger.info(f"Limiting check to {len(ips)} randomly selected hosts")
            except ValueError:
                # If input was invalid, use default
                ips = ips[:1000]
                logger.info("Limiting check to 1000 hosts (default)")

    # Banner-grab and check hosts
    print(f"[+] Banner-grabbing {len(ips)} host(s)...")
    logger.info(f"Banner-grabbing {len(ips)} host(s)...")
    
    vulns = []
    with ThreadPoolExecutor(max_workers=100) as pool:
        for i, r in enumerate(pool.map(check_host, ips)):
            if r:
                vulns.append(r)
            
            # Progress update every 100 hosts
            if (i+1) % 100 == 0 or i+1 == len(ips):
                print(f"  Progress: {i+1}/{len(ips)} hosts checked, {len(vulns)} vulnerable found")
                logger.info(f"Progress: {i+1}/{len(ips)} hosts checked, {len(vulns)} vulnerable found")

    # Print results to terminal
    if vulns:
        logger.info(f"Found {len(vulns)} vulnerable hosts")
        print(f"\n[+] Found {len(vulns)} vulnerable hosts:")
        for ip, ver in vulns:
            print(f"  - {ip}, OTP {ver}")
    else:
        logger.warning("No vulnerable hosts found")
        print("\n[!] No vulnerable hosts found.")

    # Write JSON output
    json_out = 'vulnerable_hosts.json'
    with open(json_out,'w') as jf:
        json.dump([{'ip':ip,'otp_version':ver} for ip,ver in vulns], jf, indent=2)
    logger.info(f"Wrote JSON results to {json_out}")
    print(f"[+] JSON results -> {json_out}")

    # Also write CSV
    csv_out = 'vulnerable_hosts.csv'
    with open(csv_out,'w') as cf:
        cf.write('ip,otp_version\n')
        for ip,ver in vulns:
            cf.write(f"{ip},{ver}\n")
    logger.info(f"Wrote CSV results to {csv_out}")
    print(f"[+] CSV results -> {csv_out}")

    print("[✓] Done.")
    logger.info("erl_mouse.py completed successfully")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("Operation interrupted by user")
        print("\n[!] Operation interrupted by user.")
    except Exception as e:
        logger.error(f"Unhandled exception: {e}", exc_info=True)
        print(f"\n[!] Error: {e}")
