#!/usr/bin/env python3
"""
erl_mouse_v1-1.py

Hello, Makers + Breakers! This is ERL MOUSE:
Scanning and detecting vulnerable Erlang/OTP SSH servers across various CIDR ranges.
Produces CSV & JSON lists of vulnerable hosts and prints concise results.

Usage:
  sudo python3 erl_mouse_v1-1.py
"""

import sys, subprocess, json, socket, re, time, random, os, logging
from concurrent.futures import ThreadPoolExecutor

# Ensure 'packaging' is available
try:
    from packaging import version
except ImportError:
    print("Error: 'packaging' package is required. Install with: pip install packaging")
    sys.exit(1)

# ─── ASCII Banner ──────────────────────────────────────────────────────────
def default_banner():
    return r'''
__, __, _,    _, _ _  _,_  _, __,
|_  |_) |     |\/|/ \ | | (_  |_ 
|   | \ | ,   |  |\ / | | , ) |  
~~~ ~ ~ ~~~   ~  ~ ~  `~'  ~  ~~~  version 1.1
                         ____    .-.
                     .-"`    `",( __\_
      .-==:;-._    .'         .-.     `'.
    .'      `"-:'-/          (  \\} -=a  .)
   /            \/       \,== `-  __..-'
'-'              |       |   |  .'\ `;
                  \    _/---'\ (   `"`
                 /.`._ )      \ `;
                 \`-/.`        `"`
                  `"\`-.
                     `"`   m0usem0use says hi
'''

# ─── Scan settings ─────────────────────────────────────────────────────────
SCAN_PORTS = [22, 2200, 2222]
PORT_SPEC = ','.join(str(p) for p in SCAN_PORTS)
MAX_CIDR_LIMIT = 100  # Threshold for prompting sample limit

# ─── Logging configuration ──────────────────────────────────────────────────
logger = logging.getLogger("erl_mouse")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh = logging.FileHandler("erl_mouse.log"); fh.setLevel(logging.DEBUG); fh.setFormatter(formatter); logger.addHandler(fh)
sh = logging.StreamHandler(); sh.setLevel(logging.INFO); sh.setFormatter(formatter); logger.addHandler(sh)

# ─── Configuration (April 2025) ─────────────────────────────────────────────
COUNTRY_CIDRS = {
    'USA':       ['138.68.0.0/16','139.162.0.0/16','52.0.0.0/8','54.0.0.0/8','35.0.0.0/8'],
    'Germany':   ['88.198.0.0/16','136.243.0.0/16','5.9.0.0/16'],
    'France':    ['51.91.0.0/16','195.154.0.0/16','212.83.0.0/16'],
    'Netherlands':['185.14.0.0/16','46.182.0.0/16','94.229.0.0/16'],
    'UK':        ['176.58.0.0/16','109.74.0.0/16','79.170.0.0/16'],
}
TYPE_CIDRS = {
    'Cloud':      ['138.68.0.0/16','139.162.0.0/16','52.0.0.0/8','54.0.0.0/8'],
    'Telecom':    ['62.0.0.0/8','82.0.0.0/8','89.0.0.0/8'],
    'IoT':        ['192.168.0.0/16','10.0.0.0/8'],
    'RabbitMQ':   ['3.210.0.0/16','34.193.0.0/16'],     # CloudAMQP example
    'CouchDB':    ['23.136.0.0/16','169.55.32.0/20'],   # Cloudant example
    # 'China' loaded from file if present
    'Custom':     [],
}
china_file = 'china_ip_ranges.txt'
if os.path.isfile(china_file):
    try:
        with open(china_file) as cf:
            TYPE_CIDRS['China'] = [line.strip() for line in cf if line.strip()]
        logger.info(f"Loaded {len(TYPE_CIDRS['China'])} China CIDRs from {china_file}")
    except Exception as e:
        logger.error(f"Failed to load China ranges: {e}")

OTP_BANNER_RE = re.compile(
    rb'SSH-2\.0-(?:OTP-SSH|Erlang|Erlang/OTP)[_\- ]?(\d+\.\d+(?:\.\d+)?(?:\.[0-9]+)?)',
    re.IGNORECASE
)
VULN_THRESHOLDS = {25: version.parse('25.3.2.19'), 26: version.parse('26.2.5.10'), 27: version.parse('27.3.2')}

# ─── Utility functions ─────────────────────────────────────────────────────
def parse_version(v): return version.parse(v if v.count('.')>1 else v + '.0')
def is_vulnerable(v): pv = parse_version(v); thr = VULN_THRESHOLDS.get(pv.major); return thr and pv <= thr

def check_commands():
    for cmd in ['curl','masscan']:
        try: subprocess.check_output([cmd,'--version'], stderr=subprocess.STDOUT)
        except FileNotFoundError: print(f"Error: '{cmd}' not found."); sys.exit(1)
        except subprocess.CalledProcessError: pass

def fetch_aws_cidrs(r):
    data = json.loads(subprocess.check_output(['curl','-s','https://ip-ranges.amazonaws.com/ip-ranges.json']))
    return [p['ip_prefix'] for p in data.get('prefixes',[]) if p['region']==r and p['service']=='EC2']

def run_masscan(cidrs, rate=10000, out='masscan.json'):
    logger.info(f"Masscan {PORT_SPEC} on {len(cidrs)} @ {rate}pps")
    cmd = ['masscan', f'-p{PORT_SPEC}'] + cidrs + ['--rate',str(rate),'-oJ',out]
    logger.debug(' '.join(cmd))
    subprocess.call(cmd)
    return out

def parse_masscan_output(f):
    ips=[]
    for line in open(f):
        js = line.strip().rstrip(',')
        if js and js not in ['[',']',',']:
            try: obj = json.loads(js)
            except: continue
            ip = obj.get('ip') or obj.get('addr')
            for p in obj.get('ports',[]):
                if p.get('port') in SCAN_PORTS and p.get('status')=='open':
                    ips.append((ip,p['port'])); break
    logger.info(f"Parsed {len(ips)} SSH hosts")
    return ips

def grab_banner(ip,port,timeout=3,retries=2):
    for a in range(retries+1):
        try:
            if a: time.sleep(random.uniform(0.1,1.0))
            with socket.create_connection((ip,port),timeout=timeout) as s:
                s.settimeout(timeout)
                data=b''
                while b'\n' not in data:
                    chunk=s.recv(1024)
                    if not chunk: break
                    data += chunk
                logger.debug(f"Banner {ip}:{port}: {data!r}")
                return data
        except Exception as e:
            logger.debug(f"{ip}:{port} attempt {a+1} error: {e}")
    return b''

def check_host(t):
    ip,port = t
    b = grab_banner(ip,port)
    if not b: return None
    m = OTP_BANNER_RE.search(b)
    if m and is_vulnerable(m.group(1).decode()):
        return (ip, port, m.group(1).decode())
    return None

# ─── Menus ─────────────────────────────────────────────────────────────────
def menu_title(txt):
    print(default_banner())
    print(f"\n{txt}\n{'='*len(txt)}")

def choose_scan_rate():
    menu_title("Select scan rate")
    print("1) Slow (1,000 pps)")
    print("2) Medium (10,000 pps)")
    print("3) Fast (100,000 pps)")
    print("4) Custom rate")
    c = input("Choice [1-4]: ").strip() or '2'
    return {'1':1000,'2':10000,'3':100000}.get(c, int(input("Enter custom rate (pps): ") or 10000))

def choose_cidrs():
    while True:
        menu_title("Select target mode")
        print("1) Explicit CIDR list")
        print("2) Country presets")
        print("3) Type presets")
        print("4) AWS region prefixes")
        print("5) Shodan JSON import")
        ch = input("Choice [1-5]: ").strip()
        cidrs = []
        if ch == '1':
            cidrs = [x.strip() for x in input("Enter CIDRs (comma-separated): ").split(',')]
        elif ch == '2':
            for i, c in enumerate(COUNTRY_CIDRS, 1):
                print(f"{i}) {c}: {len(COUNTRY_CIDRS[c])} CIDR blocks")
            key = list(COUNTRY_CIDRS)[int(input("Choose country: ")) - 1]
            cidrs = COUNTRY_CIDRS[key]
        elif ch == '3':
            for i, k in enumerate(TYPE_CIDRS, 1):
                print(f"{i}) {k}: {len(TYPE_CIDRS[k])} CIDR blocks")
            for i, k in enumerate(TYPE_CIDRS, 1):
                print(f"{i}) {k}")
            key = list(TYPE_CIDRS)[int(input("Choose type: ")) - 1]
            cidrs = TYPE_CIDRS[key] or [x.strip() for x in input("Enter custom CIDRs: ").split(',')]
        elif ch == '4':
            cidrs = fetch_aws_cidrs(input("Enter AWS region (e.g. us-west-2): ").strip())
        elif ch == '5':
            f = input("Enter Shodan JSON file path: ").strip()
            try:
                data = json.load(open(f))
                cidrs = [f"{i['ip_str']}/32" for i in data]
            except:
                print("Invalid Shodan file.")
        else:
            print("Invalid choice, please try again.")
            continue

        # Modular sampling for large CIDR sets
        total = len(cidrs)
        if total > MAX_CIDR_LIMIT:
            print(f"Selected {total} CIDR blocks—this may scan many IPs.")
            sl = input(f"How many blocks to scan? (Enter number or 'all', default=all): ").strip().lower() or 'all'
            if sl != 'all':
                try:
                    n = int(sl)
                    random.shuffle(cidrs)
                    cidrs = cidrs[:n]
                    logger.info(f"Sampling {n} of {total} CIDR blocks")
                except:
                    print("Invalid number, scanning all blocks.")
        return cidrs

# ─── Main ───────────────────────────────────────────────────────────────────
def main():
    print(default_banner())
    check_commands()
    if os.geteuid() != 0:
        print("Warning: Masscan may require root privileges.")
    cidrs = choose_cidrs()
    rate = choose_scan_rate()
    raw = run_masscan(cidrs, rate)
    if not os.path.exists(raw):
        print(f"[!] Masscan output not found: {raw}")
        return
    targets = parse_masscan_output(raw)
    if not targets:
        print("\n[!] No SSH hosts found.")
        return
    print(f"[+] Grabbing banners for {len(targets)} hosts...")
    vulns = []
    for r in ThreadPoolExecutor(max_workers=100).map(check_host, targets):
        if r:
            vulns.append(r)
    if vulns:
        print(f"\n[+] Found {len(vulns)} vulnerable hosts:")
        for ip, p, v in vulns:
            print(f" - {ip}:{p}, OTP {v}")
    else:
        print("\n[!] No vulnerable hosts detected.")
    ts = time.strftime("%Y%m%d-%H%M%S")
    jout = f"vulnerable_hosts_{ts}.json"
    open(jout, 'w').write(json.dumps([{'ip': ip, 'port': p, 'otp': v} for ip,p,v in vulns], indent=2))
    cout = f"vulnerable_hosts_{ts}.csv"
    open(cout, 'w').write('ip,port,otp_version\n' + ''.join(f"{ip},{p},{v}\n" for ip,p,v in vulns))
    print(f"[+] Results saved: JSON->{jout}, CSV->{cout}\n[✓] Scan complete.")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user.")
    except Exception as e:
        logger.error(f"Unhandled exception: {e}", exc_info=True)
        print(f"[!] Error: {e}")
