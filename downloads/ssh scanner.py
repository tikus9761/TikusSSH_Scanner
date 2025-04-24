import socket
import concurrent.futures
import time
import sys
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Settings
INPUT_FILE = "iplist.txt"
OUTPUT_FILE = "good.txt"
PORT = 22
TIMEOUT = 1
MAX_THREADS = 1000

# Results
good_ips = []
not_ssh_ips = []
error_ips = []

# Stats
checked = 0
start_time = time.time()

def is_port_open(ip):
    global checked
    try:
        with socket.create_connection((ip, PORT), timeout=TIMEOUT):
            good_ips.append(ip)
    except socket.timeout:
        error_ips.append(ip)
    except:
        not_ssh_ips.append(ip)
    finally:
        checked += 1
        show_status()

def show_status():
    elapsed = time.time() - start_time
    speed = checked / elapsed if elapsed > 0 else 0
    status_line = (f"{Fore.CYAN}[🔁 CHECKED: {checked}]  "
                   f"{Fore.GREEN}GOOD: {len(good_ips)}  "
                   f"{Fore.YELLOW}ERROR: {len(error_ips)}  "
                   f"{Fore.MAGENTA}⚡ SPEED: {speed:.2f} IPs/sec")
    # Print in-place (overwrite line)
    sys.stdout.write('\r' + status_line + ' ' * 10)
    sys.stdout.flush()

def main():
    with open(INPUT_FILE, "r") as f:
        ips = [line.strip() for line in f if line.strip()]

    print(f"{Fore.CYAN}[INFO] Loaded {len(ips)} IPs. Scanning port {PORT} using {MAX_THREADS} threads...\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        executor.map(is_port_open, ips)

    with open(OUTPUT_FILE, "w") as f:
        for ip in good_ips:
            f.write(ip + "\n")

    print(f"\n\n{Fore.GREEN}[✅ DONE] {len(good_ips)} SSH servers found. Saved to {OUTPUT_FILE}\n")

if __name__ == "__main__":
    main()
