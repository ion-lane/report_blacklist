#!/usr/bin/env python3
import re
import sys
import time
import ipaddress
from collections import Counter, defaultdict
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
PREFIXES = ['blinp_', 'blfwd_', 'grchc_', 'dns_', 'invalid_', 'private_', 'drop_', 'icmp_']
EXCLUDE_NETWORKS = [
    '77.34.131.45',
    '10.0.0.0/24',
]
SPINNER_CHARS = ['|', '/', '-', '\\']
def compile_exclude_networks(networks):
    compiled = []
    for net in networks:
        try:
            network = ipaddress.ip_network(net)
            compiled.append(network)
        except ValueError:
            try:
                ip = ipaddress.ip_address(net)
                network = ipaddress.ip_network(ip.exploded + '/32')
                compiled.append(network)
            except ValueError:
                print(f"[WARNING] Некорректный IP или подсеть в EXCLUDE_NETWORKS: {net}")
    return compiled
EXCLUDE_COMPILED = compile_exclude_networks(EXCLUDE_NETWORKS)
def ip_is_excluded(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net in EXCLUDE_COMPILED:
            if ip_obj in net:
                return True
        return False
    except ValueError:
        return True
def extract_ips_by_prefix(filename):
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ips_by_prefix = defaultdict(list)
    with open(filename, 'r') as f:
        for line in f:
            words = line.strip().split()
            matched_prefix = None
            for word in words:
                for prefix in PREFIXES:
                    if word.startswith(prefix):
                        matched_prefix = prefix
                        break
                if matched_prefix:
                    break
            if matched_prefix:
                ips = ip_pattern.findall(line)
                filtered_ips = [ip for ip in ips if not ip_is_excluded(ip)]
                ips_by_prefix[matched_prefix].extend(filtered_ips)
    for prefix in PREFIXES:
        print(f"[DEBUG] Найдено IP с префиксом '{prefix}': {len(ips_by_prefix[prefix])}")
    return ips_by_prefix
def whois_field(ip, fieldnames):
    try:
        result = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=5)
        output = result.stdout.lower()
        for line in output.splitlines():
            for field in fieldnames:
                if line.startswith(field.lower()):
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        value = parts[1].strip()
                        if value:
                            return value
    except Exception:
        pass
    return 'N/A'
def whois_netname(ip):
    return whois_field(ip, ['netname', 'orgname', 'organisation'])
def whois_description(ip):
    desc_fields = ['descr', 'description', 'organization', 'org-name', 'owner', 'cust-name', 'comment']
    return whois_field(ip, desc_fields)
def whois_country(ip):
    return whois_field(ip, ['country'])
def fetch_whois(ip):
    return ip, whois_netname(ip), whois_description(ip), whois_country(ip)
def spinner_while_futures(futures):
    spinner_index = 0
    while True:
        done = all(f.done() for f in futures)
        sys.stdout.write('\r' + SPINNER_CHARS[spinner_index] + ' Получение whois данных...')
        sys.stdout.flush()
        if done:
            break
        spinner_index = (spinner_index + 1) % len(SPINNER_CHARS)
        time.sleep(0.1)
    sys.stdout.write('\r' + ' ' * 40 + '\r')
def print_tables(ips_by_prefix, top_n=10):
    for prefix in PREFIXES:
        ips = ips_by_prefix.get(prefix, [])
        if not ips:
            print(f"[DEBUG] Нет IP для префикса '{prefix}', пропускаем таблицу.")
            continue
        counter = Counter(ips)
        top_ips = counter.most_common(top_n)
        print(f"\n=== Таблица для префикса: {prefix} ===")
        print(f"{'IP Address':<20} {'Count':<7} {'Country':<10} {'Netname':<30} {'Description'}")
        print("-" * 100)
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(fetch_whois, ip) for ip, _ in top_ips]
            spinner_while_futures(futures)
            results = {}
            for future in futures:
                ip, netname, description, country = future.result()
                results[ip] = (netname, description, country)
        for ip, count in top_ips:
            netname, description, country = results.get(ip, ('N/A', 'N/A', 'N/A'))
            print(f"{ip:<20} {count:<7} {country:<10} {netname:<30} {description}")
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py logfile.txt [top_n]")
        sys.exit(1)
    logfile = sys.argv[1]
    top_n = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    ips_by_prefix = extract_ips_by_prefix(logfile)
    print_tables(ips_by_prefix, top_n)
