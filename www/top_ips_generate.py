#!/usr/bin/env python3
import os
import sys
import json
import datetime
import ipaddress
import subprocess
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import shutil
import zipfile

LOG_FILE = sys.argv[1] if len(sys.argv) > 1 else 'log.txt'
DATA_DIR = '/var/www/top_ips/data'
BACKUP_DIR = '/var/log/mikrotik_backup'

PREFIXES = ['blinp_', 'blfwd_', 'grchc_', 'dns_']
EXCLUDE_NETWORKS = ['192.168.0.0/24', '10.0.0.0/24']

def ip_in_network(ip, network):
    try:
        ip_obj = ipaddress.ip_address(ip)
        net_obj = ipaddress.ip_network(network, strict=False)
        return ip_obj in net_obj
    except ValueError:
        return False

def ip_is_excluded(ip, exclude_networks):
    for net in exclude_networks:
        if '/' in net:
            if ip_in_network(ip, net):
                return True
        else:
            if ip == net:
                return True
    return False

def extract_ips_by_prefix(lines, prefixes, exclude_networks):
    ips_by_prefix = {p: [] for p in prefixes}
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    import re
    for line in lines:
        matched_prefix = None
        for word in line.split():
            for prefix in prefixes:
                if word.startswith(prefix):
                    matched_prefix = prefix
                    break
            if matched_prefix:
                break
        if matched_prefix:
            ips = re.findall(ip_pattern, line)
            for ip in ips:
                if not ip_is_excluded(ip, exclude_networks):
                    ips_by_prefix[matched_prefix].append(ip)
    return ips_by_prefix

def whois_field(ip, fields):
    try:
        out = subprocess.check_output(['whois', ip], stderr=subprocess.DEVNULL, text=True, timeout=5)
    except Exception:
        return 'N/A'
    out = out.lower()
    for line in out.splitlines():
        for field in fields:
            if line.startswith(field.lower()):
                parts = line.split(':', 1)
                if len(parts) == 2:
                    val = parts[1].strip()
                    if val:
                        return val
    return 'N/A'

def whois_netname(ip):
    return whois_field(ip, ['netname', 'orgname', 'organisation'])

def whois_description(ip):
    return whois_field(ip, ['descr', 'description', 'organization', 'org-name', 'owner', 'cust-name', 'comment'])

def whois_country(ip):
    return whois_field(ip, ['country'])

def fetch_whois(ip):
    return (ip, whois_netname(ip), whois_description(ip), whois_country(ip))

def backup_and_clear_log(logfile_path, backup_dir):
    os.makedirs(backup_dir, exist_ok=True)
    today_str = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    basename = os.path.basename(logfile_path)
    archive_name = os.path.join(backup_dir, f"{basename}_{today_str}.zip")

    try:
        with zipfile.ZipFile(archive_name, 'w', compression=zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(logfile_path, arcname=basename)
    except Exception as e:
        print(f"Ошибка архивации лога: {e}", file=sys.stderr)
        return False

    # Очистка исходного файла после успешного архива
    try:
        with open(logfile_path, 'w') as f:
            pass
    except Exception as e:
        print(f"Ошибка очистки файла лога: {e}", file=sys.stderr)
        return False

    print(f"Лог заархивирован в {archive_name} и исходный файл очищен.")
    return True

def main():
    with open(LOG_FILE, encoding='utf-8', errors='ignore') as f:
        lines = f.read().splitlines()

    ips_by_prefix = extract_ips_by_prefix(lines, PREFIXES, EXCLUDE_NETWORKS)

    result = {}
    for prefix in PREFIXES:
        ips = ips_by_prefix.get(prefix, [])
        counter = Counter(ips)
        top_ips = counter.most_common(10)
        res_list = []

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(fetch_whois, ip): ip for ip, _ in top_ips}
            for future in futures:
                ip, netname, desc, country = future.result()
                count = dict(top_ips)[ip]
                res_list.append({
                    'ip': ip,
                    'count': count,
                    'netname': netname,
                    'description': desc,
                    'country': country
                })

        result[prefix] = res_list

    os.makedirs(DATA_DIR, exist_ok=True)
    filename = datetime.datetime.now().strftime('%Y-%m-%d') + '.json'
    with open(os.path.join(DATA_DIR, filename), 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    # Архивируем лог и очищаем
    backup_and_clear_log(LOG_FILE, BACKUP_DIR)

if __name__ == '__main__':
    main()
