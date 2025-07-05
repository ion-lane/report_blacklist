#!/usr/bin/env python3
import os
import sys
import json
import datetime
import ipaddress
import re
import zipfile
import pwd
import grp
import shutil
import time
import subprocess
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
LOG_FILE = sys.argv[1] if len(sys.argv) > 1 else 'log.txt'
DATA_DIR = '/var/www/top_ips/data'
BACKUP_DIR = '/var/log/mikrotik_backup'
TEMP_LOG = '/tmp/log_copy.txt'
PREFIXES = ['blinp_', 'blfwd_', 'grchc_', 'dns_', 'invalid_', 'private_', 'drop_', 'icmp_']
EXCLUDE_NETWORKS = ['192.168.0.0/16', '10.0.0.0/24']
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
def backup_temp_log(temp_log_path, backup_dir):
    os.makedirs(backup_dir, exist_ok=True)
    today_str = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    archive_name = os.path.join(backup_dir, f"log_copy_{today_str}.zip")
    try:
        with zipfile.ZipFile(archive_name, 'w', compression=zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(temp_log_path, arcname='log_copy.txt')
    except Exception as e:
        print(f"Ошибка архивации копии лога: {e}", file=sys.stderr)
        return False
    print(f"Копия лога заархивирована в {archive_name}")
    return True
def cleanup_old_archives(directory, days=10):
    now = time.time()
    cutoff = now - (days * 86400)
    deleted = 0
    for fname in os.listdir(directory):
        if not fname.endswith('.zip'):
            continue
        full_path = os.path.join(directory, fname)
        try:
            if os.path.isfile(full_path):
                mtime = os.path.getmtime(full_path)
                if mtime < cutoff:
                    os.remove(full_path)
                    deleted += 1
        except Exception as e:
            print(f"Ошибка при удалении {fname}: {e}", file=sys.stderr)
    if deleted:
        print(f"Удалено архивов старше {days} дней: {deleted}")
    else:
        print(f"Архивы старше {days} дней не найдены.")
def main():
    # Копирование и очистка
    try:
        shutil.copy2(LOG_FILE, TEMP_LOG)
        with open(LOG_FILE, 'w'):
            pass
    except Exception as e:
        print(f"Ошибка при копировании или очистке лога: {e}", file=sys.stderr)
        return
    with open(TEMP_LOG, encoding='utf-8', errors='ignore') as f:
        lines = f.read().splitlines()
    ips_by_prefix = extract_ips_by_prefix(lines, PREFIXES, EXCLUDE_NETWORKS)
    result = {}
    whois_cache = {}
    for prefix in PREFIXES:
        ips = ips_by_prefix.get(prefix, [])
        counter = Counter(ips)
        top_ips = counter.most_common(1000)
        res_list = []
        def cached_lookup(ip):
            if ip not in whois_cache:
                whois_cache[ip] = fetch_whois(ip)
            return whois_cache[ip]
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(cached_lookup, ip): ip for ip, _ in top_ips}
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
    file_path = os.path.join(DATA_DIR, filename)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    os.chmod(file_path, 0o440)
    try:
        uid = pwd.getpwnam("root").pw_uid
        gid = grp.getgrnam("apache").gr_gid
        os.chown(file_path, uid, gid)
    except KeyError as e:
        print(f"Ошибка установки владельца: {e}", file=sys.stderr)
    backup_temp_log(TEMP_LOG, BACKUP_DIR)
    try:
        os.remove(TEMP_LOG)
    except OSError:
        pass
    cleanup_old_archives(BACKUP_DIR, days=10)
if __name__ == '__main__':
    main()
