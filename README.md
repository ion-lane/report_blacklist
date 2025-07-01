# report_blacklist
Shows report from mikrotik logs.
Logs saved on rsyslog server to /var/log/mikrotik.log

Using manual
python3 top_ips.py /var/log/mikrotik.log 10 # show top 10 ip

Using as web server
copy index.php and data to www directory of web server.
add script to crontab 0 0 * * * /usr/bin/python3 /var/www/top_ips/top_ips.py /var/log/mikrotik.log
