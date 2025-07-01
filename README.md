# report_blacklist

<h5>Shows report from mikrotik logs.</h5>

Logs saved on rsyslog server to /var/log/mikrotik.log


<h5>Using manual</h5>

python3 top_ips.py /var/log/mikrotik.log 10 # show top 10 ip


<h5>Using as web server</h5>

copy index.php and data to www directory of web server.

add script to crontab 0 0 * * * /usr/bin/python3 /var/www/top_ips/top_ips.py /var/log/mikrotik.log
