#!/bin/bash
set -e
iptables -A DOCKER-USER -p tcp --dport 1514 -s 100.64.0.0/10 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 1515 -s 100.64.0.0/10 -j ACCEPT
iptables -A DOCKER-USER -p udp --dport 514  -s 100.64.0.0/10 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 1514 -s 192.168.0.0/16 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 1515 -s 192.168.0.0/16 -j ACCEPT
iptables -A DOCKER-USER -p udp --dport 514  -s 192.168.0.0/16 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 1514 -s 127.0.0.0/8 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 1515 -s 127.0.0.0/8 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 1514 -j DROP
iptables -A DOCKER-USER -p tcp --dport 1515 -j DROP
iptables -A DOCKER-USER -p udp --dport 514  -j DROP
iptables -A DOCKER-USER -p tcp --dport 55000 -s 127.0.0.0/8 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 55000 -s 172.16.0.0/12 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 55000 -s 100.64.0.0/10 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 55000 -j DROP
iptables -A DOCKER-USER -p tcp --dport 9200 -s 127.0.0.0/8 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 9200 -s 172.16.0.0/12 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 9200 -s 100.64.0.0/10 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 9200 -j DROP
iptables -A DOCKER-USER -p tcp --dport 443 -s 100.64.0.0/10 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 443 -s 127.0.0.0/8 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 443 -j DROP
iptables -A DOCKER-USER -p tcp --dport 3000 -s 100.64.0.0/10 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 3000 -s 127.0.0.0/8 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 8080 -s 100.64.0.0/10 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 8080 -s 127.0.0.0/8 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 8080 -s 172.16.0.0/12 -j ACCEPT
echo OK
