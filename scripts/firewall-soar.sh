#!/bin/bash
# firewall-soar.sh - Firewall hardening idempoten untuk SOAR stack (IPv4 + IPv6).
#
# - Memakai dedicated chain SOAR-DOCKER (dimasukkan di posisi 1 DOCKER-USER via -I,
#   sebelum rule RETURN bawaan Docker) untuk layanan bridge-network.
# - Memakai dedicated chain SOAR-HOST (dimasukkan di posisi 1 INPUT) untuk layanan
#   network_mode: host (fleet-monitor :8080, misp-index :8090, alert-log :8091).
# - Menutup akses publik pada port 1514, 1515, 514, 55000, 9200, 443, 3000, 5678,
#   8080, 8090, 8091 kecuali dari loopback, Docker bridge, Tailscale (100.64.0.0/10),
#   atau subnet LAN yang diizinkan (SOAR_LAN_CIDR, default 192.168.0.0/16).

set -euo pipefail

LAN_CIDR="${SOAR_LAN_CIDR:-192.168.0.0/16}"
TAILSCALE_CIDR="${SOAR_TAILSCALE_CIDR:-100.64.0.0/10}"
DOCKER_CIDR="${SOAR_DOCKER_CIDR:-172.16.0.0/12}"

apply_v4() {
  # 1. Chain untuk kontainer Docker bridge (DOCKER-USER)
  iptables -N SOAR-DOCKER 2>/dev/null || iptables -F SOAR-DOCKER
  if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    iptables -C DOCKER-USER -j SOAR-DOCKER 2>/dev/null || iptables -I DOCKER-USER 1 -j SOAR-DOCKER
  fi

  # Wazuh agent enrollment & syslog (1514, 1515, 514)
  for port in 1514 1515; do
    iptables -A SOAR-DOCKER -p tcp --dport "$port" -s 127.0.0.0/8 -j ACCEPT
    iptables -A SOAR-DOCKER -p tcp --dport "$port" -s "$TAILSCALE_CIDR" -j ACCEPT
    iptables -A SOAR-DOCKER -p tcp --dport "$port" -s "$LAN_CIDR" -j ACCEPT
    iptables -A SOAR-DOCKER -p tcp --dport "$port" -j DROP
  done
  iptables -A SOAR-DOCKER -p udp --dport 514 -s "$TAILSCALE_CIDR" -j ACCEPT
  iptables -A SOAR-DOCKER -p udp --dport 514 -s "$LAN_CIDR" -j ACCEPT
  iptables -A SOAR-DOCKER -p udp --dport 514 -j DROP

  # Wazuh Manager API (55000), Indexer (9200), Wazuh Dashboard (443)
  for port in 55000 9200; do
    iptables -A SOAR-DOCKER -p tcp --dport "$port" -s 127.0.0.0/8 -j ACCEPT
    iptables -A SOAR-DOCKER -p tcp --dport "$port" -s "$DOCKER_CIDR" -j ACCEPT
    iptables -A SOAR-DOCKER -p tcp --dport "$port" -s "$TAILSCALE_CIDR" -j ACCEPT
    iptables -A SOAR-DOCKER -p tcp --dport "$port" -j DROP
  done

  # Dashboard UI (3000), n8n (5678), Wazuh HTTPS (443)
  for port in 443 3000 5678; do
    iptables -A SOAR-DOCKER -p tcp --dport "$port" -s 127.0.0.0/8 -j ACCEPT
    iptables -A SOAR-DOCKER -p tcp --dport "$port" -s "$DOCKER_CIDR" -j ACCEPT
    iptables -A SOAR-DOCKER -p tcp --dport "$port" -s "$TAILSCALE_CIDR" -j ACCEPT
    iptables -A SOAR-DOCKER -p tcp --dport "$port" -j DROP
  done
  iptables -A SOAR-DOCKER -j RETURN

  # 2. Chain untuk layanan network_mode: host (INPUT)
  iptables -N SOAR-HOST 2>/dev/null || iptables -F SOAR-HOST
  iptables -C INPUT -j SOAR-HOST 2>/dev/null || iptables -I INPUT 1 -j SOAR-HOST

  # fleet-monitor (8080): izinkan loopback, docker, tailscale, LAN
  iptables -A SOAR-HOST -p tcp --dport 8080 -s 127.0.0.0/8 -j ACCEPT
  iptables -A SOAR-HOST -p tcp --dport 8080 -s "$DOCKER_CIDR" -j ACCEPT
  iptables -A SOAR-HOST -p tcp --dport 8080 -s "$TAILSCALE_CIDR" -j ACCEPT
  iptables -A SOAR-HOST -p tcp --dport 8080 -s "$LAN_CIDR" -j ACCEPT
  iptables -A SOAR-HOST -p tcp --dport 8080 -j DROP

  # misp-index (8090) & alert-log (8091): internal host + Docker saja
  for port in 8090 8091; do
    iptables -A SOAR-HOST -p tcp --dport "$port" -s 127.0.0.0/8 -j ACCEPT
    iptables -A SOAR-HOST -p tcp --dport "$port" -s "$DOCKER_CIDR" -j ACCEPT
    iptables -A SOAR-HOST -p tcp --dport "$port" -j DROP
  done

  # Dashboard (3000) & n8n (5678) jika diakses langsung pada host interface
  for port in 3000 5678; do
    iptables -A SOAR-HOST -p tcp --dport "$port" -s 127.0.0.0/8 -j ACCEPT
    iptables -A SOAR-HOST -p tcp --dport "$port" -s "$DOCKER_CIDR" -j ACCEPT
    iptables -A SOAR-HOST -p tcp --dport "$port" -s "$TAILSCALE_CIDR" -j ACCEPT
    iptables -A SOAR-HOST -p tcp --dport "$port" -j DROP
  done
  iptables -A SOAR-HOST -j RETURN
}

apply_v6() {
  command -v ip6tables >/dev/null 2>&1 || return 0
  ip6tables -N SOAR-HOST6 2>/dev/null || ip6tables -F SOAR-HOST6
  ip6tables -C INPUT -j SOAR-HOST6 2>/dev/null || ip6tables -I INPUT 1 -j SOAR-HOST6

  # Tutup seluruh port SOAR dari IPv6 eksternal (hanya izinkan ::1 loopback & Tailscale fd7a:115c:a1e0::/48)
  for port in 1514 1515 3000 5678 8080 8090 8091 9200 55000; do
    ip6tables -A SOAR-HOST6 -p tcp --dport "$port" -s ::1/128 -j ACCEPT
    ip6tables -A SOAR-HOST6 -p tcp --dport "$port" -s fd7a:115c:a1e0::/48 -j ACCEPT
    ip6tables -A SOAR-HOST6 -p tcp --dport "$port" -j DROP
  done
  ip6tables -A SOAR-HOST6 -j RETURN
}

apply_v4
apply_v6
echo "SOAR firewall rules applied (IPv4 + IPv6)"
