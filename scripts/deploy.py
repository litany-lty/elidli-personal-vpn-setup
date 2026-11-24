#!/usr/bin/env python3
"""Inspect or deploy one private Shadowsocks or Hysteria2 service over trusted OpenSSH."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import secrets
import shlex
import stat
import subprocess
import tempfile
from pathlib import Path
from public_host import normalize_public_host, require_public_resolution

try:
    import fcntl
except ImportError:  # Native Windows; use this workflow from WSL instead.
    fcntl = None


PROTOCOLS = ("ss", "hysteria2")
METHODS = ("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305")
OUTBOUND_MODES = ("auto-detect", "auto", "4", "6", "46", "64")
REMOTE_HY2_SCRIPT = r'''set -eu
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
umask 077
bundle=$1
service_id=$2
service="personal-vpn-${service_id}"
hop_service="${service}-hop"
hop_helper="/usr/local/libexec/${service}-hop"
config="/etc/hysteria/${service}.yaml"
cert="/etc/hysteria/${service}.crt"
key="/etc/hysteria/${service}.key"
unit="/etc/systemd/system/${service}.service"
hop_unit="/etc/systemd/system/${hop_service}.service"
account="personal-vpn-hy2"

exec 9>"/run/lock/${service}.lock"
flock -n 9 || { echo "another deployment is already running for ${service}" >&2; exit 1; }

cleanup() { rm -f "$bundle" "$config.new" "$unit.new" "$hop_unit.new" "$hop_helper.new"; }
trap cleanup EXIT

python3 - "$bundle" "$config" "$unit" <<'PY'
import hashlib, json, pathlib, re, sys
bundle, config_path, unit_path = map(pathlib.Path, sys.argv[1:])
d = json.loads(bundle.read_text())
expected = d.pop("_expected_remote")
config_exists, unit_exists = config_path.exists(), unit_path.exists()
if expected["state"] == "missing":
    if config_exists or unit_exists:
        raise SystemExit("same-name remote service appeared after preflight")
elif expected["state"] == "present":
    if not config_exists or not unit_exists:
        raise SystemExit("same-name remote service became incomplete after preflight")
    raw = config_path.read_text()
    m_port = re.search(r"(?m)^listen:\s*:(\d+)\s*$", raw)
    m_pass = re.search(r'(?m)^\s*password:\s*"([^"]+)"\s*$', raw)
    m_sni = re.search(r"(?m)^\s*url:\s*https://([^/\s]+)/?\s*$", raw)
    comparable = {
        "password": m_pass.group(1) if m_pass else "",
        "port": int(m_port.group(1)) if m_port else 0,
        "sni": m_sni.group(1).lower() if m_sni else "",
    }
    digest = hashlib.sha256(json.dumps(comparable, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if digest != expected["fingerprint"]:
        raise SystemExit("same-name remote service changed after preflight")
else:
    raise SystemExit("invalid expected remote state")
PY

os_id=$(. /etc/os-release; printf '%s' "$ID")
case "$os_id" in debian|ubuntu) ;; *) echo "supported remote OS is Debian or Ubuntu" >&2; exit 1;; esac

hop_range=$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])).get("hop_range"); print(f"{r[0]}-{r[1]}" if r else "")' "$bundle")
if [ -n "$hop_range" ]; then
  python3 - "$bundle" "$service" <<'PY'
import json, subprocess, sys
d = json.loads(open(sys.argv[1]).read())
service = sys.argv[2]
start_p, end_p = d["hop_range"]
listen_p = int(d["port"])
main_pid = subprocess.run(["systemctl", "show", service, "-p", "MainPID", "--value"], capture_output=True, text=True).stdout.strip()
ss_out = subprocess.run(["ss", "-H", "-lun"], capture_output=True, text=True, check=True).stdout
for line in ss_out.splitlines():
    cols = line.split()
    if len(cols) < 4:
        continue
    local = cols[3]
    try:
        bound_port = int(local.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        continue
    if start_p <= bound_port <= end_p and bound_port != listen_p:
        if main_pid and main_pid != "0" and f"pid={main_pid}," in line:
            continue
        raise SystemExit(f"UDP port {bound_port} inside --hop-ports {start_p}-{end_p} is already in use")
PY
fi

need_pkgs=""
command -v openssl >/dev/null 2>&1 || need_pkgs="$need_pkgs openssl"
[ -f /etc/ssl/certs/ca-certificates.crt ] || need_pkgs="$need_pkgs ca-certificates"
if [ -n "$hop_range" ] && ! command -v nft >/dev/null 2>&1 && ! command -v iptables >/dev/null 2>&1; then
  need_pkgs="$need_pkgs nftables"
fi
if [ -n "$need_pkgs" ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=15 update >/dev/null
  # shellcheck disable=SC2086
  apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=15 -y --no-install-recommends install $need_pkgs >/dev/null
fi

cat >/etc/sysctl.d/99-personal-vpn-quic.conf <<'EOF'
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
EOF
sysctl --system >/dev/null 2>&1 || true

if [ ! -x /usr/local/bin/hysteria ]; then
  python3 - <<'PY'
import hashlib, json, os, platform, urllib.request
machine = platform.machine().lower()
arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
if not arch:
    raise SystemExit(f"unsupported remote CPU architecture for Hysteria2: {machine}")
headers = {"User-Agent": "elidli-personal-vpn-setup"}
rel_req = urllib.request.Request("https://api.github.com/repos/apernet/hysteria/releases/latest", headers=headers)
tag = json.loads(urllib.request.urlopen(rel_req, timeout=20).read().decode())["tag_name"]
base = f"https://github.com/apernet/hysteria/releases/download/{tag}"
asset = f"hysteria-linux-{arch}"
hashes = urllib.request.urlopen(urllib.request.Request(f"{base}/hashes.txt", headers=headers), timeout=20).read().decode()
expected = next((p[0].lower() for line in hashes.splitlines() if len(p := line.split()) >= 2 and p[1].endswith(asset)), "")
if not expected:
    raise SystemExit(f"missing official SHA-256 entry for {asset}")
binary = urllib.request.urlopen(urllib.request.Request(f"{base}/{asset}", headers=headers), timeout=90).read()
actual = hashlib.sha256(binary).hexdigest().lower()
if actual != expected:
    raise SystemExit("Hysteria2 binary SHA-256 verification failed")
tmp = "/usr/local/bin/.hysteria.new"
with open(tmp, "wb") as handle:
    handle.write(binary)
os.chmod(tmp, 0o755)
os.replace(tmp, "/usr/local/bin/hysteria")
PY
fi

getent passwd "$account" >/dev/null 2>&1 || adduser --system --group --no-create-home --home /nonexistent --shell /usr/sbin/nologin "$account" >/dev/null 2>&1 || useradd -r -U -s /usr/sbin/nologin -M "$account"
install -d -m 0750 -o root -g "$account" /etc/hysteria

sni=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sni"])' "$bundle")
if [ ! -f "$key" ] || [ ! -f "$cert" ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out "$key"
  openssl req -new -x509 -key "$key" -out "$cert" \
    -subj "/CN=${sni}" -addext "subjectAltName=DNS:${sni}" -days 3650 2>/dev/null
fi
chown root:"$account" "$key" "$cert"
chmod 0640 "$key" "$cert"

python3 - "$bundle" "$config.new" "$unit.new" "$hop_unit.new" "$hop_helper.new" "$service" "$service_id" "$cert" "$key" <<'PY'
import json, pathlib, re, sys
bundle, config_path, unit_path, hop_unit_path, hop_helper_path, service, service_id, cert, key = sys.argv[1:]
d = json.loads(pathlib.Path(bundle).read_text())
sni = d["sni"]
req_mode = d.get("outbound_mode", "auto-detect")
if req_mode == "auto-detect":
    has_global_v6_addr = False
    has_v6_default_route = False
    try:
        for line in pathlib.Path("/proc/net/if_inet6").read_text().splitlines():
            cols = line.split()
            if len(cols) >= 6 and cols[3] == "00" and cols[5] != "lo" and (int(cols[0][:4], 16) & 0xE000) == 0x2000:
                has_global_v6_addr = True
                break
        for line in pathlib.Path("/proc/net/ipv6_route").read_text().splitlines():
            cols = line.split()
            if (len(cols) >= 10 and cols[0] == "0" * 32 and cols[1] == "00"
                    and cols[9] != "lo" and (int(cols[8], 16) & 0x201) == 0x1):
                has_v6_default_route = True
                break
    except OSError:
        pass
    effective_mode = "auto" if (has_global_v6_addr and has_v6_default_route) else "4"
else:
    effective_mode = req_mode

cfg = f"""listen: :{d["port"]}

tls:
  cert: {cert}
  key: {key}

auth:
  type: password
  password: "{d["password"]}"

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520

outbounds:
  - name: direct
    type: direct
    direct:
      mode: {effective_mode}

ignoreClientBandwidth: false

masquerade:
  type: proxy
  proxy:
    url: https://{sni}/
    rewriteHost: true
"""
pathlib.Path(config_path).write_text(cfg)
hop_range = d.get("hop_range")
wants_hop = f"\nWants={service}-hop.service" if hop_range else ""
unit = f"""[Unit]
Description=Private Hysteria2 service ({service})
After=network-online.target
Wants=network-online.target{wants_hop}

[Service]
Type=simple
User=personal-vpn-hy2
Group=personal-vpn-hy2
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/{service}.yaml
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
"""
pathlib.Path(unit_path).write_text(unit)
if hop_range:
    start_p, end_p = int(hop_range[0]), int(hop_range[1])
    listen_p = int(d["port"])
    safe_id = re.sub(r"[^a-z0-9_]", "_", service_id)
    tbl = f"pvpn_{safe_id}"
    helper = f"""#!/bin/sh
set -eu
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
TBL="{tbl}"
TAG="{service}-hop"
HOP_START="{start_p}"
HOP_END="{end_p}"
LISTEN_PORT="{listen_p}"
case "${{1:-}}" in
  start)
    if command -v nft >/dev/null 2>&1 && nft list tables >/dev/null 2>&1; then
      nft add table ip "$TBL"
      nft flush table ip "$TBL"
      nft "add chain ip $TBL prerouting {{ type nat hook prerouting priority dstnat; policy accept; }}"
      nft "add rule ip $TBL prerouting udp dport ${{HOP_START}}-${{HOP_END}} counter redirect to :${{LISTEN_PORT}}"
    else
      while iptables -t nat -D PREROUTING -p udp --dport "${{HOP_START}}:${{HOP_END}}" -m comment --comment "$TAG" -j REDIRECT --to-ports "$LISTEN_PORT" 2>/dev/null; do :; done
      iptables -t nat -A PREROUTING -p udp --dport "${{HOP_START}}:${{HOP_END}}" -m comment --comment "$TAG" -j REDIRECT --to-ports "$LISTEN_PORT"
    fi
    ;;
  stop)
    if command -v nft >/dev/null 2>&1 && nft list table ip "$TBL" >/dev/null 2>&1; then
      nft delete table ip "$TBL" 2>/dev/null || true
    fi
    if command -v iptables >/dev/null 2>&1; then
      while iptables -t nat -D PREROUTING -p udp --dport "${{HOP_START}}:${{HOP_END}}" -m comment --comment "$TAG" -j REDIRECT --to-ports "$LISTEN_PORT" 2>/dev/null; do :; done
    fi
    ;;
  *)
    echo "usage: $0 start|stop" >&2
    exit 2
    ;;
esac
"""
    pathlib.Path(hop_helper_path).write_text(helper)
    hop_u = f"""[Unit]
Description=Isolated UDP port-hopping redirect for {service} ({start_p}-{end_p} -> {listen_p})
After=network-online.target
PartOf={service}.service
Before={service}.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/libexec/{service}-hop start
ExecStop=/usr/local/libexec/{service}-hop stop
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
"""
    pathlib.Path(hop_unit_path).write_text(hop_u)
pathlib.Path(f"{config_path}.mode").write_text(effective_mode)
PY
effective_mode=$(cat "$config.new.mode"); rm -f "$config.new.mode"
chown root:"$account" "$config.new"
chmod 0640 "$config.new"
chmod 0644 "$unit.new"
if [ -n "$hop_range" ]; then
  install -d -m 0755 /usr/local/libexec
  chown root:root "$hop_helper.new"
  chmod 0750 "$hop_helper.new"
  chmod 0644 "$hop_unit.new"
fi

stamp=$(date +%Y%m%d%H%M%S)
old_active=0; old_enabled=0; old_hop_active=0; old_hop_enabled=0
systemctl is-active --quiet "$service" && old_active=1 || true
systemctl is-enabled --quiet "$service" && old_enabled=1 || true
systemctl is-active --quiet "$hop_service" 2>/dev/null && old_hop_active=1 || true
systemctl is-enabled --quiet "$hop_service" 2>/dev/null && old_hop_enabled=1 || true
had_config=0; had_unit=0; had_hop_unit=0; had_hop_helper=0
[ ! -e "$config" ] || had_config=1
[ ! -e "$unit" ] || had_unit=1
[ ! -e "$hop_unit" ] || had_hop_unit=1
[ ! -e "$hop_helper" ] || had_hop_helper=1
[ ! -e "$config" ] || cp -p "$config" "${config}.rollback-${stamp}"
[ ! -e "$unit" ] || cp -p "$unit" "${unit}.rollback-${stamp}"
[ ! -e "$hop_unit" ] || cp -p "$hop_unit" "${hop_unit}.rollback-${stamp}"
[ ! -e "$hop_helper" ] || cp -p "$hop_helper" "${hop_helper}.rollback-${stamp}"
restore() {
  systemctl stop "$hop_service" >/dev/null 2>&1 || true
  systemctl stop "$service" >/dev/null 2>&1 || true
  [ "$old_hop_enabled" -eq 1 ] || systemctl disable "$hop_service" >/dev/null 2>&1 || true
  [ "$old_enabled" -eq 1 ] || systemctl disable "$service" >/dev/null 2>&1 || true
  if [ "$had_config" -eq 1 ]; then mv -f "${config}.rollback-${stamp}" "$config"; else rm -f "$config"; fi
  if [ "$had_unit" -eq 1 ]; then mv -f "${unit}.rollback-${stamp}" "$unit"; else rm -f "$unit"; fi
  if [ "$had_hop_unit" -eq 1 ]; then mv -f "${hop_unit}.rollback-${stamp}" "$hop_unit"; else rm -f "$hop_unit"; fi
  if [ "$had_hop_helper" -eq 1 ]; then mv -f "${hop_helper}.rollback-${stamp}" "$hop_helper"; else rm -f "$hop_helper"; fi
  systemctl daemon-reload
  [ "$old_hop_enabled" -eq 0 ] || systemctl enable "$hop_service" >/dev/null 2>&1 || true
  [ "$old_enabled" -eq 0 ] || systemctl enable "$service" >/dev/null 2>&1 || true
  [ "$old_hop_active" -eq 0 ] || systemctl start "$hop_service" >/dev/null 2>&1 || true
  [ "$old_active" -eq 0 ] || systemctl start "$service" >/dev/null 2>&1 || true
}
finish_replacement() {
  rc=$?
  trap - EXIT HUP INT TERM
  set +e
  [ "$rc" -eq 0 ] || restore
  cleanup
  exit "$rc"
}
trap finish_replacement EXIT
trap 'exit 1' HUP INT TERM
if [ "$had_hop_unit" -eq 1 ] && [ -z "$hop_range" ]; then
  systemctl stop "$hop_service" >/dev/null 2>&1 || true
  systemctl disable "$hop_service" >/dev/null 2>&1 || true
  rm -f "$hop_unit" "$hop_helper"
fi
mv "$config.new" "$config"
mv "$unit.new" "$unit"
if [ -n "$hop_range" ]; then
  mv "$hop_helper.new" "$hop_helper"
  mv "$hop_unit.new" "$hop_unit"
fi
systemctl daemon-reload
if [ -n "$hop_range" ]; then
  if ! systemctl enable "$hop_service" >/dev/null || ! systemctl restart "$hop_service"; then
    echo "UDP port-hopping rule activation failed; restoring previous service" >&2
    exit 1
  fi
fi
if ! systemctl enable "$service" >/dev/null || ! systemctl restart "$service" || ! systemctl is-active --quiet "$service"; then
  echo "activation failed; restoring previous service" >&2
  exit 1
fi
listen_port=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["port"])' "$bundle")
listeners=""
i=0
while [ "$i" -lt 30 ]; do
  main_pid=$(systemctl show "$service" -p MainPID --value)
  listener_lines=$(ss -H -lntup "sport = :${listen_port}")
  listeners=$(printf '%s\n' "$listener_lines" | awk -v pid="pid=${main_pid}," 'index($0,pid) {print $1}' | sort -u | paste -sd, -)
  case ",$listeners," in *,udp,*) break;; esac
  i=$((i + 1)); sleep 0.1
done
case ",$listeners," in
  *,udp,*) ;;
  *)
    echo "missing UDP listener; restoring previous service" >&2
    exit 1
    ;;
esac
trap cleanup EXIT
trap - HUP INT TERM
rm -f "${config}.rollback-${stamp}" "${unit}.rollback-${stamp}" "${hop_unit}.rollback-${stamp}" "${hop_helper}.rollback-${stamp}"
svc_state=$(systemctl show "$service" -p ActiveState -p SubState -p NRestarts -p User --value | paste -sd, -)
cert_fp=$(openssl x509 -noout -fingerprint -sha256 -in "$cert" | cut -d= -f2)
python3 -c 'import json,sys; print(json.dumps({"service": sys.argv[1], "listeners": sys.argv[2], "fingerprint": sys.argv[3], "outbound_mode": sys.argv[4], "hop_range": sys.argv[5] or None}))' "$svc_state" "$listeners" "$cert_fp" "$effective_mode" "$hop_range"
'''
REMOTE_SCRIPT = r'''set -eu
umask 077
bundle=$1
service_id=$2
service="personal-vpn-${service_id}"
config="/etc/shadowsocks-libev/${service}.json"
unit="/etc/systemd/system/${service}.service"
account="personal-vpn-ss"

exec 9>"/run/lock/${service}.lock"
flock -n 9 || { echo "another deployment is already running for ${service}" >&2; exit 1; }

cleanup() { rm -f "$bundle" "$config.new" "$unit.new"; }
trap cleanup EXIT

python3 - "$bundle" "$config" "$unit" <<'PY'
import hashlib, json, pathlib, sys
bundle, config_path, unit_path = map(pathlib.Path, sys.argv[1:])
d = json.loads(bundle.read_text())
expected = d.pop("_expected_remote")
config_exists, unit_exists = config_path.exists(), unit_path.exists()
if expected["state"] == "missing":
    if config_exists or unit_exists:
        raise SystemExit("same-name remote service appeared after preflight")
elif expected["state"] == "present":
    if not config_exists or not unit_exists:
        raise SystemExit("same-name remote service became incomplete after preflight")
    current = json.loads(config_path.read_text())
    comparable = {k: current[k] for k in ("password", "server_port", "method")}
    digest = hashlib.sha256(json.dumps(comparable, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if digest != expected["fingerprint"]:
        raise SystemExit("same-name remote service changed after preflight")
else:
    raise SystemExit("invalid expected remote state")
PY

os_id=$(. /etc/os-release; printf '%s' "$ID")
case "$os_id" in debian|ubuntu) ;; *) echo "supported remote OS is Debian or Ubuntu" >&2; exit 1;; esac

export DEBIAN_FRONTEND=noninteractive
default_was_active=0
default_was_enabled=0
systemctl is-active --quiet shadowsocks-libev.service 2>/dev/null && default_was_active=1 || true
systemctl is-enabled --quiet shadowsocks-libev.service 2>/dev/null && default_was_enabled=1 || true
apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=15 update >/dev/null
apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=15 -y --no-install-recommends install shadowsocks-libev >/dev/null
if [ "$default_was_active" -eq 0 ] && systemctl is-active --quiet shadowsocks-libev.service 2>/dev/null; then
  systemctl stop shadowsocks-libev.service >/dev/null
fi
if [ "$default_was_enabled" -eq 0 ] && systemctl is-enabled --quiet shadowsocks-libev.service 2>/dev/null; then
  systemctl disable shadowsocks-libev.service >/dev/null
fi
getent passwd "$account" >/dev/null 2>&1 || adduser --system --group --no-create-home --home /nonexistent --shell /usr/sbin/nologin "$account" >/dev/null

python3 - "$bundle" "$config.new" "$unit.new" "$service_id" <<'PY'
import json, pathlib, sys
bundle, config_path, unit_path, service_id = sys.argv[1:]
d = json.loads(pathlib.Path(bundle).read_text())
config = {
  "server": "0.0.0.0", "server_port": d["port"], "password": d["password"],
  "timeout": 300, "method": d["method"], "mode": "tcp_and_udp",
  "fast_open": False, "nameserver": "1.1.1.1"
}
pathlib.Path(config_path).write_text(json.dumps(config, indent=2) + "\n")
unit = f"""[Unit]
Description=Private Shadowsocks service ({service_id})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=personal-vpn-ss
Group=personal-vpn-ss
ExecStart=/usr/bin/ss-server -c /etc/shadowsocks-libev/personal-vpn-{service_id}.json
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
"""
pathlib.Path(unit_path).write_text(unit)
PY
chown root:"$account" "$config.new"
chmod 0640 "$config.new"
chmod 0644 "$unit.new"

stamp=$(date +%Y%m%d%H%M%S)
old_active=0
old_enabled=0
systemctl is-active --quiet "$service" && old_active=1 || true
systemctl is-enabled --quiet "$service" && old_enabled=1 || true
had_config=0; had_unit=0
[ ! -e "$config" ] || had_config=1
[ ! -e "$unit" ] || had_unit=1
[ ! -e "$config" ] || cp -p "$config" "${config}.rollback-${stamp}"
[ ! -e "$unit" ] || cp -p "$unit" "${unit}.rollback-${stamp}"
restore() {
  systemctl stop "$service" >/dev/null 2>&1 || true
  [ "$old_enabled" -eq 1 ] || systemctl disable "$service" >/dev/null 2>&1 || true
  if [ "$had_config" -eq 1 ]; then mv -f "${config}.rollback-${stamp}" "$config"; else rm -f "$config"; fi
  if [ "$had_unit" -eq 1 ]; then mv -f "${unit}.rollback-${stamp}" "$unit"; else rm -f "$unit"; fi
  systemctl daemon-reload
  [ "$old_enabled" -eq 0 ] || systemctl enable "$service" >/dev/null 2>&1 || true
  [ "$old_active" -eq 0 ] || systemctl start "$service" >/dev/null 2>&1 || true
}
finish_replacement() {
  rc=$?
  trap - EXIT HUP INT TERM
  set +e
  [ "$rc" -eq 0 ] || restore
  cleanup
  exit "$rc"
}
trap finish_replacement EXIT
trap 'exit 1' HUP INT TERM
mv "$config.new" "$config"
mv "$unit.new" "$unit"
systemctl daemon-reload
if ! systemctl enable "$service" >/dev/null || ! systemctl restart "$service" || ! systemctl is-active --quiet "$service"; then
  echo "activation failed; restoring previous service" >&2
  exit 1
fi
listen_port=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["port"])' "$bundle")
listeners=""
i=0
while [ "$i" -lt 30 ]; do
  main_pid=$(systemctl show "$service" -p MainPID --value)
  listener_lines=$(ss -H -lntup "sport = :${listen_port}")
  listeners=$(printf '%s\n' "$listener_lines" | awk -v pid="pid=${main_pid}," 'index($0,pid) {print $1}' | sort -u | paste -sd, -)
  case ",$listeners," in *,tcp,*udp,*|*,udp,*tcp,*) break;; esac
  i=$((i + 1)); sleep 0.1
done
case ",$listeners," in
  *,tcp,*udp,*) ;;
  *,udp,*tcp,*) ;;
  *)
    echo "missing TCP or UDP listener; restoring previous service" >&2
    exit 1
    ;;
esac
trap cleanup EXIT
trap - HUP INT TERM
rm -f "${config}.rollback-${stamp}" "${unit}.rollback-${stamp}"
systemctl show "$service" -p ActiveState -p SubState -p NRestarts -p User --value | paste -sd, -
printf '%s\n' "$listeners"
'''


def service_id(value: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", value):
        raise argparse.ArgumentTypeError("service id must match [a-z0-9][a-z0-9-]{0,31}")
    return value


def port(value: str) -> int:
    parsed = int(value)
    if not 1024 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1024 and 65535")
    return parsed


def ssh_port(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("SSH port must be between 1 and 65535")
    return parsed


def ssh_target(value: str) -> str:
    if not value or value.startswith("-") or any(c.isspace() for c in value):
        raise argparse.ArgumentTypeError("invalid OpenSSH target")
    return value


def ssh_command(args: argparse.Namespace) -> list[str]:
    command = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"]
    if args.port:
        command += ["-p", str(args.port)]
    if args.identity:
        command += ["-i", str(args.identity)]
    if args.control_path:
        command += ["-S", str(args.control_path)]
    command += [args.target]
    return command


def remote_root_prefix(args: argparse.Namespace) -> str:
    return "" if args.remote_root else "sudo -n "


def run_ssh(args: argparse.Namespace, script: str, *, data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ssh_command(args) + [script], input=data, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=args.timeout
        )
    except FileNotFoundError as error:
        raise SystemExit("OpenSSH client was not found; install ssh and retry") from error
    except subprocess.TimeoutExpired as error:
        raise SystemExit(f"SSH operation timed out after {args.timeout} seconds") from error


def ensure_ssh(args: argparse.Namespace) -> None:
    result = run_ssh(args, "true")
    if result.returncode:
        raise SystemExit("SSH preflight failed: " + result.stderr.decode(errors="replace").strip())
    if not args.remote_root:
        result = run_ssh(args, "sudo -n true")
        if result.returncode:
            raise SystemExit("remote account needs passwordless sudo or use --remote-root")


def configured_hostname(args: argparse.Namespace) -> str:
    command = ["ssh", "-G"]
    if args.port:
        command += ["-p", str(args.port)]
    command += [args.target]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10)
    except FileNotFoundError as error:
        raise SystemExit("OpenSSH client was not found; install ssh and retry") from error
    except subprocess.TimeoutExpired as error:
        raise SystemExit("OpenSSH configuration lookup timed out") from error
    if result.returncode:
        raise SystemExit("cannot resolve OpenSSH target: " + result.stderr.decode(errors="replace").strip())
    values = {}
    for line in result.stdout.decode().splitlines():
        key, _, value = line.partition(" ")
        values[key] = value.strip()
    return values.get("hostname", "").lower().rstrip(".")


def remote_service_fingerprint(args: argparse.Namespace) -> tuple[str, str | None]:
    prefix = remote_root_prefix(args)
    service = f"personal-vpn-{args.service_id}"
    unit = f"/etc/systemd/system/{service}.service"
    if args.protocol == "hysteria2":
        config = f"/etc/hysteria/{service}.yaml"
        code = (
            "import hashlib,json,pathlib,re,sys; c=pathlib.Path(sys.argv[1]); u=pathlib.Path(sys.argv[2]); "
            "raw=c.read_text() if c.exists() else ''; "
            "mp=re.search(r'(?m)^listen:\\s*:(\\d+)\\s*$', raw); "
            "mw=re.search(r'(?m)^\\s*password:\\s*\"([^\"]+)\"\\s*$', raw); "
            "ms=re.search(r'(?m)^\\s*url:\\s*https://([^/\\s]+)/?\\s*$', raw); "
            "print('missing' if not c.exists() and not u.exists() else "
            "('partial' if not c.exists() or not u.exists() else "
            "'present '+hashlib.sha256(json.dumps({'password':mw.group(1) if mw else '','port':int(mp.group(1)) if mp else 0,'sni':ms.group(1).lower() if ms else ''},"
            "sort_keys=True,separators=(',',':')).encode()).hexdigest()))"
        )
    else:
        config = f"/etc/shadowsocks-libev/{service}.json"
        code = (
            "import hashlib,json,pathlib,sys; c=pathlib.Path(sys.argv[1]); u=pathlib.Path(sys.argv[2]); "
            "print('missing' if not c.exists() and not u.exists() else "
            "('partial' if not c.exists() or not u.exists() else "
            "'present '+hashlib.sha256(json.dumps({k:json.loads(c.read_text())[k] for k in "
            "('password','server_port','method')},sort_keys=True,separators=(',',':')).encode()).hexdigest()))"
        )
    command = prefix + "python3 -c " + shlex.quote(code) + " " + shlex.quote(config) + " " + shlex.quote(unit)
    result = run_ssh(args, command)
    if result.returncode:
        raise SystemExit("cannot inspect existing service safely: " + result.stderr.decode(errors="replace").strip())
    state, _, fingerprint = result.stdout.decode().strip().partition(" ")
    return state, fingerprint or None


def verify_order(args: argparse.Namespace) -> dict:
    if not args.order:
        raise SystemExit("deploy requires --order with a ready paid/active or owned/active receipt")
    order = json.loads(args.order.read_text())
    if order.get("stage") != "ready":
        raise SystemExit("order state is not ready")
    receipt = order.get("receipt") or {}
    try:
        expected = normalize_public_host(receipt.get("host"))
    except ValueError as error:
        raise SystemExit(f"invalid order receipt.host: {error}") from error
    if receipt.get("kind") != "vps":
        raise SystemExit("ready order must identify a VPS receipt")
    authorized = order.get("active") is True and (order.get("paid") is True or order.get("owned") is True)
    if not authorized:
        raise SystemExit("receipt must be active and either paid or explicitly owned")
    resolved = configured_hostname(args)
    if resolved != expected:
        raise SystemExit(f"OpenSSH target resolves to {resolved!r}, expected receipt host {expected!r}")
    if args.server.lower().rstrip(".") != expected:
        raise SystemExit("client server must match receipt.host in v1")
    try:
        require_public_resolution(expected)
    except ValueError as error:
        raise SystemExit(f"deployment target is not public: {error}") from error
    return order


def state_file(args: argparse.Namespace) -> Path:
    return args.state_dir / f"{args.service_id}.json"


@contextlib.contextmanager
def state_lock(args: argparse.Namespace):
    args.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(args.state_dir, 0o700)
    lock_path = args.state_dir / f".{args.service_id}.lock"
    with lock_path.open("a+") as handle:
        os.chmod(lock_path, 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("another local deployment is already running for this service")
        yield


def write_state_atomic(path: Path, state_dir: Path, service_id_val: str, state: dict[str, object]) -> None:
    temporary = tempfile.NamedTemporaryFile(
        "w", dir=state_dir, prefix=f".{service_id_val}.", delete=False
    )
    try:
        temporary.write(json.dumps(state, indent=2) + "\n")
        temporary.flush()
        os.fsync(temporary.fileno())
        temporary.close()
        os.chmod(temporary.name, 0o600)
        os.replace(temporary.name, path)
    finally:
        if not temporary.closed:
            temporary.close()
        if os.path.exists(temporary.name):
            os.unlink(temporary.name)


def apply_hy2_runtime_options(state: dict[str, object], args: argparse.Namespace) -> None:
    state["outbound_mode"] = args.outbound_mode
    if args.up_mbps > 0:
        state["up"] = f"{args.up_mbps} mbps"
    else:
        state.pop("up", None)
    if args.down_mbps > 0:
        state["down"] = f"{args.down_mbps} mbps"
    else:
        state.pop("down", None)
    if args.hop_ports:
        start_p, end_p = args.hop_ports
        ports_spec = f"{start_p}-{end_p}" if start_p <= args.listen_port <= end_p else f"{args.listen_port},{start_p}-{end_p}"
        state["ports"] = ports_spec
        state["hop_interval"] = args.hop_interval
        state["hop_range"] = [start_p, end_p]
    else:
        state.pop("ports", None)
        state.pop("hop_interval", None)
        state.pop("hop_range", None)


def prepare_state(args: argparse.Namespace) -> tuple[dict[str, object], bool]:
    """Load an existing validated state or synthesize a new in-memory state without writing prematurely."""
    path = state_file(args)
    args.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(args.state_dir, 0o700)
    if path.exists():
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode != 0o600:
            raise SystemExit(f"refusing state file with mode {mode:o}; require 600")
        state = json.loads(path.read_text())
        existing_kind = state.get("kind", "ss")
        if existing_kind != args.protocol:
            raise SystemExit(f"existing state protocol {existing_kind!r} differs from {args.protocol!r}; choose a new --service-id")
        checks: list[tuple[str, object]] = [("service_id", args.service_id), ("server", args.server), ("port", args.listen_port)]
        if args.protocol == "ss":
            checks.append(("method", args.method))
        else:
            checks.append(("sni", args.sni))
        for key, expected in checks:
            if state.get(key) != expected:
                raise SystemExit(f"existing state differs at {key}; choose a new service id or use explicit rotation workflow")
        if args.protocol == "hysteria2":
            apply_hy2_runtime_options(state, args)
        return state, True
    if args.protocol == "hysteria2":
        state: dict[str, object] = {
            "version": 1, "kind": "hysteria2", "service_id": args.service_id,
            "server": args.server, "port": args.listen_port,
            "password": secrets.token_urlsafe(24), "sni": args.sni,
        }
        apply_hy2_runtime_options(state, args)
    else:
        state = {
            "version": 1, "service_id": args.service_id, "server": args.server,
            "port": args.listen_port, "method": args.method,
            "password": secrets.token_urlsafe(32),
        }
    return state, False


def load_or_create_state(args: argparse.Namespace) -> dict[str, object]:
    state, existed = prepare_state(args)
    if not existed:
        write_state_atomic(state_file(args), args.state_dir, args.service_id, state)
    return state


def inspect(args: argparse.Namespace) -> None:
    ensure_ssh(args)
    prefix = remote_root_prefix(args)
    command = prefix + "sh -c " + shlex.quote(
        "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; "
        "set -eu; . /etc/os-release; "
        "printf '{\"id\":\"%s\",\"version\":\"%s\",' \"$ID\" \"$VERSION_ID\"; "
        "printf '\"ss_server\":\"%s\",\"hysteria\":\"%s\",\"rmem_max\":\"%s\",\"service\":\"%s\"}\\n' "
        "\"$(command -v ss-server || true)\" \"$(command -v hysteria || true)\" "
        "\"$(sysctl -n net.core.rmem_max 2>/dev/null || true)\" "
        "\"$(systemctl is-active personal-vpn-" + args.service_id + " 2>/dev/null || true)\""
    )
    result = run_ssh(args, command)
    if result.returncode:
        raise SystemExit(result.stderr.decode(errors="replace"))
    print(result.stdout.decode().strip())


def plan(args: argparse.Namespace) -> None:
    if args.protocol == "hysteria2":
        changes = [
            "verify and install official Hysteria2 binary via SHA-256 if absent",
            "tune QUIC UDP kernel buffers in /etc/sysctl.d/99-personal-vpn-quic.conf",
            "create one system account and self-signed P-256 certificate with pinned SHA-256 fingerprint",
            f"write one isolated config (outbound mode: {args.outbound_mode}) and systemd unit on UDP port without touching existing Shadowsocks ports",
            "enable and start that unit",
        ]
        if args.hop_ports:
            changes.insert(4, f"install isolated UDP port-hopping redirect ({args.hop_ports[0]}-{args.hop_ports[1]} -> {args.listen_port})")
        summary: dict[str, object] = {
            "target": args.target, "service": f"personal-vpn-{args.service_id}",
            "protocol": "hysteria2", "server": args.server, "port": args.listen_port,
            "sni": args.sni, "up_mbps": args.up_mbps, "down_mbps": args.down_mbps,
            "outbound_mode": args.outbound_mode,
            "hop_ports": f"{args.hop_ports[0]}-{args.hop_ports[1]}" if args.hop_ports else None,
            "hop_interval": args.hop_interval if args.hop_ports else None,
            "changes": changes,
            "unchanged": ["SSH policy", "global firewall", "other services and ports (e.g. 28447)", "OS installation"],
        }
    else:
        summary = {
            "target": args.target, "service": f"personal-vpn-{args.service_id}",
            "protocol": "ss", "server": args.server, "port": args.listen_port, "method": args.method,
            "changes": ["install distro shadowsocks-libev package if absent", "create one system account", "write one config and one systemd unit", "enable and start that unit"],
            "unchanged": ["SSH policy", "global firewall", "other services", "OS installation"],
        }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


def deploy(args: argparse.Namespace) -> None:
    if fcntl is None:
        raise SystemExit("Run deployment from macOS, Linux, or WSL with OpenSSH.")
    verify_order(args)
    ensure_ssh(args)
    with state_lock(args):
        remote_state, remote_hash = remote_service_fingerprint(args)
        local_path = state_file(args)
        if remote_state == "partial":
            raise SystemExit("remote service is incomplete; inspect it before deployment")
        if remote_state == "present" and not local_path.exists():
            raise SystemExit("remote service already exists but matching local state is missing; use an explicit rotation/recovery workflow")
        state, _ = prepare_state(args)
        if remote_state == "present":
            if args.protocol == "hysteria2":
                comparable: dict[str, object] = {"password": state["password"], "port": state["port"], "sni": str(state["sni"]).lower()}
            else:
                comparable = {"password": state["password"], "server_port": state["port"], "method": state["method"]}
            local_hash = hashlib.sha256(json.dumps(comparable, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if local_hash != remote_hash:
                raise SystemExit("remote service credential differs from local state; refusing to overwrite")
        bundle = dict(state)
        bundle["_expected_remote"] = {"state": remote_state, "fingerprint": remote_hash}
        remote_bundle = f"/var/tmp/personal-vpn-{args.service_id}-{secrets.token_hex(6)}.json"
        prefix = remote_root_prefix(args)
        upload = prefix + "sh -c " + shlex.quote(f"umask 077; cat > {remote_bundle}")
        result = run_ssh(args, upload, data=json.dumps(bundle).encode())
        if result.returncode:
            raise SystemExit("could not stage private deployment data: " + result.stderr.decode(errors="replace"))
        remote = prefix + "bash -s -- " + shlex.quote(remote_bundle) + " " + shlex.quote(args.service_id)
        script_body = REMOTE_HY2_SCRIPT if args.protocol == "hysteria2" else REMOTE_SCRIPT
        try:
            result = run_ssh(args, remote, data=script_body.encode())
        finally:
            run_ssh(args, prefix + "rm -f " + shlex.quote(remote_bundle))
        if result.returncode:
            raise SystemExit(result.stderr.decode(errors="replace").strip())
        remote_out = result.stdout.decode().strip()
        if args.protocol == "hysteria2":
            meta = json.loads(remote_out.splitlines()[-1])
            state["fingerprint"] = meta["fingerprint"]
        write_state_atomic(local_path, args.state_dir, args.service_id, state)
        print(json.dumps({"status": "deployed", "protocol": args.protocol, "state_file": str(local_path), "remote": remote_out}, ensure_ascii=False))


def bandwidth_mbps(value: str) -> int:
    parsed = int(value)
    if not 0 <= parsed <= 10000:
        raise argparse.ArgumentTypeError("bandwidth hint in Mbps must be between 0 and 10000")
    return parsed


def hop_port_range(value: str) -> tuple[int, int]:
    match = re.fullmatch(r"(\d+)-(\d+)", value.strip())
    if not match:
        raise argparse.ArgumentTypeError("hop port range must be START-END (for example 28500-28530)")
    start_p, end_p = int(match.group(1)), int(match.group(2))
    if not (1024 <= start_p < end_p <= 65535) or (end_p - start_p) > 1000:
        raise argparse.ArgumentTypeError("hop port range must satisfy 1024 <= START < END <= 65535 and span <= 1000 ports")
    return start_p, end_p


def hop_interval_seconds(value: str) -> int:
    parsed = int(value)
    if not 5 <= parsed <= 300:
        raise argparse.ArgumentTypeError("hop interval in seconds must be between 5 and 300")
    return parsed


def sni_hostname(value: str) -> str:
    try:
        host = normalize_public_host(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid SNI hostname: {error}") from error
    if ":" in host or all(part.isdigit() for part in host.split(".")):
        raise argparse.ArgumentTypeError("SNI must be a DNS hostname, not an IP literal")
    return host


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("plan", "inspect", "deploy"))
    p.add_argument("--target", type=ssh_target, required=True, help="OpenSSH target or Host alias")
    p.add_argument("--server", required=True, help="public IP or hostname clients will use")
    p.add_argument("--service-id", type=service_id, required=True)
    p.add_argument("--protocol", choices=PROTOCOLS, default="ss", help="ss (TCP+UDP, widest compatibility) or hysteria2 (QUIC/UDP for high-loss links, Mihomo)")
    p.add_argument("--listen-port", type=port, default=None, help="defaults to 28447 for ss, 28448 for hysteria2")
    p.add_argument("--method", choices=METHODS, default="aes-128-gcm")
    p.add_argument("--sni", type=sni_hostname, default="www.bing.com", help="TLS SNI/masquerade domain for hysteria2")
    p.add_argument("--outbound-mode", choices=OUTBOUND_MODES, default="auto-detect", help="direct outbound IP mode for hysteria2 (auto-detect sets 4 on IPv4-only hosts)")
    p.add_argument("--hop-ports", type=hop_port_range, default=None, help="optional UDP port-hopping range START-END (for example 28500-28530) for hysteria2")
    p.add_argument("--hop-interval", type=hop_interval_seconds, default=25, help="client UDP port-hopping interval in seconds when --hop-ports is set")
    p.add_argument("--up-mbps", type=bandwidth_mbps, default=15, help="client upload hint in Mbps for hysteria2 Brutal (0 for QUIC BBR)")
    p.add_argument("--down-mbps", type=bandwidth_mbps, default=50, help="client download hint in Mbps for hysteria2 Brutal (0 for QUIC BBR)")
    p.add_argument("--port", type=ssh_port, help="SSH port")
    p.add_argument("--identity", type=Path, help="SSH private key path")
    p.add_argument("--control-path", type=Path, help="existing OpenSSH control socket")
    p.add_argument("--order", type=Path, help="local ready receipt; required by deploy")
    p.add_argument("--remote-root", action="store_true", help="SSH account is root; do not use sudo")
    p.add_argument("--state-dir", type=Path, default=Path.home() / ".local/state/personal-vpn-setup")
    p.add_argument("--timeout", type=int, default=90)
    return p


if __name__ == "__main__":
    ns = parser().parse_args()
    if ns.protocol != "hysteria2" and (ns.hop_ports is not None or ns.outbound_mode != "auto-detect"):
        raise SystemExit("--hop-ports and --outbound-mode are only supported with --protocol hysteria2")
    if ns.listen_port is None:
        ns.listen_port = 28448 if ns.protocol == "hysteria2" else 28447
    {"plan": plan, "inspect": inspect, "deploy": deploy}[ns.action](ns)
