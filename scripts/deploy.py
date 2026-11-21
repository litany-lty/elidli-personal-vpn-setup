#!/usr/bin/env python3
"""Inspect or deploy one private Shadowsocks service over trusted OpenSSH."""

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


METHODS = ("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305")
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
    config = f"/etc/shadowsocks-libev/{service}.json"
    unit = f"/etc/systemd/system/{service}.service"
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


def load_or_create_state(args: argparse.Namespace) -> dict[str, object]:
    path = state_file(args)
    args.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(args.state_dir, 0o700)
    if path.exists():
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode != 0o600:
            raise SystemExit(f"refusing state file with mode {mode:o}; require 600")
        state = json.loads(path.read_text())
        for key, expected in (("service_id", args.service_id), ("server", args.server), ("port", args.listen_port), ("method", args.method)):
            if state.get(key) != expected:
                raise SystemExit(f"existing state differs at {key}; choose a new service id or use explicit rotation workflow")
        return state
    state = {
        "version": 1, "service_id": args.service_id, "server": args.server,
        "port": args.listen_port, "method": args.method,
        "password": secrets.token_urlsafe(32),
    }
    temporary = tempfile.NamedTemporaryFile(
        "w", dir=args.state_dir, prefix=f".{args.service_id}.", delete=False
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
    return state


def inspect(args: argparse.Namespace) -> None:
    ensure_ssh(args)
    prefix = remote_root_prefix(args)
    command = prefix + "sh -c " + shlex.quote(
        "set -eu; . /etc/os-release; "
        "printf '{\"id\":\"%s\",\"version\":\"%s\",' \"$ID\" \"$VERSION_ID\"; "
        "printf '\"ss_server\":\"%s\",\"service\":\"%s\"}\\n' "
        "\"$(command -v ss-server || true)\" \"$(systemctl is-active personal-vpn-" + args.service_id + " 2>/dev/null || true)\""
    )
    result = run_ssh(args, command)
    if result.returncode:
        raise SystemExit(result.stderr.decode(errors="replace"))
    print(result.stdout.decode().strip())


def plan(args: argparse.Namespace) -> None:
    summary = {
        "target": args.target, "service": f"personal-vpn-{args.service_id}",
        "server": args.server, "port": args.listen_port, "method": args.method,
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
        state = load_or_create_state(args)
        if remote_state == "present":
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
        try:
            result = run_ssh(args, remote, data=REMOTE_SCRIPT.encode())
        finally:
            run_ssh(args, prefix + "rm -f " + shlex.quote(remote_bundle))
        if result.returncode:
            raise SystemExit(result.stderr.decode(errors="replace").strip())
        print(json.dumps({"status": "deployed", "state_file": str(state_file(args)), "remote": result.stdout.decode().strip()}, ensure_ascii=False))


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("plan", "inspect", "deploy"))
    p.add_argument("--target", type=ssh_target, required=True, help="OpenSSH target or Host alias")
    p.add_argument("--server", required=True, help="public IP or hostname clients will use")
    p.add_argument("--service-id", type=service_id, required=True)
    p.add_argument("--listen-port", type=port, default=28447)
    p.add_argument("--method", choices=METHODS, default="aes-128-gcm")
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
    {"plan": plan, "inspect": inspect, "deploy": deploy}[ns.action](ns)
