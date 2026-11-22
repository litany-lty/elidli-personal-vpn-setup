#!/usr/bin/env python3
"""Render private Clash-compatible client profiles from a secret state file."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import stat
import tempfile
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


LOCAL_DOMAINS = ("localhost", "local", "lan", "home.arpa")
LOCAL_V4 = ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "169.254.0.0/16", "100.64.0.0/10", "224.0.0.0/4", "255.255.255.255/32")
LOCAL_V6 = ("::1/128", "fc00::/7", "fe80::/10", "ff00::/8")
DOMESTIC_DNS_SUFFIXES = (
    "cn", "baidu.com", "bdstatic.com", "qq.com", "weixin.com", "taobao.com", "tmall.com",
    "alipay.com", "jd.com", "360buyimg.com", "bilibili.com", "bilivideo.com", "hdslb.com",
    "163.com", "126.com", "meituan.com", "dianping.com", "douyin.com", "toutiao.com",
    "zhihu.com", "zhimg.com", "weibo.com", "amap.com", "autonavi.com", "ctrip.com",
)
CLASSIC_DOMESTIC_DOH = ("https://223.5.5.5/dns-query", "https://223.6.6.6/dns-query")
MIHOMO_DOMESTIC_DOH = tuple(f"{server}#DIRECT" for server in CLASSIC_DOMESTIC_DOH)
FOREIGN_DNS_TARGETS = ("1.1.1.1:53", "9.9.9.9:53")


def private_state(path: Path) -> dict:
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise SystemExit("state file must have mode 600")
    return json.loads(path.read_bytes())


def private_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False)
    try:
        temporary.write(content)
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


def proxy_node(state: dict, name: str) -> dict:
    kind = state.get("kind", "ss")
    common = {"name": name, "server": state["server"], "port": state["port"]}
    if kind == "ss":
        return common | {"type": "ss", "cipher": state["method"], "password": state["password"], "udp": True}
    if kind not in ("socks5", "http"):
        raise SystemExit("private proxy spec kind must be ss, socks5, or http")
    for key in ("username", "password"):
        if key not in state:
            raise SystemExit(f"private proxy spec is missing {key}")
    return common | {"type": kind, "username": state["username"], "password": state["password"],
                     "udp": bool(state.get("udp", False)) if kind == "socks5" else False}


def global_profile(state: dict, name: str) -> dict:
    node_name = name + "·节点"
    node = proxy_node(state, node_name)
    if not node.get("udp"):
        raise SystemExit("mobile-global requires an outbound with confirmed UDP support")
    return {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule", "log-level": "info", "ipv6": False,
        "tun": {"enable": True, "stack": "mixed", "auto-route": True, "strict-route": True,
                "auto-detect-interface": True, "dns-hijack": ["any:53", "tcp://any:53"]},
        "dns": {"enable": True, "listen": "127.0.0.1:1053", "ipv6": False,
                "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16", "use-system-hosts": False,
                "nameserver": [f"https://1.1.1.1/dns-query#{name}", f"https://9.9.9.9/dns-query#{name}"]},
        "proxies": [node],
        "proxy-groups": [{"name": name, "type": "select", "proxies": [node_name]}],
        "rules": [f"MATCH,{name}"],
    }


def direct_ss_state_from_profile(profile: dict, node_name: str) -> dict:
    """Extract one self-contained Shadowsocks node from parsed profile data."""
    if not isinstance(profile, dict) or not isinstance(profile.get("proxies"), list):
        raise SystemExit("the base profile must contain a proxies list")
    matches = [node for node in profile["proxies"]
               if isinstance(node, dict) and node.get("name") == node_name]
    if len(matches) != 1:
        raise SystemExit("--only-node must identify exactly one proxy node in the base profile")
    if any(isinstance(group, dict) and group.get("name") == node_name
           for group in profile.get("proxy-groups", [])):
        raise SystemExit("--only-node is ambiguous because a proxy group has the same name")
    node = matches[0]
    if node.get("type") != "ss":
        raise SystemExit("--only-node currently supports a direct Shadowsocks node")
    supported = {"name", "type", "server", "port", "cipher", "password", "udp"}
    unsupported = set(node) - supported
    if unsupported:
        raise SystemExit("the selected node has unsupported dependencies or transport fields: "
                         + ", ".join(sorted(unsupported)))
    if (not isinstance(node.get("server"), str) or not node["server"].strip()
            or type(node.get("port")) is not int or not 1 <= node["port"] <= 65535
            or any(not isinstance(node.get(key), str) or not node[key] for key in ("cipher", "password"))):
        raise SystemExit("the selected Shadowsocks node has incomplete server, port, cipher or password fields")
    if node.get("udp") is not True:
        raise SystemExit("the selected node must explicitly support UDP for a full-device phone profile")
    return {
        "kind": "ss", "server": node["server"], "port": node["port"],
        "method": node["cipher"], "password": node["password"],
    }


def read_reference_profile(source: Path) -> dict:
    data = source.read_bytes()
    if yaml is None:
        try:
            profile = json.loads(data)
        except (ValueError, UnicodeError):
            raise SystemExit("reading a YAML profile requires PyYAML, or supply JSON-format profile data") from None
    else:
        try:
            profile = yaml.safe_load(data)
        except yaml.YAMLError:
            raise SystemExit("the reference profile is not valid YAML") from None
    if not isinstance(profile, dict):
        raise SystemExit("the reference profile must be a mapping")
    return profile


def valid_dns_suffix(value: str) -> str | None:
    suffix = value.strip().lower().rstrip(".")
    if not suffix or suffix.startswith(("+.", ".")) or len(suffix) > 253:
        return None
    try:
        ascii_suffix = suffix.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = ascii_suffix.split(".")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
           or not all(character.isalnum() or character == "-" for character in label)
           for label in labels):
        return None
    return ascii_suffix


def classic_domestic_dns_hints(source: Path | None) -> list[tuple[str, str]]:
    hints = [("DOMAIN-SUFFIX", suffix) for suffix in DOMESTIC_DNS_SUFFIXES]
    if not source:
        return hints
    rules = read_reference_profile(source).get("rules", [])
    parsed = [[part.strip() for part in rule.split(",")]
              for rule in rules if isinstance(rule, str)]
    domestic = {rule[2] for rule in parsed if len(rule) == 3
                and rule[0].upper() == "GEOIP" and rule[1].upper() == "CN"}
    if len(domestic) != 1:
        raise SystemExit("expected an unambiguous GEOIP,CN policy in the reference profile")
    if domestic == {"DIRECT"}:
        raise SystemExit("reference uses general DIRECT; omit --classic-rules-from or use a named domestic group")
    for rule in parsed:
        kind = rule[0].upper() if rule else ""
        suffix = valid_dns_suffix(rule[1]) if len(rule) == 3 else None
        if kind in ("DOMAIN", "DOMAIN-SUFFIX") and suffix and rule[2] in domestic:
            hints.append((kind, suffix))
    return list(dict.fromkeys(hints))


def read_cn_cidrs(source: Path) -> list[str]:
    payload = []
    for number, raw in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        if "/" not in value:
            raise SystemExit(f"--cn-cidrs line {number} is not a CIDR prefix")
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError:
            raise SystemExit(f"--cn-cidrs line {number} is not a canonical CIDR prefix") from None
        if network.prefixlen == 0:
            raise SystemExit(f"--cn-cidrs line {number} is a default route and would bypass the foreign outbound")
        payload.append(str(network))
    payload = list(dict.fromkeys(payload))
    if not payload:
        raise SystemExit("--cn-cidrs must contain at least one CIDR prefix")
    return payload


def classic_relay_chains(profile: dict) -> None:
    """Convert Mihomo dialer-proxy SS nodes to fail-closed Clash relay groups."""
    proxies = profile.get("proxies")
    groups = profile.get("proxy-groups")
    if not isinstance(proxies, list) or not isinstance(groups, list):
        raise SystemExit("classic phone profile requires proxies and proxy-groups lists")
    proxy_by_name = {node.get("name"): node for node in proxies if isinstance(node, dict)}
    all_names = set(proxy_by_name)
    all_names.update(group.get("name") for group in groups if isinstance(group, dict))
    replacements = []
    for node in list(proxies):
        front = node.get("dialer-proxy") if isinstance(node, dict) else None
        if not front:
            continue
        if node.get("type") != "ss":
            raise SystemExit("classic Clash can only convert dialer-proxy Shadowsocks nodes to relay")
        if front not in all_names:
            raise SystemExit(f"classic relay front {front!r} does not exist")
        name = node.get("name")
        if not name or any(group.get("name") == name for group in groups):
            raise SystemExit("dialer-proxy node name is missing or conflicts with an existing group")
        comparable = {key: value for key, value in node.items() if key not in ("name", "dialer-proxy")}
        exit_name = next((
            candidate.get("name") for candidate in proxies
            if candidate is not node
            and {key: value for key, value in candidate.items() if key != "name"} == comparable
        ), None)
        if not exit_name:
            suffix = 1
            exit_name = f"{name}·出口"
            while exit_name in all_names:
                suffix += 1
                exit_name = f"{name}·出口{suffix}"
            proxies.append({"name": exit_name, **comparable})
            all_names.add(exit_name)
        replacements.append((node, {
            "name": name, "type": "relay", "proxies": [front, exit_name],
            # Dreamacro Clash relay transports TCP streams only. Mark it
            # explicitly so UDP cannot bypass the front through another path.
            "disable-udp": True,
        }))
    for node, relay in replacements:
        proxies.remove(node)
        groups.append(relay)
    if replacements:
        experimental = profile.setdefault("experimental", {})
        if not isinstance(experimental, dict):
            raise SystemExit("classic phone profile experimental setting must be a mapping")
        # Clash's UDP fallback can unwrap an unsupported relay and ultimately
        # send the packet DIRECT. Keep chained selections fail-closed instead.
        experimental["udp-fallback-match"] = False


def classic_outbound_server_hosts(profile: dict, outbound: str) -> list[str]:
    proxies = {item.get("name"): item for item in profile.get("proxies", []) if isinstance(item, dict)}
    groups = {item.get("name"): item for item in profile.get("proxy-groups", []) if isinstance(item, dict)}
    pending = [outbound]
    visited = set()
    hostnames = []
    while pending:
        name = pending.pop()
        if name in visited or name in ("DIRECT", "REJECT"):
            continue
        visited.add(name)
        if name in groups:
            group = groups[name]
            if group.get("use"):
                raise SystemExit(
                    "classic outbound groups using dynamic proxy providers cannot be safely bootstrapped; "
                    "select one owned literal node with --only-node or replace provider use with explicit proxies"
                )
            members = group.get("proxies")
            if not isinstance(members, list) or not members or not all(isinstance(item, str) for item in members):
                raise SystemExit("classic outbound groups must contain explicit proxy names")
            pending.extend(members)
            continue
        node = proxies.get(name)
        if not node:
            raise SystemExit(f"classic outbound dependency {name!r} does not exist")
        server = node.get("server")
        try:
            ipaddress.ip_address(server)
        except (TypeError, ValueError):
            hostname = valid_dns_suffix(server) if isinstance(server, str) else None
            if not hostname or "." not in hostname:
                raise SystemExit("classic outbound proxy servers must be an IP address or valid hostname")
            hostnames.append(hostname)
    return list(dict.fromkeys(hostnames))


def classic_dns_tunnel_ports(profile: dict) -> tuple[int, int]:
    occupied = set()
    for key in ("port", "socks-port", "redir-port", "tproxy-port", "mixed-port"):
        if type(profile.get(key)) is int:
            occupied.add(profile[key])
    dns_listen = profile.get("dns", {}).get("listen") if isinstance(profile.get("dns"), dict) else None
    local_addresses = [dns_listen, profile.get("external-controller")]
    for tunnel in profile.get("tunnels", []):
        if isinstance(tunnel, dict):
            local_addresses.append(tunnel.get("address"))
        elif isinstance(tunnel, str):
            parts = [part.strip() for part in tunnel.split(",")]
            if len(parts) >= 2:
                local_addresses.append(parts[1])
    for address in local_addresses:
        if not isinstance(address, str):
            continue
        try:
            occupied.add(int(address.rsplit(":", 1)[1]))
        except (IndexError, ValueError):
            pass
    selected = []
    candidate = 16553
    while len(selected) < 2:
        if candidate not in occupied:
            selected.append(candidate)
        candidate += 1
    return selected[0], selected[1]


def fresh_dns(profile: dict) -> dict:
    current = profile.get("dns")
    if not isinstance(current, dict):
        raise SystemExit("phone profile must contain a dns mapping; generate a new profile or add DNS settings")
    ipv6 = current.get("ipv6", False)
    if not isinstance(ipv6, bool):
        raise SystemExit("phone profile dns.ipv6 must be true or false")
    rebuilt = {
        "enable": True,
        "listen": current.get("listen", "127.0.0.1:1053"),
        "ipv6": ipv6,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": current.get("fake-ip-range", "198.18.0.1/16"),
        "use-system-hosts": False,
        "use-hosts": bool(profile.get("hosts")),
    }
    if ipv6 and isinstance(current.get("fake-ip-range6"), str):
        rebuilt["fake-ip-range6"] = current["fake-ip-range6"]
    return rebuilt


def mainland_split(profile: dict, outbound: str, classic: bool = False,
                   rules_from: Path | None = None, cn_cidrs: Path | None = None) -> dict:
    """Apply mainland routing to a dedicated all-traffic Mihomo phone profile."""
    if profile.get("rules") != [f"MATCH,{outbound}"] or not profile.get("tun", {}).get("enable"):
        raise SystemExit("expected a full-tunnel phone profile with a single MATCH to the selected outbound")
    if profile.get("rule-providers") or any(profile.get(k) for k in ("sub-rules", "listeners")):
        raise SystemExit("this profile has custom routing; merge its rules explicitly")
    profile["mode"] = "rule"
    profile["rules"] = [
        *(f"DOMAIN-SUFFIX,{suffix},DIRECT" for suffix in LOCAL_DOMAINS),
        *(f"IP-CIDR,{cidr},DIRECT,no-resolve" for cidr in LOCAL_V4),
        *(f"IP-CIDR6,{cidr},DIRECT,no-resolve" for cidr in LOCAL_V6),
    ]
    dns = fresh_dns(profile)
    profile["dns"] = dns
    if classic:
        if cn_cidrs:
            raise SystemExit("--cn-cidrs is only supported by the Mihomo mobile-cn-split profile")
        classic_relay_chains(profile)
        bootstrap_hosts = classic_outbound_server_hosts(profile, outbound)
        profile["rules"].extend(["GEOIP,CN,DIRECT", f"MATCH,{outbound}"])
        ports = classic_dns_tunnel_ports(profile)
        existing_tunnels = profile.get("tunnels", [])
        if not isinstance(existing_tunnels, list):
            raise SystemExit("classic tunnels setting must be a list")
        profile["tunnels"] = list(existing_tunnels) + [
            {"network": ["tcp"], "address": f"127.0.0.1:{port}",
             "target": target, "proxy": outbound}
            for port, target in zip(ports, FOREIGN_DNS_TARGETS)
        ]
        cfa = profile.setdefault("clash-for-android", {})
        if not isinstance(cfa, dict):
            raise SystemExit("clash-for-android setting must be a mapping")
        cfa["append-system-dns"] = False
        dns["nameserver"] = [f"tcp://127.0.0.1:{port}" for port in ports]
        hints = [hint for hint in classic_domestic_dns_hints(rules_from)
                 if hint[1] not in X_DOMAINS]
        dns["nameserver-policy"] = {
            ("+." if kind == "DOMAIN-SUFFIX" else "") + suffix:
                CLASSIC_DOMESTIC_DOH[index % len(CLASSIC_DOMESTIC_DOH)]
            for index, (kind, suffix) in enumerate(hints)
        }
        for index, hostname in enumerate(bootstrap_hosts):
            dns["nameserver-policy"][hostname] = CLASSIC_DOMESTIC_DOH[index % len(CLASSIC_DOMESTIC_DOH)]
        return profile
    base_url = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo"
    if cn_cidrs:
        cn_provider = {"type": "inline", "behavior": "ipcidr", "payload": read_cn_cidrs(cn_cidrs)}
    else:
        cn_provider = {
            "type": "http", "behavior": "ipcidr", "format": "mrs", "interval": 86400,
            "proxy": outbound, "url": f"{base_url}/geoip/cn.mrs",
            "path": "./ruleset/personal-vpn/cn-ip.mrs",
        }
    profile["rule-providers"] = {"cn-ip": cn_provider}
    profile["rules"].extend(["RULE-SET,cn-ip,DIRECT", f"MATCH,{outbound}"])
    dns["proxy-server-nameserver"] = list(MIHOMO_DOMESTIC_DOH)
    dns["nameserver-policy"] = {
        f"+.{suffix}": MIHOMO_DOMESTIC_DOH[index % len(MIHOMO_DOMESTIC_DOH)]
        for index, suffix in enumerate(DOMESTIC_DNS_SUFFIXES)
    }
    dns["nameserver"] = [f"https://1.1.1.1/dns-query#{outbound}", f"https://9.9.9.9/dns-query#{outbound}"]
    return profile


X_DOMAINS = ("twimg.com", "x.com", "twitter.com", "t.co")


def apply_domain_priority(profile: dict, outbound: str, domains: tuple[str, ...],
                          prioritize_dns: bool = False) -> dict:
    """Place explicitly requested service suffixes ahead of DNS-dependent rules."""
    if prioritize_dns:
        normalized = []
        for domain in domains:
            suffix = valid_dns_suffix(domain)
            if suffix is None:
                raise SystemExit("expected a domain suffix for the mobile service priority rule")
            normalized.append(suffix)
        domains = tuple(normalized)
    selected = dict.fromkeys(domains)

    def is_selected_suffix(rule: str) -> bool:
        parts = rule.split(",", 2)
        return (len(parts) == 3 and parts[0].strip().upper() == "DOMAIN-SUFFIX"
                and parts[1].strip().lower().rstrip(".") in selected)

    priority = [f"DOMAIN-SUFFIX,{domain},{outbound}" for domain in selected]
    profile["rules"] = priority + [rule for rule in profile["rules"] if not is_selected_suffix(rule)]
    dns = profile.get("dns")
    policy = dns.get("nameserver-policy") if isinstance(dns, dict) else None
    nameservers = dns.get("nameserver") if isinstance(dns, dict) else None
    if prioritize_dns and isinstance(policy, dict) and isinstance(nameservers, list) and nameservers:
        foreign_dns = nameservers[0]
        if not isinstance(foreign_dns, str):
            raise SystemExit("mobile-cn-split requires a string foreign DNS upstream")
        proxy_hosts = set()
        for node in profile.get("proxies", []):
            server = node.get("server") if isinstance(node, dict) else None
            host = valid_dns_suffix(server) if isinstance(server, str) else None
            if host:
                proxy_hosts.add(host)
        for matcher in list(policy):
            policy_domain = matcher.removeprefix("+.").lower().rstrip(".")
            if not matcher.startswith("+.") and policy_domain in proxy_hosts:
                continue
            if any(domain == policy_domain or policy_domain.endswith("." + domain)
                   for domain in selected):
                del policy[matcher]
        # A specific policy is needed only below a broader domestic suffix.
        # Other services inherit the full pair of default foreign resolvers.
        parent_suffixes = tuple(key[2:] for key in policy if key.startswith("+."))
        for domain in selected:
            if any(domain.endswith("." + parent) for parent in parent_suffixes):
                # In classic Clash "+.name" also writes the exact trie entry.
                # Preserve an endpoint's exact bootstrap while routing its children.
                matcher = ("." if domain in proxy_hosts else "+.") + domain
                policy[matcher] = list(nameservers) if profile.get("rule-providers") else foreign_dns
    return profile


def apply_x_priority(profile: dict, outbound: str, prioritize_dns: bool = False) -> dict:
    return apply_domain_priority(profile, outbound, X_DOMAINS, prioritize_dns)


def desktop_profile(state: dict, name: str, domains: list[str], base: Path | None,
                    base_default: str | None) -> dict:
    if base and yaml is None:
        raise SystemExit("PyYAML is required when an existing desktop profile is supplied")
    data = (yaml.safe_load(base.read_bytes()) or {}) if base else {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule", "log-level": "info",
        "proxies": [], "proxy-groups": [], "rules": ["MATCH,DIRECT"],
    }
    prior_mode = str(data.get("mode", "rule")).lower()
    if prior_mode == "global" and not base_default:
        raise SystemExit("a base in global mode requires --base-default with its actually selected proxy/group")
    data["mode"] = "rule"
    proxies = data.setdefault("proxies", [])
    groups = data.setdefault("proxy-groups", [])
    rules = data.setdefault("rules", [])
    node_name = name + "·节点"
    if any(x.get("name") in (name, node_name) for x in proxies + groups):
        raise SystemExit("base profile already uses generated names")
    proxies.append(proxy_node(state, node_name))
    groups.append({"name": name, "type": "select", "proxies": [node_name]})
    new_rules = [f"DOMAIN-SUFFIX,{domain},{name}" for domain in domains]
    if prior_mode in ("direct", "global"):
        default = "DIRECT" if prior_mode == "direct" else base_default
        available = {x.get("name") for x in proxies + groups} | {"DIRECT", "REJECT"}
        if default not in available:
            raise SystemExit("--base-default is not a proxy/group in the supplied profile")
        data["rules"] = new_rules + [f"MATCH,{default}"]
    else:
        direct_prefix = [r for r in rules if r.startswith(("IP-CIDR,127.", "IP-CIDR6,::1"))]
        remainder = [r for r in rules if r not in direct_prefix]
        data["rules"] = direct_prefix + new_rules + remainder
    return data


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state", type=Path,
                   help="mode-600 deployment state or private proxy spec JSON")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--mode", choices=("mobile-cn-split", "mobile-global", "desktop-domains", "existing-rules"), required=True)
    p.add_argument("--name", default="个人VPN·固定出口")
    p.add_argument("--base", type=Path, help="existing YAML used only by the selected mode")
    p.add_argument("--only-node", help="exact direct Shadowsocks node to extract from --base")
    p.add_argument("--base-default", help="actual selected proxy/group when base mode is global")
    p.add_argument("--domain", action="append", default=[], help="an explicitly requested service domain suffix; repeat for dedicated asset domains")
    p.add_argument("--use-x", action="store_true", help="prioritize X/Twitter and its media for this device")
    p.add_argument("--classic-android", action="store_true", help="use classic Clash DNS tunnels and mainland GeoIP routing")
    p.add_argument("--classic-rules-from", type=Path, help="read domestic DNS hints from a named mainland group in a trusted local profile")
    p.add_argument("--cn-cidrs", type=Path,
                   help="trusted local CIDR text file for an offline Mihomo cn-ip provider")
    args = p.parse_args()
    if os.name == "nt":
        p.error("Generate private profiles in WSL. Keep the order, keys and YML inside the Linux filesystem.")
    if (args.classic_android and args.mode != "mobile-cn-split") or (args.classic_rules_from and not args.classic_android):
        p.error("--classic-rules-from requires --classic-android with --mode mobile-cn-split")
    if args.cn_cidrs and (args.mode != "mobile-cn-split" or args.classic_android):
        p.error("--cn-cidrs requires Mihomo --mode mobile-cn-split without --classic-android")
    if args.only_node is not None and (not args.only_node.strip() or args.mode not in ("mobile-cn-split", "mobile-global")
                           or not args.base or args.state or args.base_default):
        p.error("--only-node needs --base with mobile-cn-split or mobile-global, without --state")
    if any(path and args.output.resolve() == path.resolve()
           for path in (args.state, args.base, args.classic_rules_from, args.cn_cidrs)):
        p.error("output must differ from the private state and existing base profile")
    if args.only_node is not None:
        state = direct_ss_state_from_profile(read_reference_profile(args.base), args.only_node)
        profile = global_profile(state, args.name)
        if args.mode == "mobile-cn-split":
            profile = mainland_split(profile, args.name, args.classic_android,
                                     args.classic_rules_from, args.cn_cidrs)
    elif args.mode == "existing-rules":
        if not (args.use_x or args.domain) or not args.base or args.state or args.base_default:
            p.error("existing-rules needs --use-x or --domain, --base, and an existing --name")
        profile = read_reference_profile(args.base)
        if (not isinstance(profile, dict) or str(profile.get("mode", "rule")).lower() != "rule"
                or not isinstance(profile.get("rules"), list)
                or not all(isinstance(rule, str) for rule in profile["rules"])):
            p.error("the base must be a Rule-mode profile with a rules list")
        if args.name not in {group["name"] for group in profile.get("proxy-groups", [])}:
            p.error("--name must identify the existing outbound group for X")
    elif args.mode == "mobile-cn-split" and args.base:
        if yaml is None or args.state:
            p.error("phone profile migration needs PyYAML and --base alone")
        profile = yaml.safe_load(args.base.read_bytes())
        if args.name not in {item["name"] for item in profile.get("proxy-groups", [])}:
            p.error("--name must identify the original phone proxy group")
        profile = mainland_split(profile, args.name, args.classic_android,
                                 args.classic_rules_from, args.cn_cidrs)
    else:
        if not args.state:
            p.error("--state is required for a new profile")
        state = private_state(args.state)
        if args.mode == "desktop-domains":
            if not (args.domain or args.use_x):
                p.error("desktop-domains requires --use-x or at least one --domain")
            profile = desktop_profile(state, args.name, args.domain, args.base, args.base_default)
        else:
            if args.base:
                p.error("--base is supported for desktop-domains and mobile-cn-split")
            profile = global_profile(state, args.name)
            if args.mode == "mobile-cn-split":
                profile = mainland_split(profile, args.name, args.classic_android,
                                         args.classic_rules_from, args.cn_cidrs)
    if args.domain and args.mode != "desktop-domains":
        apply_domain_priority(profile, args.name, tuple(args.domain), args.mode == "mobile-cn-split")
    if args.use_x:
        apply_x_priority(profile, args.name, args.mode == "mobile-cn-split")
    if yaml is None:
        content = json.dumps(profile, ensure_ascii=False, indent=2) + "\n"
    else:
        content = yaml.safe_dump(profile, allow_unicode=True, sort_keys=False)
    private_write(args.output, content)
    print(json.dumps({"status": "rendered", "output": str(args.output), "mode": args.mode}, ensure_ascii=False))


if __name__ == "__main__":
    main()
