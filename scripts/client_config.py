#!/usr/bin/env python3
"""Render private Clash-compatible client profiles from a secret state file."""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


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


def classic_domestic_rules(source: Path | None) -> list[str]:
    if not source:
        return [f"DOMAIN-SUFFIX,{d},DIRECT" for d in
                ("baidu.com", "qq.com", "taobao.com", "tmall.com", "alipay.com", "jd.com", "bilibili.com")]
    if yaml is None:
        raise SystemExit("PyYAML is needed to read the existing rules")
    rules = yaml.safe_load(source.read_bytes()).get("rules", [])
    parsed = [r.split(",") for r in rules if isinstance(r, str)]
    domestic = {r[2] for r in parsed if len(r) >= 3 and r[:2] == ["GEOIP", "CN"]}
    if len(domestic) != 1:
        raise SystemExit("expected an unambiguous GEOIP,CN policy in the reference profile")
    # Only named domestic groups identify a curated list. DIRECT may also cover
    # unrelated service exceptions (or work hosts) in a personal profile.
    if domestic == {"DIRECT"}:
        raise SystemExit("reference uses general DIRECT; omit --classic-rules-from or use a named domestic group")
    return list(dict.fromkeys(
        f"{r[0]},{r[1]},DIRECT" for r in parsed if len(r) == 3
        and r[0] in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6")
        and r[2] in domestic
    ))


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


def mainland_split(profile: dict, outbound: str, classic: bool = False, rules_from: Path | None = None) -> dict:
    """Apply mainland routing to a dedicated all-traffic Mihomo phone profile."""
    if profile.get("rules") != [f"MATCH,{outbound}"] or not profile.get("tun", {}).get("enable"):
        raise SystemExit("expected a full-tunnel phone profile with a single MATCH to the selected outbound")
    if profile.get("rule-providers") or any(profile.get(k) for k in ("sub-rules", "listeners")):
        raise SystemExit("this profile has custom routing; merge its rules explicitly")
    local_domains = ("localhost", "local", "lan", "home.arpa")
    local_v4 = ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                "169.254.0.0/16", "100.64.0.0/10", "224.0.0.0/4", "255.255.255.255/32")
    local_v6 = ("::1/128", "fc00::/7", "fe80::/10", "ff00::/8")
    profile["mode"] = "rule"
    profile["rules"] = [
        *(f"DOMAIN-SUFFIX,{suffix},DIRECT" for suffix in local_domains),
        *(f"IP-CIDR,{cidr},DIRECT,no-resolve" for cidr in local_v4),
        *(f"IP-CIDR6,{cidr},DIRECT,no-resolve" for cidr in local_v6),
        "DOMAIN-SUFFIX,cn,DIRECT",
    ]
    dns = profile.get("dns")
    if not isinstance(dns, dict):
        raise SystemExit("phone profile must contain a dns mapping; generate a new profile or add DNS settings")
    if classic:
        classic_relay_chains(profile)
        domestic = classic_domestic_rules(rules_from)
        profile["rules"] = list(dict.fromkeys(profile["rules"] + domestic))
        profile["rules"].extend(["GEOIP,CN,DIRECT", f"MATCH,{outbound}"])
        local_doh = "https://223.5.5.5/dns-query"
        dns["nameserver"] = [local_doh, "https://223.6.6.6/dns-query"]
        dns["fallback"] = ["https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query"]
        dns["fallback-filter"] = {"geoip": True, "geoip-code": "CN"}
        dns["nameserver-policy"] = {"+.cn": local_doh}
        for rule in domestic:
            typ, domain, _ = rule.split(",")
            if typ not in ("DOMAIN", "DOMAIN-SUFFIX"):
                continue
            dns["nameserver-policy"][("+." if typ == "DOMAIN-SUFFIX" else "") + domain] = local_doh
        return profile
    base_url = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo"
    profile["rule-providers"] = {
        key: {
            "type": "http", "behavior": behavior, "format": "mrs", "interval": 86400,
            "proxy": outbound, "url": f"{base_url}/{category}/cn.mrs",
            "path": f"./ruleset/personal-vpn/{key}.mrs",
        }
        for key, behavior, category in (("cn-domains", "domain", "geosite"), ("cn-ip", "ipcidr", "geoip"))
    }
    profile["rules"].extend(["RULE-SET,cn-domains,DIRECT", "RULE-SET,cn-ip,DIRECT", f"MATCH,{outbound}"])
    domestic_dns = ["https://223.5.5.5/dns-query#DIRECT", "https://223.6.6.6/dns-query#DIRECT"]
    dns["proxy-server-nameserver"] = domestic_dns.copy()
    dns["nameserver-policy"] = {
        **{f"+.{d}": "system" for d in local_domains},
        "+.cn": domestic_dns[0], "rule-set:cn-domains": domestic_dns[0],
    }
    dns["nameserver"] = [f"https://1.1.1.1/dns-query#{outbound}", f"https://9.9.9.9/dns-query#{outbound}"]
    return profile


X_DOMAINS = ("twimg.com", "x.com", "twitter.com", "t.co")


def apply_domain_priority(profile: dict, outbound: str, domains: tuple[str, ...]) -> dict:
    """Place explicitly requested service suffixes ahead of DNS-dependent rules."""
    selected = dict.fromkeys(domains)

    def is_selected_suffix(rule: str) -> bool:
        parts = rule.split(",", 2)
        return (len(parts) == 3 and parts[0].strip().upper() == "DOMAIN-SUFFIX"
                and parts[1].strip().lower().rstrip(".") in selected)

    priority = [f"DOMAIN-SUFFIX,{domain},{outbound}" for domain in selected]
    profile["rules"] = priority + [rule for rule in profile["rules"] if not is_selected_suffix(rule)]
    return profile


def apply_x_priority(profile: dict, outbound: str) -> dict:
    return apply_domain_priority(profile, outbound, X_DOMAINS)


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
    p.add_argument("--base", type=Path, help="existing desktop YAML or full-tunnel phone YAML for mobile-cn-split")
    p.add_argument("--base-default", help="actual selected proxy/group when base mode is global")
    p.add_argument("--domain", action="append", default=[], help="an explicitly requested service domain suffix; repeat for dedicated asset domains")
    p.add_argument("--use-x", action="store_true", help="prioritize X/Twitter and its media for this device")
    p.add_argument("--classic-android", action="store_true", help="inline domain rules and GEOIP for classic Clash for Android")
    p.add_argument("--classic-rules-from", type=Path, help="optional known-working profile with a named Chinese domestic group")
    args = p.parse_args()
    if os.name == "nt":
        p.error("Generate private profiles in WSL. Keep the order, keys and YML inside the Linux filesystem.")
    if (args.classic_android and args.mode != "mobile-cn-split") or (args.classic_rules_from and not args.classic_android):
        p.error("--classic-rules-from requires --classic-android with --mode mobile-cn-split")
    if any(path and args.output.resolve() == path.resolve() for path in (args.state, args.base, args.classic_rules_from)):
        p.error("output must differ from the private state and existing base profile")
    if args.mode == "existing-rules":
        if not (args.use_x or args.domain) or not args.base or args.state or args.base_default:
            p.error("existing-rules needs --use-x or --domain, --base, and an existing --name")
        if yaml is None:
            p.error("reading an existing YAML profile requires PyYAML")
        profile = yaml.safe_load(args.base.read_bytes())
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
        profile = mainland_split(profile, args.name, args.classic_android, args.classic_rules_from)
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
                profile = mainland_split(profile, args.name, args.classic_android, args.classic_rules_from)
    if args.domain and args.mode != "desktop-domains":
        apply_domain_priority(profile, args.name, tuple(args.domain))
    if args.use_x:
        apply_x_priority(profile, args.name)
    if yaml is None:
        content = json.dumps(profile, ensure_ascii=False, indent=2) + "\n"
    else:
        content = yaml.safe_dump(profile, allow_unicode=True, sort_keys=False)
    private_write(args.output, content)
    print(json.dumps({"status": "rendered", "output": str(args.output), "mode": args.mode}, ensure_ascii=False))


if __name__ == "__main__":
    main()
