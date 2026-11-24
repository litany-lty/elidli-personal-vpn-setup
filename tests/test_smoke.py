#!/usr/bin/env python3
"""Offline smoke test for an unpacked elidli-personal-vpn-setup skill.

Run from any directory with Python 3.10+:
    python3 tests/test_smoke.py

The test uses synthetic credentials and a temporary directory. It does not
open the network, connect through SSH, or change system proxy/VPN settings.
"""

from __future__ import annotations

import csv
import copy
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
REFERENCES = ROOT / "references"
X_DOMAINS = ("twimg.com", "x.com", "twitter.com", "t.co")
TEST_STATE = {
    "kind": "ss",
    "server": "192.0.2.10",
    "port": 28447,
    "method": "aes-128-gcm",
    "password": "synthetic-smoke-test-only",
}
TEST_HY2_STATE = {
    "kind": "hysteria2",
    "server": "192.0.2.10",
    "port": 28448,
    "password": "synthetic-hy2-smoke-test-only",
    "sni": "www.bing.com",
    "fingerprint": "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
    "up": "30 mbps",
    "down": "150 mbps",
}


def run(script: str, *arguments: object) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUTF8"] = "1"
    return subprocess.run(
        [sys.executable, str(SCRIPTS / script), *(str(value) for value in arguments)],
        cwd=ROOT,
        env=environment,
        text=True,
        encoding="utf-8",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )


def expect_success(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        raise AssertionError(f"{label} failed ({result.returncode}): {result.stderr.strip()}")


def load_yaml_or_json(path: Path) -> dict:
    content = path.read_text(encoding="utf-8")
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as error:
            raise AssertionError(
                "client_config.py emitted YAML, but PyYAML is unavailable for smoke-test inspection"
            ) from error
        return yaml.safe_load(content)


def load_client_module(name: str = "elidli_client_config") -> object:
    module_spec = importlib.util.spec_from_file_location(name, SCRIPTS / "client_config.py")
    assert module_spec and module_spec.loader
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module


def check_x_priority_logic() -> None:
    """Exercise the cross-platform transformation without private files or network."""
    module = load_client_module()

    ordinary = {
        "rules": ["IP-CIDR,127.0.0.0/8,DIRECT,no-resolve", "MATCH,DIRECT"],
        "proxies": [],
        "proxy-groups": [],
    }
    unchanged = copy.deepcopy(ordinary)
    profile = copy.deepcopy(ordinary)
    profile["rules"].insert(1, "DOMAIN-SUFFIX,x.com,Old exit")

    returned = module.apply_x_priority(profile, "Japan exit")
    assert returned is profile
    expected = [f"DOMAIN-SUFFIX,{domain},Japan exit" for domain in X_DOMAINS]
    assert profile["rules"][:4] == expected
    assert profile["rules"][4:] == unchanged["rules"], "non-X routing was not preserved"

    assert module.apply_x_priority(profile, "Japan exit") is profile
    assert profile["rules"][:4] == expected
    assert all(profile["rules"].count(rule) == 1 for rule in expected), "X rules duplicated"


    sites = ("youtube.com", "googlevideo.com")
    other = copy.deepcopy(ordinary)
    module.apply_domain_priority(other, "Japan exit", sites)
    assert other["rules"] == [f"DOMAIN-SUFFIX,{site},Japan exit" for site in sites] + ordinary["rules"]


def check_single_exit_logic(directory: Path) -> None:
    """Prove a named direct node cannot carry unrelated providers into a new profile."""
    module = load_client_module("elidli_single_exit")

    own_name = "My dedicated Japan exit"
    third_party_marker = "THIRD-PARTY-SENTINEL"
    source_url = "https://subscription.invalid/PRIVATE-SOURCE-SENTINEL"
    source = {
        "proxies": [
            {"name": own_name, "type": "ss", "server": "192.0.2.10", "port": 28447,
             "cipher": "aes-128-gcm", "password": "OWN-SYNTHETIC-SECRET", "udp": True},
            {"name": "unrelated subscription node", "type": "ss", "server": "192.0.2.20",
             "port": 28448, "cipher": "aes-128-gcm", "password": third_party_marker,
             "udp": True},
            {"name": "front", "type": "ss", "server": "192.0.2.30", "port": 28449,
             "cipher": "aes-128-gcm", "password": "FRONT-SENTINEL", "udp": True},
            {"name": "chained", "type": "ss", "server": "192.0.2.10", "port": 28447,
             "cipher": "aes-128-gcm", "password": "OWN-SYNTHETIC-SECRET", "udp": True,
             "dialer-proxy": "front"},
        ],
        "proxy-groups": [
            {"name": "old selector", "type": "select", "proxies": [own_name, "chained"]},
            {"name": "old relay", "type": "relay", "proxies": ["front", own_name]},
        ],
        "proxy-providers": {"subscription": {"type": "http", "url": source_url}},
        "rules": ["DOMAIN-SUFFIX,example.cn,old selector", "MATCH,old selector"],
    }

    state = module.direct_ss_state_from_profile(source, own_name)
    assert state == {
        "kind": "ss", "server": "192.0.2.10", "port": 28447,
        "method": "aes-128-gcm", "password": "OWN-SYNTHETIC-SECRET",
    }
    for invalid in ("chained", "old relay", "missing"):
        try:
            module.direct_ss_state_from_profile(source, invalid)
        except SystemExit:
            pass
        else:
            raise AssertionError(f"unsafe --only-node selection accepted: {invalid}")

    global_only = module.global_profile(state, "Personal exit")
    assert global_only["rules"] == ["MATCH,Personal exit"]
    assert [node["name"] for node in global_only["proxies"]] == ["Personal exit·节点"]
    rebuilt = module.mainland_split(global_only, "Personal exit", classic=True)
    module.apply_x_priority(rebuilt, "Personal exit")
    encoded = json.dumps(rebuilt, ensure_ascii=False)
    assert [node["name"] for node in rebuilt["proxies"]] == ["Personal exit·节点"]
    assert rebuilt["proxy-groups"] == [
        {"name": "Personal exit", "type": "select", "proxies": ["Personal exit·节点"]}
    ]
    assert rebuilt["rules"][:4] == [
        f"DOMAIN-SUFFIX,{domain},Personal exit" for domain in X_DOMAINS
    ]
    assert rebuilt["rules"][-2:] == ["GEOIP,CN,DIRECT", "MATCH,Personal exit"]
    assert all(marker not in encoded for marker in (
        third_party_marker, "FRONT-SENTINEL", "chained", "old relay", source_url
    ))

    # The same public loader handles JSON-format profiles without optional dependencies.
    reference = directory / "synthetic-routing-reference.json"
    reference.write_text(json.dumps({
        "proxies": [{"name": "must-not-copy", "password": third_party_marker}],
        "proxy-providers": {"must-not-copy": {"url": source_url}},
        "rules": [
            "DOMAIN-SUFFIX,example.cn,Domestic",
            "IP-CIDR,203.0.113.0/24,Domestic",
            "GEOIP,CN,Domestic",
            "DOMAIN-SUFFIX,overseas.example,Foreign",
        ],
    }), encoding="utf-8")

    hints = module.classic_domestic_dns_hints(reference)
    assert ("DOMAIN-SUFFIX", "example.cn") in hints
    assert all(value != "203.0.113.0/24" for _, value in hints)

    if os.name != "nt":
        base = directory / "old-profile.json"
        base.write_text(json.dumps(source), encoding="utf-8")
        output = directory / "only-owned.yaml"
        command = ("client_config.py", "--mode", "mobile-cn-split", "--base", base,
                   "--name", "Personal exit", "--classic-android", "--use-x",
                   "--classic-rules-from", reference, "--output", output, "--only-node")
        expect_success(run(*command, own_name), "single-exit CLI")
        written = load_yaml_or_json(output)
        assert written["proxy-groups"] == rebuilt["proxy-groups"]
        assert written["proxies"] == rebuilt["proxies"]
        assert "+.example.cn" in written["dns"]["nameserver-policy"]
        assert "DOMAIN-SUFFIX,example.cn,DIRECT" not in written["rules"]
        assert "IP-CIDR,203.0.113.0/24,DIRECT" not in written["rules"]
        assert "proxy-providers" not in written and source_url not in str(written)
        assert run(*command, "").returncode != 0

        cidrs = directory / "cn-cidrs.txt"
        cidrs.write_text("# synthetic offline fixture\n1.0.1.0/24\n240e::/20\n", encoding="utf-8")
        mihomo_output = directory / "only-owned-mihomo.yaml"
        mihomo_command = (
            "client_config.py", "--mode", "mobile-cn-split", "--base", base,
            "--name", "Personal exit", "--use-x", "--cn-cidrs", cidrs,
            "--output", mihomo_output, "--only-node",
        )
        expect_success(run(*mihomo_command, own_name), "single-exit Mihomo CLI")
        mihomo_written = load_yaml_or_json(mihomo_output)
        assert mihomo_written["rules"][:4] == [
            f"DOMAIN-SUFFIX,{domain},Personal exit" for domain in X_DOMAINS
        ]
        assert mihomo_written["rule-providers"] == {
            "cn-ip": {
                "type": "inline", "behavior": "ipcidr",
                "payload": ["1.0.1.0/24", "240e::/20"],
            }
        }
        assert "proxy-providers" not in mihomo_written and source_url not in str(mihomo_written)


def check_catalog_and_cli() -> None:
    catalog = REFERENCES / "providers.csv"
    aliases = REFERENCES / "offer-id-aliases.json"
    with catalog.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows and all(row.get("报价记录ID") for row in rows), "catalog has no addressable offers"
    assert len({row["报价记录ID"] for row in rows}) == len(rows), "offer IDs are not unique"

    alias_map = json.loads(aliases.read_text(encoding="utf-8"))["legacy_to_current"]
    old_id, current_id = next(iter(alias_map.items()))
    assert current_id in {row["报价记录ID"] for row in rows}, "legacy alias targets a missing offer"
    resolved = run(
        "resolve_offer.py", old_id, "--catalog", catalog, "--aliases", aliases, "--json"
    )
    expect_success(resolved, "legacy offer resolution")
    resolution = json.loads(resolved.stdout)
    assert resolution["match_count"] == 1
    assert resolution["matches"][0]["报价记录ID"] == current_id

    countries = Counter(
        code.strip()
        for row in rows
        for code in row.get("覆盖国家/地区代码", "").split("|")
        if len(code.strip()) == 2
    )
    recommendation = None
    for country, _ in countries.most_common(5):
        candidate = run("recommend.py", "--country", country, "--limit", 1, "--json")
        if candidate.returncode == 0:
            recommendation = json.loads(candidate.stdout)
            break
    assert recommendation and recommendation["results"], "catalog returned no sample recommendation"
    assert recommendation["results"][0]["record_id"] in {row["报价记录ID"] for row in rows}


def check_order_state(directory: Path) -> None:
    state = directory / "existing-order.json"
    created = run("order.py", "--state", state, "existing", "--host", "vpn.example.org", "--owned")
    expect_success(created, "synthetic owned-host state")
    status = run("order.py", "--state", state, "status")
    expect_success(status, "ready-state reload")
    data = json.loads(status.stdout)
    assert data["stage"] == "ready"
    assert data["owned"] is True and data["active"] is True
    assert data["receipt"] == {"host": "vpn.example.org", "kind": "vps"}


def check_dual_core_generation(directory: Path) -> None:
    """Run both mobile generators as pure functions on macOS, Linux and Windows."""
    module = load_client_module("elidli_dual_core")
    outbound = "Synthetic exit"

    reference = directory / "classic-dns-reference.json"
    reference.write_text(json.dumps({
        "rules": [
            "DOMAIN-SUFFIX,example.cn,Domestic DNS",
            "DOMAIN,x.com,Domestic DNS",
            "DOMAIN-KEYWORD,ignored,Domestic DNS",
            "IP-CIDR,198.51.100.0/24,Domestic DNS",
            "GEOIP,CN,Domestic DNS",
            "DOMAIN-SUFFIX,other.example,Foreign",
        ]
    }), encoding="utf-8")
    classic = module.mainland_split(
        module.global_profile(TEST_STATE, outbound), outbound,
        classic=True, rules_from=reference,
    )
    module.apply_domain_priority(
        classic, outbound, ("Service.Example.CN.",), prioritize_dns=True,
    )
    module.apply_x_priority(classic, outbound, prioritize_dns=True)

    assert classic["clash-for-android"]["append-system-dns"] is False
    assert classic["dns"]["listen"] == "127.0.0.1:1053"
    assert classic["dns"]["nameserver"] == [
        f"tcp://{tunnel['address']}" for tunnel in classic["tunnels"]
    ]
    assert len(classic["tunnels"]) == 2
    assert {tunnel["target"] for tunnel in classic["tunnels"]} == {
        "1.1.1.1:53", "9.9.9.9:53",
    }
    assert all(
        tunnel["network"] == ["tcp"]
        and tunnel["address"].startswith("127.0.0.1:")
        and tunnel["proxy"] == outbound
        for tunnel in classic["tunnels"]
    )
    classic_policy = classic["dns"]["nameserver-policy"]
    assert "+.cn" in classic_policy
    assert "+.example.cn" in classic_policy
    assert classic_policy["+.service.example.cn"] == classic["dns"]["nameserver"][0]
    assert all(isinstance(value, str) for value in classic_policy.values())
    assert all(f"+.{domain}" not in classic_policy for domain in X_DOMAINS), "X should use both default DNS tunnels"
    assert classic["rules"][:4] == [
        f"DOMAIN-SUFFIX,{domain},{outbound}" for domain in X_DOMAINS
    ]
    assert classic["rules"][4] == f"DOMAIN-SUFFIX,service.example.cn,{outbound}"
    assert classic["rules"][-2:] == ["GEOIP,CN,DIRECT", f"MATCH,{outbound}"]
    assert "DOMAIN-SUFFIX,example.cn,DIRECT" not in classic["rules"]
    assert not any("198.51.100.0/24" in rule for rule in classic["rules"])

    mihomo = module.mainland_split(module.global_profile(TEST_STATE, outbound), outbound)
    module.apply_domain_priority(
        mihomo, outbound, ("Service.Example.CN.",), prioritize_dns=True,
    )
    module.apply_x_priority(mihomo, outbound, prioritize_dns=True)
    assert mihomo["rules"][:4] == [
        f"DOMAIN-SUFFIX,{domain},{outbound}" for domain in X_DOMAINS
    ]
    assert mihomo["rules"][4] == f"DOMAIN-SUFFIX,service.example.cn,{outbound}"
    assert mihomo["rules"][-2:] == ["RULE-SET,cn-ip,DIRECT", f"MATCH,{outbound}"]
    domain_direct = {
        rule for rule in mihomo["rules"]
        if rule.startswith(("DOMAIN,", "DOMAIN-SUFFIX,")) and rule.endswith(",DIRECT")
    }
    assert domain_direct == {
        f"DOMAIN-SUFFIX,{suffix},DIRECT" for suffix in ("localhost", "local", "lan", "home.arpa")
    }
    assert mihomo["rule-providers"] == {
        "cn-ip": {
            "type": "http", "behavior": "ipcidr", "format": "mrs", "interval": 86400,
            "proxy": outbound,
            "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs",
            "path": "./ruleset/personal-vpn/cn-ip.mrs",
        }
    }
    assert mihomo["dns"]["nameserver"] == [
        f"https://1.1.1.1/dns-query#{outbound}",
        f"https://9.9.9.9/dns-query#{outbound}",
    ]
    assert all(value.endswith("#DIRECT") for value in mihomo["dns"]["proxy-server-nameserver"])
    foreign_policy_keys = {"+.service.example.cn"}
    assert all(f"+.{domain}" not in mihomo["dns"]["nameserver-policy"] for domain in X_DOMAINS)
    assert all(isinstance(value, str) and value.endswith("#DIRECT")
               for key, value in mihomo["dns"]["nameserver-policy"].items()
               if key not in foreign_policy_keys)
    assert "+.cn" in mihomo["dns"]["nameserver-policy"]
    assert all(
        mihomo["dns"]["nameserver-policy"][key] == mihomo["dns"]["nameserver"]
        for key in foreign_policy_keys
    )
    assert TEST_STATE["server"] not in json.dumps({
        "rules": mihomo["rules"], "dns": mihomo["dns"],
        "rule-providers": mihomo["rule-providers"],
    })

    cidrs = directory / "pure-cn-cidrs.txt"
    cidrs.write_text("1.0.1.0/24\n# comment\n240e::/20\n1.0.1.0/24\n", encoding="utf-8")
    inline = module.mainland_split(
        module.global_profile(TEST_STATE, outbound), outbound, cn_cidrs=cidrs,
    )
    assert inline["rule-providers"] == {
        "cn-ip": {
            "type": "inline", "behavior": "ipcidr",
            "payload": ["1.0.1.0/24", "240e::/20"],
        }
    }


def check_client_generation(directory: Path) -> str:
    if os.name == "nt":
        return "private CLI skipped on Windows; dual-core pure generation passed"

    state = directory / "private-state.json"
    state.write_text(
        json.dumps(
            {
                **TEST_STATE,
            }
        ),
        encoding="utf-8",
    )
    os.chmod(state, 0o600)
    assert stat.S_IMODE(state.stat().st_mode) == 0o600

    phone = directory / "phone.yaml"
    generated = run(
        "client_config.py",
        "--state", state,
        "--output", phone,
        "--mode", "mobile-cn-split",
        "--classic-android",
    )
    expect_success(generated, "classic Android profile generation")
    profile = load_yaml_or_json(phone)
    ordinary_x_rules = [
        f"DOMAIN-SUFFIX,{domain},个人VPN·固定出口" for domain in X_DOMAINS
    ]
    assert not any(rule in profile["rules"] for rule in ordinary_x_rules), (
        "ordinary phone generation enabled X priority without --use-x"
    )
    assert profile["tun"]["enable"] is True
    assert profile["rules"][-2:] == ["GEOIP,CN,DIRECT", "MATCH,个人VPN·固定出口"]
    assert "rule-providers" not in profile
    assert all(isinstance(value, str) for value in profile["dns"]["nameserver-policy"].values())
    assert profile["proxies"][0]["password"] == "synthetic-smoke-test-only"
    assert stat.S_IMODE(phone.stat().st_mode) == 0o600

    x_phone = directory / "phone-x.yaml"
    generated = run(
        "client_config.py",
        "--state", state,
        "--output", x_phone,
        "--mode", "mobile-cn-split",
        "--classic-android",
        "--use-x",
    )
    expect_success(generated, "classic Android X profile generation")
    x_profile = load_yaml_or_json(x_phone)
    x_rules = ordinary_x_rules
    assert x_profile["rules"][:4] == x_rules
    assert x_profile["rules"][4:] == profile["rules"], "X mode changed non-X mobile rules"

    existing = directory / "existing-rules-domain.yaml"
    generated = run(
        "client_config.py",
        "--base", phone,
        "--output", existing,
        "--mode", "existing-rules",
        "--name", "个人VPN·固定出口",
        "--domain", "service.example.cn",
    )
    expect_success(generated, "existing-rules DNS preservation")
    existing_profile = load_yaml_or_json(existing)
    assert existing_profile["rules"][0] == (
        "DOMAIN-SUFFIX,service.example.cn,个人VPN·固定出口"
    )
    assert existing_profile["dns"] == profile["dns"], "existing-rules rewrote existing DNS"

    desktop = directory / "desktop-x.yaml"
    generated = run(
        "client_config.py",
        "--state", state,
        "--output", desktop,
        "--mode", "desktop-domains",
        "--use-x",
    )
    expect_success(generated, "desktop X profile generation without --domain")
    desktop_profile = load_yaml_or_json(desktop)
    assert desktop_profile["rules"][:4] == x_rules
    assert desktop_profile["rules"][-1] == "MATCH,DIRECT"
    return "private CLI and dual-core pure generation passed"


def check_hysteria2_and_deploy_plan(directory: Path) -> None:
    """Verify Hysteria2 Mihomo profiles, classic Clash boundary, --only-node, and offline deploy plan."""
    plan_res = run(
        "deploy.py", "plan", "--target", "root@192.0.2.10", "--server", "192.0.2.10",
        "--service-id", "personal-hy2", "--protocol", "hysteria2",
    )
    expect_success(plan_res, "hysteria2 deploy plan")
    plan_data = json.loads(plan_res.stdout)
    assert plan_data["protocol"] == "hysteria2"
    assert plan_data["port"] == 28448
    assert plan_data["sni"] == "www.bing.com"
    assert plan_data["up_mbps"] == 15 and plan_data["down_mbps"] == 50

    module = load_client_module("elidli_hy2_test")
    outbound = "Personal Hy2 exit"
    hy2_global = module.global_profile(TEST_HY2_STATE, outbound)
    node = hy2_global["proxies"][0]
    assert node["type"] == "hysteria2"
    assert node["port"] == 28448
    assert node["fingerprint"] == TEST_HY2_STATE["fingerprint"]
    assert node["skip-cert-verify"] is True
    assert node["up"] == "30 mbps" and node["down"] == "150 mbps" and node["udp"] is True

    hy2_mihomo = module.mainland_split(hy2_global, outbound)
    module.apply_x_priority(hy2_mihomo, outbound, prioritize_dns=True)
    assert hy2_mihomo["rules"][:4] == [f"DOMAIN-SUFFIX,{d},{outbound}" for d in X_DOMAINS]
    assert hy2_mihomo["rules"][-2:] == ["RULE-SET,cn-ip,DIRECT", f"MATCH,{outbound}"]

    mixed_source = {
        "proxies": [
            node | {"name": "Own Hy2"},
            {"name": "dead free node", "type": "vmess", "server": "192.0.2.99", "port": 443, "uuid": "DEAD-SENTINEL"},
        ],
        "proxy-groups": [{"name": "Select", "type": "select", "proxies": ["Own Hy2", "dead free node"]}],
        "rules": ["MATCH,Select"],
    }
    extracted = module.direct_node_state_from_profile(mixed_source, "Own Hy2", allow_hysteria2=True)
    assert extracted["kind"] == "hysteria2" and extracted["fingerprint"] == TEST_HY2_STATE["fingerprint"]
    try:
        module.direct_node_state_from_profile(mixed_source, "Own Hy2", allow_hysteria2=False)
    except SystemExit:
        pass
    else:
        raise AssertionError("classic Clash boundary failed to reject Hysteria2 --only-node")

    if os.name != "nt":
        hy2_state = directory / "hy2-state.json"
        hy2_state.write_text(json.dumps(TEST_HY2_STATE), encoding="utf-8")
        os.chmod(hy2_state, 0o600)
        hy2_out = directory / "phone-hy2.yaml"
        expect_success(
            run("client_config.py", "--state", hy2_state, "--output", hy2_out, "--mode", "mobile-cn-split", "--use-x"),
            "Mihomo Hysteria2 CLI generation",
        )
        written = load_yaml_or_json(hy2_out)
        assert written["proxies"][0]["type"] == "hysteria2"
        assert written["proxies"][0]["fingerprint"] == TEST_HY2_STATE["fingerprint"]
        rejected = run(
            "client_config.py", "--state", hy2_state, "--output", directory / "bad-classic.yaml",
            "--mode", "mobile-cn-split", "--classic-android",
        )
        assert rejected.returncode != 0, "classic-android accepted hysteria2 state"

        # Guardrail: migrating a Hysteria2 global base profile with --classic-android must also fail closed
        hy2_glob_file = directory / "hy2-global-base.yaml"
        expect_success(
            run("client_config.py", "--state", hy2_state, "--output", hy2_glob_file, "--mode", "mobile-global"),
            "Mihomo Hysteria2 global generation",
        )
        try:
            import yaml as _yaml_check  # type: ignore[import-not-found]
        except ImportError:
            _yaml_check = None
        if _yaml_check is not None:
            rejected_base = run(
                "client_config.py", "--mode", "mobile-cn-split", "--base", hy2_glob_file,
                "--name", "个人VPN·固定出口", "--classic-android", "--output", directory / "bad-migrated-classic.yaml",
            )
            assert rejected_base.returncode != 0, "classic-android --base migration leaked hysteria2 node"

    # Domain-backed CA-verified Hysteria2 (skip-cert-verify=false without fingerprint) must succeed,
    # whereas skip-cert-verify=true without fingerprint must fail closed.
    ca_hy2_source = {
        "proxies": [{
            "name": "CA Hy2", "type": "hysteria2", "server": "vpn.example.org", "port": 443,
            "password": "SYNTHETIC-CA-SECRET", "sni": "vpn.example.org", "skip-cert-verify": False, "udp": True,
        }],
        "proxy-groups": [{"name": "G", "type": "select", "proxies": ["CA Hy2"]}],
        "rules": ["MATCH,G"],
    }
    ca_extracted = module.direct_node_state_from_profile(ca_hy2_source, "CA Hy2", allow_hysteria2=True)
    assert ca_extracted["skip_cert_verify"] is False and "fingerprint" not in ca_extracted
    ca_prof = module.global_profile(ca_extracted, outbound)
    assert ca_prof["proxies"][0]["skip-cert-verify"] is False and "fingerprint" not in ca_prof["proxies"][0]

    insecure_hy2_source = copy.deepcopy(ca_hy2_source)
    insecure_hy2_source["proxies"][0]["skip-cert-verify"] = True
    try:
        module.direct_node_state_from_profile(insecure_hy2_source, "CA Hy2", allow_hysteria2=True)
    except SystemExit:
        pass
    else:
        raise AssertionError("unpinned skip-cert-verify=true Hysteria2 node was accepted")

    # Verify deploy.py REMOTE_HY2_SCRIPT invariants (iproute2 -lntup Netid column, group creation, IPv4 auto-detect, isolated hop redirect, deferred atomic state)
    deploy_spec = importlib.util.spec_from_file_location("elidli_deploy_check", SCRIPTS / "deploy.py")
    assert deploy_spec and deploy_spec.loader
    deploy_mod = importlib.util.module_from_spec(deploy_spec)
    sys.path.insert(0, str(SCRIPTS))
    try:
        deploy_spec.loader.exec_module(deploy_mod)
    finally:
        sys.path.pop(0)
    assert 'ss -H -lntup "sport = :${listen_port}"' in deploy_mod.REMOTE_HY2_SCRIPT, (
        "REMOTE_HY2_SCRIPT must pass both -t and -u to ss so Linux iproute2 emits the Netid column"
    )
    assert "adduser --system --group" in deploy_mod.REMOTE_HY2_SCRIPT
    assert "/proc/net/if_inet6" in deploy_mod.REMOTE_HY2_SCRIPT and "/proc/net/ipv6_route" in deploy_mod.REMOTE_HY2_SCRIPT
    assert "outbounds:" in deploy_mod.REMOTE_HY2_SCRIPT and "mode: {effective_mode}" in deploy_mod.REMOTE_HY2_SCRIPT
    assert "prerouting udp dport" in deploy_mod.REMOTE_HY2_SCRIPT and "REDIRECT --to-ports" in deploy_mod.REMOTE_HY2_SCRIPT

    hop_plan = run(
        "deploy.py", "plan", "--target", "root@192.0.2.10", "--server", "192.0.2.10",
        "--service-id", "personal-hy2", "--protocol", "hysteria2",
        "--outbound-mode", "4", "--hop-ports", "28500-28530", "--hop-interval", "20",
    )
    expect_success(hop_plan, "hysteria2 hop-ports deploy plan")
    hop_plan_data = json.loads(hop_plan.stdout)
    assert hop_plan_data["outbound_mode"] == "4"
    assert hop_plan_data["hop_ports"] == "28500-28530" and hop_plan_data["hop_interval"] == 20
    assert run(
        "deploy.py", "plan", "--target", "root@192.0.2.10", "--server", "192.0.2.10",
        "--service-id", "bad-ss-hop", "--protocol", "ss", "--hop-ports", "28500-28530",
    ).returncode != 0, "ss accepted hysteria2 --hop-ports"
    assert run(
        "deploy.py", "plan", "--target", "root@192.0.2.10", "--server", "192.0.2.10",
        "--service-id", "bad-wide-hop", "--protocol", "hysteria2", "--hop-ports", "20000-40000",
    ).returncode != 0, "overly wide >1000 port range was accepted"

    ns = deploy_mod.parser().parse_args([
        "deploy", "--target", "root@192.0.2.10", "--server", "192.0.2.10",
        "--service-id", "atomic-check", "--protocol", "hysteria2",
        "--hop-ports", "28500-28530", "--hop-interval", "25",
        "--state-dir", str(directory / "st"),
    ])
    ns.listen_port = 28448
    st_mem, existed = deploy_mod.prepare_state(ns)
    assert existed is False and not (directory / "st" / "atomic-check.json").exists(), (
        "prepare_state must not write partial state to disk before SSH deploy completes"
    )
    assert st_mem["ports"] == "28448,28500-28530" and st_mem["hop_interval"] == 25
    assert st_mem["outbound_mode"] == "auto-detect"

    # Verify client_config.py port-hopping, 0.0.0.0/8 bogon guard, and non-.cn domestic DNS/Fake-IP leak filters
    hop_prof = module.mainland_split(module.global_profile(TEST_HY2_STATE | {"ports": "28448,28500-28530", "hop_interval": "15-30"}, outbound), outbound)
    hop_node = hop_prof["proxies"][0]
    assert hop_node["ports"] == "28448,28500-28530" and hop_node["hop-interval"] == "15-30"
    assert "IP-CIDR,0.0.0.0/8,DIRECT,no-resolve" in hop_prof["rules"]
    for dom in ("+.tencent-cloud.net", "+.meituan.net", "+.sandai.net", "+.xiaomixiaoai.com"):
        assert dom in hop_prof["dns"]["nameserver-policy"], f"missing domestic DNS policy for {dom}"
    for filt in ("+.tencent-cloud.net", "+.meituan.net", "+.sandai.net"):
        assert filt in hop_prof["dns"]["fake-ip-filter"], f"missing fake-ip-filter for {filt}"

    extracted_hop = module.direct_node_state_from_profile(
        {"proxies": [hop_node | {"name": "Hop Hy2"}], "proxy-groups": [], "rules": []},
        "Hop Hy2", allow_hysteria2=True,
    )
    assert extracted_hop["ports"] == "28448,28500-28530" and extracted_hop["hop_interval"] == "15-30"
    for bad_spec in (
        TEST_HY2_STATE | {"ports": "28530-28500"},
        TEST_HY2_STATE | {"ports": "28448", "hop_interval": 2},
        TEST_HY2_STATE | {"hop_interval": 25},
    ):
        try:
            module.proxy_node(bad_spec, "Bad")
        except SystemExit:
            pass
        else:
            raise AssertionError(f"invalid hysteria2 hop spec accepted: {bad_spec}")


def main() -> int:
    required = (
        "SKILL.md", "README.md", "LICENSE", "references/data-sources.md",
        "agents/openai.yaml",
        "references/providers.csv",
        "references/fx.json",
        "references/offer-id-aliases.json",
        "scripts/recommend.py",
        "scripts/resolve_offer.py",
        "scripts/order.py",
        "scripts/client_config.py",
        "scripts/deploy.py",
        "scripts/public_host.py",
    )
    missing = [name for name in required if not (ROOT / name).is_file()]
    assert not missing, "missing packaged files: " + ", ".join(missing)

    check_catalog_and_cli()
    check_x_priority_logic()
    with tempfile.TemporaryDirectory(prefix="personal-vpn-smoke-") as temporary:
        directory = Path(temporary)
        check_single_exit_logic(directory)
        check_order_state(directory)
        check_dual_core_generation(directory)
        check_hysteria2_and_deploy_plan(directory)
        client_result = check_client_generation(directory)
    print("PASS: package layout, catalog recommendation, legacy ID and ready order state")
    print("PASS: X intent adds four prioritized, de-duplicated rules and preserves other routes")
    print("PASS: single-exit generation excludes unrelated nodes, chains and providers")
    print("PASS: classic and Mihomo mobile profiles enforce their DNS and mainland-IP contracts")
    print("PASS: Hysteria2 parallel plan, Mihomo profile pinning and classic-core guardrails")
    print(f"Private CLI profiles: {client_result}")
    print("No network, SSH, VPN or system-proxy action was performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
