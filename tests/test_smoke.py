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


def check_x_priority_logic() -> None:
    """Exercise the cross-platform transformation without private files or network."""
    module_spec = importlib.util.spec_from_file_location(
        "elidli_client_config", SCRIPTS / "client_config.py"
    )
    assert module_spec and module_spec.loader
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)

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
    module_spec = importlib.util.spec_from_file_location(
        "elidli_single_exit", SCRIPTS / "client_config.py"
    )
    assert module_spec and module_spec.loader
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)

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

    imported = module.classic_domestic_rules(reference)
    assert imported == [
        "DOMAIN-SUFFIX,example.cn,DIRECT", "IP-CIDR,203.0.113.0/24,DIRECT"
    ]

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
        assert all(rule in written["rules"] for rule in imported)
        assert "proxy-providers" not in written and source_url not in str(written)
        assert run(*command, "").returncode != 0


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


def check_client_generation(directory: Path) -> str:
    if os.name == "nt":
        return "skipped on Windows because v1 enforces POSIX mode 0600 for private credentials"

    state = directory / "private-state.json"
    state.write_text(
        json.dumps(
            {
                "kind": "ss",
                "server": "192.0.2.10",
                "port": 28447,
                "method": "aes-128-gcm",
                "password": "synthetic-smoke-test-only",
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
    return "passed"


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
        client_result = check_client_generation(directory)
    print("PASS: package layout, catalog recommendation, legacy ID and ready order state")
    print("PASS: X intent adds four prioritized, de-duplicated rules and preserves other routes")
    print("PASS: single-exit generation excludes unrelated nodes, chains and providers")
    print(f"Classic Android and desktop X profiles: {client_result}")
    print("No network, SSH, VPN or system-proxy action was performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
