#!/usr/bin/env python3
"""Record one user's local selection, official quote and provisioning state."""
import argparse
import csv
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import urlsplit
from public_host import normalize_public_host

BASE = Path(__file__).resolve().parents[1]
CATALOG = BASE / "references" / "providers.csv"
# Official storefront and customer portal domain suffixes, matched at DNS label boundaries.
DOMAINS = {
    "ByteVirt": ("bytevirt.com",), "xTom / V.PS": ("v.ps", "vps.hosting"),
    "Google Cloud": ("cloud.google.com",), "AWS Lightsail": ("aws.amazon.com",),
    "Akamai Cloud / Linode": ("akamai.com", "linode.com"), "Hetzner Cloud": ("hetzner.com", "hetzner.cloud"),
    "DigitalOcean": ("digitalocean.com",), "Vultr": ("vultr.com",), "IPRoyal": ("iproyal.com",),
    "Surflare": ("surflare.com",),
}
IDENTITY = ("provider", "sku", "country", "location", "term", "currency", "kind")
MATERIAL = IDENTITY + ("quantity", "ipv4", "due_now", "renewal", "setup_fee", "auto_renew", "ip_terms", "traffic_terms", "extras")
MONEY = ("due_now", "renewal", "setup_fee")
CATALOG_KINDS = {
    "自管VPS": "vps",
    "ISP主机": "vps",
    "共享IP VPS": "vps",
    "出口代理": "proxy",
    "托管VPN": "managed",
}


def catalog_rows():
    with CATALOG.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def catalog_kind_for_identity(provider, sku, country):
    kinds = {
        CATALOG_KINDS[row["产品类型"]]
        for row in catalog_rows()
        if row["供应商"] == provider
        and row["具体套餐或SKU"] == sku
        and country in row["覆盖国家/地区代码"].split("|")
        and row["产品类型"] in CATALOG_KINDS
    }
    return next(iter(kinds)) if len(kinds) == 1 else None


def normalize_known_selection(state):
    selection = state.get("selection")
    offer_id = state.get("offer_id")
    if not selection or not offer_id:
        return
    row = next((item for item in catalog_rows() if item["报价记录ID"] == offer_id), None)
    if not row:
        return
    kind = CATALOG_KINDS.get(row["产品类型"])
    if kind:
        selection["kind"] = kind


def require_catalog_item_kind(doc):
    catalog_kind = catalog_kind_for_identity(doc["provider"], doc["sku"], doc["country"])
    if catalog_kind:
        require(doc["kind"] == catalog_kind,
                f"目录中的同一 SKU 应记录为 {catalog_kind}，不能记录为 {doc['kind']}")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def load(path):
    with path.open("rb") as handle:
        data = json.load(handle)
    require(isinstance(data, dict), "输入须为 JSON 对象")
    return data


def save(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as out:
        temp = Path(out.name)
        try:
            json.dump(data, out, ensure_ascii=False, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        except BaseException:
            temp.unlink(missing_ok=True)
            raise
    try:
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def money(value):
    if value is None or value == "":
        return None
    d = Decimal(str(value))
    require(d.is_finite() and d >= 0, "金额应为非负数，未知填 null")
    return format(d.normalize(), "f")


def official(source, provider):
    u = urlsplit(source)
    require(u.scheme == "https" and not u.username and not u.password and u.port in (None, 443),
            "证据应来自商家 HTTPS 官网")
    domains = DOMAINS.get(provider, ())
    require(any(u.hostname == d or (u.hostname or "").endswith("." + d) for d in domains),
            "网址与记录的供应商不匹配。请打开该商家官方账户或订单页")
    # Signed portal links and session tokens never belong in the record.
    return u.scheme + "://" + u.hostname


def clean_host(host):
    return normalize_public_host(host)


def evidence(raw, receipt=False):
    required = ["provider", "sku", "country", "term", "currency", "kind", "source"]
    require(all(isinstance(raw.get(k), str) and raw[k].strip() for k in required),
            "缺少供应商、SKU、地区、账期、币种、产品类型或官网证据")
    doc = {k: raw.get(k) for k in MATERIAL}
    doc["source"] = official(raw["source"], doc["provider"])
    doc["country"] = doc["country"].upper()
    doc["currency"] = doc["currency"].upper()
    if not receipt or doc["quantity"] is not None:
        require(type(doc["quantity"]) is int and doc["quantity"] > 0, "请填写已核实的正整数购买数量 quantity")
    require(doc["ipv4"] in (None, "dedicated_public", "provider_exit", "shared", "none"), "IPv4 类型无效")
    require(re.fullmatch("[A-Z]{2}", doc["country"]) and re.fullmatch("[A-Z]{3}", doc["currency"]), "地区或币种代码无效")
    require(doc["kind"] in {"vps", "proxy", "managed"}, "kind 应为 vps、proxy 或 managed")
    for k in MONEY:
        doc[k] = money(doc[k])
    for k in ("location", "ip_terms", "traffic_terms", "extras"):
        require(doc[k] is None or isinstance(doc[k], str), k + " 应为文字或 null")
    require(doc["auto_renew"] is None or type(doc["auto_renew"]) is bool, "续费开关应为 true/false/null")
    if receipt:
        require(all(type(raw.get(k)) is bool for k in ("paid", "active")), "请分别核对是否付款与是否开通")
        doc.update(paid=raw["paid"], active=raw["active"])
        if raw.get("host"):
            doc["host"] = clean_host(raw["host"])
    else:
        require(type(raw.get("available")) is bool, "请核对所选地域和 SKU 的可订状态")
        doc["available"] = raw["available"]
        doc["billing"] = raw.get("billing", "prepaid")
        require(doc["billing"] in {"prepaid", "metered"}, "billing 无效")
        if doc["available"] and doc["billing"] == "prepaid":
            require(doc["due_now"] is not None, "预付产品需读出当前首付总额")
        if doc["available"] and doc["billing"] == "metered":
            require(bool(doc["extras"]) and bool(doc["traffic_terms"]), "按量方案需给出费率、流量口径及预计月总额")
    doc["observed_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return doc


def changes(previous, current, receipt=False):
    result = {}
    for k in MATERIAL:
        a, b = previous.get(k), current.get(k)
        if a is None or a == "" or a == b:
            continue
        # A short receipt often omits limits/tariffs. Keep the confirmed quote and
        # only compare those fields when the portal explicitly reports them.
        if receipt and b is None and k not in ("due_now",):
            continue
        result[k] = {"agreed": a, "observed": b}
    return result


def ticket(state, stage, diff):
    state["stage"] = stage
    state["differences"] = diff
    state["fingerprint"] = hashlib.sha256(json.dumps([stage, diff], sort_keys=True,
                                                     ensure_ascii=False).encode()).hexdigest()[:16]


def receipt_stage(doc):
    if not doc["paid"]:
        return "awaiting_payment"
    if not doc["active"] or (doc["kind"] == "vps" and not doc.get("host")):
        return "awaiting_activation"
    return "ready" if doc["kind"] == "vps" else "provider_setup"


def check_completed_order(state):
    if state.get("stage") not in ("ready", "provider_setup"):
        return
    receipt = state.get("receipt") or {}
    if all(receipt.get(k) for k in ("provider", "sku", "country", "kind")):
        require_catalog_item_kind(receipt)
    if state["stage"] == "ready":
        require(receipt.get("kind") == "vps", "请重新核对回执中的主机类型")
        clean_host(receipt.get("host"))


def select(args, state):
    require(not state, "每个选购方案使用一个新的私有状态文件")
    country = args.country.upper()
    row = next((item for item in catalog_rows() if item["报价记录ID"] == args.id), None)
    require(row is not None, "报价 ID 已变化，请用 resolve_offer.py 加国家或机房定位")
    catalog_kind = CATALOG_KINDS.get(row["产品类型"])
    require(catalog_kind is not None, "该目录记录不是可单独购买的主机、代理或托管服务")
    require(args.kind == catalog_kind,
            f"目录中的产品类型应使用 --kind {catalog_kind}，不能记录为 {args.kind}")
    regions = set(row["覆盖国家/地区代码"].split("|"))
    require(country in regions, "所选地区与记录不符；需要明确地区的同一报价")
    require(args.traffic_gb is None or args.traffic_gb > 0, "最低流量应大于零")
    require(args.quantity > 0, "购买数量应大于零")
    state.update(stage="selected", offer_id=args.id, requirements=sorted(set(args.require)),
                 traffic_gb=args.traffic_gb,
                 selection=dict(provider=row["供应商"], sku=row["具体套餐或SKU"], country=country,
                                term=row["付款/计费周期"], currency=row["币种"], location=args.location,
                                kind=args.kind, quantity=args.quantity, ipv4=args.ipv4,
                                due_now=money(row["首期参考金额"]) if args.quantity == 1 else None,
                                renewal=money(row["已核周期续费额"]) if args.quantity == 1 else None,
                                setup_fee=money(row["一次性安装费"]) if args.quantity == 1 else None),
                 sources={k:row[k] for k in ("报价来源", "配置器或库存入口", "计费和退款来源")})


def advance(args, state):
    stage = state.get("stage")
    if args.action == "select":
        select(args, state)
    elif args.action == "existing":
        require(not state and args.owned, "已有主机入口需要确认资源归属，且使用独立状态文件")
        state.update(stage="ready", owned=True, active=True, receipt={"host":clean_host(args.host), "kind":"vps"})
    elif args.action == "recheck":
        require(stage in ("selected", "quote_changed", "unavailable", "conditions_unconfirmed", "reviewed"), "先记录用户选定的方案")
        raw = load(args.file)
        doc = evidence(raw)
        require(doc["provider"] == state["selection"]["provider"], "仅复核用户选定的商家")
        require_catalog_item_kind(doc)
        state["quote"] = doc
        diff = changes(state.get("approved_quote") or state["selection"], doc)
        findings = raw.get("requirements", {})
        require(isinstance(findings, dict), "硬条件核验结果应为对象")
        gaps = [key for key in state.get("requirements", []) if findings.get(key) != "confirmed"]
        if state.get("traffic_gb") is not None:
            capacity = money(raw.get("effective_gb"))
            if raw.get("unlimited_verified") is not True and (capacity is None or Decimal(capacity) < Decimal(str(state["traffic_gb"]))):
                gaps.append("traffic_gb")
        state["open_requirements"] = gaps
        if not doc["available"]:
            state["stage"] = "unavailable"
        elif gaps:
            state["stage"] = "conditions_unconfirmed"
        elif diff:
            ticket(state, "quote_changed", diff)
        else:
            state["stage"] = "reviewed"
            state["approved_quote"] = doc
    elif args.action == "receipt":
        require(not state.get("owned"), "已有主机与新订单须使用各自的状态文件")
        doc = evidence(load(args.file), receipt=True)
        # Receipt-first is a normal entry. An actually paid item may differ from the chosen item.
        expected = state.get("accepted_receipt") or state.get("approved_quote") or state.get("selection") or {}
        require_catalog_item_kind(doc)
        diff = changes(expected, doc, receipt=True)
        if expected.get("host") and doc.get("host") != expected["host"]:
            diff["host"] = {"agreed":expected["host"], "observed":doc.get("host")}
        state.update(receipt=doc, paid=doc["paid"], active=doc["active"])
        if diff:
            ticket(state, "receipt_changed", diff)
        else:
            state["stage"] = receipt_stage(doc)
            state["accepted_receipt"] = doc
    elif args.action == "accept":
        require(stage in ("quote_changed", "receipt_changed") and args.fingerprint == state.get("fingerprint"),
                "当前差异与用户确认的摘要不一致")
        if stage == "receipt_changed":
            state["accepted_receipt"] = state["receipt"]
            state["stage"] = receipt_stage(state["receipt"])
        else:
            state["stage"] = "reviewed"
            state["approved_quote"] = state["quote"]
    if state["stage"] not in ("quote_changed", "receipt_changed"):
        state.pop("fingerprint", None)
        state.pop("differences", None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True, help="本机私有订单记录")
    subs = parser.add_subparsers(dest="action", required=True)
    p = subs.add_parser("select")
    p.add_argument("--id", required=True)
    p.add_argument("--country", required=True)
    p.add_argument("--location", help="已确认的具体机房，有则记录")
    p.add_argument("--kind", choices=("vps","proxy","managed"), required=True)
    p.add_argument("--quantity", type=int, default=1)
    p.add_argument("--ipv4", choices=("dedicated_public", "provider_exit", "shared", "none"))
    p.add_argument("--require", choices=("static","exclusive","isp","residential"), action="append", default=[])
    p.add_argument("--traffic-gb", type=int, help="必须满足的终端每月流量，GB")
    for name in ("recheck", "receipt"):
        subs.add_parser(name).add_argument("--file", type=Path, required=True)
    subs.add_parser("accept").add_argument("--fingerprint", required=True)
    p = subs.add_parser("existing")
    p.add_argument("--host", required=True)
    p.add_argument("--owned", action="store_true", required=True)
    subs.add_parser("status")
    args = parser.parse_args()
    try:
        state = load(args.state) if args.state.exists() else {}
        normalize_known_selection(state)
        if args.action != "status":
            advance(args, state)
        check_completed_order(state)
        if args.action != "status":
            save(args.state, state)
        print(json.dumps(state or {"stage":"new"}, ensure_ascii=False, indent=2))
    except (OSError, ValueError, InvalidOperation) as exc:
        parser.exit(2, f"{exc}\n")


if __name__ == "__main__":
    main()
