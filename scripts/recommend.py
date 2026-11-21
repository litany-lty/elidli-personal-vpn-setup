#!/usr/bin/env python3
"""Query the bundled VPN offer catalog without network access."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_CATALOG = Path(__file__).resolve().parents[1] / "references" / "providers.csv"
DEFAULT_FX = Path(__file__).resolve().parents[1] / "references" / "fx.json"


@dataclass
class Candidate:
    row: dict[str, str]
    status: str = "合格"
    gaps: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    budget_value: float | None = None
    upfront_budget_value: float | None = None
    effective_traffic_gb: float | None = None
    score: float = 0.0


def number(value: str | None) -> float | None:
    if value is None or not value.strip():
        return None
    try:
        return float(value)
    except ValueError:
        return None


def load_catalog(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    required = {
        "供应商", "具体套餐或SKU", "产品类型", "覆盖国家/地区代码",
        "IP属性", "地址固定性", "地址独享性", "币种", "付款/计费周期",
        "报价类型", "首期参考金额", "月成本参考", "流量额度",
        "流量单位", "流量计量方向", "库存/可用性快照", "报价记录ID",
    }
    missing = required - set(rows[0] if rows else ())
    if missing:
        raise ValueError("供应商表缺少字段：" + "、".join(sorted(missing)))
    return rows


def load_fx(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("base") != "EUR" or "EUR" not in data.get("rates", {}):
        raise ValueError("汇率文件必须使用 EUR 基准并包含 EUR")
    return data


def convert(amount: float, source: str, target: str, fx: dict[str, Any]) -> float:
    rates = fx["rates"]
    if source not in rates or target not in rates:
        raise KeyError(f"缺少 {source}→{target} 的参考汇率")
    return amount / float(rates[source]) * float(rates[target])


def country_matches(row: dict[str, str], country: str) -> bool:
    return country.upper() in {part.strip().upper() for part in row["覆盖国家/地区代码"].split("|") if part.strip()}


def commitment_months(row: dict[str, str]) -> float | None:
    explicit = number(row.get("周期月数"))
    if explicit is not None:
        return explicit
    period = row["付款/计费周期"]
    if any(token in period for token in ("月付", "30天", "30日", "1个月", "小时", "按秒", "月度封顶", "每小时")):
        return 1.0
    if "季付" in period or "90天" in period:
        return 3.0
    if "半年" in period or "60天" in period:
        return 6.0 if "半年" in period else 2.0
    if "年付" in period or "365天" in period:
        return 12.0
    return None


def traffic_capacity(row: dict[str, str]) -> float | None:
    quota = number(row["流量额度"])
    unit = row["流量单位"]
    if quota is None:
        return math.inf if "不限" in unit else None
    if unit.startswith("TiB"):
        quota *= 1099.511627776
    elif unit.startswith("TB"):
        quota *= 1000
    elif unit.startswith("GiB"):
        quota *= 1.073741824
    elif not unit.startswith("GB"):
        return None
    # Proxy traffic and most cloud egress quotas are already expressed in end-user bytes.
    # A relay VPS whose provider counts both directions consumes about twice the user's traffic.
    if "入站+出站" in row["流量计量方向"] and row["产品类型"] in {"自管VPS", "ISP主机"}:
        quota /= 2
    return quota


def unavailable(row: dict[str, str]) -> bool:
    stock = row["库存/可用性快照"]
    return any(token in stock for token in ("售罄", "不可用", "API 显示不可用")) or bool(
        re.search(r"(?<!\d)0\s+Available(?!\d)", stock, flags=re.IGNORECASE)
    )


def static_state(text: str) -> str:
    if any(token in text for token in ("动态", "轮换", "粘性", "否")):
        return "no"
    if any(token in text for token in ("存续期内", "订阅期内", "租期内", "静态", "需绑定", "可持有", "可预留", "已预留", "创建后须")):
        return "yes"
    return "unknown"


def exclusive_state(text: str) -> str:
    if any(token in text for token in ("共享", "无独立")):
        return "no"
    if any(token in text for token in ("独享", "已明确", "单个资源", "单独分配", "关联到一个资源", "关联到单个", "分配给单个", "dedicated")):
        return "yes"
    return "unknown"


def is_ipv4_candidate(row: dict[str, str]) -> bool:
    value = row.get("IPv4配置", "")
    return not any(token in value for token in ("IPv6-only", "不含IPv4", "共享NAT", "不含"))


def quote_is_complete(row: dict[str, str]) -> bool:
    return row["报价类型"] not in {"公开起价/选区待核", "未公开金额", "配套费率", "仅计算资源价", "公开按量单价", "有条件免费"}


def classify(row: dict[str, str], args: argparse.Namespace, fx: dict[str, Any]) -> Candidate | None:
    if not country_matches(row, args.country) or unavailable(row):
        return None
    if row["产品类型"] in {"增购", "共享IP VPS"}:
        return None
    if row["产品类型"] == "出口代理" and not args.accept_proxy:
        return None
    if row["产品类型"] == "出口代理" and not args.has_front:
        # It may work directly in Clash, but a separate encrypted/stable access path is unresolved.
        proxy_without_front = True
    else:
        proxy_without_front = False
    if row["产品类型"] == "托管VPN" and args.ip_type in {"isp", "residential"}:
        return None
    if not is_ipv4_candidate(row):
        return None

    mapping = {"isp": "ISP登记", "residential": "真实家宽池", "datacenter": "机房"}
    if args.ip_type != "any" and row["IP属性"] != mapping[args.ip_type]:
        return None

    months = commitment_months(row)
    if args.max_months is not None and (months is None or months > args.max_months + 1e-9):
        return None

    result = Candidate(row=row)
    fixed = static_state(row["地址固定性"])
    exclusive = exclusive_state(row["地址独享性"])
    if args.static == "required":
        if fixed == "no":
            return None
        if fixed == "unknown":
            result.gaps.append("固定性待官网确认")
    elif args.static == "preferred" and fixed != "yes":
        result.notes.append("固定性未确认")
    if args.exclusive == "required":
        if exclusive == "no":
            return None
        if exclusive == "unknown":
            result.gaps.append("独享性待官网确认")
    elif args.exclusive == "preferred" and exclusive != "yes":
        result.notes.append("独享性未确认")

    result.effective_traffic_gb = traffic_capacity(row)
    if args.traffic_gb is not None:
        if result.effective_traffic_gb is None:
            result.gaps.append("流量额度未公开")
        elif result.effective_traffic_gb < args.traffic_gb:
            return None

    if not quote_is_complete(row):
        result.gaps.append("报价不是完整可购买总价")
    if proxy_without_front:
        result.gaps.append("尚未确认稳定或加密前置")
    if "待核" in row["必要或可选附加费"]:
        result.notes.append("附加费待结账确认")

    monthly = number(row["月成本参考"])
    upfront = number(row["首期参考金额"])
    cost = monthly
    if args.budget is not None:
        if cost is None:
            result.gaps.append("月成本未知，无法验证预算")
        else:
            result.budget_value = convert(cost, row["币种"], args.budget_currency, fx)
            if result.budget_value > args.budget + 1e-9:
                return None
    elif cost is not None and args.budget_currency in fx["rates"]:
        result.budget_value = convert(cost, row["币种"], args.budget_currency, fx)
    if upfront is not None and args.budget_currency in fx["rates"]:
        result.upfront_budget_value = convert(upfront, row["币种"], args.budget_currency, fx)
    if args.max_upfront is not None:
        if upfront is None:
            result.gaps.append("首期金额未知，无法验证首付上限")
        elif result.upfront_budget_value is not None and result.upfront_budget_value > args.max_upfront + 1e-9:
            return None

    if result.gaps:
        result.status = "条件候选"

    score = 0.0
    score += 35 if result.status == "合格" else 0
    score += 16 if row["产品类型"] == "ISP主机" and args.ip_type == "isp" else 0
    score += 16 if fixed == "yes" else 0
    score -= 10 if args.static == "required" and fixed == "unknown" else 0
    score += 8 if exclusive == "yes" else 0
    score -= 8 if args.exclusive == "required" and exclusive == "unknown" else 0
    score += 5 if "有货" in row["库存/可用性快照"] or "仅剩" in row["库存/可用性快照"] else 0
    score += 4 if quote_is_complete(row) else 0
    score += 3 if months == 1 else 0
    if result.budget_value is not None:
        score -= result.budget_value / max(args.budget or 100.0, 1.0)
    score -= len(result.gaps) * 3
    result.score = score
    return result


def target_region(row: dict[str, str], country: str) -> str:
    region = row["机房/地区或同价组"]
    token_map = {
        "JP": ("东京", "大阪", "日本", "Tokyo", "Osaka", "Japan", "ap-northeast-1"),
        "TW": ("台湾", "台北", "Taiwan", "Taipei", "asia-east1"),
    }
    parts = [part.strip() for part in region.replace("；", "|").split("|") if part.strip()]
    matched = [part for part in parts if any(token.lower() in part.lower() for token in token_map.get(country, (country,)))]
    return " | ".join(matched) if matched else region


def serialize(candidate: Candidate, args: argparse.Namespace, fx: dict[str, Any]) -> dict[str, Any]:
    row = candidate.row
    capacity = candidate.effective_traffic_gb
    component_only = row["报价类型"] == "仅计算资源价"
    return {
        "status": candidate.status,
        "record_id": row["报价记录ID"],
        "target_country": args.country,
        "provider": row["供应商"],
        "sku": row["具体套餐或SKU"],
        "product_type": row["产品类型"],
        "region": target_region(row, args.country),
        "billing_period": row["付款/计费周期"],
        "currency": row["币种"],
        "quoted_price": number(row["原始报价"]),
        "upfront_reference": number(row["首期参考金额"]),
        "recurring_reference": number(row["已核周期续费额"]),
        "monthly_reference": number(row["月成本参考"]),
        "budget_value": round(candidate.budget_value, 2) if candidate.budget_value is not None else None,
        "budget_value_scope": "计算资源部分，未含磁盘、IPv4和公网出站" if component_only else "方案月成本参考",
        "upfront_budget_value": round(candidate.upfront_budget_value, 2) if candidate.upfront_budget_value is not None else None,
        "budget_currency": args.budget_currency,
        "effective_traffic_gb": None if capacity in (None, math.inf) else round(capacity, 2),
        "ip_type": row["IP属性"],
        "static": row["地址固定性"],
        "exclusive": row["地址独享性"],
        "gaps": candidate.gaps,
        "notes": candidate.notes,
        "verify_url": row["配置器或库存入口"] or row["报价来源"],
        "verified_at": row["公开资料核对日期"],
    }


def render_text(results: list[dict[str, Any]], fx: dict[str, Any]) -> str:
    if not results:
        return "没有找到满足硬条件的记录。请放宽地区、IP 类型、账期、预算或流量条件。"
    output = [f"离线索引建议（报价资料日见各记录；预算换算采用 {fx['date']} ECB 参考汇率）"]
    labels = ["主选", "备选"] + [f"候选{i}" for i in range(3, len(results) + 1)]
    for label, item in zip(labels, results):
        upfront = item["upfront_reference"]
        price = f"首期参考 {upfront:g} {item['currency']}" if upfront is not None else "首期金额待官网确认"
        recurring = item["recurring_reference"]
        if recurring is not None:
            price += f"，续费/周期参考 {recurring:g} {item['currency']}"
        else:
            price += "，续费金额未知"
        if item["budget_value"] is None:
            budget = ""
        elif item["budget_value_scope"].startswith("计算资源部分"):
            budget = f"，计算资源部分约 {item['budget_value']:g} {item['budget_currency']}（磁盘、IPv4和公网出站另计）"
        else:
            budget = f"，月成本约 {item['budget_value']:g} {item['budget_currency']}"
        gaps = "；待核：" + "、".join(item["gaps"]) if item["gaps"] else ""
        output.append(
            f"{label} [{item['status']}] {item['provider']} {item['sku']} · {item['region']} · "
            f"{item['billing_period']} · {price}{budget}{gaps}\n"
            f"  资料日期 {item['verified_at'] or '未知'} · ID {item['record_id']} · 选定后复核 {item['verify_url']}"
        )
    return "\n".join(output)


def nonnegative_number(value: str) -> float:
    amount = float(value)
    if not math.isfinite(amount) or amount < 0:
        raise argparse.ArgumentTypeError("请输入大于或等于 0 的有限数值")
    return amount


def positive_months(value: str) -> float:
    months = nonnegative_number(value)
    if months == 0:
        raise argparse.ArgumentTypeError("最长账期必须大于 0 个月")
    return months


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="离线查询 VPN 供应商索引，输出一主一备选")
    result.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    result.add_argument("--fx", type=Path, default=DEFAULT_FX)
    result.add_argument("--country", required=True, help="目标出口 ISO 两字母代码，例如 JP、TW")
    result.add_argument("--budget", type=nonnegative_number, help="可接受的每月成本上限")
    result.add_argument("--budget-currency", default="CNY")
    result.add_argument("--max-upfront", type=nonnegative_number, help="同一币种下可接受的首次付款上限")
    result.add_argument("--max-months", type=positive_months, help="最长接受预付月数，例如 1")
    result.add_argument("--traffic-gb", type=nonnegative_number, help="终端每月预计流量 GB")
    result.add_argument("--ip-type", choices=("any", "isp", "residential", "datacenter"), default="any")
    result.add_argument("--static", choices=("required", "preferred", "no"), default="preferred")
    result.add_argument("--exclusive", choices=("required", "preferred", "no"), default="preferred")
    result.add_argument("--accept-proxy", action="store_true", help="接受单独购买出口代理")
    result.add_argument("--has-front", action="store_true", help="已经有可复用的稳定前置线路")
    result.add_argument("--limit", type=int, default=2, help="返回候选数，1 到 10，默认 2")
    result.add_argument("--json", action="store_true")
    return result


def main() -> int:
    args = parser().parse_args()
    args.country = args.country.upper()
    args.budget_currency = args.budget_currency.upper()
    try:
        catalog = load_catalog(args.catalog)
        fx = load_fx(args.fx)
        if (args.budget is not None or args.max_upfront is not None) and args.budget_currency not in fx["rates"]:
            raise ValueError(f"汇率表没有 {args.budget_currency}。请提供更新后的 --fx 文件，或使用同币种预算。")
        if not 1 <= args.limit <= 10:
            raise ValueError("--limit 必须在 1 到 10 之间")
        candidates = [item for row in catalog if (item := classify(row, args, fx))]
        candidates.sort(key=lambda item: (-item.score, item.budget_value if item.budget_value is not None else math.inf, item.row["供应商"], item.row["具体套餐或SKU"]))
        selected: list[Candidate] = []
        providers: set[str] = set()
        for item in candidates:
            provider = item.row["供应商"]
            if provider not in providers:
                selected.append(item)
                providers.add(provider)
                if len(selected) == args.limit:
                    break
        if len(selected) < args.limit:
            for item in candidates:
                if item in selected:
                    continue
                selected.append(item)
                if len(selected) == args.limit:
                    break
        output = [serialize(item, args, fx) for item in selected]
        print(json.dumps({"fx": {"date": fx["date"], "source": fx["source"]}, "results": output}, ensure_ascii=False, indent=2) if args.json else render_text(output, fx))
        return 0 if output else 3
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"错误：{error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
