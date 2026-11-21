#!/usr/bin/env python3
"""Resolve a current catalog row from a durable product anchor or legacy ID."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def normalized(value: str | None) -> str:
    return (value or "").strip().casefold()


def tokens(value: str | None) -> set[str]:
    return {part.strip().upper() for part in (value or "").split("|") if part.strip()}


def anchor_from_record_id(record_id: str) -> str | None:
    parts = record_id.split("-")
    if len(parts) >= 2 and parts[0] == "VPN" and parts[1].startswith("A"):
        return "-".join(parts[:2])
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="按稳定产品锚点、当前报价ID或旧版ID解析统一供应商表。"
    )
    parser.add_argument("reference", help="当前报价ID、产品锚点或旧版报价ID")
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--aliases", type=Path)
    parser.add_argument("--country", help="用户确认的 ISO 两字母地区代码，例如 JP、TW")
    parser.add_argument("--region", help="用户确认的机房、城市或地区文字")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args()

    with args.catalog.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))

    reference = args.reference.strip()
    if args.aliases and args.aliases.exists():
        alias_data = json.loads(args.aliases.read_text(encoding="utf-8"))
        reference = alias_data.get("legacy_to_current", {}).get(reference, reference)

    exact = [row for row in rows if row["报价记录ID"] == reference]
    anchor = anchor_from_record_id(reference)
    if exact:
        anchor = anchor_from_record_id(exact[0]["报价记录ID"])
        candidates = exact
    elif anchor:
        candidates = [row for row in rows if row["报价记录ID"].startswith(anchor + "-")]
    else:
        candidates = []

    if args.country:
        country = args.country.strip().upper()
        candidates = [row for row in candidates if country in tokens(row["覆盖国家/地区代码"])]
    if args.region:
        region = normalized(args.region)
        candidates = [row for row in candidates if region in normalized(row["机房/地区或同价组"])]

    result = {
        "input": args.reference,
        "resolved_reference": reference,
        "product_anchor": anchor,
        "match_count": len(candidates),
        "requires_region_confirmation": len(candidates) != 1,
        "matches": candidates,
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"product_anchor={anchor or ''} match_count={len(candidates)}")
        for row in candidates:
            print(
                "\t".join(
                    row[key]
                    for key in (
                        "报价记录ID",
                        "供应商",
                        "具体套餐或SKU",
                        "机房/地区或同价组",
                        "付款/计费周期",
                    )
                )
            )
    return 0 if candidates else 2


if __name__ == "__main__":
    raise SystemExit(main())
