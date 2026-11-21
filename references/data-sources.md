# Data sources and maintenance

This file documents the bundled public catalog. It does not contain private orders, account data, proxy credentials, server addresses, or device profiles.

## What is bundled

- `providers.csv` is a point-in-time compilation of publicly visible product facts. The current snapshot contains 1,396 records from 10 providers and was checked on 2026-11-21. Every row retains its quote, specification, policy, inventory, and location source fields when those sources were available.
- `fx.json` contains the European Central Bank reference rates dated 2026-11-20. They are used only for offline budget screening. Checkout currency, taxes, payment fees, and the provider's live total remain authoritative.
- `offer-id-aliases.json` is generated from the catalog. It maps the previous catalog IDs to stable product anchors and current record IDs. It is not provider data.

The catalog is an initial index for narrowing candidates. It is not a live inventory service, a complete market census, or a promise of speed, IP reputation, residential access, platform acceptance, tax, refund eligibility, or continued availability. The selected SKU, region, billing term, address type, traffic accounting, initial charge, renewal charge, and required add-ons must be checked again on the provider's official site before payment.

## Provider sources

The row-level URLs in `providers.csv` are the detailed provenance. These official entry points summarize the source families used for the snapshot.

| Provider | Primary public sources |
|---|---|
| ByteVirt | [store](https://bytevirt.com/index.php?m=bvstore), [Japan ISP VPS](https://bytevirt.com/store/jp-isp-vps), [traffic documentation](https://help.bytevirt.com/en/docs/billing/traffic/) |
| xTom / V.PS | [locations](https://v.ps/locations/), [documentation](https://v.ps/docs/), [FAQ](https://v.ps/faq/) |
| AWS Lightsail | [pricing](https://aws.amazon.com/lightsail/pricing/), [regions](https://docs.aws.amazon.com/lightsail/latest/userguide/understanding-regions-and-availability-zones-in-amazon-lightsail.html), [static IPs](https://docs.aws.amazon.com/lightsail/latest/userguide/understanding-static-ip-addresses-in-amazon-lightsail.html) |
| Google Cloud | [Compute pricing](https://cloud.google.com/products/compute/pricing), [E2 machine types](https://docs.cloud.google.com/compute/docs/general-purpose-machines#e2_shared-core), [Cloud SKUs](https://cloud.google.com/skus) |
| Vultr | [plans API](https://api.vultr.com/v2/plans?per_page=500), [regions API](https://api.vultr.com/v2/regions?per_page=500), [bandwidth accounting](https://docs.vultr.com/support/platform/billing/how-are-bandwidth-caps-calculated) |
| Akamai Cloud / Linode | [compute types API](https://api.linode.com/v4/linode/types), [compute pricing](https://www.akamai.com/cloud/pricing/cpu), [network transfer](https://techdocs.akamai.com/cloud-computing/docs/network-transfer) |
| DigitalOcean | [Droplet pricing](https://www.digitalocean.com/pricing/droplets), [pricing details](https://docs.digitalocean.com/products/droplets/details/pricing/), [bandwidth billing](https://docs.digitalocean.com/platform/billing/bandwidth/) |
| Hetzner Cloud | [cloud products](https://www.hetzner.com/cloud/), [Primary IPs](https://docs.hetzner.com/cloud/servers/primary-ips/overview/), [billing FAQ](https://docs.hetzner.com/cloud/billing/faq/) |
| IPRoyal | [ISP proxy pricing](https://iproyal.com/pricing/isp-proxies/), [ISP proxies](https://iproyal.com/isp-proxies/), [protocol support](https://help.iproyal.com/en/articles/7222110-what-protocols-do-isp-proxies-support) |
| Surflare | [pricing](https://www.surflare.com/welcome/pricing/), [Japan locations](https://www.surflare.com/locations/japan), [Taiwan locations](https://www.surflare.com/locations/taiwan) |

Currency conversion source: [ECB euro foreign exchange reference rates](https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml).

## Refresh procedure

1. Read each affected provider's current official page, API, product configurator, billing documentation, and refund or cancellation terms. Do not reuse authenticated URLs, session parameters, account-only order values, or user-specific discounts.
2. Update the relevant row fields and `公开资料核对日期`. Preserve an unknown value as empty or `待核`. Do not infer a first payment, renewal amount, static-IP guarantee, residential classification, inventory, or complete cloud total from a monthly average or component price.
3. Regenerate stable IDs with the catalog builder. Price, inventory, and check-date changes must not alter the product anchor. Region-scope changes may alter the record suffix, so regenerate the legacy mapping too.
4. Refresh `fx.json` from the ECB source and record its actual publication date. If the rate file cannot be refreshed, keep the prior dated values and tell the user that conversion is a dated estimate. The CLI also accepts a caller-supplied `--fx` file or a budget in a currency already present in the bundled file.
5. Validate the CSV schema, row count, unique record IDs, URL schemes and hostnames, old-ID mapping, offline recommendation scenarios, and derived spreadsheet. Run the public smoke test from a freshly extracted package.
6. Recheck the selected candidate live before a user pays. A catalog refresh never replaces this step.

There is no automatic catalog updater in this release. If a source disappears or its meaning becomes ambiguous, keep the last snapshot date visible, mark the affected facts as unverified, and remove the row from actionable recommendations until it is confirmed again.

## Privacy and redistribution boundary

The public package must exclude passwords, private keys, subscription URLs, controller secrets, personal IP addresses, SSH aliases, account emails, customer IDs, invoices, screenshots, device profiles, browser sessions, signed URLs, and absolute user paths. Only the explicit package allowlist may be shipped.

The repository's MIT license covers the original code and documentation. The provider names, factual product observations, and linked source material remain attributable to their respective sources. The source terms for redistributing provider material were not separately audited for this snapshot, so maintainers should keep the compilation factual, retain provenance, and avoid copying protected page content beyond what is needed to identify and compare an offer.

## 中文维护摘要

预置表是带日期的公开资料快照，用于首轮筛选。它不是实时库存、全网完整排名或效果保证。用户选定后，必须回到官网复核地区、SKU、账期、IP 类型、流量、首付、续费和必选附加项。公开包只允许包含公共表、来源、脚本和说明，不能包含任何个人订单、账号、节点、密码、设备配置或会话链接。MIT 许可证适用于原创代码与说明，供应商名称、事实和链接仍归各自来源。
