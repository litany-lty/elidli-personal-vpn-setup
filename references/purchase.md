# 报价复核与已付款接续

以下操作由助手完成。使用本机私有项目目录（例如先执行 `umask 077` 和 `mkdir -p "$private_dir"`，其中 `private_dir` 为实际用户数据目录），把一个购买项的状态保存为 `$private_dir/order.json`。状态只记录选定方案、非敏感报价和目标主机。多个商品逐一核价，向用户展示合计。不要保存登录凭据、支付信息、私人订单号或带登录参数的网址。

## 锁定用户选中的报价

```sh
python3 scripts/order.py --state "$private_dir/order.json" select --id "$offer_id" --country JP --kind vps --require static --traffic-gb 100
```

按实际要求传入 `--location` 和可重复的 `--require static|exclusive|isp|residential`，只有硬条件才传。`--kind` 必须与统一表一致：自管 VPS、ISP 主机和共享 IP VPS 使用 `vps`，单独的出口代理使用 `proxy`，托管 VPN 使用 `managed`；增购记录不能单独选择。保存价格所列套餐的数量和 IPv4 配置，默认一台主机或一个 IP。多件传 `--quantity`，已确认地址形态可传 `--ipv4 dedicated_public|provider_exit|shared|none`。多 IP、额外地址或多商品时在 `extras` 写明数量及各项总价。遇到旧 ID，运行 `scripts/resolve_offer.py OLD_ID --catalog references/providers.csv --aliases references/offer-id-aliases.json --country JP --json`；多个结果再按已确认机房定位。

从输出中的官方商品地址进入。核对机房、订购周期、确切型号、数量、地址类型、协议、库存、首付及所有必要附加费、续费、税、自动扣款、退款/取消。云主机以用户用量合计计算、磁盘、保留 IP、可能的流量费；有按目的地计价时使用实际传输方向。固定 IP 核对保留期限、停机/重建能否保留。关心自有地址时查看分配条款。若支付摘要需登录，用户登录后继续。页面仍无法访问就只交付已核项目和官方入口，保持“待核”。

## 记录已读到的官网信息

将界面中实际可见的值存入临时 `quote.json`。下段是格式示例，带尖括号处均须按证据替换；金额未知填 JSON null，金额可用十进制数字或字符串，0 只表示官方明确为零。国家用 ISO 两字母，币种用 ISO 三字母。SKU 和账期按目录同一含义规范化，例如 Monthly 对应「月付」。若页面中变成另一个产品或周期，必须记录实际值。source 填官方页面；保存状态时只保留其域名。供应商为统一表中的全称。

```json
{
  "provider": "ByteVirt", "sku": "<页面显示的 SKU>", "country": "JP", "location": "<所选机房>",
  "term": "月付", "currency": "USD", "kind": "vps", "quantity": 1, "ipv4": "dedicated_public", "billing": "prepaid", "available": true,
  "due_now": null, "renewal": null, "setup_fee": null, "auto_renew": null,
  "ip_terms": "<分配、保留、独享的明示条款>",
  "traffic_terms": "<额度、计量方向、超额处理>", "extras": "<数量、地址选项、税费、其他必选项及退款条款>",
  "requirements": {"static":"unknown"}, "effective_gb": null,
  "source": "https://bytevirt.com/store/jp-isp-vps"
}
```

只有商家证据确实支持该硬条件时，把 `requirements` 中对应项写为 `confirmed`。冲突用 `failed`，未知用 `unknown`。按可用于终端的月额度填 `effective_gb`；官方确实给出适用的不限量规则才可写 `unlimited_verified: true`。预付方案需填结账首期实价。按量云服务用 `billing: "metered"`，在 `extras` 和 `traffic_terms` 写明单价、用量、月总估算及计费起止；当场扣款未知保留 null。若用户给出严格预算，还需以完整复核总价核对用户原预算和首期上限。

```sh
python3 scripts/order.py --state "$private_dir/order.json" recheck --file "$private_dir/quote.json"
```

`conditions_unconfirmed` 显示尚未满足的硬条件；`unavailable` 表示所选方案不可订。继续查该商家的正式条款或请用户选择备选。成功复核时向用户提供本次首付、未来账单或变动计费规则和真实可点击的官网入口。出现 `quote_changed`，以一条消息列出实质差异；用户认可当前差异后，执行以下命令，fingerprint 取自这次差异。不要代用户接受。

```sh
python3 scripts/order.py --state "$private_dir/order.json" accept --fingerprint "$fingerprint"
```

## 已付款和已有主机

用户说「已经付钱」时先找当前订单状态，再从其主动提供的发票、商家门户或截图核对所购项目与服务页。已开通和到账是两个事实。若有既有选型，沿用该状态文件；从已购起步可以直接使用新的状态文件。收据字段使用上面的 provider、sku、country、term、currency、kind、source 与可见金额等，补上布尔值 `paid`、`active` 和服务页分配的公网 `host`，金额 `due_now` 在此处代表当期实付。`host` 只能是可公开路由的 IPv4 或公网主机名；部署前还会解析主机名并拒绝回环、私网、链路本地、保留或多播地址。还未分配地址时省略 host，后续用同一状态文件补录。门户的订单状态仅能证明所显示的事实。未取得回执，不推测已开通或默认年付。

```sh
python3 scripts/order.py --state "$private_dir/order.json" receipt --file "$private_dir/receipt.json"
python3 scripts/order.py --state "$private_dir/order.json" status
```

若原选月付、实付年付，`receipt_changed` 时只问「实际订单是年付，今天付了 ××。这是你主动选的吗？」已经明确答复过则沿用；执行本次 `accept` 后承接实际订单。核实已开通的单卖代理/托管服务走 `provider_setup`，按产品说明接入。自有 VPS 的 `ready` 可进入 SSH 配置。若是已有主机或按量后付资源，用户明确控制该活跃实例且授权配置，可用 `existing --owned --host HOST` 记录，无需捏造已付发票。

订单状态从 `awaiting_activation` 恢复时只复查这项服务；无需再推荐或重买。续费开关以账户页实际读回为准。用户要求关闭时仅变更其指明的自动扣费项，再刷新核对；先辨明“停止续费”和“立即删除服务”的区别。
