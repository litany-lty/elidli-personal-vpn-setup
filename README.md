# ELIDLI 个人 VPN 搭建助手 · Personal VPN Setup

一个可在 Codex 中使用的 Skill。告诉它预算、希望的出口地区以及各设备怎么分流，它会先查本地供应商表。选定套餐后，它核对官网实价；你自行付款，待主机开通，再由它配置你授权管理的服务器和客户端。已经买了主机，可以直接从已购订单开始。首轮选型和自检可在本机离线运行。

## 在 Codex 中开始

1. 下载[最新发布包](https://github.com/litany-lty/elidli-personal-vpn-setup/releases/latest/download/elidli-personal-vpn-setup.zip)，解压出 **elidli-personal-vpn-setup** 文件夹。只想给当前项目使用，就把它放进项目的 `.agents/skills/`。要在自己的所有项目使用，macOS/Linux 放入 `~/.agents/skills/`，Windows 放入 `%USERPROFILE%\.agents\skills\`。使用 GitHub 自动生成的源码 ZIP 时，把含有 `SKILL.md` 的那层目录命名为 `elidli-personal-vpn-setup`。
2. 检查最终路径以 `.agents/skills/elidli-personal-vpn-setup/SKILL.md` 结束。在 Codex 中输入 `$elidli-personal-vpn-setup`。若列表暂未刷新，重启 Codex。也可以把 ZIP 交给能操作本机文件的 Codex，说「把这个 Skill 安装到当前项目，然后帮我选方案」。[Codex 的 Skill 发现与安装说明](https://developers.openai.com/codex/skills/)
3. 直接说你的需求。例如「我在杭州用联通，每月最多 15 美元、约 100 GB，想要日本固定出口。手机国内直连、国外走日本，电脑只有 X 走日本。先查表，选定后再核价。」用英语或其他语言描述也可以。说「已经付款，继续」会从订单核对开始。

首次查表用 Python 3.10 或更高版本，只用标准库。可以随时把条件换成自己的国家、预算、用量和客户端。供应商库有覆盖范围，找不到符合硬条件的套餐时，会指出缺口。租用主机、保留 IP、流量或代理可产生商家费用，具体金额在付款前核对。

如已安装 Git，可在项目根目录直接安装当前发布版本。在本机新建技能目录后，执行：

```sh
git clone --depth 1 --branch v1.5.5 https://github.com/litany-lty/elidli-personal-vpn-setup.git .agents/skills/elidli-personal-vpn-setup
```

从旧版升级时，将名称为 `personal-vpn-setup` 的旧 Skill 目录移出 Codex 扫描路径，避免出现两个入口。既有服务器服务名和密钥状态目录沿用原有位置。

如果某台设备要用 X（Twitter），直接告诉助手，例如「手机刷 X 图片和视频，电脑只让 X 走日本」。助手会为相应设备自动把 X 和媒体域名放在国内 IP 判断之前。无需手动维护域名清单。对于点名的其他国外服务，也可参考本机已有分流配置，将站点和专属资源域名一起优先匹配；其余流量沿用已有策略。

手机选择国内外分流时，局域网和大陆公网 IP 直连，其余目的地走所选出口。国内常用域名清单用于选择 DNS。经典 Clash 使用本地 DNS 隧道，Mihomo `mobile-cn-split` 采用无状态国内 UDP DNS 与 `fake-ip` 远端代理解析（兼顾手机 Wi-Fi / 蜂窝切网不卡死），支持 `Hy2` 与同 IP `SS` 直接手动切换。Mihomo 默认自动更新大陆 IP 规则，也可从可信 CIDR 文本生成单文件配置。

**只用自己的节点也可以借鉴别人的规则。** 例如「手机国内直连、国外只走自己的日本 VPS。参考 iKuuu 的规则，X 优先」。助手会保留一个自有出口，参考配置仅提供域名分流。若直接从旧手机 YAML 重建，可以用 `--only-node` 指定已确认的自有节点。线路慢时，助手会在这个出口上区分选路等待与视频传输耗时。[单出口示例](references/deployment.md#single-exit-phone)

## 先试一次

从解压后含有 `SKILL.md` 的目录执行：

```sh
python3 tests/test_smoke.py
python3 scripts/recommend.py --country JP --ip-type isp --static required --budget 15 --budget-currency USD --traffic-gb 100 --max-months 1 --limit 1
```

Windows PowerShell 将开头的 `python3` 换成 `py -3 -X utf8`。自检输出 `PASS`，会说明本机执行了哪些项目。示例查询展示报价资料日期、原币首付、预算参考和仍待官网确认的项目。要求查表的用户无需 SSH 密钥、云账户或运行中的 VPN。

## 支持范围

| 目的 | 环境和要求 |
|---|---|
| 查价、读报价 ID 和记录订单 | Python 3.10+。macOS、Linux 和 Windows 原生可走此路径。已有服务的发票、账户和真实凭据保存在自己的数据目录。 |
| 自动部署自己的服务器 | 从 macOS、Linux 或 WSL 调用 OpenSSH。目标是有公网 IPv4、systemd 的 Debian/Ubuntu VPS，支持默认 `Shadowsocks` 及针对跨国高丢包普通线路的 `Hysteria2`（可独立端口无损并存）。先从商家控制台核对 SSH 主机指纹。root 登录时给检查与部署命令都加 `--remote-root`，普通账号使用免密 `sudo -n`。 |
| 生成手机和电脑配置 | 在 macOS、Linux 或 WSL 的私有目录生成。Windows 使用 WSL 时把密钥、订单和 YML 放在 WSL 的 Linux 文件系统。新配置只需标准库。读取已有 YAML、继承已有节点或域名规则需要 PyYAML。 |
| 手机实际使用 | Android 经典 Clash 与 Mihomo 各用对应配置。中国大陆常用方式是国内直连、国外走选定代理。明确选择链式备用时，经典 Clash 使用 TCP relay，Mihomo 使用 dialer-proxy。设备需要授予系统 VPN 权限并选择规则模式。iOS 和路由器需按具体客户端手动适配。 |
| 电脑按站点分流 | 可指定 X 或其他域名，只改变匹配站点的出口。已有桌面配置可生成独立副本，验收时应分别查看目标站点与普通站点的实际连接。 |

需要合并已有 YAML 时，在 macOS、Linux 或 WSL 上用独立 Python 环境安装可选依赖，例如：

```sh
python3 -m venv .venv
.venv/bin/python -m pip install "PyYAML>=6,<7"
```

之后用 `.venv/bin/python` 运行生成器，或告诉 Codex 使用该解释器。首次 SSH、root 和普通用户示例、客户端导入及回退步骤见[部署说明](references/deployment.md)。已付款但还没开通时见[订单接续](references/purchase.md)。

## 数据、升级与分发

公开数据在 `references/providers.csv`，覆盖 10 家供应商。每行保留采集日期和来源。首轮给目录估算；用户选定后，通过对应官网复核库存、账期、首付、续费和 IP 条款。真实线路质量与分配的出口 IP 需要在使用环境中验证。[数据来源与维护](references/data-sources.md)

升级时替换旧的 Skill 文件夹，避免同一个 Skill 在多个路径出现。卸载时移除该文件夹。已购买的主机和续费由供应商管理，服务器停用与取消续费是单独操作。维持订单状态及密钥的私有目录应放在 Skill 外。

维护者可在源码根目录运行 `python3 scripts/package_release.py`，默认产生 `dist/elidli-personal-vpn-setup.zip`。打包只收录列明的公共文件。如果把源码放在 GitHub 仓库根目录，可在 Actions 中手动运行 **Public smoke test**，让 Ubuntu、Windows 和 macOS 分别重建并自检发布包。分享这个 ZIP；为个人生成的 YML 内含代理凭据，应通过个人私有渠道传递。原创代码和说明采用 MIT 许可证。[LICENSE](LICENSE)

## English quick start

Download the [release ZIP](https://github.com/litany-lty/elidli-personal-vpn-setup/releases/latest/download/elidli-personal-vpn-setup.zip) and extract it into your project's `.agents/skills/` or your user's `~/.agents/skills/`. The final folder must be `elidli-personal-vpn-setup` with `SKILL.md` directly inside. Invoke `$elidli-personal-vpn-setup` in Codex and describe your devices, budget, monthly traffic and desired exit country in your own language. For example: “My phone should access mainland Chinese sites directly and use Japan for other sites. On my laptop only X should use Japan. Show me a monthly plan first.”

To use only your own VPS, state that constraint per device. A local reference profile can supply domestic DNS hints. Use the confirmed node as the sole outbound when the user wants a single exit.

From the extracted folder, run `python3 tests/test_smoke.py` to check the catalog and supported local workflows without credentials. On Windows use `py -3 -X utf8 tests/test_smoke.py`. Python 3.10+ is required. Use macOS, Linux or WSL for private profile generation and SSH deployment to your own Debian/Ubuntu VPS. The provider catalog is a dated snapshot. Pick an offer before checking live prices, pay the provider yourself, and verify your exit and routing on each device.
