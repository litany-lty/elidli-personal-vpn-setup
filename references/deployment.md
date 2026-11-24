# Deployment contract

Use this path only after the user has bought or otherwise controls a Debian/Ubuntu VPS and explicitly authorized configuration of that host.

Run the deployment commands on macOS, Linux, or WSL with Python 3.10+ and the OpenSSH `ssh` client. Native Windows is not supported for the deployment step because local secret files and process locks use POSIX semantics. On Windows, install or open WSL and run the complete deployment and client-generation sequence there, keeping private state inside the WSL filesystem. The catalog and order commands use only the Python standard library. Client generation also uses only the standard library for a new profile. Reading or merging an existing YAML profile requires PyYAML; use the virtual environment described in [the quick start](../README.md).

## Supported in v1

- OpenSSH target or Host alias with a trusted host key. A custom port, identity file, or existing ControlMaster socket is accepted. Mind `ControlPersist` expiry on temporary sockets so post-deploy checks do not fall back to interactive host-key prompts.
- Root login, or a non-root account with passwordless `sudo -n`.
- Two isolated server protocols that can run alone or side by side on separate ports and `--service-id` units:
  - `ss` (default): Debian/Ubuntu `shadowsocks-libev` (`28447` TCP+UDP by default), compatible with both legacy Clash Premium / Clash for Android and Mihomo.
  - `hysteria2` (`--protocol hysteria2`, `28448` UDP by default): official `apernet/hysteria` binary verified against upstream `hashes.txt` via Python standard library (works on minimal cloud images without `curl` or `/usr/sbin` in non-login `PATH`), `16 MB` QUIC UDP kernel buffer sysctl (`/etc/sysctl.d/99-personal-vpn-quic.conf`), automatic IPv4-only direct outbound detection (`--outbound-mode auto-detect`, setting `direct.mode: 4` when `/proc/net/if_inet6` + `/proc/net/ipv6_route` show no global IPv6 egress so dual-stack targets such as Cloudflare challenges never fail with `dial tcp6: network is unreachable`), self-signed P-256 TLS cert with pinned SHA-256 `fingerprint`, and Brutal bandwidth hints (`--up-mbps 30 --down-mbps 150` by default) for high-packet-loss ordinary international ISP routes. An optional `--hop-ports` companion unit exists for advanced setups, but **leave `--hop-ports` off by default** for Mihomo clients behind Port-Restricted Cone NAT because single-source-port destination hopping triggers `nf_conntrack` reply-tuple and Cone NAT drops (`0.1–0.7 Mbps` throughput collapse); always verify multi-round 5 MB+ download throughput after any transport change. Requires Mihomo (Clash Meta / Clash Verge).
- One isolated systemd service named `personal-vpn-<service-id>`, a dedicated non-login service account, one private server config, and one local state file with mode `0600`. Deploying a parallel `hysteria2` unit never alters an existing `ss` port or unit.
- Mihomo Android full-device profile with TUN, fake-IP, proxied DoH, TCP and UDP (supports both `ss` and `hysteria2`). Classic Clash for Android requires `ss`. The user must grant Android VPN permission and enable always-on/block-without-VPN when that behavior is requested.
- Desktop domain routing as a private copy of an existing YAML. The original file is never overwritten. Load or select the generated copy in the matching Clash client, then verify the active rule and public exit.

Run `deploy.py plan` first, `inspect` for read-only OS/service discovery, then `deploy`. The deploy action is idempotent while its local state remains available. It refuses a state mismatch and never places the password in command arguments or normal output.

Before the first automated inspection, verify the server's SSH host-key fingerprint through the provider console or another trusted provider channel. Then connect once with normal OpenSSH so the verified key is saved in `known_hosts`. The scripts require strict host-key checking and will stop when the key is unknown or changes. Password prompts are not handled by the script. Use an SSH key, or establish an explicitly authorized ControlMaster session and pass its `--control-path`.

The default SSH operation timeout is 90 seconds. If the first package installation uses a slow mirror, pass a larger value such as `--timeout 300` to both inspection and deployment rather than repeatedly starting the same deployment.

For root login on a fresh Debian/Ubuntu VPS, set `vps_host` to the public address on the activated service receipt. Use `--remote-root` for both inspection and deployment. This path works on a minimal image without sudo. If the SSH login uses a custom port, pass the same `--port` on both commands.

```bash
: "${vps_host:?Set vps_host to the public host on the activated service receipt}"
python3 scripts/deploy.py inspect --target "root@$vps_host" --server "$vps_host" --service-id personal --remote-root
python3 scripts/deploy.py deploy --target "root@$vps_host" --server "$vps_host" --service-id personal --order private/order.json --remote-root
# Optional zero-cost parallel Hysteria2 unit for high-loss links on Mihomo / Clash Verge (leaves port 28447 untouched):
python3 scripts/deploy.py deploy --target "root@$vps_host" --server "$vps_host" --service-id personal-hy2 --protocol hysteria2 --listen-port 28448 --order private/order.json --remote-root
```

For a non-root SSH account replace `root@$vps_host` with its SSH alias or `user@$vps_host` and omit `--remote-root` from both commands. This path requires passwordless `sudo -n`. Use the appropriate client mode once the service is ready.

```bash
python3 scripts/client_config.py --state ~/.local/state/personal-vpn-setup/personal.json --mode mobile-cn-split --output private/phone.yaml
python3 scripts/client_config.py --state ~/.local/state/personal-vpn-setup/personal.json --mode desktop-domains --base ~/.config/clash/current.yaml --use-x --output private/desktop-x.yaml
```

In `mobile-cn-split`, keep the phone in Rule mode with VPN capture enabled. Local networks and local names go direct. For other destinations, mainland IP addresses go direct and the remaining traffic uses the selected outbound. Domain-specific service rules such as `--use-x` take precedence. Domestic DNS hints affect the resolver used for a name.

**Mihomo.** Domestic DNS-over-HTTPS uses `#DIRECT`. Foreign DoH uses the selected outbound. By default the client downloads `cn-ip.mrs` through that outbound, caches it and refreshes it daily. For a self-contained profile, pass `--cn-cidrs path/to/CIDRs.txt` with one trusted mainland IPv4 or IPv6 prefix per line. The generator embeds the list in the YML. Refresh that list and regenerate the profile when you need updated coverage. [Mihomo rule providers](https://wiki.metacubex.one/config/rule-providers/) · [Rule data](https://github.com/MetaCubeX/meta-rules-dat)

**Classic Clash for Android.** Add `--classic-android`. Two loopback TCP tunnels carry default DNS queries through the selected outbound. The last hop from the exit to the public resolver uses TCP port 53. Each domestic DNS policy takes one string and Android's `append-system-dns` is disabled. The client uses its Country.mmdb for `GEOIP,CN,DIRECT` and sends remaining connections to the outbound. When a proxy server uses a hostname, its exact DNS bootstrap entry lets the client reach the proxy before the tunnel is available.

For a classic group populated by a dynamic subscription, generate from a confirmed deployment state or an explicit node in the base profile. This gives the generator the proxy addresses it needs to bootstrap DNS.

A trusted local profile can supply extra classic DNS hints through `--classic-rules-from PATH`. It must identify a single named domestic group with `GEOIP,CN,<group>`. The generator reads that group’s `DOMAIN` and `DOMAIN-SUFFIX` entries. Credentials and nodes come from the selected state or base profile. Use `--only-node` when rebuilding from a base that contains unrelated nodes or subscriptions.

When the user explicitly keeps a Shadowsocks detour, classic Clash uses a TCP-only relay with the front node first and the final exit second. Mihomo uses `dialer-proxy`. With the backup selected, verify an HTTPS request through the front and the expected public exit. Make the front temporarily unreachable in a test copy and check that the request fails.

Use `mobile-global` when the user explicitly wants a proxy for every destination. When the user wants to retain the existing outbound choices, for a full-tunnel phone profile with TUN enabled, a DNS section, and one MATCH rule, the following migration preserves the proxy definitions and choices. Supply the actual original group name. Use a separate private output file.

```bash
python3 scripts/client_config.py --mode mobile-cn-split --base private/phone-old.yaml --name 'Original phone group' --output private/phone-split.yaml
```

### Single-exit phone

For “only my VPS” requests, build from that server's private deployment state. When the credentials are in an old profile, match the node against the user's server details and extract only the confirmed direct SS node by its exact name. This creates a fresh phone profile. Reapply the user's requested domain exceptions and select the client engine explicitly.

```sh
python3 scripts/client_config.py --mode mobile-cn-split --base private/old.yaml --only-node 'My direct VPS' --name 'My Japan exit' --classic-android --use-x --output private/phone-only.yaml
```

The only allowed traffic path for foreign destinations in a single-exit profile is through the selected node. Check the node list, group membership, final rule and observed public exit. A previously authorized relay for another device is a separate choice. When diagnosing speed, measure only approved paths and distinguish TLS handshake, first-byte latency, and sustained delivery of media.

### Peak-hour packet loss, mobile Mihomo migration, TUN benchmarking, and desktop cleanup

- **Diagnosing ISP-exit slowdowns & mobile CMFA migration.** Clean ISP/residential VPS plans often route back over ordinary international transit without China-optimized return paths. When server-local fetches take tens of milliseconds while client transfers suffer 30%–50% packet loss and heavy TCP retransmissions, single-stream TCP (`ss`) collapses even with BBR + fq—and legacy Clash for Android compounds the stall because its foreign DNS also rides loopback TCP tunnels. Deploy a parallel `hysteria2` unit (`--protocol hysteria2`) before suggesting paid transit add-ons; on Android, recommend migrating to official **Clash Meta for Android (`CMFA`, `arm64-v8a-release.apk` from `MetaCubeX/ClashMetaForAndroid` GitHub Releases)** or `FlClash` with an inline `--cn-cidrs` single-file profile (so first boot needs no external ruleset download) and per-app bypass (Access Control blacklist) for domestic high-traffic apps. Keep the `ss` unit running until all legacy clients have cut over.
- **Speed verification & Brutal pacing calibration.** Under mainland split routing, instruct users to test proxy throughput with foreign endpoints (`fast.com` or `speed.cloudflare.com`), never domestic speedtest apps/servers (which match `DIRECT` and measure local broadband). When Cloudflare CSV results show healthy idle latency (~100–120 ms), **upload notably faster than download** (typical asymmetric return-path congestion on ISP routes), and spiked loaded upload latency (`500–1900 ms` bufferbloat), lower Brutal `up`/`down` hints (for example `15 / 50 mbps` or `10 / 30 mbps`) rather than blasting 100+ Mbps into a narrow cross-border queue. When zero-cost `Hysteria2` achieves 0% timeouts and `3–4+ Mbps` (sufficient for AI chat, web, and 720p short video), advise using it before spending extra on paid front-end relays; add a pay-as-you-go relay or China-optimized VPS (`dialer-proxy`) only if sustained HD/4K throughput is required, and never use metered-egress cloud VMs (such as GCP) as media relays.
- **TUN isolation and SSH safety.** When a desktop client runs `TUN` (`utun`), bind any standalone test core directly to the physical interface (for example `interface-name: en0`) so benchmark packets do not traverse the active `utun` tunnel twice. Ensure the VPS public IP bypasses `TUN` (`IP-CIDR,<vps_ip>/32,DIRECT,no-resolve`) so reloading rules or closing connections (`DELETE /connections`) does not stall an active SSH `ControlMaster` session.
- **Single-exit desktop cleanup, Mihomo DNS anti-poisoning & CLI wrappers.** Before removing expired subscriptions or legacy fallback nodes from a desktop GUI (`profiles.yaml`, `dns_config.yaml`, legacy port configs), inspect user shell aliases and launcher scripts (`~/.zshrc`, `~/.local/bin`, `~/.local/libexec`) that wrap desktop AI/IDE apps (such as `chatgpt` or `gemini` launchers) or auto-regenerate proxy profiles on startup. Update their single source of truth and port helpers (`7897` vs legacy `7890`) so launching an app from the terminal does not overwrite the cleaned profile with deleted nodes. In Mihomo desktop `dns_config.yaml`, remember that **`fallback` / `fallback-filter` is ignored whenever `nameserver-policy` is non-empty**: set `dns.nameserver` to encrypted foreign DoH via the proxy group (`https://1.1.1.1/dns-query#<group>`) and keep domestic suffixes, `proxy-server-nameserver`, and `direct-nameserver` on domestic DoH so unlisted foreign sites never receive GFW-poisoned answers. When pinning multi-domain web apps (for example `muse.ai` backed by `meta.ai`, `meta.com`, `metaaiusercontent.com`, `ecto1usercontent.com`, and `facebook.com`), include their auth/asset suffixes ahead of `GeoIP:cn`. Always pass `--noproxy '*'` when calling `curl --unix-socket` against a local Mihomo control socket, and use `ConnectTimeout=25`, `ConnectionAttempts=3`, and `NumberOfPasswordPrompts=3` in temporary SSH `ControlMaster` helpers over high-loss links.

When X/Twitter is a stated purpose for the device, include `--use-x` with its chosen mode. The four domain suffixes (`twimg.com`, `x.com`, `twitter.com`, `t.co`) go to the selected group before mainland IP classification. The `twimg.com` suffix covers both image and video subdomains. For an existing Rule-mode profile use `--mode existing-rules --use-x --base private/current.yaml --name "Existing group" --output private/with-x.yaml`. Use repeated `--domain` only for other services the user actually requested, including their dedicated asset domains. Do not publish or hard-code a user's international domains, exit host or address. Check for existing direct/block exceptions before promoting a suffix. Then verify a target site, its media request, a non-target connection and the observed public exit in the intended client.

After deployment, `active,running` and both `tcp,udp` are required. Then load the generated profile in the intended client and verify the expected public exit. For a desktop split profile, also verify one non-target request retains its previous route. To recover before client cutover, keep using the original profile. If a same-name remote service replacement fails, the deployer restores and restarts the previous same-name unit; if a later manual rollback is required, use the provider console or SSH to stop `personal-vpn-<service-id>` and restore from your normal host backup procedure.

For an existing desktop profile in `direct` mode, the generated copy routes only the requested domains through the new node and keeps every other request direct. For an existing profile in `global` mode, pass `--base-default '<currently selected proxy or group>'`; the generated copy routes only the requested domains through the new node and sends all other traffic to that selected default. A `rule` profile keeps its existing rules. The output path is required to differ from both the private state and base file.

`deploy` requires the order file written by `order.py`. For purchased services it records paid and active status. For existing servers it records ownership and active status. The SSH destination must match the public host on the ready receipt, including when an SSH alias is used. Check the user's authorization for that host before deployment.

## Deliberate boundaries

- It does not reinstall the OS, alter SSH policy, open a firewall, remove another service, or buy/cancel/renew a product.
- If a provider firewall blocks the chosen port, ask the user to authorize the specific provider-side rule. Do not disable a host firewall globally.
- HTTP/SOCKS ISP proxy credentials can be expressed as Clash nodes using a mode-`0600` private JSON spec such as `{"kind":"socks5","server":"proxy.example","port":1080,"username":"...","password":"...","udp":true}`. A desktop domain profile can use HTTP or SOCKS5. A mobile-global profile is refused unless the spec explicitly confirms UDP. The proxy is not described as an encrypted VPN, and secrets remain outside the installed shared catalog.
- WireGuard, VLESS/Reality, router deployment, iOS-specific profiles, NAT-only VPS port mapping, dynamic DNS, credential rotation, and automatic provider control panels are future adapters.
- A parsed profile is static evidence. Completion requires the server service to be active, an actual client request to show the expected exit, and for split routing, one non-target request to retain its prior route. Phone receipt remains pending until the user checks the phone itself.

## Recovery

The original desktop YAML remains unchanged. Remote deployment stages new files, preserves any same-name config/unit during replacement, and restores the prior service when activation fails. Keep the local state file while the service exists; losing it requires an explicit credential-rotation workflow rather than silently replacing the remote secret.
