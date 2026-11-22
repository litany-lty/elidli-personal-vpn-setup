# Deployment contract

Use this path only after the user has bought or otherwise controls a Debian/Ubuntu VPS and explicitly authorized configuration of that host.

Run the deployment commands on macOS, Linux, or WSL with Python 3.10+ and the OpenSSH `ssh` client. Native Windows is not supported for the deployment step because local secret files and process locks use POSIX semantics. On Windows, install or open WSL and run the complete deployment and client-generation sequence there, keeping private state inside the WSL filesystem. The catalog and order commands use only the Python standard library. Client generation also uses only the standard library for a new profile. Reading or merging an existing YAML profile requires PyYAML; use the virtual environment described in [the quick start](../README.md).

## Supported in v1

- OpenSSH target or Host alias with a trusted host key. A custom port, identity file, or existing ControlMaster socket is accepted.
- Root login, or a non-root account with passwordless `sudo -n`.
- Debian/Ubuntu package `shadowsocks-libev`, with AEAD methods compatible with legacy Clash Premium and Mihomo.
- One isolated systemd service named `personal-vpn-<service-id>`, a shared non-login service account, one private server config, and one local state file with mode `0600`.
- Mihomo Android full-device profile with TUN, fake-IP, proxied DoH, TCP and UDP. The user must grant Android VPN permission and enable always-on/block-without-VPN when that behavior is requested.
- Desktop domain routing as a private copy of an existing YAML. The original file is never overwritten. Load or select the generated copy in the matching Clash client, then verify the active rule and public exit.

Run `deploy.py plan` first, `inspect` for read-only OS/service discovery, then `deploy`. The deploy action is idempotent while its local state remains available. It refuses a state mismatch and never places the password in command arguments or normal output.

Before the first automated inspection, verify the server's SSH host-key fingerprint through the provider console or another trusted provider channel. Then connect once with normal OpenSSH so the verified key is saved in `known_hosts`. The scripts require strict host-key checking and will stop when the key is unknown or changes. Password prompts are not handled by the script. Use an SSH key, or establish an explicitly authorized ControlMaster session and pass its `--control-path`.

The default SSH operation timeout is 90 seconds. If the first package installation uses a slow mirror, pass a larger value such as `--timeout 300` to both inspection and deployment rather than repeatedly starting the same deployment.

For root login on a fresh Debian/Ubuntu VPS, set `vps_host` to the public address on the activated service receipt. Use `--remote-root` for both inspection and deployment. This path works on a minimal image without sudo. If the SSH login uses a custom port, pass the same `--port` on both commands.

```bash
: "${vps_host:?Set vps_host to the public host on the activated service receipt}"
python3 scripts/deploy.py inspect --target "root@$vps_host" --server "$vps_host" --service-id personal --remote-root
python3 scripts/deploy.py deploy --target "root@$vps_host" --server "$vps_host" --service-id personal --order private/order.json --remote-root
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

The only allowed traffic path for foreign destinations in a single-exit profile is through the selected node. Check the node list, group membership, final rule and observed public exit. A previously authorized relay for another device is a separate choice. When diagnosing speed, measure only approved paths and distinguish first-byte latency from sustained delivery of media.

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
