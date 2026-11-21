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
python3 scripts/client_config.py --state ~/.local/state/personal-vpn-setup/personal.json --mode desktop-domains --base ~/.config/clash/current.yaml --domain x.com --domain twitter.com --output private/desktop-x.yaml
```

For a mainland-China phone running Mihomo, use `mobile-cn-split` in the client's Rule mode. VPN capture stays enabled. Local networks, mainland domains and mainland destination IPs use DIRECT. Other destinations use the selected outbound. Known mainland domains resolve through direct domestic DoH. The default resolver for other domains uses the outbound. The public domain and IP rule sets download through the selected proxy on first import, are cached on the phone, and refresh daily while the client is running. Check that both providers load before accepting the profile. Use the Connections panel to check a mainland site and an overseas site separately. Routing depends on the matched domain or destination IP; services can use multiple domains. [Mihomo rule providers](https://wiki.metacubex.one/config/rule-providers/) · [Rule data](https://github.com/MetaCubeX/meta-rules-dat)

For classic Clash for Android, add `--classic-android` to `--mode mobile-cn-split`. This emits string-valued DNS policies, inline domestic domain rules, and a final GEOIP,CN direct rule followed by the selected proxy. The classic client uses its local Country.mmdb. If the user has a known working routing profile with a named mainland group targeted by GEOIP,CN, pass `--classic-rules-from PATH` to import its domestic domain, keyword and IP-prefix rules. Proxy credentials are taken only from the selected private state or base profile. When the original profile uses a Shadowsocks detour, classic files use a relay group with the front node first and the final exit second. This classic backup carries TCP only. A Mihomo file uses dialer-proxy for the same route. Test the form for its intended engine. With the backup selected, verify a public HTTPS request through the front with the expected fixed exit, then temporarily block the front in a test copy and check that the request fails. A matching public IP alone cannot establish the path.

Use `mobile-global` when the user explicitly wants a proxy for every destination. For an existing full-tunnel phone profile with TUN enabled, a DNS section, and one MATCH rule, the following migration preserves the proxy definitions and choices. Supply the actual original group name. Use a separate private output file.

```bash
python3 scripts/client_config.py --mode mobile-cn-split --base private/phone-old.yaml --name 'Original phone group' --output private/phone-split.yaml
```

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
