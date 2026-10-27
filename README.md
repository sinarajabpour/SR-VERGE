<h1 align="center">
  <img src="./src-tauri/icons/icon.png" alt="SR Verge" width="128" />
  <br>
  SR Verge
  <br>
</h1>

<h3 align="center">
A fast, easy proxy client for Windows, macOS and Linux, built on
<a href="https://github.com/MetaCubeX/mihomo">mihomo (Clash Meta)</a> and
<a href="https://github.com/tauri-apps/tauri">Tauri</a>. Tuned for users in Iran.
</h3>

<p align="center">
  <b>English</b> ·
  <a href="./docs/README_fa.md">فارسی</a>
</p>

## Preview

| Dark                                      | Light                                      |
| ----------------------------------------- | ------------------------------------------ |
| ![Dark preview](./docs/preview_dark.png) | ![Light preview](./docs/preview_light.png) |

## What is SR Verge?

SR Verge is a desktop app for connecting to the internet through proxy servers
(V2Ray / Xray / Clash nodes). You add a subscription link or paste a config
link, pick a server, and turn the connection on. You can send all of your
computer's traffic through the proxy, or only the apps and sites you choose.

SR Verge is a fork of [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev).
It keeps everything Clash Verge does and adds features for networks with heavy
filtering, especially in Iran.

## Download & install

Download the latest installer from the
[Releases page](https://github.com/sinarajabpour/SR-VERGE/releases/latest).

| System                  | File to download                        |
| :---------------------- | :-------------------------------------- |
| Windows 10/11 (64-bit)  | `SR.Verge_x.y.z_x64-setup.exe`          |
| macOS (Apple Silicon)   | `SR.Verge_x.y.z_aarch64.dmg`            |
| Linux (64-bit)          | `.deb` or `.rpm`           |

The installers are not code-signed, so your system may warn you the first time:

- **Windows:** if SmartScreen appears, click **More info → Run anyway**.
- **macOS:** drag SR Verge into *Applications*. If macOS says the app is
  damaged or can't be opened, run this once in Terminal:

  ```shell
  sudo xattr -r -d com.apple.quarantine "/Applications/SR Verge.app"
  ```

### Turning on TUN mode

TUN mode routes **all** traffic (including apps that ignore system proxy
settings) through SR Verge. It needs a small helper service:

1. Open **Settings → System Setting**.
2. Click the 🔧 (wrench) icon next to **Tun Mode** and enter your
   administrator password when asked. This installs the service.
3. Turn on the **Tun Mode** switch.

On **Windows** you can skip the service: right-click SR Verge → **Run as
administrator**, then turn on **Tun Mode**.

## Features

### Everything from Clash Verge

- Built on Rust and Tauri 2, so it's fast and light.
- Bundled [mihomo (Clash Meta)](https://github.com/MetaCubeX/mihomo) core,
  with an optional Alpha core.
- **System proxy** and **TUN (virtual network adapter)** modes.
- Rule, Global and Direct proxy modes, with visual proxy and rule editing.
- Profile management, Merge/Script enhancements and syntax hints.
- Live connections, traffic, logs and latency tests.
- Custom themes, tray icons and CSS injection.
- WebDAV backup and sync.

### New in SR Verge (not in Clash Verge)

| Feature | What it does |
| :--- | :--- |
| **V2Ray / Base64 subscriptions** | Imports V2Ray-style subscriptions (a Base64 or plain-text list of links, as served by Marzban, 3x-ui, Hiddify and most Iranian providers) and converts them to a Clash Meta profile automatically. Clash Verge only accepts Clash YAML. |
| **Every common link format** | `vless://` (REALITY, Vision), `vmess://` (v2rayN, Shadowrocket and Xray formats), `trojan://`, `ss://` (incl. Shadowsocks 2022 and obfs/v2ray-plugin), `ssr://`, `hysteria://`, `hysteria2://`/`hy2://` (incl. port hopping), `tuic://`, `anytls://`, `socks://` and `wireguard://`. Transports: TCP, HTTP header, WebSocket (incl. early data), HTTPUpgrade, HTTP/2, gRPC and XHTTP. |
| **Paste config links directly** | Paste one or more links (`vless://…`, `vmess://…`, etc.), even several on one line, or a raw Base64 blob, into the import box. No subscription URL needed. `clash://install-config`, `sub://` and `hiddify://import` links are unwrapped too. |
| **One broken server can't break the profile** | mihomo refuses a whole config when a single server is invalid. On import and update, SR Verge checks the profile with the core, skips the servers it can't use, and tells you which ones were skipped. |
| **Minimal Clash configs that actually route** | A Clash subscription that only lists `proxies` (no groups or rules) gets a server selector and routing rules, instead of silently sending everything DIRECT. |
| **Clear import errors** | A blocked or expired link (an HTML page) or a sing-box/Xray JSON config gets a message you can act on, instead of "invalid yaml". |
| **Duplicate-name fix** | Some providers ship several servers with the same name, which mihomo rejects. SR Verge renames duplicates on import so the profile loads. |
| **TUN DNS that works under filtering** | In TUN mode, server addresses are resolved with your system DNS first instead of blocked DoH servers (Cloudflare/Google). In Iran, servers now connect in TUN mode instead of timing out. |
| **One-click Iran routing** | Two buttons on the **Rules** page send Iranian sites and IPs **direct** while everything else uses the proxy: <br>• **Iran Direct**: uses the built-in geo data and works offline. <br>• **Iran Direct (Online List)**: adds a much larger Iranian domain list that updates in the background. |
| **Per-site and per-app routing** | Choose which websites or programs (e.g. `Telegram.exe`) skip the proxy or always use it. Local network traffic (router, NAS, localhost) stays direct, and a **DIRECT** option is added to the server list. |
| **Edit Rules & Global Rules editors** | Edit routing rules from the Rules page with a ready-to-use template and examples. Global rules apply to every profile and survive subscription updates. A rule that points at a group the current profile doesn't have is skipped (and logged) instead of breaking the whole profile. |
| **Working `prepend-rules` / `append-rules`** | These Global Extend Config keys are now applied correctly. Before this fix they were silently ignored. |
| **Reliable TUN service on macOS and Windows** | The bundled TUN helper service is pinned to the exact version the app speaks to (a mismatch caused "Install Service failed: IPC path not ready"), and reinstalling the service on Windows waits for the old one to be removed. |
| **No more freezes when offline** | Config validation now has a 20-second limit. Losing the connection no longer locks the app until a reboot. |
| **Persian (فارسی) interface** | Improved Persian translation with the Vazirmatn font. |
| **Quiet by default** | Upstream auto-update checks are off, so the app never replaces itself with Clash Verge. |

## Building from source

Install the [Tauri prerequisites](https://tauri.app/start/prerequisites/),
Node.js and pnpm, then run:

```shell
pnpm i
pnpm run prebuild
pnpm dev
```

Run the backend tests (link parsing, profile import/update and rules). To
also load the generated configs in the real core, point the tests at a mihomo
binary and a folder holding `geosite.dat` and `Country.mmdb`:

```shell
cargo test -p clash-verge
SR_VERGE_MIHOMO=/path/to/mihomo SR_VERGE_GEODATA=/path/to/geodata cargo test -p clash-verge
```

To publish a release, push a version tag (for example `v2.6.0`) or run the
**Release** workflow from the Actions tab. GitHub Actions builds the Windows,
macOS and Linux installers and publishes them as a release.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for more details.

## Acknowledgements

SR Verge is based on these projects:

- [clash-verge-rev/clash-verge-rev](https://github.com/clash-verge-rev/clash-verge-rev): the project SR Verge is forked from.
- [zzzgydi/clash-verge](https://github.com/zzzgydi/clash-verge): the original Clash Verge.
- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo): the proxy core.
- [tauri-apps/tauri](https://github.com/tauri-apps/tauri): the desktop app framework.

## License

GPL-3.0. See [LICENSE](./LICENSE).
