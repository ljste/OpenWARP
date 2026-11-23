# OpenWARP

OpenWARP is an independent, open-source macOS menu-bar client for Cloudflare's consumer WARP service. It sends IPv4, IPv6, and default system DNS through an encrypted tunnel to Cloudflare. A native Swift menu and a Rust tunnel helper run independently of the official app.

On one M2 Pro Mac, the connected menu used about 19 MB and the helper used 3.3 MB, compared with 190 MB and 81 MB for the official client on the same Mac. These are snapshots of the macOS `top` MEM column while connected. Workload and macOS version affect the numbers.

## Install and connect

1. Install the Apple Silicon preview package from [Releases](https://github.com/ljste/OpenWARP/releases), or build a package on your Mac using the commands below. The preview installer is unsigned and unnotarized. The deployment target is macOS 14 or later. The tested hardware is Apple Silicon.
2. Disconnect any active VPN, then open **OpenWARP** in Applications. Click the shield in the menu bar and choose **Connect**. On first use, review the Cloudflare application terms and choose **Agree and Connect** to register a device identity.
3. Wait for **Connected**. OpenWARP tests DNS inside the tunnel, checks macOS routing and resolver selection, and requires Cloudflare to confirm WARP egress over both IPv4 and IPv6.

The menu offers **Disconnect** and optional **Connect at Login**. Quitting releases the tunnel. Installing the helper requires administrator approval. The helper accepts local connections from members of the Mac's admin group.

## What the tunnel covers

OpenWARP implements **Traffic and DNS (UDP)** using MASQUE over HTTP/3 on UDP port 443. It registers a device public key through Cloudflare's HTTPS enrollment service, pins the returned tunnel peer's public key, and requires TLS 1.3 with the hybrid `P256Kyber768Draft00` key exchange. The Mac generates the device private key locally and stores it in an owner-only file in `~/Library/Application Support/OpenWARP/`. OpenWARP has no analytics or traffic logs. Cloudflare operates the network and resolves default system DNS. [Cloudflare's WARP modes](https://developers.cloudflare.com/warp-client/warp-modes/)

The tunnel captures ordinary Internet routes and sets the default macOS resolver to Cloudflare. The two tunnel endpoint addresses use the physical network. Local network routes, more-specific routes, and domain-specific DNS settings can take precedence. The first registration uses the existing network connection.

OpenWARP retries a lost connection while its helper is running. When the app quits or the helper exits, macOS resumes ordinary networking. There is no persistent kill switch. This preview supports consumer UDP mode only. Enterprise Zero Trust enrollment, DNS-only modes, WARP+ account management, and TCP fallback are outside its scope. OpenWARP is an independent project and has no affiliation with Cloudflare.

## Build from source

Install the Xcode Command Line Tools, a current stable Rust toolchain with Cargo, CMake, and Python 3. From the repository root, run

```sh
./script/build_and_run.sh --package
open "dist/OpenWARP-$(uname -m).pkg"
```

The installer includes the menu-bar app, a socket-activated launchd helper, and dependency notices. Installing the package places the app in Applications. The QUIC implementation is Cloudflare's [quiche](https://github.com/cloudflare/quiche). The [usque project](https://github.com/Diniboy1123/usque) documents the consumer MASQUE protocol.

To check the current connection from the repository, run

```sh
./script/verify_connection.sh
```

The check reads the active tunnel interface and DNS configuration, inspects IPv4 and IPv6 routes, queries Cloudflare over HTTPS on both address families, and exercises the macOS system resolver.

## Uninstall

Turn off **Connect at Login**, quit OpenWARP, then remove the helper and its installer receipt.

```sh
sudo launchctl bootout system/io.github.ljste.openwarp.tunnel
sudo rm -f /Library/LaunchDaemons/io.github.ljste.openwarp.tunnel.plist
sudo rm -f /Library/PrivilegedHelperTools/io.github.ljste.openwarp.tunnel
sudo pkgutil --forget io.github.ljste.openwarp.pkg
```

Move OpenWARP from Applications to the Trash. To discard the local device identity as well, remove `~/Library/Application Support/OpenWARP/`.

## License

OpenWARP is released under the [MIT license](LICENSE). The installed app includes third-party licenses in `Contents/Resources/ThirdPartyNotices.txt`.
