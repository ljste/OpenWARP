# OpenWARP

OpenWARP is an independent, open-source macOS menu-bar client for Cloudflare's consumer WARP service. It sends IPv4, IPv6, and default system DNS through an encrypted tunnel to Cloudflare. A native Swift menu and a Rust tunnel helper run independently of the official app.

On one M2 Pro Mac, the connected menu used about 19 MB and the helper used 3.3 MB, compared with 190 MB and 81 MB for the official client on the same Mac. These are snapshots of the macOS `top` MEM column while connected. Workload and macOS version affect the numbers.

## Install and connect

1. Install the Apple Silicon preview package from [Releases](https://github.com/ljste/OpenWARP/releases), or build a package on your Mac using the commands below. The preview installer is unsigned and unnotarized. The deployment target is macOS 14 or later. The tested hardware is Apple Silicon.
2. Disconnect any active VPN, then open **OpenWARP** in Applications. Click the shield in the menu bar and choose **Connect**. On first use, review the Cloudflare application terms and choose **Agree and Connect** to register a device identity.
3. Wait for **Connected**. OpenWARP tests DNS inside the tunnel, checks macOS routing and resolver selection, and requires Cloudflare to confirm WARP egress over both IPv4 and IPv6.

Choose **Settings > Connect at Login** from the shield menu to start OpenWARP and connect automatically when you log in. Choosing **Disconnect** or **Quit OpenWARP** in the menu releases the tunnel and allows ordinary networking. Installing the helper requires administrator approval. The helper accepts local connections from members of the Mac's admin group.

## Public Wi-Fi sign-in

With OpenWARP running and a connection requested, join the Wi-Fi network. If the hotspot requires sign-in, OpenWARP opens its login window automatically. Complete the form there. The window closes when the network grants access, and OpenWARP retries a failed tunnel connection. You can leave **Kill Switch** enabled throughout.

OpenWARP checks Wi-Fi on connection, on a Wi-Fi network change, and when a working tunnel drops. It checks the hotspot’s advertised portal API or Apple’s HTTP connectivity page directly over Wi-Fi. If the checks stay inconclusive after retries or the automatic login page fails to load, **Sign In to Wi-Fi…** appears in the shield menu. If a connection error appears at that point, you can also open the login window from the alert. **Done** requests a tunnel retry, and closing the window cancels sign-in. Choosing **Disconnect** stops automatic checks.

The sign-in window uses a temporary WebKit data store and a password-protected local proxy. The proxy binds DNS and web connections to Wi-Fi. The hotspot and sites loaded inside the window see the Wi-Fi connection’s public address. With the kill switch armed, other apps continue through WARP or stay blocked. When necessary, the sign-in service temporarily adds an interface-scoped route and removes it when the session ends. With the kill switch off, other software that explicitly binds to Wi-Fi can also use that route. The sign-in processes exit when the window closes, the parent app quits, or the ten-minute session expires.

OpenWARP supports intercepted HTTP sign-in pages and HTTPS captive-portal APIs advertised through DHCPv4 option 114. The window checks Apple’s captive-network test page when an advertised portal is unavailable. The proxy supports HTTP and HTTPS on ports 80, 443, 8000, 8080, 8443, 8843, and 8880. Portals requiring external apps, other ports, or interactive certificate exceptions may need a different sign-in method.

## Kill switch

**Settings > Kill Switch** is off on a fresh installation. Enable it while connected to arm it immediately, or while disconnected to arm it on the next connection. The setting applies to the whole Mac. Turning it on can interrupt existing connections because OpenWARP clears existing packet-filter states when arming.

| Event | With the kill switch enabled |
| --- | --- |
| Tunnel interruption, app crash, or helper crash | Ordinary IPv4, IPv6, and DNS traffic stays blocked. The tunnel can reconnect through its registered Cloudflare endpoints. |
| Choose **Disconnect** or **Quit OpenWARP** in the menu | Ordinary Internet access resumes. The switch stays checked and arms again on the next connection. |
| Restart the Mac while armed | The system launch daemon reapplies protection at startup, independently of login. The switch stays enabled across reboots. |
| Restart after a deliberate disconnect | Ordinary Internet access continues until the next connection, including a connection started by **Connect at Login**. |
| Want Internet access after a failure | Select **Settings > Resume Ordinary Internet** to pause protection, or uncheck **Kill Switch** to turn it off. |

The switch uses a dedicated anchor in the standard macOS packet filter (PF). While armed it also blocks ordinary LAN traffic. Exceptions cover loopback, the tunnel, UDP to the registered WARP endpoints for the root helper, the dedicated Wi-Fi sign-in service, and DHCP and IPv6 neighbor discovery for network setup. Boot-time protection starts when launchd restores the filter. Traffic before that point, external changes to PF, and third-party or customized firewall configurations are outside its guarantee.

For recovery from Terminal, a local Mac administrator can turn the setting off using the installed control service, even while the menu app is closed.

```sh
/Library/PrivilegedHelperTools/io.github.ljste.openwarp.tunnel kill-switch disable
```

If the control service is unavailable, run the same command with `sudo` to clear the OpenWARP filter directly.

## What the tunnel covers

OpenWARP implements **Traffic and DNS (UDP)** using MASQUE over HTTP/3 on UDP port 443. It registers a device public key through Cloudflare's HTTPS enrollment service, pins the returned tunnel peer's public key, and requires TLS 1.3 with the hybrid `P256Kyber768Draft00` key exchange. The Mac generates the device private key locally and stores it in an owner-only file in `~/Library/Application Support/OpenWARP/`. OpenWARP has no analytics or traffic logs. Cloudflare operates the network and resolves default system DNS. [Cloudflare's WARP modes](https://developers.cloudflare.com/warp-client/warp-modes/)

The tunnel captures ordinary Internet routes and sets the default macOS resolver to Cloudflare. The two tunnel endpoint addresses use the physical network. Local network routes, more-specific routes, and domain-specific DNS settings can take precedence. The first registration uses the existing network connection.

OpenWARP retries a lost connection while its helper is running. With the kill switch off, an app or helper exit returns the Mac to ordinary networking. This preview supports consumer UDP mode only. Enterprise Zero Trust enrollment, DNS-only modes, WARP+ account management, and TCP fallback are outside its scope. OpenWARP is an independent project and has no affiliation with Cloudflare.

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

Uncheck **Settings > Kill Switch** and **Settings > Connect at Login**, then quit OpenWARP. Remove the services and their installer receipt.

```sh
sudo launchctl bootout system/io.github.ljste.openwarp.portal
sudo launchctl bootout system/io.github.ljste.openwarp.guard
sudo launchctl bootout system/io.github.ljste.openwarp.tunnel
sudo rm -f /Library/LaunchDaemons/io.github.ljste.openwarp.portal.plist
sudo rm -f /Library/LaunchDaemons/io.github.ljste.openwarp.guard.plist
sudo rm -f /Library/LaunchDaemons/io.github.ljste.openwarp.tunnel.plist
sudo rm -f /Library/PrivilegedHelperTools/io.github.ljste.openwarp.tunnel
sudo dseditgroup -o delete -n . _openwarpportal
sudo pkgutil --forget io.github.ljste.openwarp.pkg
```

Move OpenWARP from Applications to the Trash. To discard the local device identity as well, remove `~/Library/Application Support/OpenWARP/`.

## License

OpenWARP is released under the [MIT license](LICENSE). The installed app includes third-party licenses in `Contents/Resources/ThirdPartyNotices.txt`.
