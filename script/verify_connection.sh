#!/bin/bash
set -euo pipefail
service='State:/Network/Service/io.github.ljste.openwarp/DNS'
iface="$(scutil <<< "show $service" | awk '/InterfaceName :/ {print $3}')"
[[ "$iface" == utun* ]] || { echo 'OpenWARP has no active tunnel DNS service.' >&2; exit 1; }
for address in 1.1.1.1 8.8.8.8 2606:4700:4700::1111 2001:4860:4860::8888; do
    family=-inet
    [[ "$address" == *:* ]] && family=-inet6
    actual="$(/sbin/route -n get "$family" "$address" | awk '/interface:/ {print $2}')"
    [[ "$actual" == "$iface" ]] || { echo "$address uses $actual, expected $iface." >&2; exit 1; }
done
resolver="$(scutil --dns | awk '/^resolver #[0-9]+/ {section++} section == 1 && /nameserver\[0\]/ {print $3}')"
case "$resolver" in 1.1.1.1|1.0.0.1|2606:4700:4700::1111|2606:4700:4700::1001) ;;
    *) echo "macOS selected an unexpected default resolver: $resolver" >&2; exit 1;;
esac
for address in '1.1.1.1' '[2606:4700:4700::1111]'; do
    trace="$(curl --noproxy '*' -fsS --max-time 12 --resolve "one.one.one.one:443:$address" https://one.one.one.one/cdn-cgi/trace)"
    grep -Eq '^warp=(on|plus)$' <<< "$trace" || { echo "Cloudflare did not confirm WARP for $address." >&2; exit 1; }
done
dscacheutil -q host -a name example.com | grep 'ip_address:' >/dev/null
echo "Verified $iface, macOS DNS, and Cloudflare WARP egress over IPv4 and IPv6."
