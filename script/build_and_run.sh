#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mode="${1:-run}"
case "$mode" in run|--verify|--package) ;; *) echo 'usage: build_and_run.sh [--package|--verify]' >&2; exit 2;; esac
export MACOSX_DEPLOYMENT_TARGET=14.0
export CARGO_TARGET_DIR="$PWD/.build/cargo"
arch="$(uname -m)"
app="$PWD/dist/OpenWARP.app"
mkdir -p .build
stage="$(mktemp -d "$PWD/.build/pkg.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" "$stage/root/Applications" "$stage/root/Library/PrivilegedHelperTools" "$stage/root/Library/LaunchDaemons"
cargo build --locked --release --manifest-path core/Cargo.toml
xcrun swiftc -O -target "$arch-apple-macos14.0" App/*.swift -o "$app/Contents/MacOS/OpenWARP"
install -m 644 Packaging/Info.plist "$app/Contents/Info.plist"
install -m 644 LICENSE "$app/Contents/Resources/LICENSE"
target="$(rustc -vV | awk '/^host:/ {print $2}')"
python3 script/notices.py "$app/Contents/Resources/ThirdPartyNotices.txt" "$target"
codesign --force --sign - --identifier io.github.ljste.openwarp "$app"
ditto "$app" "$stage/root/Applications/OpenWARP.app"
install -m 755 "$CARGO_TARGET_DIR/release/openwarp-tunnel" "$stage/root/Library/PrivilegedHelperTools/io.github.ljste.openwarp.tunnel"
install -m 644 Packaging/io.github.ljste.openwarp.*.plist "$stage/root/Library/LaunchDaemons/"
pkgbuild --analyze --root "$stage/root" "$stage/components.plist"
plutil -replace 0.BundleIsRelocatable -bool NO "$stage/components.plist"
pkgbuild --root "$stage/root" --component-plist "$stage/components.plist" --scripts Packaging/scripts --ownership recommended --identifier io.github.ljste.openwarp.pkg --version "$(plutil -extract CFBundleShortVersionString raw Packaging/Info.plist)" --install-location / "dist/OpenWARP-$arch.pkg"
if [[ "$mode" != "--package" ]]; then
    if pgrep -x OpenWARP >/dev/null; then
        osascript -e 'tell application id "io.github.ljste.openwarp" to quit'
    fi
    open -n "$app"
    if [[ "$mode" == "--verify" ]]; then sleep 1; pgrep -x OpenWARP; fi
fi
