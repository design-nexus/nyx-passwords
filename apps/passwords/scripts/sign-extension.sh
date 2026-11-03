#!/usr/bin/env bash
# Builds the Firefox extension and has Mozilla sign it as an unlisted add-on (it doesn't
# appear in the public store), then keeps the signed package where installs leave it:
#   ~/.local/share/nyx-passwords/browser/signed/nyx-passwords-<version>-signed.xpi
#
# The AMO API key is read from the desktop keyring (service addons.mozilla.org, kind
# issuer and secret) and passed to web-ext only; it's never printed. Mozilla signs each
# version once, so raise the version in both manifests first.
#
#   apps/passwords/scripts/sign-extension.sh
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
dest="${XDG_DATA_HOME:-$HOME/.local/share}/nyx-passwords/browser/signed"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

out=$("$here/scripts/build-extension.sh" "$work/build" | tail -1)
mkdir "$work/src"
(cd "$work/src" && unzip -q "$out/nyx-passwords-firefox.xpi")
version=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["version"])' "$work/src/manifest.json")
if [[ -e "$dest/nyx-passwords-$version-signed.xpi" ]]; then
  echo "$version is signed already: $dest/nyx-passwords-$version-signed.xpi" >&2
  exit 1
fi

key=$(secret-tool lookup service addons.mozilla.org kind issuer) || { echo "no AMO API key in the keyring" >&2; exit 1; }
secret=$(secret-tool lookup service addons.mozilla.org kind secret) || { echo "no AMO API secret in the keyring" >&2; exit 1; }
WEB_EXT_API_KEY="$key" WEB_EXT_API_SECRET="$secret" npx --yes web-ext@10.8.0 sign --channel unlisted \
  --source-dir "$work/src" --artifacts-dir "$work/signed" 2>&1 | grep -v -i -e secret -e jwt -e issuer
unset key secret

mkdir -p "$dest"
install -m 644 "$work"/signed/*.xpi "$dest/nyx-passwords-$version-signed.xpi"
echo "$dest/nyx-passwords-$version-signed.xpi"
