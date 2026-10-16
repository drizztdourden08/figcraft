#!/usr/bin/env bash
# Build the browser version and zip it:  $DIST/figcraft-web-<version>.zip
#
# Usage: packaging/web/package.sh [--skip-build] [--server wss://host/] [--site DIR]
#
#   --server wss://host/  build the version a figcraft-server hosts: it works with that server
#                         only (next to local files), and the person can't add others. The zip is
#                         figcraft-web-<version>-<host>.zip. Without it, the build uses the default
#                         server (FIGCRAFT_DEFAULT_SERVER when set, else the project's).
#   --site DIR            also copy the site's files into DIR (emptied first), with .gz (and .br
#                         when brotli is installed) copies of the .wasm, .js and page: what you
#                         upload to the web root (docs/server.md, "Hosting the browser app").
#   --skip-build          package the last build (dist/web) again; with --server it must have been
#                         built for that server.
#
# Needs: trunk (brew install trunk / cargo install trunk --locked) and the wasm32-unknown-unknown
# target. The zip holds a self-contained static site in figcraft-web-<version>/ that works
# from any URL path and inside an <iframe>. Hosting notes: packaging/web/README.md.
set -euo pipefail
# shellcheck source=../env.sh
. "$(dirname "${BASH_SOURCE[0]}")/../env.sh"
HERE="$ROOT/packaging/web"

BUILD=1
SERVER=""
SITE_OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --skip-build) BUILD=0 ;;
    --server) SERVER="${2:-}"; shift ;;
    --server=*) SERVER="${1#--server=}" ;;
    --site) SITE_OUT="${2:-}"; shift ;;
    --site=*) SITE_OUT="${1#--site=}" ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "error: unknown option $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

SUFFIX=""
if [ -n "$SERVER" ]; then
  # wss://host/ or wss://host/path/ (ws:// only for trying it out on this machine).
  case "$SERVER" in
    wss://?*|ws://localhost*|ws://127.0.0.1*) ;;
    *) echo "error: --server takes the server's address, wss://host/ (got $SERVER)" >&2; exit 2 ;;
  esac
  case "$SERVER" in */) ;; *) SERVER="$SERVER/" ;; esac
  case "$SERVER" in *\?*|*\#*|*" "*) echo "error: --server takes the address without a key or anything after it" >&2; exit 2 ;; esac
  # The app bakes it in (crates/engine/src/live.rs, DEFAULT_SERVER); cargo rebuilds when it changes.
  export FIGCRAFT_DEFAULT_SERVER="$SERVER"
  HOST="${SERVER#*://}"; HOST="${HOST%%/*}"
  SUFFIX="-${HOST//[^A-Za-z0-9.-]/_}"
fi

SITE="$ROOT/dist/web"
# Which server the last build in dist/web was made for (empty: the default one).
BUILT_FOR="$SITE/.figcraft-server"
if [ "$BUILD" = 1 ]; then
  command -v trunk >/dev/null || { echo "error: trunk not found (cargo install trunk --locked)" >&2; exit 1; }
  (cd "$ROOT/apps/figcraft-web" && trunk build --release)
  printf '%s
' "${FIGCRAFT_DEFAULT_SERVER:-}" >"$BUILT_FOR"
elif [ -n "$SERVER" ] && [ "$(cat "$BUILT_FOR" 2>/dev/null)" != "$SERVER" ]; then
  echo "error: the last build wasn't made for $SERVER: run without --skip-build" >&2
  exit 1
fi

SITE="$ROOT/dist/web"
[ -f "$SITE/index.html" ] || { echo "error: $SITE/index.html missing; run without --skip-build" >&2; exit 1; }
# Paths must be relative so the site works under any prefix (public_url = "./" in Trunk.toml).
if grep -Eq '(src|href)="/[^/]' "$SITE/index.html"; then
  echo "error: $SITE/index.html has root-absolute URLs; it would break when served from a sub-path" >&2
  exit 1
fi

# Size gate: Cloudflare Pages/Workers reject any single file over 25 MiB, and other
# hosts and CDNs have similar caps. Fail well before that so a regression shows up here, not at
# upload time. Override with FIGCRAFT_WASM_MAX_BYTES only to investigate.
MAX_WASM_BYTES="${FIGCRAFT_WASM_MAX_BYTES:-25165824}" # 24 MiB
WASM_COUNT=0
for wasm in "$SITE"/*.wasm; do
  [ -f "$wasm" ] || continue
  WASM_COUNT=$((WASM_COUNT + 1))
  size=$(wc -c <"$wasm" | tr -d ' ')
  echo "$(basename "$wasm"): $size bytes ($((size / 1048576)) MiB; limit $MAX_WASM_BYTES)"
  if [ "$size" -gt "$MAX_WASM_BYTES" ]; then
    echo "error: $(basename "$wasm") is $size bytes, over the $MAX_WASM_BYTES-byte limit (Cloudflare's per-file cap is 25 MiB)" >&2
    exit 1
  fi
done
[ "$WASM_COUNT" -gt 0 ] || { echo "error: no .wasm in $SITE" >&2; exit 1; }

if [ -n "$SITE_OUT" ]; then
  mkdir -p "$SITE_OUT"
  case "$(cd "$SITE_OUT" && pwd)" in
    /|"$HOME"|"$ROOT") echo "error: --site $SITE_OUT would empty a folder that isn't only the site's" >&2; exit 2 ;;
  esac
  find "$SITE_OUT" -mindepth 1 -delete
  cp -R "$SITE/." "$SITE_OUT/"
  rm -f "$SITE_OUT/.figcraft-server"
  # Compressed copies for servers that send them as they are (Caddy's `precompressed`, nginx's
  # `gzip_static`): no compressing 20 MiB for every visitor.
  for f in "$SITE_OUT"/*.wasm "$SITE_OUT"/*.js "$SITE_OUT"/index.html; do
    [ -f "$f" ] || continue
    gzip -9 -k -f "$f"
    if command -v brotli >/dev/null; then brotli -q 11 -k -f "$f"; fi
  done
  echo "site files in $SITE_OUT${SERVER:+ (for $SERVER)}"
fi

NAME="figcraft-web-$VERSION$SUFFIX"
WORK="$CARGO_TARGET_DIR/web-package"
rm -rf "$WORK"
mkdir -p "$WORK/$NAME"
cp -R "$SITE/." "$WORK/$NAME/"
rm -f "$WORK/$NAME/.figcraft-server"
# Sample server configs (MIME type, caching, compression); harmless where unused.
cp "$HERE/_headers" "$HERE/.htaccess" "$WORK/$NAME/"
cp "$HERE/README.md" "$WORK/$NAME/HOSTING.md"
copy_docs "$WORK/$NAME"
rm -f "$DIST/$NAME.zip"
(cd "$WORK" && zip -qr9 "$DIST/$NAME.zip" "$NAME")
echo "wrote $DIST/$NAME.zip"
ls -lh "$DIST/$NAME.zip"

