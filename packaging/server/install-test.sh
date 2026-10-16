#!/usr/bin/env bash
# Checks install.sh's Caddyfile handling without installing anything (no root, no network):
# a Caddyfile with other sites is never replaced, only gains one import line, and stays the same
# however often install.sh runs. Also how it tells that server.toml turns accounts on (which lifts
# the systemd unit's network limit). Run by the packaging lint workflow.
#
# Usage: packaging/server/install-test.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FAILED=0

main() { bash "$HERE/install.sh" --caddy-main "$1" ops@example.com; }
fail() { printf 'FAIL: %s\n' "$*" >&2; FAILED=1; }

# Missing: ours.
main "$WORK/none" >"$WORK/out"
grep -qx 'import figcraft-server.caddy' "$WORK/out" || fail "a new Caddyfile imports our site"
grep -q 'email ops@example.com' "$WORK/out" || fail "a new Caddyfile has the certificate email"

# The example site the package ships: replaced by ours.
printf '# The Caddyfile is an easy way to configure your Caddy web server.\n:80 {\n\troot * /usr/share/caddy\n\tfile_server\n}\n' >"$WORK/default"
main "$WORK/default" >"$WORK/out"
grep -q 'usr/share/caddy' "$WORK/out" && fail "the packaged example site is replaced"

# Someone else's sites: kept, one import added, and the next run changes nothing.
printf 'shop.example.com {\n\treverse_proxy 127.0.0.1:8080\n}\n' >"$WORK/theirs"
cp "$WORK/theirs" "$WORK/run1"
main "$WORK/run1" >"$WORK/run2"
grep -q 'shop.example.com' "$WORK/run2" || fail "the operator's site is kept"
[ "$(grep -c 'import figcraft-server.caddy' "$WORK/run2")" = 1 ] || fail "one import line is added"
main "$WORK/run2" >"$WORK/run3"
cmp -s "$WORK/run2" "$WORK/run3" || fail "running again leaves a Caddyfile with other sites as it is"
main "$WORK/run3" >"$WORK/run4"
cmp -s "$WORK/run3" "$WORK/run4" || fail "and again"

# Ours, run again: unchanged (it imports our site).
main "$WORK/none" >"$WORK/ours1"
main "$WORK/ours1" >"$WORK/ours2"
cmp -s "$WORK/ours1" "$WORK/ours2" || fail "our own Caddyfile stays the same"

# Accounts in server.toml: the server may reach identity providers.
accounts() { printf '%b' "$1" >"$WORK/server.toml"; bash "$HERE/install.sh" --accounts-on "$WORK/server.toml"; }
accounts 'listen = "127.0.0.1:47900"\n[auth]\nmode = "accounts"\n' || fail "[auth] mode = accounts"
accounts '[auth]\nadmins = ["a@b.c"]\nmode="accounts+links" # teams\n[[auth.provider]]\nid = "g"\n' || fail "accounts+links, no spaces, a comment"
accounts "[ auth ]\n\tmode = 'accounts'\n" || fail "single quotes, spaces and tabs"
accounts 'auth.mode = "accounts"\n' || fail "a dotted key at the top"
accounts 'listen = "127.0.0.1:47900"\n' && fail "no [auth]: no accounts"
accounts '[auth]\nmode = "links"\n' && fail "links mode: no accounts"
accounts '# mode = "accounts"\n[auth]\n# mode = "accounts"\nmode = "links"\n' && fail "comments don't count"
accounts '[e2e]\nmode = "accounts"\n' && fail "another section's mode doesn't count"
accounts '[auth]\nmode = "links"\n[[auth.provider]]\nmode = "accounts"\n' && fail "a provider's key doesn't count"

if [ "$FAILED" = 0 ]; then echo "install.sh Caddyfile handling and accounts detection: ok"; fi
exit "$FAILED"
