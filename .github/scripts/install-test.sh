#!/bin/sh
# Tests the message www/install.sh ends with (#102). Runs the real script with
# curl and systemctl replaced by stubs; needs no root and no network.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/stubs" "$tmp/bin"

# curl -fsSL -o FILE URL: a fake binary, and the checksum that matches it.
cat > "$tmp/stubs/curl" <<'STUB'
#!/bin/sh
while [ $# -gt 0 ]; do
  case $1 in -o) out=$2; shift ;; http*) url=$1 ;; esac
  shift
done
case $url in
  *.sha256) printf '%s  openbloxd\n' "$(printf 'fake openbloxd\n' | sha256sum | cut -d' ' -f1)" > "$out" ;;
  *) printf 'fake openbloxd\n' > "$out" ;;
esac
STUB
# systemctl answers from SERVICE: active, stopped (a unit that is not running)
# or none.
cat > "$tmp/stubs/systemctl" <<'STUB'
#!/bin/sh
case "$1:$SERVICE" in
  is-active:active) exit 0 ;;
  cat:active | cat:stopped) exit 0 ;;
  *) exit 1 ;;
esac
STUB
chmod +x "$tmp/stubs/curl" "$tmp/stubs/systemctl"

# The host's own tools, minus any real gh, systemctl or curl.
for tool in sh uname mktemp sha256sum cut install cp chmod mkdir rm printf head sed; do
  path=$(command -v "$tool") && ln -sf "$path" "$tmp/stubs/$tool"
done

fails=0
run() { # service state
  SERVICE=$1 PATH="$tmp/stubs" OPENBLOX_VERSION=v9.9.9 OPENBLOX_BIN_DIR="$tmp/bin" \
    sh "$here/www/install.sh" 2>&1
}
has() { # name, output, want
  case $2 in *"$3"*) printf 'ok   %s\n' "$1" ;;
    *) printf 'FAIL %s\n  want: %s\n  got:\n%s\n' "$1" "$3" "$2"; fails=$((fails + 1)) ;; esac
}
lacks() { # name, output, unwanted
  case $2 in *"$3"*) printf 'FAIL %s\n  must not say: %s\n' "$1" "$3"; fails=$((fails + 1)) ;;
    *) printf 'ok   %s\n' "$1" ;; esac
}

out=$(run active)
has   "upgrade on a running host says to restart" "$out" "sudo systemctl restart openbloxd"
has   "upgrade names the new version"             "$out" "to run v9.9.9"
lacks "upgrade does not claim it is not running"  "$out" "not running"
lacks "upgrade does not claim it is unconfigured" "$out" "not configured"

out=$(run stopped)
has   "a stopped service says to start it"         "$out" "sudo systemctl start openbloxd"
lacks "a stopped service is not called unconfigured" "$out" "not configured"

out=$(run none)
has   "a first install keeps today's text" "$out" "installed but not running, and it is not configured yet"
has   "a first install points at the docs" "$out" "https://docs.openblox.sh/production/"

rm "$tmp/stubs/systemctl"
out=$(run active)
has   "a host without systemctl gets the first-install text" "$out" "not configured yet"

[ "$fails" -eq 0 ] || { printf '%s failed\n' "$fails"; exit 1; }
