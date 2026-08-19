#!/bin/sh
# breach-exit installer — turns a fresh Linux VPS into a working exit.
#
# Installs Docker if missing, pulls the published image, drops a compose stack in
# /opt/breach, opens the relay port in ufw/firewalld, starts the exit and prints
# the first client's config block. Nothing is compiled on the server.
#
# It fetches NOTHING from GitHub: the compose files ride inside the image and are
# extracted from it, so this works fine with a PRIVATE repo. The only thing that
# must be reachable is the image itself.
#
# Getting this script onto the box (pick one):
#   scp breach/deploy/install.sh root@vps:  &&  ssh root@vps sh install.sh
#   # or, if the box already has docker and can pull the image:
#   docker run --rm --entrypoint cat ghcr.io/getbreach/breach-exit:latest \
#     /usr/local/share/breach/install.sh | sudo sh
#
# Private GHCR package? Pass a PAT with read:packages and it logs in for you:
#   sudo GH_USER=you GH_TOKEN=ghp_xxx sh install.sh
#
# Env (all optional):
#   PROTO=both|wg|hy2   RELAY_PORT=48000   HY2_SNI=www.bing.com
#   PUBLIC_ENDPOINT=ip:port                LOG_LEVEL=info
#   CLIENT=<name>       first client to provision (default: client1; "" to skip)
#   BREACH_IMAGE=ghcr.io/getbreach/breach-exit:latest
#   GH_USER / GH_TOKEN  GHCR credentials, if the package is private
#   DIR=/opt/breach     install location
set -eu

PROTO="${PROTO:-both}"
RELAY_PORT="${RELAY_PORT:-48000}"
HY2_SNI="${HY2_SNI:-www.bing.com}"
LOG_LEVEL="${LOG_LEVEL:-info}"
PUBLIC_ENDPOINT="${PUBLIC_ENDPOINT:-}"
KEEPALIVE_MS="${KEEPALIVE_MS:-50}"
BREACH_IMAGE="${BREACH_IMAGE:-ghcr.io/getbreach/breach-exit:latest}"
DIR="${DIR:-/opt/breach}"
CLIENT="${CLIENT-client1}"
GH_USER="${GH_USER:-}"
GH_TOKEN="${GH_TOKEN:-${GHCR_TOKEN:-}}"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root (sudo sh install.sh)"
case "$PROTO" in both|wg|hy2) ;; *) die "PROTO must be both|wg|hy2 (got '$PROTO')";; esac

# ---- docker ------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  say "installing Docker via get.docker.com"
  curl -fsSL https://get.docker.com | sh || die "Docker install failed — install it manually and re-run"
fi
systemctl enable --now docker >/dev/null 2>&1 || true
docker info >/dev/null 2>&1 || die "Docker daemon is not running"

if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DC="docker-compose"
else
  die "docker compose plugin missing — install docker-compose-plugin and re-run"
fi

# ---- registry auth (only needed if the GHCR package is private) --------------
if [ -n "$GH_TOKEN" ]; then
  # First path component is a registry host only if it looks like one (has a dot
  # or a port); otherwise the image is a bare/local tag and there's nothing to
  # log in to.
  case "$BREACH_IMAGE" in */*) REG="${BREACH_IMAGE%%/*}" ;; *) REG="" ;; esac
  case "$REG" in *.*|*:*) ;; *) REG="" ;; esac
  [ -n "$REG" ] || die "BREACH_IMAGE='$BREACH_IMAGE' has no registry host — drop GH_TOKEN"
  say "logging in to $REG"
  printf '%s' "$GH_TOKEN" | docker login "$REG" -u "${GH_USER:-x}" --password-stdin >/dev/null \
    || die "docker login to $REG failed — check GH_USER/GH_TOKEN (needs read:packages)"
fi

# ---- tun sanity (WireGuard half only) -----------------------------------------
OVERLAY=""
if [ "$PROTO" != hy2 ] && [ ! -e /dev/net/tun ]; then
  modprobe tun 2>/dev/null || true
  [ -e /dev/net/tun ] || die "no /dev/net/tun on this host — WireGuard can't run here; re-run with PROTO=hy2"
fi
if [ "$PROTO" = hy2 ]; then OVERLAY="-f docker-compose.hy2.yml"; fi

# ---- image -------------------------------------------------------------------
say "pulling $BREACH_IMAGE"
if ! docker pull "$BREACH_IMAGE" 2>/tmp/breach-pull.err; then
  # Already loaded locally (`docker save | ssh ... docker load`, or a local build)?
  # Then a failed pull is fine — an unreachable/private registry isn't fatal.
  if docker image inspect "$BREACH_IMAGE" >/dev/null 2>&1; then
    say "pull failed, but the image is already present locally — using it"
  else
    cat /tmp/breach-pull.err >&2
    if grep -qiE 'denied|unauthorized|not found' /tmp/breach-pull.err; then
      cat >&2 <<'EOF'

The image could not be pulled. A package pushed from a private repo is private
too — its visibility is separate from the repo's. Either:
  * make just the PACKAGE public (the source stays private):
    GitHub -> owner's Packages -> breach-exit -> Package settings
    -> Change visibility -> Public
  * or re-run with a PAT that has read:packages:
    sudo GH_USER=<login> GH_TOKEN=<pat> sh install.sh
  * or ship the image without a registry, from your machine:
    docker save breach-exit | gzip | ssh root@thisbox 'gunzip | docker load'
    then re-run with BREACH_IMAGE=breach-exit
EOF
    fi
    die "docker pull failed"
  fi
fi

# ---- stack (compose files come OUT OF THE IMAGE, not from GitHub) -------------
say "installing to $DIR"
mkdir -p "$DIR"
cd "$DIR"

extract() { # extract <name> — keep an existing file, never clobber local edits
  if [ -f "$1" ]; then say "keeping existing $1"; return 0; fi
  docker run --rm --entrypoint cat "$BREACH_IMAGE" "/usr/local/share/breach/$1" > "$1" \
    || { rm -f "$1"; die "could not extract $1 from $BREACH_IMAGE"; }
  [ -s "$1" ] || { rm -f "$1"; die "extracted an empty $1 from $BREACH_IMAGE"; }
}
extract docker-compose.yml
if [ "$PROTO" = hy2 ]; then extract docker-compose.hy2.yml; fi

if [ -f .env ]; then
  say "keeping existing .env (delete it to re-seed from env vars)"
else
  umask 077
  cat > .env <<EOF
BREACH_IMAGE=$BREACH_IMAGE
PROTO=$PROTO
RELAY_PORT=$RELAY_PORT
PUBLIC_ENDPOINT=$PUBLIC_ENDPOINT
HY2_SNI=$HY2_SNI
LOG_LEVEL=$LOG_LEVEL
KEEPALIVE_MS=$KEEPALIVE_MS
EOF
fi

# ---- firewall ----------------------------------------------------------------
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  say "ufw: allowing $RELAY_PORT/udp"
  ufw allow "$RELAY_PORT/udp" >/dev/null || true
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  say "firewalld: allowing $RELAY_PORT/udp"
  firewall-cmd --permanent --add-port="$RELAY_PORT/udp" >/dev/null || true
  firewall-cmd --reload >/dev/null || true
else
  say "no active ufw/firewalld — make sure udp/$RELAY_PORT is open (also in the VPS provider's panel)"
fi

# ---- run ---------------------------------------------------------------------
say "starting exit (PROTO=$PROTO, udp/$RELAY_PORT)"
# shellcheck disable=SC2086
$DC $OVERLAY up -d

i=0
while [ "$i" -lt 40 ]; do
  docker logs breach-exit 2>&1 | grep -q 'breach-exit: PROTO=' && break
  sleep 1; i=$((i+1))
done
docker logs --tail 20 breach-exit 2>&1 || true
[ "$(docker inspect -f '{{.State.Running}}' breach-exit 2>/dev/null)" = true ] \
  || die "container is not running — see: docker logs breach-exit"

# ---- first client -------------------------------------------------------------
if [ -n "$CLIENT" ]; then
  say "provisioning client '$CLIENT'"
  docker exec breach-exit provision-client "$CLIENT" || \
    say "provisioning failed (client may already exist) — run: docker exec breach-exit provision-client <name>"
fi

cat <<EOF

$(say "done — exit is live")

  add a user     docker exec breach-exit provision-client <name>
  list users     docker exec breach-exit list-clients
  revoke         docker exec breach-exit remove-client <name>
  traffic/load   docker exec breach-exit stats
  logs           docker logs -f breach-exit
  upgrade        cd $DIR && $DC $OVERLAY pull && $DC $OVERLAY up -d
  uninstall      cd $DIR && $DC $OVERLAY down -v   (-v also wipes keys/users)

Paste the config block above into the app (Deploy screen / manual profile).
EOF
