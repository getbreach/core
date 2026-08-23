# breach-exit — one-container Breach tunnel exit

A single Docker image that terminates a Breach tunnel exit. `breach-server` decrypts
the MAX-TURN relay streams to plain UDP and feeds the inner-protocol server —
**WireGuard** *or* **Hysteria2** — which egresses to the internet.

```
WireGuard:  TURN relay --udp/48000--> [breach-server] --127.0.0.1:51820--> [wireguard-go wg0] --NAT--> internet
Hysteria2:  TURN relay --udp/48000--> [breach-server] --127.0.0.1:51820--> [sing-box hy2]     --direct--> internet
```

Both inner servers are **baked into the image**, independent of the host kernel:

- **WireGuard** is terminated by **`wireguard-go`** (userspace) — *not* sing-box.
  sing-box's `wireguard` endpoint is initiator-only; it never answers an inbound
  handshake, so it cannot be the exit's WG server. wireguard-go is a full
  responder. It uses a real `tun`, so the WG mode needs
  `--cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.ip_forward=1`.
- **Hysteria2** is terminated by **sing-box** (`hysteria2` inbound), which *does*
  work as a server. Capless — egresses via a `direct` outbound, Docker's bridge
  MASQUERADEs the return path.

The image is **prebuilt and published** — a server never compiles anything:

```
ghcr.io/getbreach/breach-exit:latest      # linux/amd64 + linux/arm64
```

`.github/workflows/exit-image.yml` builds and pushes it on every `main` push and
`v*` tag. Before a run goes green it smoke-tests the *pushed* image twice: once
`PROTO=hy2` (boots, provisions a user, the emitted block must be valid JSON) and
once `PROTO=both`, which is the mode that actually brings up `wg0` and sing-box's
`singtun` and so proves the WireGuard path.

## Size

**~59 MiB on disk, ~22 MiB to pull** (amd64; arm64 is ~5% smaller):

| Component | On disk | Pulled |
|---|---:|---:|
| sing-box (custom minimal build) | 31.2 MiB | 11.3 MiB |
| apk packages (24, incl. deps) | 10.9 MiB | 3.8 MiB |
| alpine:3.20 base | 8.4 MiB | 3.5 MiB |
| breach-server | 5.0 MiB | 2.0 MiB |
| wireguard-go | 3.1 MiB | 1.3 MiB |

sing-box is built here from source instead of copied from the official image,
with only `with_quic` (hysteria2) and `with_gvisor` (the tun stack) — the stock
binary ships every protocol and service upstream supports and is **71 MiB**. That
one change plus the `-minimal`/`-wg` apk subpackages takes the image from ~101 MiB
down to ~59 MiB. Details and the exact tags are in the Dockerfile's sing-box stage.

**This repo is private, and that's fine.** Nothing on the server is fetched from
GitHub: `docker-compose.yml`, the Hy2 overlay, `.env.example` and `install.sh`
all ship *inside the image* under `/usr/local/share/breach/`, and `install.sh`
extracts them from there. The only thing a server must reach is the image —
see [Private repo, private package](#private-repo-private-package).

## Install on a fresh VPS

Copy the script over and run it (it needs no repo checkout — it's one file):

```bash
scp breach/deploy/install.sh root@vps:
ssh root@vps sh install.sh
```

Or, on a box that already has Docker and can pull the image, skip the copy
entirely — the script lives in the image too:

```bash
docker run --rm --entrypoint cat ghcr.io/getbreach/breach-exit:latest \
  /usr/local/share/breach/install.sh | sudo sh
```

It installs Docker if missing, pulls the image, writes a compose stack to
`/opt/breach`, opens `udp/48000` in ufw/firewalld, starts the exit, and prints the
first client's config block. Tune it with env vars:

```bash
sudo PROTO=hy2 RELAY_PORT=48000 HY2_SNI=www.bing.com CLIENT=phoneA sh install.sh
```

`CLIENT=` (empty) skips provisioning. Re-running is safe: an existing `.env` and
`docker-compose.yml` are kept, and the state volume is never touched.

## Or by hand — compose

```bash
docker run --rm --entrypoint cat ghcr.io/getbreach/breach-exit:latest \
  /usr/local/share/breach/docker-compose.yml > docker-compose.yml
docker run --rm --entrypoint cat ghcr.io/getbreach/breach-exit:latest \
  /usr/local/share/breach/.env.example > .env            # optional, edit it
docker compose up -d
docker compose exec breach-exit provision-client phoneA
```

Hy2-only (no NET_ADMIN, no `/dev/net/tun`, no `ip_forward`) — add the overlay:

```bash
docker compose -f docker-compose.yml -f docker-compose.hy2.yml up -d
```

## Or by hand — plain docker run

One container serves **both protocols on the one UDP port** (breach-server sniffs
each client's first packet and dispatches it to wireguard-go or sing-box) and
**many users at once**. State (server keys, peers, Hy2 users, cert) lives in a
volume, so it survives restarts *and image upgrades*.

```bash
docker run -d --name breach-exit --restart unless-stopped --init \
  --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 \
  -p 48000:48000/udp \
  -v breach-data:/etc/breach \
  -e PROTO=both -e HY2_SNI=www.bing.com \
  ghcr.io/getbreach/breach-exit:latest
```

`PROTO=hy2` runs Hy2-only and needs none of the WG caps/sysctl. The caps/sysctl
are required whenever WG is enabled (`both`/`wg`).

## Private repo, private package

A package pushed from a private repo is **private too**, and its visibility is
*independent of the repo's* — you can publish the image while the source stays
closed. Three ways to get the image onto a server, pick one:

**1. Make just the package public** (simplest; source stays private).
GitHub → owner's **Packages** → `breach-exit` → *Package settings* → *Change
visibility* → **Public**. Then `docker pull` needs no credentials anywhere. What
leaks is the compiled `breach-server` binary, not the repo. (Org-level policy can
forbid public packages — then use 2 or 3.)

**2. Keep it private, log in on each server** with a PAT that has
`read:packages` (classic PAT, or a fine-grained one with *Packages: read*):

```bash
sudo GH_USER=<login> GH_TOKEN=<pat> sh install.sh     # installer logs in for you
# equivalently, by hand:
echo <pat> | docker login ghcr.io -u <login> --password-stdin
```

The token is stored in `/root/.docker/config.json` on that box — use a token
scoped to read-only package access, and revoke it when you retire the server.

**3. No registry at all** — ship the image over SSH from your machine:

```bash
cd breach/breach
docker build -f deploy/Dockerfile -t breach-exit .
docker save breach-exit | gzip | ssh root@vps 'gunzip | docker load'
ssh root@vps 'BREACH_IMAGE=breach-exit sh -s' < deploy/install.sh
```

The installer tries to pull first, but falls back to an image that's already
loaded locally — so a local-only tag like `breach-exit` just works. Build on the
same CPU architecture as the VPS (or `docker build --platform linux/amd64 …`).

## Build it yourself instead

Context is the breach module root (so the Go build sees `go.mod`):

```bash
cd breach/breach
docker build -f deploy/Dockerfile -t breach-exit .
```

Then point compose at it: `BREACH_IMAGE=breach-exit docker compose up -d`.

## Upgrade

```bash
cd /opt/breach && docker compose pull && docker compose up -d
```

Keys, peers, Hy2 users and the cert live in the volume, so clients keep working
across upgrades. Pin `BREACH_IMAGE` to a `v*` tag in `.env` if you'd rather not
track `:latest`.

## Per-user keys (multi-client)

Each user gets its **own** WireGuard keypair + `10.9.0.x` **and** its own
Hysteria2 password. Register one (applied live — WG peers hot, Hy2 reloaded; no
container restart):

```bash
docker exec breach-exit provision-client phoneA
```

```
===BREACH-CLIENT-CONFIG-BEGIN===
{"name":"phoneA","server":"203.0.113.7:48000","wireguard":{"privateKey":"...","peerPublicKey":"...","presharedKey":"...","address":"10.9.0.2/32"},"hysteria2":{"password":"...","sni":"www.bing.com","insecure":true,"alpn":["h3"]}}
===BREACH-CLIENT-CONFIG-END===
```

This block maps onto one app `ServerConfig` — **both** `wireguard.*` and
`hysteria2.*` filled, the user toggles protocol. MAX account fields
(token/deviceId/mint…) come from the app's saved `MaxAccount`. The app's
**Deploy over SSH** screen runs exactly this: ensure the container, then
`provision-client`, then create the profile.

`PUBLIC_ENDPOINT` and `HY2_SNI` are captured at first boot (in `meta`) so
`provision-client` can emit complete blocks.

## Environment

Env vars only **seed** a fresh state dir; once `/etc/breach` is populated they're
ignored (the volume is authoritative).

| Var | Default | Meaning |
|-----|---------|---------|
| `PROTO` | `both` | `both` / `wg` / `hy2` |
| `RELAY_LISTEN` | `:48000` | public UDP the TURN relay delivers to |
| `LOG_LEVEL` | `info` | `info` / `debug` / `trace` |
| `KEEPALIVE_MS` | `50` | breach-server per-stream keepalive |
| `PUBLIC_ENDPOINT` | autodetect via api.ipify.org | `ip:port` advertised to clients |
| `WG_SERVER_PRIVKEY` / `WG_PSK` / `WG_PEERS` | generated / generated / — | seed WG identity + peers (pubkeys) |
| `HY2_PASSWORD` / `HY2_SNI` | — / `www.bing.com` | seed a Hy2 user + the cert SNI |

## Firewall

Open inbound **udp/48000** on the VPS (the TURN relay delivers here). Nothing else
is needed — egress is plain outbound.

## Notes / rough edges

- WG uses userspace `wireguard-go` (a real tun), marginally slower than kernel
  `wg`, but the MAX-TURN throttle (~M×N×2.5 Mbit/s) is the real ceiling.
- The WG mode **requires** `--cap-add NET_ADMIN --device /dev/net/tun
  --sysctl net.ipv4.ip_forward=1`; without the sysctl the container logs a WARN
  and traffic won't egress. Hy2 mode needs none of these.
- Both protocols share one port via first-packet sniffing (QUIC fixed bit vs WG
  message type). Keep Hy2 **obfs off** in `both` mode — obfs hides the QUIC header
  the dispatcher reads. For obfs, run a Hy2-only exit on its own port.
- Adding a Hy2 user briefly bounces sing-box (auto-restarted by a wrapper); WG is
  a separate process and is untouched.
- Per-user **Hy2** traffic and online state come from sing-box's Clash API
  (loopback only, secret in `$CONF_DIR/clash-secret`), polled by `breach-mgmt`
  into `$CONF_DIR/hy2_stats`, which `stats` joins with the WireGuard numbers.
  So an image built with `MGMT=0`, or one run with `MGMT_ENABLE=0`, reports
  zeros for Hy2 clients — WireGuard is unaffected either way. Totals are
  integrated from a live snapshot, so a connection that opens and closes between
  two polls is missed: good enough to show data use, not billing-grade.
- Verified end-to-end on a real VPS (phone → MAX TURN → breach-server →
  wireguard-go/sing-box → internet), both protocols, multiple per-user keys.
