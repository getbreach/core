# Breach

Tunnel arbitrary UDP (WireGuard, Hysteria2, …) through **MAX messenger's TURN
relays**, disguised as a WebRTC call. The MAX equivalent of `vk-turn-proxy`:
MAX and VK share the same OK calls infrastructure (`videowebrtc.okcdn.ru`, coturn
on `155.212.0.0/16`), and MAX is the state messenger that won't be blocked — so
its TURN makes a durable, unblocked relay.

```
[WireGuard/Hysteria]      breach-client            MAX TURN            breach-server      [WG/Hysteria server]
   (censored side)   mint creds + pool of      155.212.x:19302         VPS :48000           (uncensored side)
        ──udp──>      DTLS-SRTP streams    ──relay (ChannelData)──>   decrypt → backend ──> internet
```

Everything here was built by reverse-engineering MAX's packet protocol and its
TURN behaviour from a custom MAX client. **For educational / research use.**

## Components

| Dir | What |
|-----|------|
| `turnprobe/` | TURN relay probe + throughput/throttle benchmark used to reverse-engineer MAX's anti-abuse. |
| `breach/` | The tunnel: `breach-client` (mints creds, opens a pool of DTLS-SRTP streams over TURN allocations) and `breach-server` (plain UDP endpoint → WireGuard/Hysteria). |
| `docs/` | Reverse-engineered MAX calls API (opcodes, ws2 signalling, TURN params). |

## How it works (reverse-engineered)

1. **Mint** — login (opcode 6 → 19), start a 1:1 call (opcode 78) to a friend;
   the call-setup response carries `turn{urls,username,credential}` (TTL ~8 h).
   The callee is never answered — it's only there to satisfy the call API.
2. **Relay** — open TURN allocations with those creds and `ChannelBind` to the
   server; shove tunnel traffic through as ChannelData.
3. **Anti-throttle** — MAX caps *unidirectional* relay to ~8 pps; a low-rate
   bidirectional keepalive on every allocation keeps it unthrottled. The
   allocation quota is per-credential (~6–8), so scale by minting more creds.
4. **Masking** — each allocation runs a real **DTLS handshake then SRTP-AEAD**
   media, so the wire trace is exactly a WebRTC call (sustained DTLS app-data is
   throttled by MAX; SRTP media is not).

## Quick start

**Server (VPS abroad)** — nothing to build; the exit container (breach-server +
wireguard-go + sing-box/Hysteria2) is published to GHCR as
`ghcr.io/getbreach/breach-exit`:

```bash
scp breach/deploy/install.sh root@vps: && ssh root@vps sh install.sh
# prints a ready client block; add more users with:
ssh root@vps docker exec breach-exit provision-client phoneB
```

See [`breach/deploy/README.md`](breach/deploy/README.md) for compose, env vars,
Hy2-only mode, upgrades, and pulling the image while this repo stays private.
Running the pieces by hand instead:

```bash
# server: WireGuard on udp/51820 + NAT, then
cd breach && go build -o bin/breach-server ./cmd/server
./bin/breach-server -listen :48000 -wg 127.0.0.1:51820

# client (censored side): get a MAX token by SMS, then fill in the rest
go build -o bin/breach-client ./cmd/client
./bin/breach-client -login +7XXXXXXXXXX > config.json   # asks for the SMS code
# add "server"/"wgListen" (and a friend's id for mintMode "call") to config.json
./bin/breach-client -config config.json
```

`-login` prints a ready config block with a long-lived LOGIN token bound to a
freshly generated device identity — keep `token`, `deviceId` and `instanceId`
together, a new identity means a new SMS. An existing token still works: copy
`breach/config.example.json` and paste it in instead.

See `breach/DEPLOY.md` for the full WireGuard wiring (incl. the routing-loop
exclusion) and `breach/README.md` for the throttle/protocol details. Android runs
the client in Termux (`GOOS=android` build) + the WireGuard app with Termux excluded.

## Status

Working prototype: proven end-to-end on real MAX infrastructure (Android phone →
MAX TURN → VPS → internet). Rough edges: single-client server (downstream is
round-robined), naive scheduling, no graceful re-mint overlap.
