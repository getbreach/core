# breach — MAX TURN tunnel

A `vk-turn-proxy`-style tunnel that carries arbitrary UDP (e.g. WireGuard)
through **MAX's TURN relays** instead of VK's. MAX and VK share the same OK calls
infrastructure (`videowebrtc.okcdn.ru`, coturn on `155.212.x:19302`), and MAX is
the state messenger that won't be blocked in RU — so its TURN makes a durable,
unblocked relay.

```
[WireGuard client]            breach-client                 MAX TURN          breach-server      [WireGuard server]
 127.0.0.1:51821  ──udp──>  mint creds (opcode 78)  ──┐   relay edges        plain UDP :48000  ──> 127.0.0.1:51820
                            pool of TURN allocations  ─┼─> 155.212.x:19302 ──>  (no TURN here)
                            shard / round-robin       ─┘   (ChannelData)
```

The **client** does all the TURN work (Allocate + ChannelBind to the server,
ChannelData transport, keepalive, re-mint). The **server** is a plain UDP relay:
packets arrive from MAX TURN relay addresses, it forwards them to local
WireGuard and fans replies back across the live relay streams.

## Mint modes

How the client obtains TURN credentials, chosen by `"mintMode"` in the config:

### `"silent"` (default, recommended)

Creates a group conference (opcode 76 — **rings nobody**) and joins it by link
(opcode 166); the join response carries the TURN creds. One account, no friend
disturbed, no `calleeId` needed.

```json
{
  "token": "<MAX login token>",
  "deviceId": "<spoofed device id>",
  "instanceId": "<instance id>",
  "clientSessionId": 118,
  "userAgent": { "deviceType": "ANDROID", "appVersion": "26.23.2", "osVersion": "Android 14",
                 "timezone": "Europe/Moscow", "screen": "420dpi 420dpi 1080x2340",
                 "pushDeviceType": "GCM", "arch": "arm64-v8a", "locale": "ru",
                 "buildNumber": 6779, "deviceName": "Google Pixel 7 Pro", "deviceLocale": "ru" },

  "mintMode": "silent",

  "server": "YOUR_VPS_IP:48000",
  "wgListen": "127.0.0.1:51821",
  "streams": 4,
  "mints": 1,
  "dns": "77.88.8.8:53"
}
```

`appVersion` / `buildNumber` / `arch` are not free-form: the anti-spoof
fingerprint (`mode` in authRequest, `chatCacheFingerprint` in login) is built
from the APK digests of that exact release and ABI, and `maxproto` only carries
digests for the builds listed in `apkBuilds` (`breach/maxproto/fingerprint.go`).
Announcing a version we have no digests for still authenticates, but the
fingerprint then contradicts the announced version. Add a build by copying its
entry from <https://hashes.pymax.org/versions.json> — `certificate_meta_sha256`,
`dex_meta_sha256` and `so_meta_sha256[arch]`.

### `"call"` (rings a friend)

Places a real 1:1 call (opcode 78) to `calleeId`; the call-setup response carries
the creds. The callee (a friend, ideally a throwaway second account) gets a brief
unanswered call at every mint (~every 8 h). Same config as above but:

```json
{
  "token": "…", "deviceId": "…", "instanceId": "…", "clientSessionId": 118,
  "userAgent": { … },

  "mintMode": "call",
  "calleeId": 43509532,

  "server": "YOUR_VPS_IP:48000",
  "wgListen": "127.0.0.1:51821",
  "streams": 4,
  "mints": 1,
  "dns": "77.88.8.8:53"
}
```

`dns` is needed on Android (no `/etc/resolv.conf`); `wgListen` is the local UDP
the WireGuard/Hysteria client targets. See `config.example.json`.

## Multiple clients on one server

One `breach-server` serves many independent clients. Each client tags every
packet with a random 8-byte clientID (inside SRTP); the server groups a client's
allocations and gives each client its **own backend socket**, so WireGuard sees
distinct source ports and replies route back to the right client. Downstream for
a client is fanned only across that client's own allocations — no cross-talk
(measured: two clients at once, ~1.5–3% loss each, no leakage).

To add a client: generate it a WireGuard keypair, add its pubkey as a peer on the
server's `wg0` (own `10.9.0.x/32`), and run `breach-client` with its own config
(ideally its own MAX account) pointing at the same `:48000`. The server
auto-demuxes — no per-client server config.

## Proven on live MAX infrastructure

- TURN relays UDP to an arbitrary peer (your VPS) — not restricted to call peers.
- Credential TTL ~8 h; allocation quota is **per credential** (~6–8), so scale by
  minting more creds. Each allocation sustains ~2.5 Mbit/s; streams aggregate
  linearly (4 streams ≈ 8 Mbit/s @ <1% loss).
- End-to-end through the full tunnel: 5.7 Mbit/s @ 0.8% loss over 4 allocations.

## Packages

- `maxproto/` — MAX packet protocol (TLS, msgpack, lenient LZ4) + `Mint()`
  (opcode 6 handshake → 19 login → 78 start-call → harvest TURN creds).
- `turn/` — minimal TURN client: `NewAlloc` (Allocate + ChannelBind), `Send`,
  `In()`, `Keepalive` (Refresh + rebind, stale-nonce recovery).
- `cmd/server`, `cmd/client`.

## Build

```bash
cd breach
go build -o bin/breach-server ./cmd/server
go build -o bin/breach-client ./cmd/client
```

## Run

**Config** — `config.json` (token +
spoofing profile + `calleeId` of a *friend* to call when minting). Each mint
briefly rings that friend; use a second account you control that auto-rejects.

**Server (VPS, public IP):**
```bash
./bin/breach-server -listen :48000 -wg 127.0.0.1:51820
# plus a WireGuard server listening on udp/51820
```

**Client (censored side):**
```bash
./bin/breach-client -config config.json -server <VPS_IP>:48000 \
    -wg-listen 127.0.0.1:51821 -streams 4 -mints 2
# point the WireGuard client's Endpoint at 127.0.0.1:51821
```

`-streams` = allocations per credential, `-mints` = credentials minted
(bandwidth ≈ mints × streams × ~2 Mbit/s, capped by the per-cred quota).

### WireGuard wiring notes

- WG **client** peer `Endpoint = 127.0.0.1:51821`; WG **server** listens on
  `udp/51820` (breach-server forwards both directions to it).
- **Avoid the routing loop:** breach-client talks to MAX TURN (`155.212.0.0/16`,
  `*.okcdn.ru`) directly — those must NOT be routed back into the WG tunnel.
  Exclude them from the client's default route (a more-specific route to the
  TURN edges via the physical gateway), or run breach-client in a netns.
- Set WG `MTU ≈ 1380` so `WG payload + 4 (ChannelData) + IP/UDP` stays under the
  path MTU to the TURN server.

## ROOT CAUSE (reverse-engineered): MAX throttles UNIDIRECTIONAL relay

Definitive finding from `cmd/throttletest` (self-contained client+counting peer,
fresh credential per run):

| Traffic on the allocation | Upstream delivered (sent 1000–1200 @ 100 pps) |
|---|---|
| one-way (peer silent) | ~8% — a hard **~8 packets/sec** cap |
| peer echoes ~2 pps back | ~39% |
| peer echoes ~10 pps back | ~90% |
| peer echoes everything (bidirectional) | ~100% |

- The cap is **packet-rate (~8 pps), size-independent** (64 B and 1400 B both cap at ~80 pkts).
- **Return traffic unlocks the forward direction** roughly proportionally; ~10–15 pps
  of return per allocation ≈ unthrottled.
- It is **per-allocation, per-direction**: MAX enforces that each relay path looks
  like a real (symmetric) call. A one-way flood is throttled to a trickle.

This is why a raw echo test (turnprobe, bidirectional) sustained 5.7 Mbit/s while
the DTLS tunnel collapsed: the server's round-robin downstream fan left individual
allocations under-fed on the return path, tripping the per-allocation throttle.

**The fix (next step, not yet wired):** keep every allocation bidirectional —
pin a flow's upstream and downstream to the *same* allocation, and/or run a
low-rate (~15–20 pps) padding/keepalive in *both* directions on each allocation.
Then DTLS (or raw) data flows freely. This is exactly why vk-turn-proxy keeps its
multi-stream tunnel symmetric.

## FIX APPLIED: raw data + per-allocation bidirectional keepalive

The data path is **raw ChannelData** (no DTLS — MAX throttles real DTLS
application-data, see below), and each allocation runs a low-rate (~20–50 pps)
keepalive in **both** directions. That keeps every allocation bidirectional, so
MAX's unidirectional throttle never engages. Result: upstream is consistently
~99% delivered; the tunnel sustained **~3 Mbit/s @ 8% loss at 400 pps / 4
streams** (on a non-degraded account).

We verified (cmd/throttletest, `-peerPad`) that **independent** return padding
unlocks the forward direction just as well as tightly-coupled echo — 100 pps
forward + 20 pps independent return ≈ 98% delivered. So the keepalive approach is
sufficient; the full kcp/smux stack vk-turn-proxy uses (where kcp ACKs supply the
return traffic for free) is **not required** for MAX.

### Two throttle tiers (reverse-engineered)

1. **Per-allocation, unidirectional** (~8 pps cap) — defeated by the bidirectional
   keepalive above.
2. **Account / IP level, escalating** — sustained high-rate relay abuse from one
   account progressively lowers the ceiling (a fresh account did ~200–500 pps
   clean; after an hour of heavy testing even a plain bidirectional relay dropped
   ~30% at 400 pps). This is MAX's higher-tier anti-abuse and is the real
   production ceiling. Mitigate by spreading load across accounts/IPs and not
   hammering a single credential.

### How vk-turn-proxy compares (from its sources)

`cacggghp/vk-turn-proxy` uses **real DTLS 1.2** (`pion/dtls/v3`) over
`pion/turn/v5` ChannelData, then **kcp + smux** per allocation; no keepalive (kcp
ACKs keep each stream bidirectional). Defaults `-n 10` streams, ~5 Mbit/s/stream,
WG MTU 1280, excludes `155.212.192.0/20`. It runs on **VK** TURN, where real DTLS
app-data is **not** throttled — unlike MAX (below).

## DTLS on MAX — throttled (do not use real DTLS app-data)

A DTLS session now runs over each TURN stream (`dtlscfg`, pion/dtls, per-stream,
WebRTC cipher + use_srtp extension). Handshakes succeed and small flows work, but
**throughput collapses — permanently — above ~5–25 pps per stream.** Extensive
isolation:

- NOT packet size / MTU — raw ChannelData of 1023–1280 B relays cleanly (cliff is >1300).
- NOT payload content — zeros, random, and DTLS-shaped payloads all relay cleanly.
- NOT pion — pion DTLS over loopback does 1000/1000 at 200 pps.
- NOT DTLS anti-replay — a 16384 window changes nothing.
- Loss is on the **wire**: client emits N (no send errors), only ~⅕ arrive at the
  server socket (counted with our own `ListenUDP`).

**Discovered:** MAX TURN **throttles per credential** under sustained relay abuse —
a fresh mint relays 200 pps cleanly; a hammered credential degrades to timeouts.
A fresh-mint *raw* stream does 200 pps, but a fresh-mint *DTLS* stream dies at
~25–100 pps. So MAX's anti-abuse trips on the DTLS/bidirectional pattern far more
aggressively than on raw relay — not yet fully reverse-engineered.

Leading hypothesis: real calls go DTLS-handshake → **SRTP** (RTP-framed, first
byte 0x80+); our streams send sustained bulk **DTLS application-data** (0x17),
which is anomalous for a call. Next experiment: after the handshake, carry tunnel
payloads inside **SRTP/RTP-shaped** packets instead of DTLS app-data.

The **non-DTLS tunnel works** (5.7 Mbit/s, §"Proven"). For now that's the usable
path; ChannelData already frames traffic as TURN media to a DPI box.

## Other v1 gaps

- Re-mint replaces the whole pool at once (brief overlap, no graceful drain).
- No congestion control / per-stream health scoring (round-robin is naive).
- `[stat]` diagnostic logging is still wired in client/server and `turn` counters.
