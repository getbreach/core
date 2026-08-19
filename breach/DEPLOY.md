# breach deployment

```
[WG client]              [breach-client]            MAX TURN          [breach-server]          [WG server]
 in RU         127.0.0.1:51821  (mints creds,   155.212.x:19302      VPS :48000  127.0.0.1:51820   on VPS
 wg0 ──────────────────> pool of allocations) ──relay──────────────> (plain UDP) ────────────────> wg0
   Endpoint=127.0.0.1:51821                                            (no MAX account needed)
```

## Accounts

- **Client:** one MAX account **A** (its login token + spoofing profile go in
  `config.json`) and the user-id of a **friend B** (`calleeId`). Minting places a
  brief call to B every ~8 h; use a throwaway B that is friends with A so nobody
  real is bothered. B runs nothing.
- **Server:** no MAX account.

## 1. Server (VPS abroad)

WireGuard server `wg0` (listens udp/51820), one peer = the client:

```ini
# /etc/wireguard/wg0.conf  (server)
[Interface]
Address = 10.9.0.1/24
ListenPort = 51820
PrivateKey = <SERVER_PRIV>

[Peer]                       # the client
PublicKey = <CLIENT_PUB>
AllowedIPs = 10.9.0.2/32
```

```bash
wg-quick up wg0
# enable NAT so client traffic reaches the internet:
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o eth0 -j MASQUERADE

./breach-server -listen :48000 -wg 127.0.0.1:51820
```

Open inbound **udp/48000** on the VPS firewall (the TURN relay delivers here).

## 2. Client (RU device)

`config.json` — MAX account A token + spoofing + friend B id (same shape as
`config.json`; `calleeId` = B's user id).

WireGuard client points at breach-client, **not** the VPS:

```ini
# wg client config
[Interface]
Address = 10.9.0.2/24
PrivateKey = <CLIENT_PRIV>
MTU = 1280                       # leave headroom for ChannelData/relay

[Peer]
PublicKey = <SERVER_PUB>
Endpoint = 127.0.0.1:51821       # <-- breach-client, the local tunnel mouth
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 15
```

```bash
./breach-client -config config.json -server <VPS_PUBLIC_IP>:48000 \
    -wg-listen 127.0.0.1:51821 -streams 4 -mints 1
wg-quick up wg-client
```

### CRITICAL: avoid the routing loop

The WG client routes `0.0.0.0/0` into the tunnel, but breach-client's own traffic
to MAX (`155.212.0.0/16` TURN + `api2.oneme.ru` for minting) must go out the
**physical** interface, or it loops into the tunnel and deadlocks. Pin those
routes to the real gateway:

```bash
GW=$(ip route show default | awk '/default/{print $3; exit}')
DEV=$(ip route show default | awk '/default/{print $5; exit}')
ip route add 155.212.0.0/16 via $GW dev $DEV          # MAX/OK TURN edges
ip route add $(getent ahostsv4 api2.oneme.ru | awk 'NR==1{print $1}')/32 via $GW dev $DEV
# add VPS_PUBLIC_IP/32 via $GW too if the server is reached over the internet
ip route add <VPS_PUBLIC_IP>/32 via $GW dev $DEV
```

(Run these after `wg-quick up`, or put them in `PostUp`/`PostDown`.)

## Tuning

- `-streams N` allocations per credential (~2.5 Mbit/s each), `-mints M`
  credentials (each rings B once). Bandwidth ≈ M × N × ~2.5 Mbit/s, but see the
  **account/IP throttle** in README — pushing one account too hard lowers its
  ceiling. Start with `-streams 4 -mints 1` and scale up cautiously.
- `-keepalive-ms` (default 50) — lower = more return padding = throttle stays
  open under more asymmetric load, at small overhead.

## Status

Prototype. Works (per-allocation throttle defeated), but: no graceful re-mint
overlap, naive round-robin, and the account/IP-level throttle is the real ceiling
(spread load across multiple accounts/IPs for sustained high bandwidth).
