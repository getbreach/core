# syntax=docker/dockerfile:1
#
# breach-exit: one image that terminates a Breach tunnel exit.
#
#   TURN relay --udp/48000--> [breach-server] --127.0.0.1:51820--> [sing-box]
#                              (DTLS-SRTP ->                         inbound: wireguard endpoint / hysteria2 server
#                               plain UDP)                          outbound: direct -> internet
#
# sing-box terminates the inner protocol in userspace (gVisor stack) and egresses
# via a `direct` outbound, so the container needs NO kernel WireGuard module and
# NO NET_ADMIN -- Docker's bridge MASQUERADEs the return path.
#
# Ready-made images are published to ghcr.io/getbreach/breach-exit (linux/amd64 +
# linux/arm64) by .github/workflows/exit-image.yml, so a server never has to build.
# To build locally instead (context = the breach module root):
#   docker build -f deploy/Dockerfile -t breach-exit .
#
# ~59 MiB on disk / ~22 MiB to pull, mostly because sing-box is built here with
# only the two build tags this exit needs -- see the sing-box stage below.

# --- build breach-server (pure Go, no cgo) ---
# Runs on the BUILD platform and cross-compiles to the TARGET one: pure Go needs
# no emulation, so multi-arch buildx stays fast.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETARCH
ARG TARGETVARIANT
ENV CGO_ENABLED=0 GOOS=linux
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN GOARCH="$TARGETARCH" GOARM="${TARGETVARIANT#v}" \
    go build -trimpath -ldflags='-s -w' -o /out/breach-server ./cmd/server
# userspace WireGuard server impl (no host kernel module); pinned for reproducible
# images. Built from a throwaway module rather than `go install pkg@version`,
# because `go install` refuses a fixed output path when cross-compiling
# ("cannot install cross-compiled binaries when GOBIN is set").
RUN mkdir /wg && cd /wg && go mod init wgbuild >/dev/null \
 && go get golang.zx2c4.com/wireguard@v0.0.0-20260522210424-ecfc5a8d5446 \
 && GOARCH="$TARGETARCH" GOARM="${TARGETVARIANT#v}" \
    go build -trimpath -ldflags='-s -w' -o /out/wireguard golang.zx2c4.com/wireguard
# Optional management API (breach-mgmt). Built ONLY when MGMT=1, into a SEPARATE
# dir so the final stage can copy it with a single directory COPY that is a
# no-op when the dir is empty (Docker has no conditional COPY). MGMT=0 => the
# binary is never compiled and never lands in the image. The `mgmt` build tag
# gates every mgmt source file, so nothing of it links into breach-server either.
ARG MGMT=1
RUN mkdir -p /mgmt-out \
 && if [ "$MGMT" = "1" ]; then \
      GOARCH="$TARGETARCH" GOARM="${TARGETVARIANT#v}" \
      go build -tags mgmt -trimpath -ldflags='-s -w' -o /mgmt-out/breach-mgmt ./cmd/mgmt; \
    else echo "MGMT=$MGMT — breach-mgmt omitted from image"; fi

# --- build a MINIMAL sing-box (version still matches SINGBOX_PIVOT.md) --------
# The official binary carries every protocol and service sing-box supports
# (tailscale, naive/cronet, dhcp, acme, clash api, ccm/ocm...) and weighs ~71 MiB
# -- 70% of the whole image. This exit uses exactly two features:
#   with_quic   -> the hysteria2 inbound (without it: "QUIC is not included in
#                  this build" at startup)
#   with_gvisor -> the tun inbound's "stack": "gvisor" that WG egress rides on.
#                  NOTE: `sing-box check` does NOT catch a missing with_gvisor --
#                  the config validates and only fails when the tun actually
#                  starts. Don't drop it.
# badlinkname/tfogo_checklinkname0 + -checklinkname=0 are what upstream ships
# (release/DEFAULT_BUILD_TAGS_OTHERS + release/LDFLAGS); dropping them breaks the
# go:linkname usage in tfo-go and the TLS record code.
# Result: 31.2 MiB instead of 71.0 MiB, same behaviour for our config.
#
# with_clash_api -> the Clash API, which is how `stats` gets per-user Hysteria2
#                  traffic and online state (WireGuard has `wg show`; Hy2 has
#                  nothing without an API). Costs ~0.4 MiB. breach-mgmt polls
#                  /connections on loopback and accumulates per-user totals.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS singbox
ARG TARGETARCH
ARG TARGETVARIANT
ARG SINGBOX_VERSION=v1.13.13
ARG SINGBOX_TAGS="with_quic,with_gvisor,with_clash_api,badlinkname,tfogo_checklinkname0"
ENV CGO_ENABLED=0 GOOS=linux
# rebuild-singbox.sh ALWAYS emits an experimental.clash_api block, and sing-box
# refuses to start when that key is present in a build without the tag ("clash
# api is not included in this build"). That failure is nasty in production: the
# container still prints its banner and the healthcheck still passes, while both
# Hy2 and WireGuard egress are dead. Refuse to produce such an image at all.
RUN case ",$SINGBOX_TAGS," in \
      *,with_clash_api,*) ;; \
      *) echo "FATAL: SINGBOX_TAGS must include with_clash_api (the generated sing-box config always sets experimental.clash_api)"; exit 1 ;; \
    esac
RUN apk add --no-cache git
RUN git clone --depth 1 -b "$SINGBOX_VERSION" https://github.com/SagerNet/sing-box /sb
WORKDIR /sb
# The Clash API knows which Hy2 user a connection belongs to (the hysteria2
# inbound puts it in InboundContext.User), but its JSON serializer drops the
# field -- the metadata map it emits has nine keys and `user` is not one of them.
# Add it, so traffic can be attributed without inferring the user from routing
# rules. Verified after patching: a missing/renamed anchor must FAIL the build
# rather than silently produce an image whose stats are always empty.
RUN sed -i 's|\("processPath":[[:space:]]*processPath,\)|\1\n\t\t\t"user":            t.Metadata.User,|' \
      experimental/clashapi/trafficontrol/tracker.go \
 && grep -q '"user":            t.Metadata.User,' experimental/clashapi/trafficontrol/tracker.go \
 || { echo "FATAL: clashapi tracker.go patch did not apply -- per-user Hy2 stats would be silently empty"; exit 1; }
RUN GOARCH="$TARGETARCH" GOARM="${TARGETVARIANT#v}" \
    go build -tags "$SINGBOX_TAGS" -trimpath \
      -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=${SINGBOX_VERSION#v}' \
                -X 'internal/godebug.defaultGODEBUG=multipathtcp=0' \
                -checklinkname=0 -s -w -buildid=" \
      -o /out/sing-box ./cmd/sing-box

# --- final image ---
FROM alpine:3.20
# Deliberately the -minimal/-wg subpackages: the scripts only ever call `ip` and
# `wg` (no wg-quick, no tc/ss), and the full packages drag in bash + openresolv +
# ncurses for nothing (~2.5 MiB).
#   wireguard-tools-wg = `wg` (genkey/pubkey/genpsk/setconf/set/show)
#   iproute2-minimal   = `ip` (+ rt_tables, needed for `ip rule ... table 100`)
#   iptables           = MSS clamp + FORWARD policy   openssl = the Hy2 cert
#   procps             = `pkill`/`pgrep` -- alpine's busybox ships NEITHER applet,
#                        so this one can't be dropped (sing-box reload needs it)
#   curl               = best-effort public-IP detect
RUN apk add --no-cache wireguard-tools-wg iproute2-minimal iptables openssl procps ca-certificates curl
COPY --from=build   /out/breach-server      /usr/local/bin/breach-server
COPY --from=build   /out/wireguard          /usr/local/bin/wireguard-go
COPY --from=singbox /out/sing-box           /usr/local/bin/sing-box
# breach-mgmt if built (empty dir => copies nothing when MGMT=0).
COPY --from=build   /mgmt-out/              /usr/local/bin/
COPY deploy/entrypoint.sh        /usr/local/bin/entrypoint.sh
COPY deploy/breach-lib.sh        /usr/local/bin/breach-lib.sh
COPY deploy/provision-client.sh  /usr/local/bin/provision-client
COPY deploy/remove-client.sh     /usr/local/bin/remove-client
COPY deploy/list-clients.sh      /usr/local/bin/list-clients
COPY deploy/stats.sh             /usr/local/bin/stats
COPY deploy/set-routes.sh        /usr/local/bin/set-routes
COPY deploy/rebuild-singbox.sh   /usr/local/bin/rebuild-singbox.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/provision-client \
             /usr/local/bin/remove-client /usr/local/bin/list-clients /usr/local/bin/stats \
             /usr/local/bin/set-routes /usr/local/bin/rebuild-singbox.sh
# The deployment files ride INSIDE the image, so a server never fetches them from
# GitHub -- which matters when the repo is private (raw.githubusercontent 404s).
# install.sh extracts them with:
#   docker run --rm --entrypoint cat $IMAGE /usr/local/share/breach/docker-compose.yml
COPY deploy/docker-compose.yml     /usr/local/share/breach/docker-compose.yml
COPY deploy/docker-compose.hy2.yml /usr/local/share/breach/docker-compose.hy2.yml
COPY deploy/.env.example           /usr/local/share/breach/.env.example
COPY deploy/install.sh             /usr/local/share/breach/install.sh
LABEL org.opencontainers.image.title="breach-exit" \
      org.opencontainers.image.description="Breach tunnel exit: MAX-TURN relay -> WireGuard (wireguard-go) / Hysteria2 (sing-box) -> internet" \
      org.opencontainers.image.source="https://github.com/getbreach/core" \
      org.opencontainers.image.licenses="MIT"
EXPOSE 48000/udp
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
