//go:build mgmt

// Command breach-mgmt is the exit's management API daemon. It is compiled and
// shipped ONLY when the image is built with --build-arg MGMT=1 (which sets the
// `mgmt` build tag); with MGMT=0 this binary is absent from the image entirely.
//
// The entrypoint co-launches it (restart-supervised, so a mgmt crash never takes
// the tunnel down) and passes the listen address, state dir and advertised host
// as flags. See breach/mgmt for the API and its security model.
package main

import (
	"flag"
	"log"

	"breach/mgmt"
)

func main() {
	listen := flag.String("listen", ":48000", "TCP listen address for the HTTPS management API")
	confDir := flag.String("conf-dir", "/etc/breach", "state dir (mgmt secret/cert + the client registry)")
	binDir := flag.String("bin-dir", "/usr/local/bin", "dir holding provision-client/list-clients/remove-client/stats")
	advHost := flag.String("advertise-host", "", "public host/IP embedded in the handle URL the app connects to")
	clashPort := flag.Int("clash-port", 51822, "sing-box Clash API port on loopback (per-user Hysteria2 traffic)")
	flag.Parse()

	if err := mgmt.Run(mgmt.Options{
		Listen:        *listen,
		ConfDir:       *confDir,
		BinDir:        *binDir,
		AdvertiseHost: *advHost,
		ClashPort:     *clashPort,
	}); err != nil {
		log.Fatalf("breach-mgmt: %v", err)
	}
}
