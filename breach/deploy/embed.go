// Package deploy embeds the exit deployment scripts as Go strings so the app's
// one-tap provisioner (breach/mobile) can ship them to a fresh VPS over SSH
// without fetching anything from GitHub or needing Docker pre-installed. The
// same install.sh also rides inside the exit image (see deploy/Dockerfile); this
// embed keeps the app and the image on one source of truth.
package deploy

import _ "embed"

// InstallSh is deploy/install.sh — the fresh-VPS installer. It bootstraps Docker
// if missing, pulls the published exit image, starts the stack, opens the relay
// (+ management) port, and prints the client-config and management-handle blocks.
//
//go:embed install.sh
var InstallSh string
