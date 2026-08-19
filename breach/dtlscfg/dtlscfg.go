// Package dtlscfg builds DTLS configs tuned to look like WebRTC media: a
// DTLS 1.2 handshake with the WebRTC cipher suite and the use_srtp extension,
// so each TURN stream is indistinguishable from a real call's DTLS-SRTP setup.
// Authentication is intentionally skipped — WireGuard inside provides the real
// crypto; DTLS here is for confidentiality + DPI mimicry.
package dtlscfg

import (
	"crypto/tls"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
)

var (
	cipherSuites = []dtls.CipherSuiteID{
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}
	srtpProfiles = []dtls.SRTPProtectionProfile{
		dtls.SRTP_AEAD_AES_128_GCM,
		dtls.SRTP_AES128_CM_HMAC_SHA1_80,
	}
)

func Server() (*dtls.Config, error) {
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, err
	}
	return &dtls.Config{
		Certificates:           []tls.Certificate{cert},
		CipherSuites:           cipherSuites,
		SRTPProtectionProfiles: srtpProfiles,
		ExtendedMasterSecret:   dtls.RequireExtendedMasterSecret,
		ReplayProtectionWindow: 16384,
	}, nil
}

func Client() *dtls.Config {
	return &dtls.Config{
		InsecureSkipVerify:     true,
		CipherSuites:           cipherSuites,
		SRTPProtectionProfiles: srtpProfiles,
		ExtendedMasterSecret:   dtls.RequireExtendedMasterSecret,
	}
}
