//go:build !sidecar_http && !js

// sni_tlsa_live (§15.5, D-MAIL-4; MAIL-M7-08): whether the SNI host's TLSA held this receiver's key when the message
// arrived, compared by SPKI as §12 publishes it, 3 1 1: DANE-EE, the SubjectPublicKeyInfo, its SHA-256. Labels read
// it for owner decision 135's operator rule. A lookup that fails or is cut leaves it false, which only weakens a
// label.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
)

// TLSA's fields for §12's records (RFC 6698, RFC 7218).
const (
	mailTlsaUsageDaneEe    = 3
	mailTlsaSelectorSpki   = 1
	mailTlsaMatchingSha256 = 1
)

// Whether _25._tcp.<sniHost> holds a 3 1 1 record of spkiSha256.
func (self *MailAuthChecker) checkTlsa(ctx context.Context, resolver *MailAuthResolver, sniHost string, spkiSha256 []byte) bool {
	if sniHost == "" || len(spkiSha256) != sha256.Size {
		return false
	}
	records, _, err := resolver.LookupTLSA(ctx, 25, "tcp", mailDnsName(sniHost)+".")
	if err != nil {
		return false
	}
	for _, record := range records {
		if record.Usage == mailTlsaUsageDaneEe && record.Selector == mailTlsaSelectorSpki &&
			record.MatchType == mailTlsaMatchingSha256 && bytes.Equal(record.CertAssoc, spkiSha256) {
			return true
		}
	}
	return false
}
