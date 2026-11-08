//go:build !sidecar_http

// The DNSSEC trust anchors dnssec_chain validates under: the root zone's key-signing keys, as DS
// records, embedded in the sidecar and updated by release (plan-SMTP-small-readings#2). The edge's
// chain can bring nothing that replaces them.
//
// DefaultSmtpDnssecAnchors holds every key of IANA's root-anchors file: KSK-2017 (key tag 20326) and
// KSK-2024 (key tag 38696), RSA/SHA-256 with SHA-256 digests. Their digests here were written from the
// published file without a copy of it on the build machine, so a release must check them against
// https://data.iana.org/root-anchors/root-anchors.xml; a wrong one fails closed, since no chain would
// then validate and TL1 would never be reached.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"encoding/hex"
	"fmt"
)

// The root's DS records a chain must reach. Immutable, and so safe for concurrent use.
type SmtpDnssecAnchors struct {
	ds []*smtpDnsDs
}

// IANA's root anchors, each as key tag, algorithm, digest type and hex digest.
var smtpDnssecRootAnchors = []struct {
	keyTag     uint16
	algorithm  uint8
	digestType uint8
	digest     string
}{
	// KSK-2017
	{keyTag: 20326, algorithm: smtpDnssecAlgorithmRsaSha256, digestType: smtpDnssecDigestSha256, digest: "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"},
	// KSK-2024
	{keyTag: 38696, algorithm: smtpDnssecAlgorithmRsaSha256, digestType: smtpDnssecDigestSha256, digest: "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"},
}

// The anchors a release embeds: every key of IANA's root-anchors file.
func DefaultSmtpDnssecAnchors() *SmtpDnssecAnchors {
	anchors := &SmtpDnssecAnchors{}
	for _, anchor := range smtpDnssecRootAnchors {
		digest, err := hex.DecodeString(anchor.digest)
		if err != nil {
			panic(err)
		}
		anchors.ds = append(anchors.ds, &smtpDnsDs{keyTag: anchor.keyTag, algorithm: anchor.algorithm, digestType: anchor.digestType, digest: digest})
	}
	return anchors
}

// Anchors from the root's DS records as uncompressed wire RRs, as a test's own root gives them
// (sidecartest.MxWorld.TrustAnchorDs). Each must be a DS owned by the root.
func NewSmtpDnssecAnchors(dsRrs ...[]byte) (*SmtpDnssecAnchors, error) {
	anchors := &SmtpDnssecAnchors{}
	for _, wire := range dsRrs {
		rrs, err := parseSmtpDnsRrs(wire, 1)
		if err != nil {
			return nil, err
		}
		if len(rrs) != 1 || rrs[0].owner != smtpDnsRoot || rrs[0].rrtype != smtpDnsTypeDs {
			return nil, fmt.Errorf("%w: an anchor is not the root's ds", ErrSmtpDnssecBogus)
		}
		ds, err := parseSmtpDnsDs(rrs[0].rdata)
		if err != nil {
			return nil, err
		}
		anchors.ds = append(anchors.ds, ds)
	}
	if len(anchors.ds) == 0 {
		return nil, fmt.Errorf("%w: no anchor", ErrSmtpDnssecBogus)
	}
	return anchors, nil
}
