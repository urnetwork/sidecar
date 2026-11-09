//go:build !sidecar_http

// TL1 (§14.4, D-SMTP-2): DANE for SMTP (RFC 7672) over the edge's dnssec_chain, which
// smtp_dnssec_chain.go validates to the sidecar's own anchors on its own clock. Only DANE-EE (3) and
// DANE-TA (2) records are usable; PKIX-TA (0) and PKIX-EE (1) are ignored (RFC 7672 §3.1.3), as are
// unknown selectors and matching types. DANE-EE matches the leaf alone and ignores its names and
// expiry (RFC 7672 §3.1.1); DANE-TA matches a CA certificate the MX presented, which then anchors an
// ordinary chain check of the leaf for the MX host or the recipient domain, expiry included (§3.1.2).
//
// The outcomes, and what the caller (SmtpTlsPolicy, SMTP-M9-06) does with each:
//
//   - Authenticated: TL1.
//   - NotApplicable: the chain proves no TLSA, an insecure path, or TLSA records none of which is
//     usable, so DANE does not apply and TL2 and TL3 follow under the pin rule.
//   - Bogus: the chain does not validate, which is no authentication at all, and TL2 and TL3 follow
//     under the pin rule too. A host pinned at TL1 is refused either way.
//   - Mismatch, with ErrSmtpDaneMismatch: a validated, usable TLSA RRset that the MX's certificate
//     does not match. That MX is refused outright (RFC 7672 §2.2), whatever else could authenticate it.
//
// mx_host must be in the validated MX RRset, which Validate holds, or a chain for another host would
// pass. Nothing here logs, and an error names no host or domain (I-13).
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"time"
)

// TLSA format values (RFC 6698 §2.1, RFC 7218).
const (
	smtpTlsaUsageDaneTa         uint8 = 2
	smtpTlsaUsageDaneEe         uint8 = 3
	smtpTlsaSelectorFull        uint8 = 0
	smtpTlsaSelectorSpki        uint8 = 1
	smtpTlsaMatchingExact       uint8 = 0
	smtpTlsaMatchingSha256      uint8 = 1
	smtpTlsaMatchingSha512      uint8 = 2
	smtpTlsaSha256DataByteCount       = sha256.Size
	smtpTlsaSha512DataByteCount       = sha512.Size
)

// A validated, usable TLSA RRset matched nothing the MX presented: refuse that MX.
var ErrSmtpDaneMismatch = errors.New("smtp dane: no tlsa record matches the mx")

// What TL1 decided for one MX.
type SmtpDaneStatus uint32

const (
	// Never a result.
	SmtpDaneStatusUnspecified SmtpDaneStatus = 0
	// A usable TLSA record matched: TL1.
	SmtpDaneStatusAuthenticated SmtpDaneStatus = 1
	// DANE does not apply: TL2 and TL3 follow, under the pin rule.
	SmtpDaneStatusNotApplicable SmtpDaneStatus = 2
	// The chain does not validate: no authentication, and TL2 and TL3 follow, under the pin rule.
	SmtpDaneStatusBogus SmtpDaneStatus = 3
	// Usable TLSA records matched nothing: the MX is refused.
	SmtpDaneStatusMismatch SmtpDaneStatus = 4
)

// What Authenticate found.
type SmtpDaneResult struct {
	Status SmtpDaneStatus
	// What the chain proved, unset when it did not validate.
	Dnssec SmtpDnssecStatus
	// When authenticated: the usage that matched, DANE-EE (3) or DANE-TA (2).
	MatchedUsage uint8
}

// TL1's check. Safe for concurrent use.
type SmtpDane struct {
	anchors  *SmtpDnssecAnchors
	clock    Clock
	settings *SmtpDaneSettings
}

// A check under anchors (nil is DefaultSmtpDnssecAnchors', the release's), reading signature validity
// and DANE-TA expiry from clock (nil is real time), within settings (nil is the default).
func NewSmtpDane(anchors *SmtpDnssecAnchors, clock Clock, settings *SmtpDaneSettings) *SmtpDane {
	if anchors == nil {
		anchors = DefaultSmtpDnssecAnchors()
	}
	if settings == nil {
		settings = DefaultSmtpDaneSettings()
	}
	return &SmtpDane{anchors: anchors, clock: clockOrReal(clock), settings: settings}
}

// Whether a TLSA record is one RFC 7672 lets SMTP use.
func smtpTlsaUsable(record *SmtpTlsaRecord) bool {
	if record.Usage != smtpTlsaUsageDaneTa && record.Usage != smtpTlsaUsageDaneEe {
		return false
	}
	if record.Selector != smtpTlsaSelectorFull && record.Selector != smtpTlsaSelectorSpki {
		return false
	}
	switch record.MatchingType {
	case smtpTlsaMatchingExact:
		return 0 < len(record.Data)
	case smtpTlsaMatchingSha256:
		return len(record.Data) == smtpTlsaSha256DataByteCount
	case smtpTlsaMatchingSha512:
		return len(record.Data) == smtpTlsaSha512DataByteCount
	}
	return false
}

// Whether record's selector and matching type name certificate.
func smtpTlsaMatches(record *SmtpTlsaRecord, certificate *x509.Certificate) bool {
	selected := certificate.Raw
	if record.Selector == smtpTlsaSelectorSpki {
		selected = certificate.RawSubjectPublicKeyInfo
	}
	switch record.MatchingType {
	case smtpTlsaMatchingExact:
		return bytes.Equal(selected, record.Data)
	case smtpTlsaMatchingSha256:
		digest := sha256.Sum256(selected)
		return bytes.Equal(digest[:], record.Data)
	case smtpTlsaMatchingSha512:
		digest := sha512.Sum512(selected)
		return bytes.Equal(digest[:], record.Data)
	}
	return false
}

// Decides TL1 for the MX the edge chose, from its dnssec_chain and the chain the MX presented, leaf
// first (this file's header). Its error is ErrSmtpDaneMismatch and nothing else.
func (self *SmtpDane) Authenticate(recipientDomain string, mxHost string, dnssecChain []byte, peerChain []*x509.Certificate) (*SmtpDaneResult, error) {
	parsed, err := ParseSmtpDnssecChain(dnssecChain, self.settings)
	if err != nil {
		return &SmtpDaneResult{Status: SmtpDaneStatusBogus}, nil
	}
	now := self.clock.Now()
	proven, err := parsed.Validate(self.anchors, now, recipientDomain, mxHost)
	if err != nil {
		return &SmtpDaneResult{Status: SmtpDaneStatusBogus}, nil
	}
	result := &SmtpDaneResult{Status: SmtpDaneStatusNotApplicable, Dnssec: proven.Status}
	if proven.Status != SmtpDnssecStatusTlsa {
		return result, nil
	}
	var usable []*SmtpTlsaRecord
	for _, record := range proven.TlsaRecords {
		if smtpTlsaUsable(record) {
			usable = append(usable, record)
		}
	}
	if len(usable) == 0 {
		return result, nil
	}
	if 0 < len(peerChain) {
		leaf := peerChain[0]
		for _, record := range usable {
			if record.Usage == smtpTlsaUsageDaneEe && smtpTlsaMatches(record, leaf) {
				result.Status, result.MatchedUsage = SmtpDaneStatusAuthenticated, smtpTlsaUsageDaneEe
				return result, nil
			}
		}
		for _, record := range usable {
			if record.Usage != smtpTlsaUsageDaneTa {
				continue
			}
			for _, anchor := range peerChain[1:] {
				if smtpTlsaMatches(record, anchor) && smtpDaneTaVerifies(peerChain, anchor, now, mxHost, recipientDomain) {
					result.Status, result.MatchedUsage = SmtpDaneStatusAuthenticated, smtpTlsaUsageDaneTa
					return result, nil
				}
			}
		}
	}
	result.Status = SmtpDaneStatusMismatch
	return result, ErrSmtpDaneMismatch
}

// Whether the leaf chains to anchor through the other presented certificates, valid at now, for the MX
// host or, as RFC 7672 §3.2.2 also accepts, the recipient domain.
func smtpDaneTaVerifies(peerChain []*x509.Certificate, anchor *x509.Certificate, now time.Time, mxHost string, recipientDomain string) bool {
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	intermediates := x509.NewCertPool()
	for _, certificate := range peerChain[1:] {
		if certificate != anchor {
			intermediates.AddCert(certificate)
		}
	}
	for _, name := range []string{mxHost, recipientDomain} {
		options := x509.VerifyOptions{
			DNSName:       name,
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   now,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		if _, err := peerChain[0].Verify(options); err == nil {
			return true
		}
	}
	return false
}
