//go:build !sidecar_http

// dnssec_chain validated to the root (§14.4's TL1, D-SMTP-2): the edge sends it in SmtpPreambleResult,
// and the sidecar trusts nothing from the edge but the chain itself, its own embedded root anchors and
// its own clock. A chain is plan-SMTP-small-readings#2's: the MX RRset or its denial, the TLSA RRset or
// its denial, each with RRSIGs, then every zone cut's DNSKEY and DS RRsets up to the root's DNSKEY, in
// RFC 9102's order.
//
// Validation walks down from the root. A zone's keys hold once its DNSKEY RRset carries a key a
// validated DS (or, at the root, an anchor) names and that key signs the set (RFC 4035 §5). Data holds
// once a key of the zone that signed it verifies its RRSIG over RFC 4034 §6's canonical form, inside the
// signature's validity on the injected clock; a signature that names fewer labels than its owner is a
// wildcard's, and holds only beside a proof that no closer name exists (RFC 4035 §5.3.4). Absence holds
// by NSEC (RFC 4035 §5.4) or NSEC3 (RFC 5155 §8): a name with no such type, a name that does not exist,
// and a delegation with no DS, which makes everything below it insecure rather than bogus. RSA/SHA-256,
// ECDSA P-256/SHA-256 and Ed25519 (algorithms 8, 13 and 15); DS digests SHA-256 and SHA-384 (types 2
// and 4). A DS RRset naming none of those leaves its zone insecure (RFC 4035 §5.2).
//
// So the result tells three outcomes apart: TLSA records proven, TLSA proven absent, and an insecure
// path, where DANE does not apply. Anything else, a broken signature, an expired one, a missing DS or
// an unparseable record, is ErrSmtpDnssecBogus, which is no authentication at all.
//
// Work is bounded by SmtpDaneSettings: records, records per RRset, signature checks and CNAME hops.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"
	"time"
)

// DNSSEC format values (RFC 4034 Appendix A, RFC 5155, RFC 8624).
const (
	smtpDnssecAlgorithmRsaSha256       uint8 = 8
	smtpDnssecAlgorithmEcdsaP256Sha256 uint8 = 13
	smtpDnssecAlgorithmEd25519         uint8 = 15
	smtpDnssecDigestSha256             uint8 = 2
	smtpDnssecDigestSha384             uint8 = 4
	smtpDnssecNsec3HashSha1            uint8 = 1
	// The largest dnssec_chain: what one SmtpPreambleResult frame can hold (plan-SMTP-wire-gaps#3).
	SmtpDnssecChainMaxByteCount = SmtpFrameMaxBodyByteCount
	// RSA key sizes a zone may sign with (RFC 8624 §3.1).
	smtpDnssecRsaMinBitCount = 1024
	smtpDnssecRsaMaxBitCount = 4096
)

// NSEC3's owner labels: RFC 4648's extended hex alphabet in lowercase, unpadded.
var smtpDnssecBase32Hex = base32.NewEncoding("0123456789abcdefghijklmnopqrstuv").WithPadding(base32.NoPadding)

// How much work one chain may cost. Every number must be positive.
type SmtpDaneSettings struct {
	// Records one chain may hold: 512, far past a chain of a dozen zones.
	MaxRrCount int
	// Records one RRset may hold: 64.
	MaxRrsetCount int
	// Signatures one validation may check: 256.
	MaxSignatureCheckCount int
	// CNAME hops from _25._tcp.<mx_host> to its TLSA RRset: 8.
	MaxCnameDepth int
	// NSEC3 iterations a denial may use. RFC 9276 asks for 0 and lets a validator refuse more, so a
	// chain past this is bogus: 100.
	MaxNsec3IterationCount int
}

// A fresh value each call.
func DefaultSmtpDaneSettings() *SmtpDaneSettings {
	return &SmtpDaneSettings{
		MaxRrCount:             512,
		MaxRrsetCount:          64,
		MaxSignatureCheckCount: 256,
		MaxCnameDepth:          8,
		MaxNsec3IterationCount: 100,
	}
}

// Whether every limit is positive.
func (self *SmtpDaneSettings) valid() bool {
	return self != nil && 0 < self.MaxRrCount && 0 < self.MaxRrsetCount && 0 < self.MaxSignatureCheckCount &&
		0 < self.MaxCnameDepth && 0 <= self.MaxNsec3IterationCount
}

// What one RRset is keyed by.
type smtpDnsRrsetKey struct {
	owner  smtpDnsName
	rrtype uint16
}

// One RRset of a chain with the RRSIGs covering it.
type smtpDnsRrset struct {
	key        smtpDnsRrsetKey
	rrs        []*smtpDnsRr
	signatures []*smtpDnsRrsig
}

// A dnssec_chain parsed and grouped into RRsets, nothing in it yet trusted. Immutable, and so safe for
// concurrent use.
type SmtpDnssecChain struct {
	settings *SmtpDaneSettings
	rrsets   map[smtpDnsRrsetKey]*smtpDnsRrset
	// NSEC and NSEC3 RRsets, which a denial searches.
	denials []*smtpDnsRrset
}

// Parses a dnssec_chain under settings (nil is DefaultSmtpDaneSettings'). An empty chain parses and
// validates nothing, which is what an edge sends when the chain would pass the frame
// (plan-SMTP-wire-gaps#3). Errors are ErrSmtpDnssecBogus.
func ParseSmtpDnssecChain(chain []byte, settings *SmtpDaneSettings) (*SmtpDnssecChain, error) {
	if settings == nil {
		settings = DefaultSmtpDaneSettings()
	}
	if !settings.valid() {
		return nil, fmt.Errorf("%w: settings", ErrSmtpDnssecBogus)
	}
	if SmtpDnssecChainMaxByteCount < len(chain) {
		return nil, fmt.Errorf("%w: a %d-octet chain", ErrSmtpDnssecBogus, len(chain))
	}
	rrs, err := parseSmtpDnsRrs(chain, settings.MaxRrCount)
	if err != nil {
		return nil, err
	}
	parsed := &SmtpDnssecChain{settings: settings, rrsets: map[smtpDnsRrsetKey]*smtpDnsRrset{}}
	rrset := func(key smtpDnsRrsetKey) *smtpDnsRrset {
		found, ok := parsed.rrsets[key]
		if !ok {
			found = &smtpDnsRrset{key: key}
			parsed.rrsets[key] = found
		}
		return found
	}
	for _, rr := range rrs {
		if rr.rrtype == smtpDnsTypeRrsig {
			signature, _ := parseSmtpDnsRrsig(rr.rdata)
			target := rrset(smtpDnsRrsetKey{owner: rr.owner, rrtype: signature.typeCovered})
			if settings.MaxRrsetCount <= len(target.signatures) {
				return nil, fmt.Errorf("%w: an rrset past %d signatures", ErrSmtpDnssecBogus, settings.MaxRrsetCount)
			}
			target.signatures = append(target.signatures, signature)
			continue
		}
		target := rrset(smtpDnsRrsetKey{owner: rr.owner, rrtype: rr.rrtype})
		duplicate := slices.ContainsFunc(target.rrs, func(existing *smtpDnsRr) bool {
			return bytes.Equal(existing.canonicalRdata(), rr.canonicalRdata())
		})
		if duplicate {
			continue
		}
		if settings.MaxRrsetCount <= len(target.rrs) {
			return nil, fmt.Errorf("%w: an rrset past %d records", ErrSmtpDnssecBogus, settings.MaxRrsetCount)
		}
		target.rrs = append(target.rrs, rr)
	}
	for _, found := range parsed.rrsets {
		if found.key.rrtype == smtpDnsTypeNsec || found.key.rrtype == smtpDnsTypeNsec3 {
			parsed.denials = append(parsed.denials, found)
		}
	}
	return parsed, nil
}

// What a validated chain says about one MX host (§14.4's TL1).
type SmtpDnssecStatus uint32

const (
	// Never a result.
	SmtpDnssecStatusUnspecified SmtpDnssecStatus = 0
	// The MX RRset names mx_host, and _25._tcp.<mx_host> has a TLSA RRset, all validated.
	SmtpDnssecStatusTlsa SmtpDnssecStatus = 1
	// The MX RRset names mx_host, and _25._tcp.<mx_host> has no TLSA RRset, proven.
	SmtpDnssecStatusNoTlsa SmtpDnssecStatus = 2
	// The MX RRset or the TLSA name lies under an insecure delegation, proven: DANE does not apply.
	SmtpDnssecStatusInsecure SmtpDnssecStatus = 3
)

// What Validate proved.
type SmtpDnssecResult struct {
	Status SmtpDnssecStatus
	// The validated TLSA RRset, when Status is SmtpDnssecStatusTlsa.
	TlsaRecords []*SmtpTlsaRecord
}

// One validation's state: the zones whose keys hold so far and the work spent.
type smtpDnssecValidator struct {
	chain   *SmtpDnssecChain
	anchors *SmtpDnssecAnchors
	now     time.Time
	// validated DNSKEYs by zone, and the zones whose keys failed
	zoneKeys      map[smtpDnsName][]*smtpDnsDnskey
	zoneKeyErrors map[smtpDnsName]error
	// each RRset's verdict, nil for valid, so each is checked once; one being checked reads as bogus,
	// which ends any cycle a crafted chain could make
	rrsetErrors    map[*smtpDnsRrset]error
	signatureCount int
}

// What an RRset reads as while its own check is running.
var errSmtpDnssecInProgress = fmt.Errorf("%w: an rrset's check depends on itself", ErrSmtpDnssecBogus)

// What looking up one name and type proved.
type smtpDnssecAnswer struct {
	// Exactly one of these holds, or insecure.
	rrset    *smtpDnsRrset
	cname    smtpDnsName
	absent   bool
	insecure bool
}

// Validates the chain for one recipient domain and the MX host the edge chose, at now. mx_host must be
// in the validated MX RRset, or, with no MX RRset proven, be the domain itself (RFC 5321 §5.1's implicit
// MX, plan-SMTP-small-readings#13), or the chain is bogus: otherwise a chain for another host would pass.
func (self *SmtpDnssecChain) Validate(anchors *SmtpDnssecAnchors, now time.Time, domain string, mxHost string) (*SmtpDnssecResult, error) {
	if anchors == nil || len(anchors.ds) == 0 {
		return nil, fmt.Errorf("%w: no trust anchor", ErrSmtpDnssecBogus)
	}
	domainName, domainOk := smtpDnsNameFromText(domain)
	hostName, hostOk := smtpDnsNameFromText(mxHost)
	if !domainOk || !hostOk || domainName == smtpDnsRoot || hostName == smtpDnsRoot {
		return nil, fmt.Errorf("%w: a domain or host outside its form", ErrSmtpDnssecBogus)
	}
	validator := &smtpDnssecValidator{
		chain:         self,
		anchors:       anchors,
		now:           now,
		zoneKeys:      map[smtpDnsName][]*smtpDnsDnskey{},
		zoneKeyErrors: map[smtpDnsName]error{},
		rrsetErrors:   map[*smtpDnsRrset]error{},
	}
	mx, err := validator.lookup(domainName, smtpDnsTypeMx)
	if err != nil {
		return nil, err
	}
	switch {
	case mx.insecure:
		return &SmtpDnssecResult{Status: SmtpDnssecStatusInsecure}, nil
	case mx.rrset != nil:
		named := false
		for _, rr := range mx.rrset.rrs {
			exchange, _ := parseSmtpDnsMx(rr.rdata)
			named = named || exchange == hostName
		}
		if !named {
			return nil, fmt.Errorf("%w: the mx rrset does not name the host", ErrSmtpDnssecBogus)
		}
	case mx.absent && hostName == domainName:
		// the implicit MX
	default:
		return nil, fmt.Errorf("%w: no mx proves the host", ErrSmtpDnssecBogus)
	}
	tlsaName := hostName.child("_tcp").child("_25")
	for range self.settings.MaxCnameDepth + 1 {
		tlsa, err := validator.lookup(tlsaName, smtpDnsTypeTlsa)
		if err != nil {
			return nil, err
		}
		switch {
		case tlsa.insecure:
			return &SmtpDnssecResult{Status: SmtpDnssecStatusInsecure}, nil
		case tlsa.absent:
			return &SmtpDnssecResult{Status: SmtpDnssecStatusNoTlsa}, nil
		case tlsa.rrset != nil:
			result := &SmtpDnssecResult{Status: SmtpDnssecStatusTlsa}
			for _, rr := range tlsa.rrset.rrs {
				record, _ := parseSmtpDnsTlsa(rr.rdata)
				result.TlsaRecords = append(result.TlsaRecords, record)
			}
			return result, nil
		}
		tlsaName = tlsa.cname
	}
	return nil, fmt.Errorf("%w: past %d cname hops", ErrSmtpDnssecBogus, self.settings.MaxCnameDepth)
}

// What name holds of rrtype: the validated RRset, a validated CNAME to follow, a proven absence, or an
// insecure path. Anything that does not validate is ErrSmtpDnssecBogus.
func (self *smtpDnssecValidator) lookup(name smtpDnsName, rrtype uint16) (*smtpDnssecAnswer, error) {
	insecure, err := self.insecureAbove(name)
	if err != nil {
		return nil, err
	}
	if insecure {
		return &smtpDnssecAnswer{insecure: true}, nil
	}
	if rrset, ok := self.chain.rrsets[smtpDnsRrsetKey{owner: name, rrtype: rrtype}]; ok && 0 < len(rrset.rrs) {
		if err := self.validateData(rrset); err != nil {
			return nil, err
		}
		return &smtpDnssecAnswer{rrset: rrset}, nil
	}
	if rrset, ok := self.chain.rrsets[smtpDnsRrsetKey{owner: name, rrtype: smtpDnsTypeCname}]; ok && 0 < len(rrset.rrs) {
		if len(rrset.rrs) != 1 {
			return nil, fmt.Errorf("%w: a name with two cnames", ErrSmtpDnssecBogus)
		}
		if err := self.validateData(rrset); err != nil {
			return nil, err
		}
		target, _ := parseSmtpDnsCname(rrset.rrs[0].rdata)
		return &smtpDnssecAnswer{cname: target}, nil
	}
	if err := self.proveAbsent(name, rrtype); err != nil {
		return nil, err
	}
	return &smtpDnssecAnswer{absent: true}, nil
}

// Whether the path from the root down to name passes a delegation proven to have no DS (or no DS of a
// supported algorithm), below which nothing is signed. Every cut the chain shows a DS for must have its
// keys hold on the way.
func (self *smtpDnssecValidator) insecureAbove(name smtpDnsName) (bool, error) {
	labels := name.labelCount()
	zone := smtpDnsRoot
	if _, err := self.keys(zone); err != nil {
		return false, err
	}
	for count := 1; count <= labels; count += 1 {
		candidate := name.suffix(count)
		ds, hasDs := self.chain.rrsets[smtpDnsRrsetKey{owner: candidate, rrtype: smtpDnsTypeDs}]
		_, hasKeys := self.chain.rrsets[smtpDnsRrsetKey{owner: candidate, rrtype: smtpDnsTypeDnskey}]
		switch {
		case hasDs && 0 < len(ds.rrs):
			if !self.supportedDs(ds) {
				// RFC 4035 §5.2: no DS this validator can use is an insecure delegation
				if err := self.validateData(ds); err != nil {
					return false, err
				}
				return true, nil
			}
			if _, err := self.keys(candidate); err != nil {
				return false, err
			}
			zone = candidate
		case hasKeys:
			// a zone cut whose DS is missing: either proven absent, or the chain is broken
			if self.provenInsecureDelegation(zone, candidate) {
				return true, nil
			}
			return false, fmt.Errorf("%w: a zone with keys and no ds", ErrSmtpDnssecBogus)
		default:
			if self.provenInsecureDelegation(zone, candidate) {
				return true, nil
			}
		}
	}
	return false, nil
}

// Whether a DS RRset names a key algorithm and digest type this validator verifies.
func (self *smtpDnssecValidator) supportedDs(rrset *smtpDnsRrset) bool {
	for _, rr := range rrset.rrs {
		ds, _ := parseSmtpDnsDs(rr.rdata)
		if smtpDnssecAlgorithmSupported(ds.algorithm) && (ds.digestType == smtpDnssecDigestSha256 || ds.digestType == smtpDnssecDigestSha384) {
			return true
		}
	}
	return false
}

// Whether this validator verifies a key algorithm.
func smtpDnssecAlgorithmSupported(algorithm uint8) bool {
	return algorithm == smtpDnssecAlgorithmRsaSha256 || algorithm == smtpDnssecAlgorithmEcdsaP256Sha256 || algorithm == smtpDnssecAlgorithmEd25519
}

// zone's validated keys, from its parent's DS or, at the root, the anchors (RFC 4035 §5.2).
func (self *smtpDnssecValidator) keys(zone smtpDnsName) ([]*smtpDnsDnskey, error) {
	if keys, ok := self.zoneKeys[zone]; ok {
		return keys, nil
	}
	if err, ok := self.zoneKeyErrors[zone]; ok {
		return nil, err
	}
	keys, err := self.validateKeys(zone)
	if err != nil {
		self.zoneKeyErrors[zone] = err
		return nil, err
	}
	self.zoneKeys[zone] = keys
	return keys, nil
}

// The work behind keys, uncached.
func (self *smtpDnssecValidator) validateKeys(zone smtpDnsName) ([]*smtpDnsDnskey, error) {
	// a zone whose keys are being checked reads as failed, as an rrset does
	self.zoneKeyErrors[zone] = errSmtpDnssecInProgress
	defer delete(self.zoneKeyErrors, zone)
	keySet, ok := self.chain.rrsets[smtpDnsRrsetKey{owner: zone, rrtype: smtpDnsTypeDnskey}]
	if !ok || len(keySet.rrs) == 0 {
		return nil, fmt.Errorf("%w: a zone's dnskey rrset is missing", ErrSmtpDnssecBogus)
	}
	var dsRecords []*smtpDnsDs
	if zone == smtpDnsRoot {
		dsRecords = self.anchors.ds
	} else {
		dsSet, ok := self.chain.rrsets[smtpDnsRrsetKey{owner: zone, rrtype: smtpDnsTypeDs}]
		if !ok || len(dsSet.rrs) == 0 {
			return nil, fmt.Errorf("%w: a zone's ds rrset is missing", ErrSmtpDnssecBogus)
		}
		if err := self.validateData(dsSet); err != nil {
			return nil, err
		}
		for _, rr := range dsSet.rrs {
			ds, _ := parseSmtpDnsDs(rr.rdata)
			dsRecords = append(dsRecords, ds)
		}
	}
	var keys []*smtpDnsDnskey
	for _, rr := range keySet.rrs {
		key, _ := parseSmtpDnsDnskey(rr.rdata)
		keys = append(keys, key)
	}
	// a key a DS names must sign the whole DNSKEY RRset
	for _, key := range keys {
		if !smtpDnssecUsableKey(key) || !slices.ContainsFunc(dsRecords, func(ds *smtpDnsDs) bool { return smtpDnssecDsMatches(ds, zone, key) }) {
			continue
		}
		for _, signature := range keySet.signatures {
			if signature.signer != zone || signature.keyTag != key.keyTag || signature.algorithm != key.algorithm {
				continue
			}
			if self.verify(keySet, signature, key) == nil {
				var usable []*smtpDnsDnskey
				for _, candidate := range keys {
					if smtpDnssecUsableKey(candidate) {
						usable = append(usable, candidate)
					}
				}
				return usable, nil
			}
		}
	}
	return nil, fmt.Errorf("%w: no key a ds names signs the zone's keys", ErrSmtpDnssecBogus)
}

// Whether a DNSKEY may sign: a zone key of DNSSEC's protocol, not revoked, of a supported algorithm.
func smtpDnssecUsableKey(key *smtpDnsDnskey) bool {
	return key.flags&smtpDnsDnskeyZone != 0 && key.flags&smtpDnsDnskeyRevoke == 0 && key.protocol == 3 && smtpDnssecAlgorithmSupported(key.algorithm)
}

// Whether ds names key at zone: tag, algorithm and digest over the owner and rdata (RFC 4034 §5.1.4).
func smtpDnssecDsMatches(ds *smtpDnsDs, zone smtpDnsName, key *smtpDnsDnskey) bool {
	if ds.keyTag != key.keyTag || ds.algorithm != key.algorithm {
		return false
	}
	input := append([]byte(zone), key.rdata...)
	switch ds.digestType {
	case smtpDnssecDigestSha256:
		digest := sha256.Sum256(input)
		return bytes.Equal(digest[:], ds.digest)
	case smtpDnssecDigestSha384:
		digest := sha512.Sum384(input)
		return bytes.Equal(digest[:], ds.digest)
	}
	return false
}

// Validates an RRset other than a zone's DNSKEY set: some RRSIG by a validated key of a zone at or
// above its owner verifies it. A DS's signer must be strictly above it, since a DS is the parent's.
func (self *smtpDnssecValidator) validateData(rrset *smtpDnsRrset) error {
	if err, ok := self.rrsetErrors[rrset]; ok {
		return err
	}
	self.rrsetErrors[rrset] = errSmtpDnssecInProgress
	err := self.validateDataUncached(rrset)
	self.rrsetErrors[rrset] = err
	return err
}

// The work behind validateData.
func (self *smtpDnssecValidator) validateDataUncached(rrset *smtpDnsRrset) error {
	owner := rrset.key.owner
	ownerLabelCount := owner.labelCount()
	if owner.wildcard() {
		ownerLabelCount -= 1
	}
	for _, signature := range rrset.signatures {
		if !owner.under(signature.signer) || (rrset.key.rrtype == smtpDnsTypeDs && owner == signature.signer) {
			continue
		}
		keys, err := self.keys(signature.signer)
		if err != nil {
			continue
		}
		for _, key := range keys {
			if key.keyTag != signature.keyTag || key.algorithm != signature.algorithm {
				continue
			}
			if self.verify(rrset, signature, key) != nil {
				continue
			}
			if int(signature.labels) < ownerLabelCount {
				// a wildcard's expansion: no closer name may exist (RFC 4035 §5.3.4)
				nextCloser := owner.suffix(int(signature.labels) + 1)
				if !self.provenNameAbsent(signature.signer, nextCloser) {
					continue
				}
			}
			return nil
		}
	}
	return fmt.Errorf("%w: no signature verifies an rrset", ErrSmtpDnssecBogus)
}

// Whether signature by key verifies rrset over RFC 4034 §3.1.8.1's signed data, inside its validity.
func (self *smtpDnssecValidator) verify(rrset *smtpDnsRrset, signature *smtpDnsRrsig, key *smtpDnsDnskey) error {
	if self.chain.settings.MaxSignatureCheckCount <= self.signatureCount {
		return fmt.Errorf("%w: past %d signature checks", ErrSmtpDnssecBogus, self.chain.settings.MaxSignatureCheckCount)
	}
	self.signatureCount += 1
	owner := rrset.key.owner
	labelCount := owner.labelCount()
	if owner.wildcard() {
		labelCount -= 1
	}
	if labelCount < int(signature.labels) {
		return fmt.Errorf("%w: an rrsig names more labels than its owner", ErrSmtpDnssecBogus)
	}
	// RFC 1982 serial arithmetic, as RFC 4034 §3.1.5 reads the validity
	now := uint32(self.now.Unix())
	if int32(now-signature.inception) < 0 || int32(signature.expiration-now) < 0 {
		return fmt.Errorf("%w: an rrsig outside its validity", ErrSmtpDnssecBogus)
	}
	signedOwner := owner
	if int(signature.labels) < labelCount {
		signedOwner = owner.suffix(int(signature.labels)).child("*")
	}
	rdatas := make([][]byte, 0, len(rrset.rrs))
	for _, rr := range rrset.rrs {
		rdatas = append(rdatas, rr.canonicalRdata())
	}
	slices.SortFunc(rdatas, bytes.Compare)
	data := append([]byte{}, signature.signedPrefix...)
	for _, rdata := range rdatas {
		data = append(data, signedOwner...)
		data = binary.BigEndian.AppendUint16(data, rrset.key.rrtype)
		data = binary.BigEndian.AppendUint16(data, smtpDnsClassIn)
		data = binary.BigEndian.AppendUint32(data, signature.originalTtl)
		data = binary.BigEndian.AppendUint16(data, uint16(len(rdata)))
		data = append(data, rdata...)
	}
	if !smtpDnssecVerifySignature(key, data, signature.signature) {
		return fmt.Errorf("%w: an rrsig does not verify", ErrSmtpDnssecBogus)
	}
	return nil
}

// Whether signature by key is good over data, by the key's algorithm.
func smtpDnssecVerifySignature(key *smtpDnsDnskey, data []byte, signature []byte) bool {
	switch key.algorithm {
	case smtpDnssecAlgorithmRsaSha256:
		// RFC 3110: an exponent length of one octet, or zero and then two, the exponent, the modulus
		publicKey := key.publicKey
		if len(publicKey) < 1 {
			return false
		}
		exponentByteCount, offset := int(publicKey[0]), 1
		if exponentByteCount == 0 {
			if len(publicKey) < 3 {
				return false
			}
			exponentByteCount, offset = int(binary.BigEndian.Uint16(publicKey[1:3])), 3
		}
		if exponentByteCount == 0 || 4 < exponentByteCount || len(publicKey) <= offset+exponentByteCount {
			return false
		}
		exponent := new(big.Int).SetBytes(publicKey[offset : offset+exponentByteCount])
		modulus := new(big.Int).SetBytes(publicKey[offset+exponentByteCount:])
		if !exponent.IsInt64() || exponent.Int64() < 3 || 1<<31-1 < exponent.Int64() || modulus.BitLen() < smtpDnssecRsaMinBitCount || smtpDnssecRsaMaxBitCount < modulus.BitLen() {
			return false
		}
		digest := sha256.Sum256(data)
		return rsa.VerifyPKCS1v15(&rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, crypto.SHA256, digest[:], signature) == nil
	case smtpDnssecAlgorithmEcdsaP256Sha256:
		if len(key.publicKey) != 64 || len(signature) != 64 {
			return false
		}
		publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{4}, key.publicKey...))
		if err != nil {
			return false
		}
		digest := sha256.Sum256(data)
		return ecdsa.Verify(publicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:]))
	case smtpDnssecAlgorithmEd25519:
		return len(key.publicKey) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(key.publicKey), data, signature)
	}
	return false
}

// The validated denial records of zone: each NSEC or NSEC3 RRset under it whose signature verifies,
// signed by zone itself.
func (self *smtpDnssecValidator) denialsOf(zone smtpDnsName, rrtype uint16) []*smtpDnsRrset {
	var denials []*smtpDnsRrset
	for _, rrset := range self.chain.denials {
		if rrset.key.rrtype != rrtype || !rrset.key.owner.under(zone) || len(rrset.rrs) != 1 {
			continue
		}
		signedByZone := slices.ContainsFunc(rrset.signatures, func(signature *smtpDnsRrsig) bool { return signature.signer == zone })
		if !signedByZone || self.validateData(rrset) != nil {
			continue
		}
		denials = append(denials, rrset)
	}
	return denials
}

// The deepest zone above or at name whose keys hold.
func (self *smtpDnssecValidator) zoneOf(name smtpDnsName) smtpDnsName {
	for candidate := name; ; candidate = candidate.parent() {
		if _, ok := self.zoneKeys[candidate]; ok {
			return candidate
		}
		if candidate == smtpDnsRoot {
			return smtpDnsRoot
		}
	}
}

// Proves name has no RRset of rrtype and no CNAME, or does not exist, in the zone that holds it.
func (self *smtpDnssecValidator) proveAbsent(name smtpDnsName, rrtype uint16) error {
	zone := self.zoneOf(name)
	if self.nsecProvesAbsent(zone, name, rrtype) || self.nsec3ProvesAbsent(zone, name, rrtype) {
		return nil
	}
	return fmt.Errorf("%w: nothing proves an absence", ErrSmtpDnssecBogus)
}

// Whether name does not exist at all in zone, by either kind of denial.
func (self *smtpDnssecValidator) provenNameAbsent(zone smtpDnsName, name smtpDnsName) bool {
	for _, rrset := range self.denialsOf(zone, smtpDnsTypeNsec) {
		nsec, _ := parseSmtpDnsNsec(rrset.rrs[0].rdata)
		if smtpDnssecNsecCovers(rrset.key.owner, nsec.next, name) {
			return true
		}
	}
	nsec3s := self.nsec3sOf(zone)
	return nsec3s != nil && nsec3s.covering(name) != nil
}

// Whether the parent zone proves child, one label below the deepest zone above it, a delegation with
// no DS: its NSEC or NSEC3 holds NS and no DS or SOA, or an opt-out NSEC3 covers it (RFC 5155 §8.6).
func (self *smtpDnssecValidator) provenInsecureDelegation(parent smtpDnsName, child smtpDnsName) bool {
	if !child.under(parent) || child == parent {
		return false
	}
	for _, rrset := range self.denialsOf(parent, smtpDnsTypeNsec) {
		nsec, _ := parseSmtpDnsNsec(rrset.rrs[0].rdata)
		if rrset.key.owner == child && smtpDnsBitmapHas(nsec.bitmap, smtpDnsTypeNs) && !smtpDnsBitmapHas(nsec.bitmap, smtpDnsTypeDs) && !smtpDnsBitmapHas(nsec.bitmap, smtpDnsTypeSoa) {
			return true
		}
	}
	nsec3s := self.nsec3sOf(parent)
	if nsec3s == nil {
		return false
	}
	if matching := nsec3s.matching(child); matching != nil {
		return smtpDnsBitmapHas(matching.bitmap, smtpDnsTypeNs) && !smtpDnsBitmapHas(matching.bitmap, smtpDnsTypeDs) && !smtpDnsBitmapHas(matching.bitmap, smtpDnsTypeSoa)
	}
	closest, nextCloser := nsec3s.closestEncloser(child)
	if closest == "" {
		return false
	}
	covering := nsec3s.covering(nextCloser)
	return covering != nil && covering.flags&smtpDnsNsec3OptOut != 0
}

// Whether an NSEC from owner to next covers name: name falls strictly between them in canonical
// order, the last NSEC of a zone wrapping to its apex.
func smtpDnssecNsecCovers(owner smtpDnsName, next smtpDnsName, name smtpDnsName) bool {
	if owner.compare(next) < 0 {
		return owner.compare(name) < 0 && name.compare(next) < 0
	}
	// the zone's last NSEC: everything after it, under the apex it points back to
	return owner.compare(name) < 0 && name.under(next)
}

// RFC 4035 §5.4 by NSEC: name exists without rrtype or a CNAME and is no delegation, or name and the
// wildcard at its closest encloser are both covered.
func (self *smtpDnssecValidator) nsecProvesAbsent(zone smtpDnsName, name smtpDnsName, rrtype uint16) bool {
	nsecs := self.denialsOf(zone, smtpDnsTypeNsec)
	for _, rrset := range nsecs {
		nsec, _ := parseSmtpDnsNsec(rrset.rrs[0].rdata)
		if rrset.key.owner != name {
			continue
		}
		delegation := smtpDnsBitmapHas(nsec.bitmap, smtpDnsTypeNs) && !smtpDnsBitmapHas(nsec.bitmap, smtpDnsTypeSoa) && rrtype != smtpDnsTypeDs
		return !delegation && !smtpDnsBitmapHas(nsec.bitmap, rrtype) && !smtpDnsBitmapHas(nsec.bitmap, smtpDnsTypeCname)
	}
	var nameCovered, wildcardCovered bool
	for _, rrset := range nsecs {
		nsec, _ := parseSmtpDnsNsec(rrset.rrs[0].rdata)
		if !smtpDnssecNsecCovers(rrset.key.owner, nsec.next, name) {
			continue
		}
		nameCovered = true
		// the closest encloser is the longer common ancestor of name with the NSEC's ends
		closest := smtpDnssecCommonAncestor(name, rrset.key.owner)
		if other := smtpDnssecCommonAncestor(name, nsec.next); closest.labelCount() < other.labelCount() {
			closest = other
		}
		wildcard := closest.child("*")
		for _, candidate := range nsecs {
			candidateNsec, _ := parseSmtpDnsNsec(candidate.rrs[0].rdata)
			if smtpDnssecNsecCovers(candidate.key.owner, candidateNsec.next, wildcard) {
				wildcardCovered = true
			}
		}
	}
	return nameCovered && wildcardCovered
}

// The longest name both are under.
func smtpDnssecCommonAncestor(left smtpDnsName, right smtpDnsName) smtpDnsName {
	for candidate := left; ; candidate = candidate.parent() {
		if right.under(candidate) || candidate == smtpDnsRoot {
			return candidate
		}
	}
}

// One zone's validated NSEC3 records, all of one parameter set (RFC 5155 §8.2).
type smtpDnssecNsec3Set struct {
	zone       smtpDnsName
	iterations uint16
	salt       []byte
	// by hashed owner, the base32hex label
	records map[string]*smtpDnsNsec3
	// the hashed owners, in order
	owners []string
}

// zone's NSEC3 records if every one shares SHA-1 and one salt and count within the bound, else nil.
func (self *smtpDnssecValidator) nsec3sOf(zone smtpDnsName) *smtpDnssecNsec3Set {
	rrsets := self.denialsOf(zone, smtpDnsTypeNsec3)
	if len(rrsets) == 0 {
		return nil
	}
	set := &smtpDnssecNsec3Set{zone: zone, records: map[string]*smtpDnsNsec3{}}
	for i, rrset := range rrsets {
		nsec3, _ := parseSmtpDnsNsec3(rrset.rrs[0].rdata)
		labels := rrset.key.owner.labels()
		if rrset.key.owner.parent() != zone || len(labels) == 0 || nsec3.hashAlgorithm != smtpDnssecNsec3HashSha1 || len(nsec3.nextHashed) != sha1.Size {
			return nil
		}
		if i == 0 {
			set.iterations, set.salt = nsec3.iterations, nsec3.salt
		} else if nsec3.iterations != set.iterations || !bytes.Equal(nsec3.salt, set.salt) {
			return nil
		}
		if int(nsec3.iterations) > self.chain.settings.MaxNsec3IterationCount {
			return nil
		}
		set.records[labels[0]] = nsec3
		set.owners = append(set.owners, labels[0])
	}
	slices.Sort(set.owners)
	return set
}

// RFC 5155 §5: name's hash as its owner label.
func (self *smtpDnssecNsec3Set) hash(name smtpDnsName) string {
	digest := sha1.Sum(append([]byte(name), self.salt...))
	for range self.iterations {
		digest = sha1.Sum(append(digest[:], self.salt...))
	}
	return smtpDnssecBase32Hex.EncodeToString(digest[:])
}

// The NSEC3 whose owner is name's hash.
func (self *smtpDnssecNsec3Set) matching(name smtpDnsName) *smtpDnsNsec3 {
	if !name.under(self.zone) {
		return nil
	}
	return self.records[self.hash(name)]
}

// The NSEC3 whose span holds name's hash strictly inside it, the last wrapping to the first.
func (self *smtpDnssecNsec3Set) covering(name smtpDnsName) *smtpDnsNsec3 {
	if !name.under(self.zone) {
		return nil
	}
	hashed := self.hash(name)
	for _, owner := range self.owners {
		record := self.records[owner]
		next := smtpDnssecBase32Hex.EncodeToString(record.nextHashed)
		if owner < next && owner < hashed && hashed < next {
			return record
		}
		if next <= owner && (owner < hashed || hashed < next) {
			return record
		}
	}
	return nil
}

// RFC 5155 §8.3: the longest proper ancestor of name with a matching NSEC3 that is no delegation, and
// the name one label below it toward name. Empty when none.
func (self *smtpDnssecNsec3Set) closestEncloser(name smtpDnsName) (smtpDnsName, smtpDnsName) {
	nextCloser := name
	for candidate := name.parent(); candidate.under(self.zone); candidate = candidate.parent() {
		if record := self.matching(candidate); record != nil {
			delegation := smtpDnsBitmapHas(record.bitmap, smtpDnsTypeNs) && !smtpDnsBitmapHas(record.bitmap, smtpDnsTypeSoa) && candidate != self.zone
			if delegation || smtpDnsBitmapHas(record.bitmap, smtpDnsTypeDname) {
				return "", ""
			}
			return candidate, nextCloser
		}
		nextCloser = candidate
		if candidate == self.zone {
			break
		}
	}
	return "", ""
}

// RFC 5155 §8.4 to §8.7 for a type other than DS: a matching NSEC3 without the type or a CNAME, a
// wildcard's matching NSEC3 without them at the closest encloser, or the name and that wildcard both
// covered. An opt-out span proves nothing about a name that is not a delegation.
func (self *smtpDnssecValidator) nsec3ProvesAbsent(zone smtpDnsName, name smtpDnsName, rrtype uint16) bool {
	set := self.nsec3sOf(zone)
	if set == nil {
		return false
	}
	without := func(record *smtpDnsNsec3) bool {
		return !smtpDnsBitmapHas(record.bitmap, rrtype) && !smtpDnsBitmapHas(record.bitmap, smtpDnsTypeCname)
	}
	if record := set.matching(name); record != nil {
		delegation := smtpDnsBitmapHas(record.bitmap, smtpDnsTypeNs) && !smtpDnsBitmapHas(record.bitmap, smtpDnsTypeSoa) && name != zone
		return !delegation && without(record)
	}
	closest, nextCloser := set.closestEncloser(name)
	if closest == "" {
		return false
	}
	covering := set.covering(nextCloser)
	if covering == nil || covering.flags&smtpDnsNsec3OptOut != 0 {
		return false
	}
	wildcard := closest.child("*")
	if record := set.matching(wildcard); record != nil {
		return without(record)
	}
	return set.covering(wildcard) != nil
}
