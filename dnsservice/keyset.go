// The keys an edge signs with (§12.6's Keys, D-DNS-5): a released DNSKEY window, which is all an edge
// holds of the KSK, and the current ZSK from secret_files, which never leaves the edge. A DnsKeySet is
// what the feed and secret_files hand over. A DnsSigningKeys is one SelfCheck parsed and passed, and
// only that reaches Signer, so a set that failed the check cannot sign an answer.
//
// ECDSA P-256 is the only algorithm (§12.6): one key shape keeps the parse small, and a window naming
// another algorithm is refused rather than half-served.

package dnsservice

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// The one algorithm §12.6 signs with: ECDSA P-256 with SHA-256 (RFC 6605).
const dnsSigningAlgorithm = dns.ECDSAP256SHA256

// A P-256 scalar and one public coordinate, RFC 6605 §4.
const dnsP256ByteCount = 32

// RFC 4034 §2.1.2: a DNSKEY's protocol is always 3.
const dnsKeyProtocol = 3

// What the private key file may say it is, BIND's two versions with ECDSA (dnssec-keygen, ldns and
// miekg's PrivateKeyString write them).
var dnsPrivateKeyFormats = []string{"v1.2", "v1.3"}

var (
	// A ZSK file, window or anchor that cannot sign or be checked. The wrapping error names the part,
	// never a key's bytes.
	ErrDnsKeyRefused = errors.New("dns key refused")
)

// Reads the ZSK from its secret_files entry: BIND's private key format, Private-key-format v1.2 or
// v1.3, Algorithm 13, and PrivateKey the 32-byte scalar in base64. Other lines, such as BIND's dates,
// are ignored. The scalar is handed to the privacy harness the moment it is decoded (§22.7). DNS-M5-19
// owns the file format and may replace this reading of it.
func LoadZsk(data []byte) (crypto.Signer, error) {
	refuse := func(format string, arguments ...any) error {
		return fmt.Errorf("%w: zsk file: %s", ErrDnsKeyRefused, fmt.Sprintf(format, arguments...))
	}
	fields := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, refuse("a line holds no field")
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if _, seen := fields[name]; seen {
			return nil, refuse("%s given twice", name)
		}
		fields[name] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, refuse("%v", err)
	}
	if !slices.Contains(dnsPrivateKeyFormats, fields["private-key-format"]) {
		return nil, refuse("not a private key format this reads")
	}
	algorithm, _, _ := strings.Cut(fields["algorithm"], " ")
	if algorithm != fmt.Sprint(dnsSigningAlgorithm) {
		return nil, refuse("algorithm is not ECDSAP256SHA256")
	}
	encoded, ok := fields["privatekey"]
	if !ok {
		return nil, refuse("no PrivateKey")
	}
	scalar, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, refuse("PrivateKey is not base64")
	}
	testHookSecret("dns_zsk", scalar)
	if len(scalar) != dnsP256ByteCount {
		return nil, refuse("PrivateKey is not a P-256 scalar")
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		return nil, refuse("PrivateKey is not a P-256 scalar")
	}
	return key, nil
}

// The DNSKEY rdata of a P-256 public key: X and Y, each 32 bytes (RFC 6605 §4).
func dnsP256PublicKeyText(public crypto.PublicKey) (string, bool) {
	key, ok := public.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return "", false
	}
	// the uncompressed point, 0x04 then X then Y
	point, err := key.Bytes()
	if err != nil || len(point) != 1+2*dnsP256ByteCount {
		return "", false
	}
	return base64.StdEncoding.EncodeToString(point[1:]), true
}

// Whether two DNSKEYs carry the same key: protocol, algorithm and public key, flags aside, since
// one key may be published with the SEP bit or without.
func dnsSameKey(a *dns.DNSKEY, b *dns.DNSKEY) bool {
	if a.Protocol != b.Protocol || a.Algorithm != b.Algorithm {
		return false
	}
	aBytes, aErr := base64.StdEncoding.DecodeString(a.PublicKey)
	bBytes, bErr := base64.StdEncoding.DecodeString(b.PublicKey)
	return aErr == nil && bErr == nil && bytes.Equal(aBytes, bBytes)
}

// Whether a DNSKEY can sign an RRset in this zone: a zone key of the one algorithm, not revoked.
func dnsUsableZoneKey(key *dns.DNSKEY) bool {
	return key.Flags&dns.ZONE != 0 && key.Flags&dns.REVOKE == 0 && key.Protocol == dnsKeyProtocol &&
		key.Algorithm == dnsSigningAlgorithm
}

// A key set parsed and checked, as SelfCheck returns it. Immutable, so an edge publishes it beside its
// view and every answer reads it with no lock.
type DnsSigningKeys struct {
	root   string
	window *DnsKeyWindow
	zsk    crypto.Signer
	// The window's record of the ZSK, which signatures name by key tag.
	zskRecord *dns.DNSKEY
	zskTag    uint16
	// The ZSK's identity in the signature cache: SHA-256 of its public key, so another key's
	// signatures are never served for it even where key tags collide.
	zskId [sha256.Size]byte
	// The window's RRset as served, owned by the root, its TTL the one the KSK signed.
	dnskeys []*dns.DNSKEY
	// The KSK's signatures over that RRset.
	dnskeyRrsigs []*dns.RRSIG
	notBefore    time.Time
	notAfter     time.Time
}

// The window these keys serve, which the feed compares with each answer's.
func (self *DnsSigningKeys) Window() *DnsKeyWindow {
	return self.window
}

// The ZSK these keys sign with.
func (self *DnsSigningKeys) Zsk() crypto.Signer {
	return self.zsk
}

// The KSK's window end, past which no signature made here is valid.
func (self *DnsSigningKeys) NotAfter() time.Time {
	return self.notAfter
}

// The window's DNSKEY RRset with owner as the question spelled it, shared with nothing.
func (self *DnsSigningKeys) dnskeyRecords(owner string) []dns.RR {
	records := make([]dns.RR, 0, len(self.dnskeys))
	for _, key := range self.dnskeys {
		copied := dns.Copy(key)
		copied.Header().Name = owner
		records = append(records, copied)
	}
	return records
}

// The KSK's signatures over the window with owner as the question spelled it, shared with nothing.
func (self *DnsSigningKeys) dnskeyRrsigRecords(owner string) []dns.RR {
	records := make([]dns.RR, 0, len(self.dnskeyRrsigs))
	for _, rrsig := range self.dnskeyRrsigs {
		copied := dns.Copy(rrsig)
		copied.Header().Name = owner
		records = append(records, copied)
	}
	return records
}

// Parses a key set for root: the window's records, and the ZSK's place among them. Checks nothing a
// signature or the clock decides; SelfCheck does that.
func newDnsSigningKeys(root string, keySet *DnsKeySet) (*DnsSigningKeys, error) {
	refuse := func(format string, arguments ...any) error {
		return fmt.Errorf("%w: %s", ErrDnsKeyRefused, fmt.Sprintf(format, arguments...))
	}
	if keySet == nil || keySet.Window == nil {
		return nil, refuse("no key window")
	}
	if keySet.Zsk == nil {
		return nil, refuse("no zsk")
	}
	window := keySet.Window
	if dns.CanonicalName(window.Root) != root {
		return nil, refuse("a window for another root")
	}
	if !window.NotBefore.Before(window.NotAfter) {
		return nil, refuse("a window that ends before it starts")
	}
	rrsigSet := DnsRecordSet{Owner: root, Type: dns.TypeRRSIG, Kind: DnsRecordKindKey, Rdata: window.Rrsigs}
	rrsigRecords, err := rrsigSet.Records()
	if err != nil || len(rrsigRecords) == 0 {
		return nil, refuse("the window's signatures do not parse")
	}
	self := &DnsSigningKeys{
		root:      root,
		window:    window,
		zsk:       keySet.Zsk,
		notBefore: window.NotBefore,
		notAfter:  window.NotAfter,
	}
	for _, record := range rrsigRecords {
		rrsig := record.(*dns.RRSIG)
		if rrsig.TypeCovered != dns.TypeDNSKEY || dns.CanonicalName(rrsig.SignerName) != root {
			return nil, refuse("a window signature over something else")
		}
		if rrsig.OrigTtl != rrsigRecords[0].(*dns.RRSIG).OrigTtl {
			return nil, refuse("window signatures disagree on the TTL")
		}
		rrsig.Hdr.Ttl = rrsig.OrigTtl
		self.dnskeyRrsigs = append(self.dnskeyRrsigs, rrsig)
	}
	// the KSK signed the RRset at this TTL, so it is the TTL served
	ttl := self.dnskeyRrsigs[0].OrigTtl
	keySetRows := DnsRecordSet{Owner: root, Type: dns.TypeDNSKEY, Ttl: ttl, Kind: DnsRecordKindKey, Rdata: window.Dnskeys}
	keyRecords, err := keySetRows.Records()
	if err != nil || len(keyRecords) == 0 {
		return nil, refuse("the window's DNSKEYs do not parse")
	}
	publicText, ok := dnsP256PublicKeyText(keySet.Zsk.Public())
	if !ok {
		return nil, refuse("the zsk is not a P-256 key")
	}
	zskProbe := &dns.DNSKEY{Flags: dns.ZONE, Protocol: dnsKeyProtocol, Algorithm: dnsSigningAlgorithm, PublicKey: publicText}
	for _, record := range keyRecords {
		key := record.(*dns.DNSKEY)
		self.dnskeys = append(self.dnskeys, key)
		if dnsSameKey(key, zskProbe) {
			if !dnsUsableZoneKey(key) || key.Flags&dns.SEP != 0 {
				return nil, refuse("the window publishes the zsk as no zone signing key")
			}
			self.zskRecord = key
		}
	}
	if self.zskRecord == nil {
		return nil, refuse("the zsk is not in the window's DNSKEY RRset")
	}
	self.zskTag = self.zskRecord.KeyTag()
	self.zskId = sha256.Sum256([]byte(publicText))
	return self, nil
}

// Parses the KSK's DNSKEY records for root, as a host's configuration holds them, one presentation-form
// RDATA each: the trust anchors SelfCheck holds a window to. Each must be a usable zone key of the one
// algorithm with the SEP bit, as a KSK is published.
func ParseDnsTrustAnchors(root string, rdatas []string) ([]*dns.DNSKEY, error) {
	root = dns.CanonicalName(root)
	if err := validateDnsRoot(root); err != nil {
		return nil, fmt.Errorf("%w: anchors: %w", ErrDnsKeyRefused, err)
	}
	set := DnsRecordSet{Owner: root, Type: dns.TypeDNSKEY, Kind: DnsRecordKindKey, Rdata: rdatas}
	records, err := set.Records()
	if err != nil || len(records) == 0 {
		return nil, fmt.Errorf("%w: anchors do not parse", ErrDnsKeyRefused)
	}
	anchors := make([]*dns.DNSKEY, 0, len(records))
	for _, record := range records {
		key := record.(*dns.DNSKEY)
		if !dnsUsableZoneKey(key) || key.Flags&dns.SEP == 0 {
			return nil, fmt.Errorf("%w: an anchor that is no key-signing key", ErrDnsKeyRefused)
		}
		if !dnsP256PublicKeyValid(key.PublicKey) {
			return nil, fmt.Errorf("%w: an anchor whose key is no P-256 point", ErrDnsKeyRefused)
		}
		anchors = append(anchors, key)
	}
	return anchors, nil
}

// Whether a DNSKEY's public key is a point on P-256, X and Y in base64 (RFC 6605 §4).
func dnsP256PublicKeyValid(publicText string) bool {
	coordinates, err := base64.StdEncoding.DecodeString(publicText)
	if err != nil || len(coordinates) != 2*dnsP256ByteCount {
		return false
	}
	_, err = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{4}, coordinates...))
	return err == nil
}
