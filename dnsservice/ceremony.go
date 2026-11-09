// §12.6's Keys ceremony (D-DNS-5, R-DNS-10; DNS-M5-19): a quarter's DNSKEY windows, signed ahead by the
// KSK on an offline HSM with two people present, and the ZSK's key file.
//
// The KSK never meets this code. There is no cgo and no PKCS#11 here, and nothing takes a KSK's private
// key, so no KSK-shaped code ships: the tests' software signer stands in for the HSM in _test.go only.
//
//   - prepare takes the root, the KSK's public DNSKEY, the ZSKs' (current, next and standby) and the span
//     to cover, and lays the span out in windows of keys.window_s starting every keys.step_s. For each
//     it gives the exact bytes an RRSIG over the DNSKEY RRset signs (RFC 4034 §3.1.8.1): the RRSIG's
//     RDATA without its signature, then each DNSKEY in canonical form and order (§6.2, §6.3), with
//     their SHA-256, which the officers read against the HSM's own.
//   - the HSM signs each window's bytes with ECDSA P-256 over SHA-256 (RFC 6605), outside this tool.
//   - assemble takes those signatures, r||s as RFC 6605 writes it or DER, verifies each against the KSK
//     over the RRset it covers, and makes the window file for vault (key_window.go). It keeps the
//     previous file's windows that have not ended, so the API block holds both quarters across the
//     boundary, and refuses a file with a gap ahead.
//   - verify, VerifyDnsKeyWindowFile, rereads a window file offline.
//
// Every window of a quarter lists the KSK and the three ZSKs, so the next ZSK is published a quarter
// before it signs (pre-publication, RFC 6781 §4.1.1.1), and the standby is in every window, so mounting
// it after a leak needs no ceremony first (§12.6's runbook). Edges move to the next ZSK while the
// windows still list the current one, at least the longest TTL before the next quarter's windows drop
// it, so no cached signature outlives its key's DNSKEY: a runbook step, not code.
//
// The ZSK's key file is BIND's private key format, Private-key-format v1.3 for algorithm 13 with the
// scalar in base64, which LoadZsk reads and MarshalDnsZsk writes. It holds only the private key; the
// public half is in each window that names it.

package dnsservice

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// The format a ceremony's plan is written in, and the highest this release reads.
const DnsCeremonyPlanFormat = 1

// How many ZSKs a ceremony publishes, in this order in every window: current, next and standby (§12.6).
const dnsCeremonyZskCount = 3

// The most keys GenerateDnsZsk draws before it gives up: sixteen tags of 0 in a row is 2^-256 likely.
const dnsZskDrawCount = 16

// A plan, request or signature a ceremony cannot use. The wrapping error names the part.
var ErrDnsCeremonyRefused = errors.New("dns ceremony refused")

// What prepare takes.
type DnsCeremonyRequest struct {
	// The root the windows serve.
	Root string
	// The KSK's DNSKEY, one presentation-form RDATA, with the SEP bit.
	Ksk string
	// The ZSKs' DNSKEYs, one presentation-form RDATA each: current, next and standby.
	Zsks []string
	// The first window's inception, truncated to the second, as an RRSIG holds it.
	From time.Time
	// Windows start at From and every keys.step_s after it while before this.
	Until time.Time
}

// What prepare writes and assemble reads: the RRset every window signs and each window's signing input.
type DnsCeremonyPlan struct {
	// Read before anything else, so a plan this release does not know stops the reader.
	Format int    `json:"format"`
	Root   string `json:"root"`
	// The KSK's DNSKEY RDATA, whose key tag each RRSIG names. The first of Dnskeys.
	Ksk string `json:"ksk"`
	// The RRset every window signs, one RDATA a key: the KSK, then current, next and standby.
	Dnskeys []string `json:"dnskeys"`
	// The RRset's TTL, each RRSIG's original TTL.
	DnskeyTtl uint32              `json:"dnskey_ttl"`
	Windows   []DnsCeremonyWindow `json:"windows"`
}

// One window of a plan.
type DnsCeremonyWindow struct {
	// The RRSIG's inception and expiration.
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	// The exact bytes the HSM signs (RFC 4034 §3.1.8.1), base64 in JSON.
	SigningInput []byte `json:"signing_input"`
	// SHA-256 of SigningInput in lowercase hex, which the officers compare with the HSM's.
	SigningInputSha256 string `json:"signing_input_sha256"`
}

// Refuses with ErrDnsCeremonyRefused and what failed.
func dnsCeremonyRefuse(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrDnsCeremonyRefused, fmt.Sprintf(format, arguments...))
}

// One DNSKEY RDATA as a record of root at ttl, which must be a P-256 zone key of the one algorithm.
func parseDnsCeremonyKey(root string, rdata string, ttl uint32) (*dns.DNSKEY, error) {
	set := DnsRecordSet{Owner: root, Type: dns.TypeDNSKEY, Ttl: ttl, Kind: DnsRecordKindKey, Rdata: []string{rdata}}
	records, err := set.Records()
	if err != nil || len(records) != 1 {
		return nil, dnsCeremonyRefuse("a DNSKEY that does not parse")
	}
	key := records[0].(*dns.DNSKEY)
	if !dnsUsableZoneKey(key) || !dnsP256PublicKeyValid(key.PublicKey) {
		return nil, dnsCeremonyRefuse("a DNSKEY that is no P-256 zone key")
	}
	return key, nil
}

// A DNSKEY as a window lists it: its RDATA in presentation form.
func dnsRdataText(record dns.RR) string {
	return strings.TrimSpace(strings.TrimPrefix(record.String(), record.Header().String()))
}

// The KSK and the ZSKs of a request or plan, checked: one KSK with the SEP bit, then exactly three
// distinct ZSKs without it, none the KSK.
func parseDnsCeremonyKeys(root string, ksk string, zsks []string, ttl uint32) ([]*dns.DNSKEY, error) {
	kskKey, err := parseDnsCeremonyKey(root, ksk, ttl)
	if err != nil {
		return nil, err
	}
	if kskKey.Flags&dns.SEP == 0 {
		return nil, dnsCeremonyRefuse("the KSK has no SEP bit")
	}
	if len(zsks) != dnsCeremonyZskCount {
		return nil, dnsCeremonyRefuse("%d ZSKs where a ceremony takes current, next and standby", len(zsks))
	}
	keys := []*dns.DNSKEY{kskKey}
	for _, rdata := range zsks {
		key, err := parseDnsCeremonyKey(root, rdata, ttl)
		if err != nil {
			return nil, err
		}
		if key.Flags&dns.SEP != 0 {
			return nil, dnsCeremonyRefuse("a ZSK with the SEP bit")
		}
		if slices.ContainsFunc(keys, func(other *dns.DNSKEY) bool { return dnsSameKey(other, key) }) {
			return nil, dnsCeremonyRefuse("a key listed twice")
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// The RRSIG a window's signature completes: over the DNSKEY RRset of root by ksk, from notBefore to
// notAfter, with no signature yet.
func newDnsWindowRrsig(root string, ksk *dns.DNSKEY, ttl uint32, notBefore time.Time, notAfter time.Time) *dns.RRSIG {
	return &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: root, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: ttl},
		TypeCovered: dns.TypeDNSKEY,
		Algorithm:   dnsSigningAlgorithm,
		Labels:      uint8(dns.CountLabel(root)),
		OrigTtl:     ttl,
		Expiration:  uint32(notAfter.Unix()),
		Inception:   uint32(notBefore.Unix()),
		KeyTag:      ksk.KeyTag(),
		SignerName:  root,
	}
}

// RFC 4034 §3.1.8.1's signed data: the RRSIG's RDATA without its signature, then each record of rrset
// in canonical form (§6.2) and order (§6.3), duplicates once. The records carry no wildcard and a DNSKEY
// names no domain in its RDATA, so canonical form is the owner in lowercase, uncompressed, and the TTL
// the RRSIG's original one.
func dnsRrsigSigningInput(rrsig *dns.RRSIG, rrset []*dns.DNSKEY) ([]byte, error) {
	signerName := make([]byte, 256)
	signerLength, err := dns.PackDomainName(dns.CanonicalName(rrsig.SignerName), signerName, 0, nil, false)
	if err != nil {
		return nil, dnsCeremonyRefuse("a signer name that does not pack")
	}
	input := binary.BigEndian.AppendUint16(nil, rrsig.TypeCovered)
	input = append(input, rrsig.Algorithm, rrsig.Labels)
	input = binary.BigEndian.AppendUint32(input, rrsig.OrigTtl)
	input = binary.BigEndian.AppendUint32(input, rrsig.Expiration)
	input = binary.BigEndian.AppendUint32(input, rrsig.Inception)
	input = binary.BigEndian.AppendUint16(input, rrsig.KeyTag)
	input = append(input, signerName[:signerLength]...)

	type packedRecord struct {
		wire  []byte
		rdata []byte
	}
	packedRecords := make([]packedRecord, 0, len(rrset))
	for _, key := range rrset {
		record := dns.Copy(key).(*dns.DNSKEY)
		record.Hdr.Name = dns.CanonicalName(record.Hdr.Name)
		record.Hdr.Ttl = rrsig.OrigTtl
		wire := make([]byte, dns.Len(record)+1)
		length, err := dns.PackRR(record, wire, 0, nil, false)
		if err != nil {
			return nil, dnsCeremonyRefuse("a DNSKEY that does not pack")
		}
		wire = wire[:length]
		// the owner, then type, class, TTL and RDATA length: 10 bytes
		_, ownerLength, err := dns.UnpackDomainName(wire, 0)
		if err != nil || len(wire) < ownerLength+10 {
			return nil, dnsCeremonyRefuse("a DNSKEY that does not pack")
		}
		packedRecords = append(packedRecords, packedRecord{wire: wire, rdata: wire[ownerLength+10:]})
	}
	slices.SortFunc(packedRecords, func(a packedRecord, b packedRecord) int {
		return bytes.Compare(a.rdata, b.rdata)
	})
	for index, record := range packedRecords {
		if 0 < index && bytes.Equal(record.wire, packedRecords[index-1].wire) {
			continue
		}
		input = append(input, record.wire...)
	}
	return input, nil
}

// Lays [From, Until) out in windows and gives each one's signing input. Deterministic: the same request
// and settings give the same plan, byte for byte.
func CeremonyPrepare(settings *DnsKeySettings, request *DnsCeremonyRequest) (*DnsCeremonyPlan, error) {
	if err := settings.validate(); err != nil {
		return nil, dnsCeremonyRefuse("keys: %v", err)
	}
	root := dns.CanonicalName(request.Root)
	if err := validateDnsRoot(root); err != nil {
		return nil, dnsCeremonyRefuse("root: %v", err)
	}
	keys, err := parseDnsCeremonyKeys(root, request.Ksk, request.Zsks, settings.DnskeyTtl)
	if err != nil {
		return nil, err
	}
	from := request.From.UTC().Truncate(time.Second)
	if !from.Before(request.Until) {
		return nil, dnsCeremonyRefuse("from is not before until")
	}
	plan := &DnsCeremonyPlan{
		Format:    DnsCeremonyPlanFormat,
		Root:      root,
		DnskeyTtl: settings.DnskeyTtl,
	}
	for _, key := range keys {
		plan.Dnskeys = append(plan.Dnskeys, dnsRdataText(key))
	}
	plan.Ksk = plan.Dnskeys[0]
	step := dnsSeconds(settings.StepSeconds)
	length := dnsSeconds(settings.WindowSeconds)
	for start := from; start.Before(request.Until); start = start.Add(step) {
		window, err := newDnsCeremonyWindow(root, keys, settings.DnskeyTtl, start, start.Add(length))
		if err != nil {
			return nil, err
		}
		plan.Windows = append(plan.Windows, *window)
	}
	return plan, nil
}

// One window's signing input and its digest.
func newDnsCeremonyWindow(root string, keys []*dns.DNSKEY, ttl uint32, notBefore time.Time, notAfter time.Time) (*DnsCeremonyWindow, error) {
	rrsig := newDnsWindowRrsig(root, keys[0], ttl, notBefore, notAfter)
	input, err := dnsRrsigSigningInput(rrsig, keys)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(input)
	return &DnsCeremonyWindow{
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		SigningInput:       input,
		SigningInputSha256: hex.EncodeToString(digest[:]),
	}, nil
}

// The plan as the ceremony's media hold it: indented JSON and a final newline, for the officers to read.
func (self *DnsCeremonyPlan) Marshal() ([]byte, error) {
	data, err := json.MarshalIndent(self, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Reads a plan, stopping at a format this release does not know before reading the rest. Check holds
// what it says to the keys it names.
func ParseDnsCeremonyPlan(data []byte) (*DnsCeremonyPlan, error) {
	var header struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, dnsCeremonyRefuse("a plan that does not read: %v", err)
	}
	if header.Format <= 0 || DnsCeremonyPlanFormat < header.Format {
		return nil, dnsCeremonyRefuse("plan format %d", header.Format)
	}
	plan := &DnsCeremonyPlan{}
	if err := json.Unmarshal(data, plan); err != nil {
		return nil, dnsCeremonyRefuse("a plan that does not read: %v", err)
	}
	return plan, nil
}

// The plan's keys, after checking that every window's input is what its keys and times give, so a plan
// altered or damaged since prepare is refused before any signature is read against it.
func (self *DnsCeremonyPlan) check() ([]*dns.DNSKEY, error) {
	if self.Format != DnsCeremonyPlanFormat {
		return nil, dnsCeremonyRefuse("plan format %d", self.Format)
	}
	if err := validateDnsRoot(self.Root); err != nil {
		return nil, dnsCeremonyRefuse("root: %v", err)
	}
	if len(self.Dnskeys) == 0 || self.Dnskeys[0] != self.Ksk {
		return nil, dnsCeremonyRefuse("the KSK is not the RRset's first key")
	}
	if self.DnskeyTtl == 0 || dnsTtlMaxSeconds < self.DnskeyTtl {
		return nil, dnsCeremonyRefuse("dnskey_ttl %d", self.DnskeyTtl)
	}
	keys, err := parseDnsCeremonyKeys(self.Root, self.Ksk, self.Dnskeys[1:], self.DnskeyTtl)
	if err != nil {
		return nil, err
	}
	if len(self.Windows) == 0 {
		return nil, dnsCeremonyRefuse("a plan with no window")
	}
	for index := range self.Windows {
		window := &self.Windows[index]
		if !window.NotBefore.Before(window.NotAfter) {
			return nil, dnsCeremonyRefuse("window %d ends before it starts", index)
		}
		if 0 < index && !self.Windows[index-1].NotBefore.Before(window.NotBefore) {
			return nil, dnsCeremonyRefuse("window %d starts no later than the one before", index)
		}
		expected, err := newDnsCeremonyWindow(self.Root, keys, self.DnskeyTtl, window.NotBefore, window.NotAfter)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(expected.SigningInput, window.SigningInput) || expected.SigningInputSha256 != window.SigningInputSha256 {
			return nil, dnsCeremonyRefuse("window %d's signing input is not what its keys and times give", index)
		}
	}
	return keys, nil
}

// One HSM signature in the forms it may come in, raw r||s first: RFC 6605's 64 bytes, and DER's
// ECDSA-Sig-Value (RFC 3279 §2.2.3), which some HSM tools write, as r||s. Which one is the signature is
// for verification to say.
func dnsCeremonySignatureForms(signature []byte) [][]byte {
	forms := [][]byte{}
	if len(signature) == 2*dnsP256ByteCount {
		forms = append(forms, signature)
	}
	var value struct {
		R *big.Int
		S *big.Int
	}
	rest, err := asn1.Unmarshal(signature, &value)
	if err == nil && len(rest) == 0 && value.R != nil && value.S != nil && 0 < value.R.Sign() && 0 < value.S.Sign() &&
		value.R.BitLen() <= 8*dnsP256ByteCount && value.S.BitLen() <= 8*dnsP256ByteCount {
		raw := make([]byte, 2*dnsP256ByteCount)
		value.R.FillBytes(raw[:dnsP256ByteCount])
		value.S.FillBytes(raw[dnsP256ByteCount:])
		forms = append(forms, raw)
	}
	return forms
}

// Takes the HSM's signatures, one a window in the plan's order, verifies each against the plan's KSK
// over the RRset it covers, and makes the window file: previous's windows that end after now and start
// before the first new one, then the new ones. The KSK must be one of dns.yml's anchors for the root,
// since an edge serves no window its anchors do not verify. Refuses a file with a gap that ends after
// now, and returns the file's coverage for the officers to read.
func CeremonyAssemble(settings *DnsSettings, plan *DnsCeremonyPlan, signatures [][]byte, previous *DnsKeyWindowFile, now time.Time) (*DnsKeyWindowFile, *DnsKeyWindowCoverage, error) {
	keys, err := plan.check()
	if err != nil {
		return nil, nil, err
	}
	ksk := keys[0]
	anchors, err := ParseDnsTrustAnchors(plan.Root, settings.TrustAnchors[plan.Root])
	if err != nil {
		return nil, nil, dnsCeremonyRefuse("dns.yml's anchors for %s: %v", plan.Root, err)
	}
	if !slices.ContainsFunc(anchors, func(anchor *dns.DNSKEY) bool { return dnsSameKey(anchor, ksk) && anchor.Flags == ksk.Flags }) {
		return nil, nil, dnsCeremonyRefuse("the KSK is not one of dns.yml's anchors for %s", plan.Root)
	}
	if len(signatures) != len(plan.Windows) {
		return nil, nil, dnsCeremonyRefuse("%d signatures for %d windows", len(signatures), len(plan.Windows))
	}
	rrset := make([]dns.RR, 0, len(keys))
	for _, key := range keys {
		rrset = append(rrset, key)
	}
	windows := make([]DnsKeyWindow, 0, len(plan.Windows))
	for index := range plan.Windows {
		planWindow := &plan.Windows[index]
		rrsig := newDnsWindowRrsig(plan.Root, ksk, plan.DnskeyTtl, planWindow.NotBefore, planWindow.NotAfter)
		verified := false
		for _, form := range dnsCeremonySignatureForms(signatures[index]) {
			rrsig.Signature = base64.StdEncoding.EncodeToString(form)
			if rrsig.Verify(ksk, rrset) == nil {
				verified = true
				break
			}
		}
		if !verified {
			return nil, nil, dnsCeremonyRefuse("window %d's signature does not verify by the KSK", index)
		}
		windows = append(windows, DnsKeyWindow{
			Root:      plan.Root,
			NotBefore: planWindow.NotBefore,
			NotAfter:  planWindow.NotAfter,
			Dnskeys:   slices.Clone(plan.Dnskeys),
			Rrsigs:    []string{dnsRdataText(rrsig)},
		})
	}
	file := &DnsKeyWindowFile{Format: DnsKeyWindowFileFormat, Root: plan.Root}
	if previous != nil {
		if previous.Root != plan.Root {
			return nil, nil, dnsCeremonyRefuse("the previous file is %s's", previous.Root)
		}
		for _, window := range previous.Windows {
			if now.Before(window.NotAfter) && window.NotBefore.Before(windows[0].NotBefore) {
				file.Windows = append(file.Windows, window)
			}
		}
	}
	file.Windows = append(file.Windows, windows...)
	coverage, err := VerifyDnsKeyWindowFile(settings, file)
	if err != nil {
		return nil, nil, err
	}
	for _, gap := range coverage.Gaps {
		if now.Before(gap.Until) {
			return nil, nil, dnsCeremonyRefuse("a gap from %s to %s", gap.From.Format(time.RFC3339), gap.Until.Format(time.RFC3339))
		}
	}
	if !now.Before(coverage.Until) {
		return nil, nil, dnsCeremonyRefuse("the windows come to keys.min_left_s by %s, which is past", coverage.Until.Format(time.RFC3339))
	}
	return file, coverage, nil
}

// The ZSK's key file (see the file header). Only a P-256 key is one.
func MarshalDnsZsk(key crypto.Signer) ([]byte, error) {
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok || ecdsaKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: zsk file: not a P-256 key", ErrDnsKeyRefused)
	}
	scalar, err := ecdsaKey.Bytes()
	if err != nil || len(scalar) != dnsP256ByteCount {
		return nil, fmt.Errorf("%w: zsk file: not a P-256 key", ErrDnsKeyRefused)
	}
	var file strings.Builder
	fmt.Fprintf(&file, "Private-key-format: v1.3\n")
	fmt.Fprintf(&file, "Algorithm: %d (ECDSAP256SHA256)\n", dnsSigningAlgorithm)
	fmt.Fprintf(&file, "PrivateKey: %s\n", base64.StdEncoding.EncodeToString(scalar))
	return []byte(file.String()), nil
}

// A new ZSK: its key file and its DNSKEY RDATA, flags 256. A key whose tag is 0 is drawn again, since
// miekg/dns will not sign under one; one draw in 65536 has it, so a bounded few draws always do. The
// scalar goes to the privacy harness as it is made (§22.7).
func GenerateDnsZsk() (keyFile []byte, dnskey string, returnErr error) {
	for range dnsZskDrawCount {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, "", err
		}
		scalar, err := key.Bytes()
		if err != nil {
			return nil, "", err
		}
		testHookSecret("dns_zsk", scalar)
		publicText, ok := dnsP256PublicKeyText(key.Public())
		if !ok {
			return nil, "", fmt.Errorf("%w: a generated key that is no P-256 point", ErrDnsKeyRefused)
		}
		record := &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
			Flags:     dns.ZONE,
			Protocol:  dnsKeyProtocol,
			Algorithm: dnsSigningAlgorithm,
			PublicKey: publicText,
		}
		if record.KeyTag() == 0 {
			continue
		}
		keyFile, err := MarshalDnsZsk(key)
		if err != nil {
			return nil, "", err
		}
		return keyFile, dnsRdataText(record), nil
	}
	return nil, "", fmt.Errorf("%w: %d draws all had key tag 0", ErrDnsKeyRefused, dnsZskDrawCount)
}
