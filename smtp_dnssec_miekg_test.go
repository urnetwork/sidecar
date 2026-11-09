//go:build !sidecar_http

package sidecar

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A differential leg against miekg/dns, test-only (dependencies.yml's test leg): zones signed by miekg
// with RSA/SHA-256 at the root, Ed25519 below it and ECDSA P-256 below that, SHA-384 and SHA-256 DS
// digests, NSEC denials, a CNAME at the TLSA name, an insecure delegation by NSEC and a DS of an
// algorithm this validator does not verify. MxWorld signs only ECDSA with NSEC3, so this is where the
// other paths meet an independent signer, and where every RRSIG's verdict is held to miekg's.

var testMiekgSignTime = time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)

// One zone miekg signs.
type testMiekgZone struct {
	name   string
	key    *dns.DNSKEY
	signer crypto.Signer
}

func newTestMiekgZone(t *testing.T, name string, algorithm uint8) *testMiekgZone {
	t.Helper()
	bits := map[uint8]int{dns.RSASHA256: 2048, dns.ECDSAP256SHA256: 256, dns.ED25519: 256}[algorithm]
	// miekg/dns will not sign under a key whose tag is 0, and about one random key in 65536 has
	// that tag, so such a key is drawn again.
	for {
		key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}, Flags: dns.ZONE | dns.SEP, Protocol: 3, Algorithm: algorithm}
		private, err := key.Generate(bits)
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyTag() != 0 {
			return &testMiekgZone{name: name, key: key, signer: private.(crypto.Signer)}
		}
	}
}

func testMiekgPack(t *testing.T, rr dns.RR) []byte {
	t.Helper()
	wire := make([]byte, dns.Len(rr)+256)
	n, err := dns.PackRR(rr, wire, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	return wire[:n]
}

// rrset and the zone's RRSIG over it, as wire.
func (self *testMiekgZone) signed(t *testing.T, rrset ...dns.RR) []byte {
	t.Helper()
	signature := &dns.RRSIG{
		Hdr:        dns.RR_Header{Ttl: 300},
		Algorithm:  self.key.Algorithm,
		KeyTag:     self.key.KeyTag(),
		SignerName: self.name,
		Inception:  uint32(testMiekgSignTime.Add(-time.Hour).Unix()),
		Expiration: uint32(testMiekgSignTime.Add(30 * 24 * time.Hour).Unix()),
	}
	if err := signature.Sign(self.signer, rrset); err != nil {
		t.Fatal(err)
	}
	var wire []byte
	for _, rr := range rrset {
		wire = append(wire, testMiekgPack(t, rr)...)
	}
	return append(wire, testMiekgPack(t, signature)...)
}

func testMiekgRr(t *testing.T, text string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(text)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

// The world of this test: root, example. under it, nsec.example. under that, insecure.example.
// delegated with no DS, and legacy. under the root with a DS only for algorithm 5.
type testMiekgWorld struct {
	root, example, nsecZone *testMiekgZone
}

func newTestMiekgWorld(t *testing.T) *testMiekgWorld {
	t.Helper()
	return &testMiekgWorld{
		root:     newTestMiekgZone(t, ".", dns.RSASHA256),
		example:  newTestMiekgZone(t, "example.", dns.ED25519),
		nsecZone: newTestMiekgZone(t, "nsec.example.", dns.ECDSAP256SHA256),
	}
}

func (self *testMiekgWorld) anchors(t *testing.T) *SmtpDnssecAnchors {
	t.Helper()
	anchors, err := NewSmtpDnssecAnchors(testMiekgPack(t, self.root.key.ToDS(dns.SHA256)))
	if err != nil {
		t.Fatal(err)
	}
	return anchors
}

// Every zone's keys and DS, deepest first, as RFC 9102 orders them.
func (self *testMiekgWorld) material(t *testing.T) []byte {
	t.Helper()
	exampleDs := self.example.key.ToDS(dns.SHA384)
	exampleDs.Hdr.Ttl = 300
	nsecDs := self.nsecZone.key.ToDS(dns.SHA256)
	nsecDs.Hdr.Ttl = 300
	var wire []byte
	wire = append(wire, self.nsecZone.signed(t, self.nsecZone.key)...)
	wire = append(wire, self.example.signed(t, nsecDs)...)
	wire = append(wire, self.example.signed(t, self.example.key)...)
	wire = append(wire, self.root.signed(t, exampleDs)...)
	return append(wire, self.root.signed(t, self.root.key)...)
}

// The MX RRset of nsec.example. naming mx.nsec.example.
func (self *testMiekgWorld) mx(t *testing.T) []byte {
	t.Helper()
	return self.nsecZone.signed(t, testMiekgRr(t, "nsec.example. 300 IN MX 10 mx.nsec.example."))
}

func testMiekgValidate(t *testing.T, chain []byte, anchors *SmtpDnssecAnchors, domain string, host string) (*SmtpDnssecResult, error) {
	t.Helper()
	parsed, err := ParseSmtpDnssecChain(chain, nil)
	if err != nil {
		return nil, err
	}
	return parsed.Validate(anchors, testMiekgSignTime.Add(time.Minute), domain, host)
}

// A CNAME at _25._tcp.<host> leads to the TLSA RRset, across three algorithms and two digest types.
func TestSmtpDnssecFollowsACnameAcrossAlgorithms(t *testing.T) {
	world := newTestMiekgWorld(t)
	chain := world.mx(t)
	chain = append(chain, world.nsecZone.signed(t, testMiekgRr(t, "_25._tcp.mx.nsec.example. 300 IN CNAME tlsa.nsec.example."))...)
	chain = append(chain, world.nsecZone.signed(t, testMiekgRr(t, "tlsa.nsec.example. 300 IN TLSA 3 1 1 "+strings.Repeat("ab", 32)))...)
	chain = append(chain, world.material(t)...)
	result, err := testMiekgValidate(t, chain, world.anchors(t), "nsec.example", "mx.nsec.example")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != SmtpDnssecStatusTlsa || len(result.TlsaRecords) != 1 || !bytes.Equal(result.TlsaRecords[0].Data, bytes.Repeat([]byte{0xab}, 32)) {
		t.Errorf("result %+v", result)
	}
}

// RFC 4035 §5.4: one NSEC covering the TLSA name and the wildcard at its closest encloser proves no
// TLSA; an NSEC at the name without TLSA does too; and an NSEC that covers nothing proves nothing.
func TestSmtpDnssecProvesNoTlsaByNsec(t *testing.T) {
	world := newTestMiekgWorld(t)
	for _, c := range []struct {
		nsec   string
		absent bool
	}{
		{nsec: "mx.nsec.example. 300 IN NSEC tlsa.nsec.example. A RRSIG NSEC", absent: true},
		{nsec: "_25._tcp.mx.nsec.example. 300 IN NSEC tlsa.nsec.example. TXT RRSIG NSEC", absent: true},
		{nsec: "tlsa.nsec.example. 300 IN NSEC nsec.example. RRSIG NSEC TLSA", absent: false},
		{nsec: "_25._tcp.mx.nsec.example. 300 IN NSEC tlsa.nsec.example. RRSIG NSEC TLSA", absent: false},
	} {
		chain := append(world.mx(t), world.nsecZone.signed(t, testMiekgRr(t, c.nsec))...)
		chain = append(chain, world.material(t)...)
		result, err := testMiekgValidate(t, chain, world.anchors(t), "nsec.example", "mx.nsec.example")
		if c.absent && (err != nil || result.Status != SmtpDnssecStatusNoTlsa) {
			t.Errorf("%s: %+v %v", c.nsec, result, err)
		}
		if !c.absent && !errors.Is(err, ErrSmtpDnssecBogus) {
			t.Errorf("%s proved an absence: %+v", c.nsec, result)
		}
	}
}

// RFC 4035 §5.2: an NSEC at a delegation with NS and no DS makes the zone below insecure, and so does
// a DS naming only an algorithm this validator does not verify.
func TestSmtpDnssecInsecureByNsecAndByAlgorithm(t *testing.T) {
	world := newTestMiekgWorld(t)
	chain := testMiekgPack(t, testMiekgRr(t, "insecure.example. 300 IN MX 10 mx.insecure.example."))
	chain = append(chain, world.example.signed(t, testMiekgRr(t, "insecure.example. 300 IN NSEC nsec.example. NS RRSIG NSEC"))...)
	chain = append(chain, world.material(t)...)
	result, err := testMiekgValidate(t, chain, world.anchors(t), "insecure.example", "mx.insecure.example")
	if err != nil || result.Status != SmtpDnssecStatusInsecure {
		t.Errorf("nsec: %+v %v", result, err)
	}

	legacyDs := testMiekgRr(t, "legacy. 300 IN DS 4242 5 2 "+strings.Repeat("00", 32))
	chain = testMiekgPack(t, testMiekgRr(t, "legacy. 300 IN MX 10 mx.legacy."))
	chain = append(chain, world.root.signed(t, legacyDs)...)
	chain = append(chain, world.root.signed(t, world.root.key)...)
	result, err = testMiekgValidate(t, chain, world.anchors(t), "legacy", "mx.legacy")
	if err != nil || result.Status != SmtpDnssecStatusInsecure {
		t.Errorf("algorithm 5: %+v %v", result, err)
	}

	// the same NSEC with DS set is a secure delegation whose keys are missing: bogus
	chain = testMiekgPack(t, testMiekgRr(t, "insecure.example. 300 IN MX 10 mx.insecure.example."))
	chain = append(chain, world.example.signed(t, testMiekgRr(t, "insecure.example. 300 IN NSEC nsec.example. NS DS RRSIG NSEC"))...)
	chain = append(chain, world.material(t)...)
	if _, err := testMiekgValidate(t, chain, world.anchors(t), "insecure.example", "mx.insecure.example"); !errors.Is(err, ErrSmtpDnssecBogus) {
		t.Errorf("a secure delegation read as insecure: %v", err)
	}
}

// Every record parses to what miekg unpacks, and every RRSIG's verdict here is miekg's, for the
// valid chain and with each signature's last octet flipped.
func TestSmtpDnssecAgreesWithMiekg(t *testing.T) {
	world := newTestMiekgWorld(t)
	chain := world.mx(t)
	chain = append(chain, world.nsecZone.signed(t, testMiekgRr(t, "_25._tcp.mx.nsec.example. 300 IN CNAME tlsa.nsec.example."))...)
	chain = append(chain, world.nsecZone.signed(t, testMiekgRr(t, "tlsa.nsec.example. 300 IN TLSA 2 0 1 "+strings.Repeat("cd", 32)))...)
	chain = append(chain, world.nsecZone.signed(t, testMiekgRr(t, "mx.nsec.example. 300 IN NSEC tlsa.nsec.example. A RRSIG NSEC"))...)
	chain = append(chain, world.material(t)...)

	rrs, err := parseSmtpDnsRrs(chain, 512)
	if err != nil {
		t.Fatal(err)
	}
	offset := 0
	for _, rr := range rrs {
		theirs, next, err := dns.UnpackRR(chain, offset)
		if err != nil {
			t.Fatal(err)
		}
		owner, _ := smtpDnsNameFromText(dns.CanonicalName(theirs.Header().Name))
		if rr.owner != owner || rr.rrtype != theirs.Header().Rrtype || !bytes.Equal(testMiekgPack(t, theirs)[len(testMiekgPack(t, theirs))-len(rr.rdata):], rr.rdata) {
			t.Errorf("at %d: %x %d against %s", offset, rr.owner, rr.rrtype, theirs)
		}
		offset = next
	}

	zonesBySigner := map[smtpDnsName]*testMiekgZone{}
	for _, zone := range []*testMiekgZone{world.root, world.example, world.nsecZone} {
		name, _ := smtpDnsNameFromText(zone.name)
		zonesBySigner[name] = zone
	}
	for _, flip := range []bool{false, true} {
		parsed, err := ParseSmtpDnssecChain(chain, nil)
		if err != nil {
			t.Fatal(err)
		}
		validator := &smtpDnssecValidator{chain: parsed, now: testMiekgSignTime.Add(time.Minute)}
		checked := 0
		for _, rrset := range parsed.rrsets {
			for _, signature := range rrset.signatures {
				zone := zonesBySigner[signature.signer]
				keyRrs, err := parseSmtpDnsRrs(testMiekgPack(t, zone.key), 1)
				if err != nil {
					t.Fatal(err)
				}
				ourKey, _ := parseSmtpDnsDnskey(keyRrs[0].rdata)
				if flip {
					signature.signature = bytes.Clone(signature.signature)
					signature.signature[len(signature.signature)-1] ^= 0x01
				}
				ours := validator.verify(rrset, signature, ourKey) == nil
				// miekg's verdict over the same records
				var theirSet []dns.RR
				for _, rr := range rrset.rrs {
					wire := append(append([]byte(rr.owner), byte(rr.rrtype>>8), byte(rr.rrtype), 0, 1, 0, 0, 1, 44, byte(len(rr.rdata)>>8), byte(len(rr.rdata))), rr.rdata...)
					theirRr, _, err := dns.UnpackRR(wire, 0)
					if err != nil {
						t.Fatal(err)
					}
					theirSet = append(theirSet, theirRr)
				}
				theirSignature := &dns.RRSIG{
					Hdr:         dns.RR_Header{Name: theirSet[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: signature.originalTtl},
					TypeCovered: signature.typeCovered, Algorithm: signature.algorithm, Labels: signature.labels, OrigTtl: signature.originalTtl,
					Expiration: signature.expiration, Inception: signature.inception, KeyTag: signature.keyTag, SignerName: zone.name,
					Signature: base64.StdEncoding.EncodeToString(signature.signature),
				}
				theirs := theirSignature.Verify(zone.key, theirSet) == nil
				if ours != theirs || ours == flip {
					t.Errorf("flip %v, type %d: ours %v, miekg's %v", flip, rrset.key.rrtype, ours, theirs)
				}
				checked += 1
			}
		}
		if checked < 8 {
			t.Errorf("%d signatures checked", checked)
		}
	}
}

// The release's anchors are IANA's two root keys, and nothing else.
func TestSmtpDnssecDefaultAnchorsAreTheRootKeys(t *testing.T) {
	anchors := DefaultSmtpDnssecAnchors()
	if len(anchors.ds) != 2 {
		t.Fatalf("%d anchors", len(anchors.ds))
	}
	for i, keyTag := range []uint16{20326, 38696} {
		ds := anchors.ds[i]
		if ds.keyTag != keyTag || ds.algorithm != smtpDnssecAlgorithmRsaSha256 || ds.digestType != smtpDnssecDigestSha256 || len(ds.digest) != 32 {
			t.Errorf("anchor %d: %+v", i, ds)
		}
	}
	if _, err := NewSmtpDnssecAnchors(); !errors.Is(err, ErrSmtpDnssecBogus) {
		t.Errorf("no anchors: %v", err)
	}
	world := newTestMiekgWorld(t)
	notRoot := world.example.key.ToDS(dns.SHA256)
	if _, err := NewSmtpDnssecAnchors(testMiekgPack(t, notRoot)); !errors.Is(err, ErrSmtpDnssecBogus) {
		t.Errorf("a non-root anchor: %v", err)
	}
}
