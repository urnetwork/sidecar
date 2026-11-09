package dnsservice_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar/dnsservice"
)

// The ceremony tests' root and quarter, which the golden files hold.
const ceremonyTestRoot = "zone.example."

var (
	ceremonyTestFrom  = time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)
	ceremonyTestUntil = time.Date(2027, time.April, 1, 0, 0, 0, 0, time.UTC)
)

// Visibly synthetic P-256 scalars: the HSM's stand-in KSK, the three ZSKs and a key no window names. No
// key here signs anything outside tests.
const (
	ceremonyTestKskScalarHex     = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	ceremonyTestCurrentScalarHex = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	ceremonyTestNextScalarHex    = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
	ceremonyTestStandbyScalarHex = "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4"
	ceremonyTestOtherScalarHex   = "e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5"
)

// Set to 1 to write the golden files under testdata/dns/windows/ from the stand-in KSK, rather than
// check them.
const ceremonyGoldenWriteEnv = "DNSSERVICE_WRITE_CEREMONY_GOLDENS"

// A P-256 key from a fixed scalar.
func ceremonyTestKey(t testing.TB, scalarHex string) *ecdsa.PrivateKey {
	t.Helper()
	scalar, err := hex.DecodeString(scalarHex)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// key's DNSKEY RDATA with flags.
func ceremonyTestDnskey(t testing.TB, key *ecdsa.PrivateKey, flags uint16) string {
	t.Helper()
	point, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	record := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ceremonyTestRoot, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: base64.StdEncoding.EncodeToString(point[1:]),
	}
	return strings.TrimSpace(strings.TrimPrefix(record.String(), record.Header().String()))
}

// The HSM's stand-in: a software KSK, in this test file only, so no KSK-shaped code ships.
type ceremonyTestHsm struct {
	key *ecdsa.PrivateKey
}

// The DER signature an HSM tool might write over input.
func (self *ceremonyTestHsm) signDer(t testing.TB, input []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(input)
	signature, err := ecdsa.SignASN1(rand.Reader, self.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

// The r||s signature RFC 6605 writes over input.
func (self *ceremonyTestHsm) signRaw(t testing.TB, input []byte) []byte {
	t.Helper()
	var value struct {
		R *big.Int
		S *big.Int
	}
	if _, err := asn1.Unmarshal(self.signDer(t, input), &value); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	value.R.FillBytes(raw[:32])
	value.S.FillBytes(raw[32:])
	return raw
}

// Each window's signature, raw.
func (self *ceremonyTestHsm) signPlan(t testing.TB, plan *dnsservice.DnsCeremonyPlan) [][]byte {
	t.Helper()
	signatures := [][]byte{}
	for index := range plan.Windows {
		signatures = append(signatures, self.signRaw(t, plan.Windows[index].SigningInput))
	}
	return signatures
}

// The ceremony's parties: the stand-in HSM, the ZSKs and dns.yml with the KSK as the root's anchor.
type ceremonyTest struct {
	hsm      *ceremonyTestHsm
	ksk      string
	current  *ecdsa.PrivateKey
	next     *ecdsa.PrivateKey
	standby  *ecdsa.PrivateKey
	zsks     []string
	settings *dnsservice.DnsSettings
}

func newCeremonyTest(t testing.TB) *ceremonyTest {
	t.Helper()
	self := &ceremonyTest{
		hsm:     &ceremonyTestHsm{key: ceremonyTestKey(t, ceremonyTestKskScalarHex)},
		current: ceremonyTestKey(t, ceremonyTestCurrentScalarHex),
		next:    ceremonyTestKey(t, ceremonyTestNextScalarHex),
		standby: ceremonyTestKey(t, ceremonyTestStandbyScalarHex),
	}
	self.ksk = ceremonyTestDnskey(t, self.hsm.key, dns.ZONE|dns.SEP)
	for _, key := range []*ecdsa.PrivateKey{self.current, self.next, self.standby} {
		self.zsks = append(self.zsks, ceremonyTestDnskey(t, key, dns.ZONE))
	}
	settings := dnsservice.DefaultDnsSettings()
	settings.Roots = []string{ceremonyTestRoot}
	settings.SignaturesPerSecond = 1
	settings.Tcp.ConnectionsPerSource = 1
	settings.Rrl.ResponsesPerSecond = 1
	settings.TrustAnchors = map[string][]string{ceremonyTestRoot: {self.ksk}}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	self.settings = settings
	return self
}

// The request for [from, until).
func (self *ceremonyTest) request(from time.Time, until time.Time) *dnsservice.DnsCeremonyRequest {
	return &dnsservice.DnsCeremonyRequest{Root: ceremonyTestRoot, Ksk: self.ksk, Zsks: slices.Clone(self.zsks), From: from, Until: until}
}

// The plan for [from, until).
func (self *ceremonyTest) prepare(t testing.TB, from time.Time, until time.Time) *dnsservice.DnsCeremonyPlan {
	t.Helper()
	plan, err := dnsservice.CeremonyPrepare(&self.settings.Keys, self.request(from, until))
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// The window file for [from, until), signed by the stand-in HSM and assembled at now over previous.
func (self *ceremonyTest) windows(t testing.TB, from time.Time, until time.Time, previous *dnsservice.DnsKeyWindowFile, now time.Time) *dnsservice.DnsKeyWindowFile {
	t.Helper()
	plan := self.prepare(t, from, until)
	file, _, err := dnsservice.CeremonyAssemble(self.settings, plan, self.hsm.signPlan(t, plan), previous, now)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

// The anchors an edge holds.
func (self *ceremonyTest) anchors(t testing.TB) []*dns.DNSKEY {
	t.Helper()
	anchors, err := dnsservice.ParseDnsTrustAnchors(ceremonyTestRoot, []string{self.ksk})
	if err != nil {
		t.Fatal(err)
	}
	return anchors
}

// A view of the root holding only its SOA, enough for SelfCheck.
func (self *ceremonyTest) view(t testing.TB) *dnsservice.ZoneView {
	t.Helper()
	rows := []dnsservice.DnsRecordSet{{
		Owner: ceremonyTestRoot, Type: dns.TypeSOA, Ttl: 3600, Kind: dnsservice.DnsRecordKindSystem,
		Rdata: []string{"ns1.zone.example. hostmaster.zone.example. 1 7200 3600 1209600 60"},
	}}
	snapshot := dnsservice.DnsSnapshot{Format: dnsservice.DnsFormat, Root: ceremonyTestRoot, Serial: 1}
	view, err := dnsservice.NewZoneView(self.settings, dnsservice.NewDnsSnapshotRows(snapshot, rows))
	if err != nil {
		t.Fatal(err)
	}
	return view
}

// Prepare lays the quarter out every step_s, each window window_s long, and assemble's windows pass an
// edge's SelfCheck with the current ZSK at a time inside each.
func TestCeremonyRoundTripPassesSelfCheck(t *testing.T) {
	ceremony := newCeremonyTest(t)
	plan := ceremony.prepare(t, ceremonyTestFrom, ceremonyTestUntil)
	// 90 days at six a window
	if len(plan.Windows) != 15 {
		t.Fatalf("%d windows", len(plan.Windows))
	}
	for index, window := range plan.Windows {
		start := ceremonyTestFrom.Add(time.Duration(index) * 6 * 24 * time.Hour)
		if !window.NotBefore.Equal(start) || !window.NotAfter.Equal(start.Add(14*24*time.Hour)) {
			t.Errorf("window %d: %v to %v", index, window.NotBefore, window.NotAfter)
		}
		digest := sha256.Sum256(window.SigningInput)
		if window.SigningInputSha256 != hex.EncodeToString(digest[:]) {
			t.Errorf("window %d's digest", index)
		}
	}
	if plan.Ksk != ceremony.ksk || !slices.Equal(plan.Dnskeys, append([]string{ceremony.ksk}, ceremony.zsks...)) {
		t.Errorf("the plan's keys %v", plan.Dnskeys)
	}
	file, coverage, err := dnsservice.CeremonyAssemble(ceremony.settings, plan, ceremony.hsm.signPlan(t, plan), nil, ceremonyTestFrom)
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Windows) != len(plan.Windows) || len(coverage.Gaps) != 0 {
		t.Fatalf("%d windows, gaps %v", len(file.Windows), coverage.Gaps)
	}
	last := plan.Windows[len(plan.Windows)-1]
	if !coverage.From.Equal(ceremonyTestFrom.Add(time.Hour)) || !coverage.Until.Equal(last.NotAfter.Add(-7*24*time.Hour)) {
		t.Errorf("coverage %v to %v", coverage.From, coverage.Until)
	}
	view := ceremony.view(t)
	for index := range file.Windows {
		window := &file.Windows[index]
		keySet := &dnsservice.DnsKeySet{Window: window, Zsk: ceremony.current}
		if _, err := dnsservice.SelfCheck(view, keySet, ceremony.anchors(t), window.NotBefore.Add(2*time.Hour)); err != nil {
			t.Errorf("window %d: %v", index, err)
		}
	}
}

// The bytes prepare gives the HSM are the bytes miekg/dns signs and verifies: a signature miekg makes
// over the RRset verifies over the input as a plain ECDSA signature of its SHA-256.
func TestCeremonySigningInputIsWhatAValidatorVerifies(t *testing.T) {
	ceremony := newCeremonyTest(t)
	plan := ceremony.prepare(t, ceremonyTestFrom, ceremonyTestUntil)
	window := plan.Windows[3]
	rrset := []dns.RR{}
	var ksk *dns.DNSKEY
	for _, rdata := range plan.Dnskeys {
		record, err := dns.NewRR(ceremonyTestRoot + " 3600 IN DNSKEY " + rdata)
		if err != nil {
			t.Fatal(err)
		}
		if ksk == nil {
			ksk = record.(*dns.DNSKEY)
		}
		rrset = append(rrset, record)
	}
	// miekg's own order is canonical, so a shuffled RRset signs the same bytes
	slices.Reverse(rrset)
	rrsig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: ceremonyTestRoot, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm:  dns.ECDSAP256SHA256,
		KeyTag:     ksk.KeyTag(),
		SignerName: ceremonyTestRoot,
		Inception:  uint32(window.NotBefore.Unix()),
		Expiration: uint32(window.NotAfter.Unix()),
	}
	if err := rrsig.Sign(ceremony.hsm.key, rrset); err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(rrsig.Signature)
	if err != nil || len(signature) != 64 {
		t.Fatal(err)
	}
	digest := sha256.Sum256(window.SigningInput)
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(&ceremony.hsm.key.PublicKey, digest[:], r, s) {
		t.Error("miekg's signature does not verify over the plan's input")
	}
}

// Assemble refuses every signature that is not the KSK's over its own window: another key's, another
// window's, a damaged one, and a count that does not match.
func TestCeremonyAssembleRefusesAWrongSignature(t *testing.T) {
	ceremony := newCeremonyTest(t)
	plan := ceremony.prepare(t, ceremonyTestFrom, ceremonyTestUntil)
	other := &ceremonyTestHsm{key: ceremonyTestKey(t, ceremonyTestOtherScalarHex)}
	cases := []struct {
		name   string
		change func(signatures [][]byte) [][]byte
	}{
		{name: "another key", change: func(signatures [][]byte) [][]byte {
			signatures[2] = other.signRaw(t, plan.Windows[2].SigningInput)
			return signatures
		}},
		{name: "another window", change: func(signatures [][]byte) [][]byte {
			signatures[0] = signatures[1]
			return signatures
		}},
		{name: "a damaged signature", change: func(signatures [][]byte) [][]byte {
			signatures[4][10] ^= 1
			return signatures
		}},
		{name: "a short signature", change: func(signatures [][]byte) [][]byte {
			signatures[4] = signatures[4][:63]
			return signatures
		}},
		{name: "one too few", change: func(signatures [][]byte) [][]byte {
			return signatures[:len(signatures)-1]
		}},
	}
	for _, c := range cases {
		signatures := c.change(ceremony.hsm.signPlan(t, plan))
		_, _, err := dnsservice.CeremonyAssemble(ceremony.settings, plan, signatures, nil, ceremonyTestFrom)
		if !errors.Is(err, dnsservice.ErrDnsCeremonyRefused) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// An HSM tool's DER takes the same path as RFC 6605's r||s, and both make the same window file.
func TestCeremonyAssembleTakesDerAndRawSignatures(t *testing.T) {
	ceremony := newCeremonyTest(t)
	plan := ceremony.prepare(t, ceremonyTestFrom, ceremonyTestUntil)
	signatures := [][]byte{}
	for index := range plan.Windows {
		if index%2 == 0 {
			signatures = append(signatures, ceremony.hsm.signDer(t, plan.Windows[index].SigningInput))
		} else {
			signatures = append(signatures, ceremony.hsm.signRaw(t, plan.Windows[index].SigningInput))
		}
	}
	file, _, err := dnsservice.CeremonyAssemble(ceremony.settings, plan, signatures, nil, ceremonyTestFrom)
	if err != nil {
		t.Fatal(err)
	}
	for index := range file.Windows {
		rrsig, err := dns.NewRR(ceremonyTestRoot + " 3600 IN RRSIG " + file.Windows[index].Rrsigs[0])
		if err != nil {
			t.Fatal(err)
		}
		signature, err := base64.StdEncoding.DecodeString(rrsig.(*dns.RRSIG).Signature)
		if err != nil || len(signature) != 64 {
			t.Errorf("window %d holds a %d-byte signature", index, len(signature))
		}
	}
}

// A plan changed after prepare, or whose KSK dns.yml does not anchor, is refused before any signature
// is read against it.
func TestCeremonyAssembleRefusesAnAlteredPlanOrAnUnanchoredKsk(t *testing.T) {
	ceremony := newCeremonyTest(t)
	plan := ceremony.prepare(t, ceremonyTestFrom, ceremonyTestUntil)
	signatures := ceremony.hsm.signPlan(t, plan)

	moved := *plan
	moved.Windows = slices.Clone(plan.Windows)
	moved.Windows[5].NotAfter = moved.Windows[5].NotAfter.Add(24 * time.Hour)
	if _, _, err := dnsservice.CeremonyAssemble(ceremony.settings, &moved, signatures, nil, ceremonyTestFrom); !errors.Is(err, dnsservice.ErrDnsCeremonyRefused) {
		t.Errorf("a moved window: %v", err)
	}
	swapped := *plan
	swapped.Dnskeys = slices.Clone(plan.Dnskeys)
	swapped.Dnskeys[3] = ceremonyTestDnskey(t, ceremonyTestKey(t, ceremonyTestOtherScalarHex), dns.ZONE)
	if _, _, err := dnsservice.CeremonyAssemble(ceremony.settings, &swapped, signatures, nil, ceremonyTestFrom); !errors.Is(err, dnsservice.ErrDnsCeremonyRefused) {
		t.Errorf("a swapped ZSK: %v", err)
	}

	unanchored := *ceremony.settings
	unanchored.TrustAnchors = map[string][]string{ceremonyTestRoot: {ceremonyTestDnskey(t, ceremonyTestKey(t, ceremonyTestOtherScalarHex), dns.ZONE|dns.SEP)}}
	if _, _, err := dnsservice.CeremonyAssemble(&unanchored, plan, signatures, nil, ceremonyTestFrom); !errors.Is(err, dnsservice.ErrDnsCeremonyRefused) {
		t.Errorf("an unanchored KSK: %v", err)
	}
}

// Prepare refuses keys a ceremony cannot use: a KSK without the SEP bit, a ZSK with it, other than three
// ZSKs, one key twice, and a key that is no P-256 point.
func TestCeremonyPrepareRefusesKeysItCannotUse(t *testing.T) {
	ceremony := newCeremonyTest(t)
	cases := []struct {
		name   string
		change func(request *dnsservice.DnsCeremonyRequest)
	}{
		{name: "a KSK with no SEP bit", change: func(request *dnsservice.DnsCeremonyRequest) {
			request.Ksk = ceremonyTestDnskey(t, ceremony.hsm.key, dns.ZONE)
		}},
		{name: "a ZSK with the SEP bit", change: func(request *dnsservice.DnsCeremonyRequest) {
			request.Zsks[1] = ceremonyTestDnskey(t, ceremony.next, dns.ZONE|dns.SEP)
		}},
		{name: "two ZSKs", change: func(request *dnsservice.DnsCeremonyRequest) {
			request.Zsks = request.Zsks[:2]
		}},
		{name: "a ZSK twice", change: func(request *dnsservice.DnsCeremonyRequest) {
			request.Zsks[2] = request.Zsks[0]
		}},
		{name: "the KSK as a ZSK", change: func(request *dnsservice.DnsCeremonyRequest) {
			request.Zsks[2] = ceremonyTestDnskey(t, ceremony.hsm.key, dns.ZONE)
		}},
		{name: "no P-256 point", change: func(request *dnsservice.DnsCeremonyRequest) {
			request.Zsks[0] = "256 3 13 " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 64))
		}},
		{name: "an empty span", change: func(request *dnsservice.DnsCeremonyRequest) {
			request.Until = request.From
		}},
	}
	for _, c := range cases {
		request := ceremony.request(ceremonyTestFrom, ceremonyTestUntil)
		c.change(request)
		if _, err := dnsservice.CeremonyPrepare(&ceremony.settings.Keys, request); !errors.Is(err, dnsservice.ErrDnsCeremonyRefused) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// The next quarter's ceremony, a fortnight before the boundary, keeps the last quarter's windows that
// have not ended and adds its own, with no gap; one whose span leaves a hole is refused.
func TestCeremonyAssembleKeepsThePreviousQuarterAndRefusesAGap(t *testing.T) {
	ceremony := newCeremonyTest(t)
	first := ceremony.windows(t, ceremonyTestFrom, ceremonyTestUntil, nil, ceremonyTestFrom)
	now := ceremonyTestUntil.Add(-14 * 24 * time.Hour)
	nextUntil := time.Date(2027, time.July, 1, 0, 0, 0, 0, time.UTC)
	plan := ceremony.prepare(t, ceremonyTestUntil, nextUntil)
	file, coverage, err := dnsservice.CeremonyAssemble(ceremony.settings, plan, ceremony.hsm.signPlan(t, plan), first, now)
	if err != nil {
		t.Fatal(err)
	}
	kept := 0
	for _, window := range first.Windows {
		if now.Before(window.NotAfter) {
			kept += 1
		}
	}
	if len(file.Windows) != kept+len(plan.Windows) || len(coverage.Gaps) != 0 {
		t.Fatalf("%d windows where %d kept and %d new, gaps %v", len(file.Windows), kept, len(plan.Windows), coverage.Gaps)
	}
	if !file.Windows[kept].NotBefore.Equal(ceremonyTestUntil) {
		t.Errorf("the first new window starts %v", file.Windows[kept].NotBefore)
	}

	// a ceremony that starts a fortnight late leaves the old quarter's last window short
	late := ceremony.prepare(t, ceremonyTestUntil.Add(14*24*time.Hour), nextUntil)
	if _, _, err := dnsservice.CeremonyAssemble(ceremony.settings, late, ceremony.hsm.signPlan(t, late), first, now); !errors.Is(err, dnsservice.ErrDnsCeremonyRefused) {
		t.Errorf("a gap ahead: %v", err)
	}
}

// The ZSK's key file: a generated key reads back through LoadZsk as the key its DNSKEY names, and
// writing what was read gives the same file.
func TestDnsZskFileRoundTrip(t *testing.T) {
	keyFile, dnskey, err := dnsservice.GenerateDnsZsk()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(keyFile), "Private-key-format: v1.3\nAlgorithm: 13 (ECDSAP256SHA256)\nPrivateKey: ") {
		t.Errorf("the key file reads %q", strings.SplitN(string(keyFile), "PrivateKey", 2)[0])
	}
	key, err := dnsservice.LoadZsk(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(dnskey, "256 3 13 ") || !strings.HasSuffix(dnskey, ceremonyTestDnskey(t, key.(*ecdsa.PrivateKey), dns.ZONE)[len("256 3 13 "):]) {
		t.Errorf("the DNSKEY %q is not the key's", dnskey)
	}
	again, err := dnsservice.MarshalDnsZsk(key)
	if err != nil || !bytes.Equal(again, keyFile) {
		t.Errorf("rewritten %v", err)
	}
	if _, err := dnsservice.MarshalDnsZsk(nil); !errors.Is(err, dnsservice.ErrDnsKeyRefused) {
		t.Errorf("no key: %v", err)
	}
}

// The golden files: prepare gives plan.json byte for byte from the fixed keys and quarter, and
// windows.json, signed once by the stand-in KSK, verifies offline against its anchor, holds the plan's
// RRset and times, and reads and writes back the same bytes. DNSSERVICE_WRITE_CEREMONY_GOLDENS=1 writes
// both instead.
func TestCeremonyGoldenFiles(t *testing.T) {
	ceremony := newCeremonyTest(t)
	directory := filepath.Join("..", "testdata", "dns", "windows")
	plan := ceremony.prepare(t, ceremonyTestFrom, ceremonyTestUntil)
	planBytes, err := plan.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv(ceremonyGoldenWriteEnv) == "1" {
		file, _, err := dnsservice.CeremonyAssemble(ceremony.settings, plan, ceremony.hsm.signPlan(t, plan), nil, ceremonyTestFrom)
		if err != nil {
			t.Fatal(err)
		}
		fileBytes, err := file.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string][]byte{"plan.json": planBytes, "windows.json": fileBytes, "ksk.dnskey": []byte(ceremony.ksk + "\n")} {
			if err := os.WriteFile(filepath.Join(directory, name), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	goldenPlan, err := os.ReadFile(filepath.Join(directory, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(planBytes, goldenPlan) {
		t.Error("prepare no longer gives plan.json")
	}
	if parsed, err := dnsservice.ParseDnsCeremonyPlan(goldenPlan); err != nil || len(parsed.Windows) != len(plan.Windows) {
		t.Errorf("plan.json reads %v", err)
	}
	goldenKsk, err := os.ReadFile(filepath.Join(directory, "ksk.dnskey"))
	if err != nil || strings.TrimSpace(string(goldenKsk)) != ceremony.ksk {
		t.Errorf("ksk.dnskey is not the stand-in KSK: %v", err)
	}
	goldenWindows, err := os.ReadFile(filepath.Join(directory, "windows.json"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := dnsservice.ParseDnsKeyWindowFile(goldenWindows)
	if err != nil {
		t.Fatal(err)
	}
	coverage, err := dnsservice.VerifyDnsKeyWindowFile(ceremony.settings, file)
	if err != nil {
		t.Fatal(err)
	}
	if len(coverage.Gaps) != 0 || len(file.Windows) != len(plan.Windows) {
		t.Errorf("%d windows, gaps %v", len(file.Windows), coverage.Gaps)
	}
	for index := range file.Windows {
		window := &file.Windows[index]
		if !slices.Equal(window.Dnskeys, plan.Dnskeys) || !window.NotBefore.Equal(plan.Windows[index].NotBefore) || !window.NotAfter.Equal(plan.Windows[index].NotAfter) {
			t.Errorf("window %d is not the plan's", index)
		}
	}
	rewritten, err := file.Marshal()
	if err != nil || !bytes.Equal(rewritten, goldenWindows) {
		t.Errorf("windows.json does not write back the same: %v", err)
	}
}
