//go:build !sidecar_http

// dnssec_chain held to sidecartest.MxWorld's zones, which miekg/dns signs: valid chains, broken ones,
// insecure delegations, NSEC3 denials, wildcard and implicit MX, and a forged host, all at a fixed time
// under the world's own root. FuzzSmtpDnssecChain is §22.6's target: nothing it reads panics, and
// every seed's broken forms are refused.

package sidecar_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

const (
	testDnssecDomain = "mail.example"
	testDnssecHost   = "mx.mail.example"
)

// When every MxWorld here signs, and a little after it validates.
var (
	testDnssecSignTime = time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	testDnssecNow      = testDnssecSignTime.Add(time.Minute)
	testDnssecAddress  = netip.MustParseAddr("198.51.100.25")
)

// A world signing at testDnssecSignTime, with testDnssecDomain's zone under options and its MX at
// testDnssecHost.
func newTestDnssecWorld(t testing.TB, options *sidecartest.MxWorldZoneOptions) *sidecartest.MxWorld {
	t.Helper()
	settings := sidecartest.DefaultMxWorldSettings()
	settings.Clock = sidecartest.NewFakeClock(testDnssecSignTime)
	world, err := sidecartest.NewMxWorld(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := world.AddZone(testDnssecDomain, options); err != nil {
		t.Fatal(err)
	}
	if err := world.SetMx(testDnssecDomain, &sidecar.SmtpMxHost{Preference: 10, Host: testDnssecHost}); err != nil {
		t.Fatal(err)
	}
	return world
}

// The world's root as anchors.
func testDnssecAnchors(t testing.TB, world *sidecartest.MxWorld) *sidecar.SmtpDnssecAnchors {
	t.Helper()
	anchors, err := sidecar.NewSmtpDnssecAnchors(world.TrustAnchorDs())
	if err != nil {
		t.Fatal(err)
	}
	return anchors
}

// The world's chain for domain and host, validated for them at now.
func testDnssecValidate(t testing.TB, world *sidecartest.MxWorld, domain string, host string, now time.Time) (*sidecar.SmtpDnssecResult, error) {
	t.Helper()
	chain, err := world.Chain(domain, host)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := sidecar.ParseSmtpDnssecChain(chain, nil)
	if err != nil {
		return nil, err
	}
	return parsed.Validate(testDnssecAnchors(t, world), now, domain, host)
}

func TestSmtpDnssecChainProvesTheTlsaRrset(t *testing.T) {
	world := newTestDnssecWorld(t, nil)
	record := &sidecar.SmtpTlsaRecord{Usage: 3, Selector: 1, MatchingType: 1, Data: bytes.Repeat([]byte{0x5a}, 32)}
	if err := world.AddMx(testDnssecHost, testDnssecAddress, nil, record); err != nil {
		t.Fatal(err)
	}
	result, err := testDnssecValidate(t, world, testDnssecDomain, testDnssecHost, testDnssecNow)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != sidecar.SmtpDnssecStatusTlsa || len(result.TlsaRecords) != 1 {
		t.Fatalf("result %+v", result)
	}
	got := result.TlsaRecords[0]
	if got.Usage != 3 || got.Selector != 1 || got.MatchingType != 1 || !bytes.Equal(got.Data, record.Data) {
		t.Errorf("record %+v", got)
	}
}

// RFC 5155's denial: a host with no TLSA is told apart from one under an insecure delegation.
func TestSmtpDnssecProvesNoTlsaByNsec3(t *testing.T) {
	world := newTestDnssecWorld(t, nil)
	if err := world.AddMx(testDnssecHost, testDnssecAddress, nil); err != nil {
		t.Fatal(err)
	}
	result, err := testDnssecValidate(t, world, testDnssecDomain, testDnssecHost, testDnssecNow)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != sidecar.SmtpDnssecStatusNoTlsa {
		t.Errorf("status %d", result.Status)
	}
}

func TestSmtpDnssecUnsignedDelegationIsInsecure(t *testing.T) {
	world := newTestDnssecWorld(t, &sidecartest.MxWorldZoneOptions{Unsigned: true})
	if err := world.AddMx(testDnssecHost, testDnssecAddress, nil); err != nil {
		t.Fatal(err)
	}
	result, err := testDnssecValidate(t, world, testDnssecDomain, testDnssecHost, testDnssecNow)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != sidecar.SmtpDnssecStatusInsecure {
		t.Errorf("status %d", result.Status)
	}
}

// An expired signature, a key the zone never published and a DS matching no key are each bogus.
func TestSmtpDnssecBrokenChainsAreBogus(t *testing.T) {
	for _, options := range []*sidecartest.MxWorldZoneOptions{{ExpiredSignatures: true}, {WrongKey: true}, {BrokenDs: true}} {
		world := newTestDnssecWorld(t, options)
		if err := world.AddMx(testDnssecHost, testDnssecAddress, nil, &sidecar.SmtpTlsaRecord{Usage: 3, Selector: 1, MatchingType: 1, Data: make([]byte, 32)}); err != nil {
			t.Fatal(err)
		}
		if _, err := testDnssecValidate(t, world, testDnssecDomain, testDnssecHost, testDnssecNow); !errors.Is(err, sidecar.ErrSmtpDnssecBogus) {
			t.Errorf("%+v: %v", options, err)
		}
	}
}

// A wildcard's expansion holds with its NSEC3 proof that no closer name exists (RFC 4035 §5.3.4).
func TestSmtpDnssecWildcardMxHolds(t *testing.T) {
	world := newTestDnssecWorld(t, nil)
	if err := world.AddZone("wild.example", nil); err != nil {
		t.Fatal(err)
	}
	if err := world.SetMx("*.wild.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mx.wild.example"}); err != nil {
		t.Fatal(err)
	}
	if err := world.AddMx("mx.wild.example", testDnssecAddress, nil, &sidecar.SmtpTlsaRecord{Usage: 3, Selector: 1, MatchingType: 1, Data: make([]byte, 32)}); err != nil {
		t.Fatal(err)
	}
	result, err := testDnssecValidate(t, world, "quietfox.wild.example", "mx.wild.example", testDnssecNow)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != sidecar.SmtpDnssecStatusTlsa {
		t.Errorf("status %d", result.Status)
	}
}

// RFC 5321 §5.1: with no MX RRset proven, only the domain itself is its host
// (plan-SMTP-small-readings#13).
func TestSmtpDnssecImplicitMxIsTheDomain(t *testing.T) {
	world := newTestDnssecWorld(t, nil)
	if err := world.AddZone("implicit.example", nil); err != nil {
		t.Fatal(err)
	}
	if err := world.AddMx("implicit.example", testDnssecAddress, nil); err != nil {
		t.Fatal(err)
	}
	result, err := testDnssecValidate(t, world, "implicit.example", "implicit.example", testDnssecNow)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != sidecar.SmtpDnssecStatusNoTlsa {
		t.Errorf("status %d", result.Status)
	}
	chain, err := world.Chain("implicit.example", "implicit.example")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := sidecar.ParseSmtpDnssecChain(chain, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Validate(testDnssecAnchors(t, world), testDnssecNow, "implicit.example", "other.implicit.example"); !errors.Is(err, sidecar.ErrSmtpDnssecBogus) {
		t.Errorf("another host passed: %v", err)
	}
}

// RFC 7505's null MX names no host, so no host passes.
func TestSmtpDnssecNullMxProvesNoHost(t *testing.T) {
	world := newTestDnssecWorld(t, nil)
	if err := world.AddZone("null.example", nil); err != nil {
		t.Fatal(err)
	}
	if err := world.SetNullMx("null.example"); err != nil {
		t.Fatal(err)
	}
	if err := world.AddMx("mx.null.example", testDnssecAddress, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := testDnssecValidate(t, world, "null.example", "mx.null.example", testDnssecNow); !errors.Is(err, sidecar.ErrSmtpDnssecBogus) {
		t.Errorf("err %v", err)
	}
}

// A malicious edge's chain naming its own host: mx_host is not in the validated MX RRset, whether the
// chain is the domain's own or carries the attacker's valid records beside it.
func TestSmtpDnssecForgedHostIsRefused(t *testing.T) {
	world := newTestDnssecWorld(t, nil)
	if err := world.AddMx(testDnssecHost, testDnssecAddress, nil); err != nil {
		t.Fatal(err)
	}
	if err := world.AddZone("attacker.example", nil); err != nil {
		t.Fatal(err)
	}
	if err := world.SetMx("attacker.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mx.attacker.example"}); err != nil {
		t.Fatal(err)
	}
	if err := world.AddMx("mx.attacker.example", netip.MustParseAddr("203.0.113.66"), nil, &sidecar.SmtpTlsaRecord{Usage: 3, Selector: 1, MatchingType: 1, Data: make([]byte, 32)}); err != nil {
		t.Fatal(err)
	}
	real, err := world.Chain(testDnssecDomain, testDnssecHost)
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := world.Chain("attacker.example", "mx.attacker.example")
	if err != nil {
		t.Fatal(err)
	}
	anchors := testDnssecAnchors(t, world)
	for _, chain := range [][]byte{real, attacker, append(append([]byte{}, real...), attacker...)} {
		parsed, err := sidecar.ParseSmtpDnssecChain(chain, nil)
		if err != nil {
			continue
		}
		if _, err := parsed.Validate(anchors, testDnssecNow, testDnssecDomain, "mx.attacker.example"); !errors.Is(err, sidecar.ErrSmtpDnssecBogus) {
			t.Errorf("a forged host passed: %v", err)
		}
	}
}

// Validity is read on the caller's clock, and only this world's root anchors its chains.
func TestSmtpDnssecReadsTheClockAndTheAnchor(t *testing.T) {
	world := newTestDnssecWorld(t, nil)
	if err := world.AddMx(testDnssecHost, testDnssecAddress, nil); err != nil {
		t.Fatal(err)
	}
	for _, now := range []time.Time{testDnssecSignTime.Add(31 * 24 * time.Hour), testDnssecSignTime.Add(-2 * time.Hour)} {
		if _, err := testDnssecValidate(t, world, testDnssecDomain, testDnssecHost, now); !errors.Is(err, sidecar.ErrSmtpDnssecBogus) {
			t.Errorf("%v: %v", now, err)
		}
	}
	other := newTestDnssecWorld(t, nil)
	chain, err := world.Chain(testDnssecDomain, testDnssecHost)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := sidecar.ParseSmtpDnssecChain(chain, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Validate(testDnssecAnchors(t, other), testDnssecNow, testDnssecDomain, testDnssecHost); !errors.Is(err, sidecar.ErrSmtpDnssecBogus) {
		t.Errorf("another root anchored it: %v", err)
	}
	if _, err := parsed.Validate(sidecar.DefaultSmtpDnssecAnchors(), testDnssecNow, testDnssecDomain, testDnssecHost); !errors.Is(err, sidecar.ErrSmtpDnssecBogus) {
		t.Errorf("the real root anchored a test chain: %v", err)
	}
}

// Every cut of a chain, a chain past the frame, and records no chain holds are refused, never
// half-read: each is bogus, from the parser or the validator.
func TestSmtpDnssecRefusesMalformedChains(t *testing.T) {
	world := newTestDnssecWorld(t, nil)
	if err := world.AddMx(testDnssecHost, testDnssecAddress, nil); err != nil {
		t.Fatal(err)
	}
	chain, err := world.Chain(testDnssecDomain, testDnssecHost)
	if err != nil {
		t.Fatal(err)
	}
	anchors := testDnssecAnchors(t, world)
	refused := func(input []byte) bool {
		parsed, err := sidecar.ParseSmtpDnssecChain(input, nil)
		if err != nil {
			return errors.Is(err, sidecar.ErrSmtpDnssecBogus)
		}
		_, err = parsed.Validate(anchors, testDnssecNow, testDnssecDomain, testDnssecHost)
		return errors.Is(err, sidecar.ErrSmtpDnssecBogus)
	}
	for cut := 0; cut < len(chain); cut += 7 {
		if !refused(chain[:cut]) {
			t.Fatalf("the chain cut at %d passed", cut)
		}
	}
	for flip := 0; flip < len(chain); flip += 11 {
		mutated := bytes.Clone(chain)
		mutated[flip] ^= 0x01
		parsed, err := sidecar.ParseSmtpDnssecChain(mutated, nil)
		if err != nil {
			continue
		}
		// a flip may land where no signature covers it, such as a TTL: then it still validates
		if result, err := parsed.Validate(anchors, testDnssecNow, testDnssecDomain, testDnssecHost); err == nil && result.Status != sidecar.SmtpDnssecStatusNoTlsa {
			t.Errorf("a flip at %d changed the answer to %d", flip, result.Status)
		}
	}
	compressed := []byte{0xc0, 0x0c, 0, 15, 0, 1, 0, 0, 0, 1, 0, 0}
	unknownType := append([]byte{0}, binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, 99), 1)...)
	unknownType = append(unknownType, 0, 0, 0, 1, 0, 0)
	for _, input := range [][]byte{compressed, unknownType, make([]byte, sidecar.SmtpDnssecChainMaxByteCount+1), nil} {
		if !refused(input) {
			t.Errorf("%x passed", input[:min(len(input), 16)])
		}
	}
	tight := sidecar.DefaultSmtpDaneSettings()
	tight.MaxRrCount = 4
	if _, err := sidecar.ParseSmtpDnssecChain(chain, tight); !errors.Is(err, sidecar.ErrSmtpDnssecBogus) {
		t.Errorf("past the record bound: %v", err)
	}
	tight = sidecar.DefaultSmtpDaneSettings()
	tight.MaxSignatureCheckCount = 2
	parsed, err := sidecar.ParseSmtpDnssecChain(chain, tight)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Validate(anchors, testDnssecNow, testDnssecDomain, testDnssecHost); !errors.Is(err, sidecar.ErrSmtpDnssecBogus) {
		t.Errorf("past the signature bound: %v", err)
	}
}

// A fuzz input: the anchor's length, the anchor's DS, then a chain.
func testDnssecFuzzInput(anchor []byte, chain []byte) []byte {
	return append(append(binary.BigEndian.AppendUint16(nil, uint16(len(anchor))), anchor...), chain...)
}

// §22.6: broken chains are refused and nothing panics. Seeds are this run's MxWorld chains with their
// own anchors, so mutations reach the signature checks, beside testdata's fixed ones.
func FuzzSmtpDnssecChain(f *testing.F) {
	world := newTestDnssecWorld(f, nil)
	world.AddMx(testDnssecHost, testDnssecAddress, nil, &sidecar.SmtpTlsaRecord{Usage: 3, Selector: 1, MatchingType: 1, Data: make([]byte, 32)})
	world.AddZone("unsigned.example", &sidecartest.MxWorldZoneOptions{Unsigned: true})
	world.SetMx("unsigned.example", &sidecar.SmtpMxHost{Preference: 10, Host: testDnssecHost})
	for _, domain := range []string{testDnssecDomain, "unsigned.example"} {
		chain, err := world.Chain(domain, testDnssecHost)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(testDnssecFuzzInput(world.TrustAnchorDs(), chain))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) < 2 || len(input) < 2+int(binary.BigEndian.Uint16(input)) {
			return
		}
		anchorEnd := 2 + int(binary.BigEndian.Uint16(input))
		anchors, err := sidecar.NewSmtpDnssecAnchors(input[2:anchorEnd])
		if err != nil {
			return
		}
		parsed, err := sidecar.ParseSmtpDnssecChain(input[anchorEnd:], nil)
		if err != nil {
			if !errors.Is(err, sidecar.ErrSmtpDnssecBogus) {
				t.Fatalf("a parse error outside ErrSmtpDnssecBogus: %v", err)
			}
			return
		}
		for _, domain := range []string{testDnssecDomain, "unsigned.example"} {
			first, firstErr := parsed.Validate(anchors, testDnssecNow, domain, testDnssecHost)
			second, secondErr := parsed.Validate(anchors, testDnssecNow, domain, testDnssecHost)
			if (firstErr == nil) != (secondErr == nil) || (firstErr == nil && first.Status != second.Status) {
				t.Fatal("two validations of one chain disagree")
			}
			if firstErr != nil {
				if !errors.Is(firstErr, sidecar.ErrSmtpDnssecBogus) {
					t.Fatalf("an error outside ErrSmtpDnssecBogus: %v", firstErr)
				}
				continue
			}
			valid := []sidecar.SmtpDnssecStatus{sidecar.SmtpDnssecStatusTlsa, sidecar.SmtpDnssecStatusNoTlsa, sidecar.SmtpDnssecStatusInsecure}
			if !slices.Contains(valid, first.Status) || (first.Status == sidecar.SmtpDnssecStatusTlsa) != (0 < len(first.TlsaRecords)) {
				t.Fatalf("result %+v", first)
			}
		}
	})
}
