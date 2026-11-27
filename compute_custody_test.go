//go:build !ios_extension && !sidecar_http && !js

// Key custody on the device (DESIGN-COMPUTE §2.5; CTRUST-M13-01): a registered compute credential is in the matcher
// Sidecar.SecretMatcher builds, in every encoding, until its source is removed, and the copies its source returned are
// cleared once encoded; a source that fails fails the build, naming its kind and never a value; the registry takes only
// the kinds §2.5's device-held rows name; and compute_custody_table.go holds §2.5's rows in order. The enrolled sidecar
// is record_secret_match_sidecar_test.go's.

package sidecar

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

// A source of fixed credentials, or a fixed error, counting its reads and keeping each copy it returned.
type testComputeCustodySource struct {
	stateLock   sync.Mutex
	credentials [][]byte
	err         error
	reads       int
	returned    [][]byte
}

func (self *testComputeCustodySource) CustodyCredentials(ctx context.Context) ([][]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.reads += 1
	copies := [][]byte{}
	for _, credential := range self.credentials {
		copies = append(copies, bytes.Clone(credential))
	}
	self.returned = append(self.returned, copies...)
	return copies, self.err
}

// Whether every copy the source returned is all zero, as the matcher leaves what it encoded.
func (self *testComputeCustodySource) returnedCleared() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, credential := range self.returned {
		if slices.ContainsFunc(credential, func(b byte) bool { return b != 0 }) {
			return false
		}
	}
	return 0 < len(self.returned)
}

// An enrolled sidecar whose matcher reads its keychain, as record_secret_match_sidecar_test.go's.
func newTestComputeCustodySidecar(t *testing.T) *Sidecar {
	t.Helper()
	_, enrollment := newTestEnrolledInstance(t)
	sidecar := newTestSidecar(t)
	func() {
		sidecar.stateLock.Lock()
		defer sidecar.stateLock.Unlock()
		sidecar.lifecycle.state = SidecarStateUnenrolled
		sidecar.coreSecrets = enrollment.secrets
	}()
	return sidecar
}

// A synthetic credential of 32 bytes, binary as a seed or a cache secret is, distinct by fill.
func testComputeCustodyBinary(fill byte) []byte {
	credential := make([]byte, 32)
	for i := range credential {
		credential[i] = fill + byte(i)*7
	}
	return credential
}

// One synthetic canary a device-held kind: binary where §2.5's key is random bytes, text where it is a password or a
// token.
func testComputeCustodyCanaries() map[ComputeCustodyKind][]byte {
	return map[ComputeCustodyKind][]byte{
		ComputeCustodyKindCacheSecret:            testComputeCustodyBinary(0x81),
		ComputeCustodyKindSshKey:                 testComputeCustodyBinary(0x91),
		ComputeCustodyKindCalendarLinkSecret:     []byte("synthetic-calendar-app-password-qwer-tyui-opas"),
		ComputeCustodyKindConnectionCredential:   []byte("1//synthetic-refresh-token-for-a-test-Zx9Kq2Lm7Np4"),
		ComputeCustodyKindEnclaveProvisioningKey: testComputeCustodyBinary(0xA1),
	}
}

// Each encoding of a credential a leak is likely to take.
func testComputeCustodyForms(credential []byte) map[string][]byte {
	lowerHex := hex.EncodeToString(credential)
	return map[string][]byte{
		"raw":            credential,
		"hex":            []byte(lowerHex),
		"upper hex":      []byte(strings.ToUpper(lowerHex)),
		"base64":         []byte(base64.StdEncoding.EncodeToString(credential)),
		"raw base64":     []byte(base64.RawStdEncoding.EncodeToString(credential)),
		"url base64":     []byte(base64.URLEncoding.EncodeToString(credential)),
		"raw url base64": []byte(base64.RawURLEncoding.EncodeToString(credential)),
	}
}

// A registered canary of each kind is matched raw, as hex and as base64 inside ordinary text; a tool result carrying
// one, as a string or as JSON's base64 of bytes, is refused, and an error naming one is matched, so MCP's checked error
// masks it (mcp/tool.go); the copies a source returned are cleared once encoded; and a removed source's canary matches
// no later matcher.
func TestComputeCustodyCredentialMatched(t *testing.T) {
	sidecar := newTestComputeCustodySidecar(t)
	canaries := testComputeCustodyCanaries()
	sources := map[ComputeCustodyKind]*testComputeCustodySource{}
	unregisters := map[ComputeCustodyKind]func(){}
	for kind, canary := range canaries {
		// without a source, nothing matches it
		if NewSecretMatcher(nil, nil).Matches(canary) {
			t.Fatalf("%s matched with no source", kind)
		}
		source := &testComputeCustodySource{credentials: [][]byte{canary}}
		unregister, err := sidecar.RegisterComputeCustody(kind, source)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		sources[kind] = source
		unregisters[kind] = unregister
	}

	matcher, err := sidecar.SecretMatcher()
	if err != nil {
		t.Fatal(err)
	}
	for kind, canary := range canaries {
		for name, form := range testComputeCustodyForms(canary) {
			text := append(append([]byte("prefix "), form...), []byte(" suffix")...)
			match := matcher.Match(text)
			if match == nil || match.Class != SecretMatchCredential || match.Offset != len("prefix ") {
				t.Errorf("%s %s: %+v", kind, name, match)
			}
		}
		// a binary credential reaches JSON as base64 of bytes, a text one as a string too
		results := map[string]any{"bytes": canary}
		if utf8.Valid(canary) {
			results["a string"] = string(canary)
		}
		for name, value := range results {
			result, err := json.Marshal(map[string]any{"result": value})
			if err != nil {
				t.Fatal(err)
			}
			if !matcher.Matches(result) {
				t.Errorf("%s: a result carrying it as %s was not refused", kind, name)
			}
		}
		toolErr := fmt.Errorf("the call with %x failed", canary)
		if !matcher.Matches([]byte(toolErr.Error())) {
			t.Errorf("%s: an error naming it was not matched", kind)
		}
		if !sources[kind].returnedCleared() {
			t.Errorf("%s: the copies its source returned were not cleared", kind)
		}
	}

	unregisters[ComputeCustodyKindConnectionCredential]()
	unregisters[ComputeCustodyKindConnectionCredential]()
	matcher, err = sidecar.SecretMatcher()
	if err != nil {
		t.Fatal(err)
	}
	if matcher.Matches(canaries[ComputeCustodyKindConnectionCredential]) {
		t.Error("a removed source's credential still matched")
	}
	if !matcher.Matches(canaries[ComputeCustodyKindCalendarLinkSecret]) {
		t.Error("removing one source removed another")
	}
}

// A source that fails fails the matcher's build, so a caller refuses rather than answers unchecked: the error wraps
// ErrComputeCustodyUnavailable and names the kind, keeps a locked store's error, and leaves cleared what the failing
// source returned beside it; a Locked sidecar refuses before reading any source; and the registry refuses a kind no
// device-held row names, and a nil source.
func TestComputeCustodySourceFailsClosed(t *testing.T) {
	sidecar := newTestComputeCustodySidecar(t)
	healthy := &testComputeCustodySource{credentials: [][]byte{testComputeCustodyBinary(0x11)}}
	if _, err := sidecar.RegisterComputeCustody(ComputeCustodyKindSshKey, healthy); err != nil {
		t.Fatal(err)
	}
	failing := &testComputeCustodySource{
		credentials: [][]byte{testComputeCustodyBinary(0x21)},
		err:         errors.New("the secret repo did not open"),
	}
	unregister, err := sidecar.RegisterComputeCustody(ComputeCustodyKindCalendarLinkSecret, failing)
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := sidecar.SecretMatcher()
	if matcher != nil || !errors.Is(err, ErrComputeCustodyUnavailable) || !strings.Contains(err.Error(), "calendar_link_secret") {
		t.Fatalf("a failing source: %v, %v", matcher, err)
	}
	if !failing.returnedCleared() || !healthy.returnedCleared() {
		t.Error("a failed build left a credential uncleared")
	}
	unregister()

	locked := &testComputeCustodySource{err: fmt.Errorf("the keychain: %w", ErrSidecarStoreLocked)}
	if _, err := sidecar.RegisterComputeCustody(ComputeCustodyKindCacheSecret, locked); err != nil {
		t.Fatal(err)
	}
	if _, err := sidecar.SecretMatcher(); !errors.Is(err, ErrComputeCustodyUnavailable) || !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("a locked source: %v", err)
	}

	func() {
		sidecar.stateLock.Lock()
		defer sidecar.stateLock.Unlock()
		sidecar.lifecycle.state = SidecarStateLocked
	}()
	reads := healthy.reads
	if _, err := sidecar.SecretMatcher(); !errors.Is(err, ErrSidecarStoreLocked) || healthy.reads != reads {
		t.Errorf("locked: %v, %d reads", err, healthy.reads-reads)
	}

	for _, kind := range []ComputeCustodyKind{0, 6, -1} {
		if _, err := sidecar.RegisterComputeCustody(kind, healthy); !errors.Is(err, ErrComputeCustodyRefused) {
			t.Errorf("kind %d: %v", int(kind), err)
		}
	}
	if _, err := sidecar.RegisterComputeCustody(ComputeCustodyKindSshKey, nil); !errors.Is(err, ErrComputeCustodyRefused) {
		t.Errorf("a nil source: %v", err)
	}
}

// §2.5's rows, in order, each found by its key in the design's table; each device-held row names one kind, no other
// row names one, each kind is named once and the registry takes exactly those; and the rows held off the device are the
// nine §2.5 gives URnetwork's hosts, its owners and its custodians.
func TestComputeCustodyTableRows(t *testing.T) {
	designKeys := []string{}
	for _, line := range testComputeDesignSection(t, "### 2.5 Key custody") {
		if !strings.HasPrefix(line, "| ") {
			continue
		}
		cell, _, _ := strings.Cut(strings.TrimPrefix(line, "| "), " | ")
		if cell != "Key" {
			designKeys = append(designKeys, cell)
		}
	}
	if len(designKeys) != len(computeCustodyTable) {
		t.Fatalf("§2.5 has %d rows and the table %d", len(designKeys), len(computeCustodyTable))
	}
	for index, row := range computeCustodyTable {
		if !strings.Contains(designKeys[index], row.designKey) {
			t.Errorf("row %d: %q is not §2.5's %q", index, row.designKey, designKeys[index])
		}
		if row.key == "" || row.holder == "" || row.misuse == "" || !slices.Contains(computeInvariantAreaCodes, row.area) {
			t.Errorf("row %d, %s: a key, a holder, who can misuse it and an area", index, row.key)
		}
		if row.held < computeCustodyHeldOnDevice || computeCustodyHeldOffDevice < row.held {
			t.Errorf("%s: held %d", row.key, row.held)
		}
		if (row.held == computeCustodyHeldOnDevice) != (row.kind != 0) {
			t.Errorf("%s: held %d names kind %s", row.key, row.held, row.kind)
		}
	}

	kinds := []ComputeCustodyKind{
		ComputeCustodyKindCacheSecret,
		ComputeCustodyKindSshKey,
		ComputeCustodyKindCalendarLinkSecret,
		ComputeCustodyKindConnectionCredential,
		ComputeCustodyKindEnclaveProvisioningKey,
	}
	named := map[ComputeCustodyKind]int{}
	for _, row := range computeCustodyTable {
		if row.kind != 0 {
			named[row.kind] += 1
		}
	}
	for _, kind := range kinds {
		if named[kind] != 1 || strings.HasPrefix(kind.String(), "compute_custody_kind(") {
			t.Errorf("%s: named by %d rows", kind, named[kind])
		}
	}
	if len(named) != len(kinds) {
		t.Errorf("the rows name %d kinds, %d declared", len(named), len(kinds))
	}
	sidecar := newTestComputeCustodySidecar(t)
	for kind := ComputeCustodyKind(-1); kind <= ComputeCustodyKind(len(kinds)+1); kind += 1 {
		_, err := sidecar.RegisterComputeCustody(kind, &testComputeCustodySource{})
		if slices.Contains(kinds, kind) != (err == nil) {
			t.Errorf("kind %d: %v", int(kind), err)
		}
	}

	offDevice := []string{}
	for _, row := range computeCustodyTable {
		if row.held == computeCustodyHeldOffDevice {
			offDevice = append(offDevice, row.designKey)
		}
	}
	want := []string{
		"provider API keys", "K_P", "compute mint coldkey", "treasury reserve", "Prime account", "compute-policy key",
		"Unreleased freshness tickets", "x402 payer key", "treasury's USDC",
	}
	if !slices.Equal(offDevice, want) {
		t.Errorf("held off the device: %q", offDevice)
	}
}

// No error the registry answers holds a credential: a source whose error names its credential, raw, as hex and as
// base64, fails the build with an error that names the kind and matches no form of it, and wraps nothing of the
// source's error but the constant ones it passes.
func TestComputeCustodyNoValueInError(t *testing.T) {
	sidecar := newTestComputeCustodySidecar(t)
	canary := testComputeCustodyCanaries()[ComputeCustodyKindConnectionCredential]
	sourceErr := fmt.Errorf("refresh with %s (%x, %s) refused", canary, canary, base64.StdEncoding.EncodeToString(canary))
	source := &testComputeCustodySource{credentials: [][]byte{canary}, err: sourceErr}
	if _, err := sidecar.RegisterComputeCustody(ComputeCustodyKindConnectionCredential, source); err != nil {
		t.Fatal(err)
	}
	_, err := sidecar.SecretMatcher()
	if err == nil {
		t.Fatal("a failing source built a matcher")
	}
	canaryMatcher := NewSecretMatcher([][]byte{canary}, nil)
	for _, text := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err.Error())} {
		if canaryMatcher.Matches([]byte(text)) {
			t.Errorf("the error holds the credential: %q", text)
		}
	}
	if errors.Is(err, sourceErr) || !strings.Contains(err.Error(), "connection_credential") {
		t.Errorf("the error: %v", err)
	}
	if !source.returnedCleared() {
		t.Error("what the failing source returned was not cleared")
	}
}
