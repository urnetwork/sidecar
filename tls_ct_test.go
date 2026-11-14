//go:build !sidecar_http && !ios_extension

// D-TLS-8's CT watch on fixtures (§22.9: staging CT is unreliable): what alarms and what does not, read through the
// real client over both sources' fixture answers, against rows whose attestations a test identity signs for the
// fixtures' keys.

package sidecar

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The fixtures' certificates, by their place in certspotter.json: the zone's certificate, which crt.sh also lists as a
// precertificate; a second for the same names on another key; the custom host's; and one past its validity.
const (
	tlsCtTestZoneCertificate = iota
	tlsCtTestSecondCertificate
	tlsCtTestCustomCertificate
	tlsCtTestExpiredCertificate
)

// Identity keys and when each was first pinned, as a test sets them.
type tlsCtTestIdentities struct {
	stateLock sync.Mutex
	keys      map[Id][]byte
	pinned    map[Id]time.Time
}

func (self *tlsCtTestIdentities) IdentityPublicKey(sidecarId Id) []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.keys[sidecarId]
}

func (self *tlsCtTestIdentities) PinnedSince(sidecarId Id, at time.Time) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	pinned, ok := self.pinned[sidecarId]
	return !ok || !pinned.Before(at)
}

// A watch over the fixture sources, a sealed store and a clock the test moves. The watch's own loop stays parked on
// its timer, and a test runs each pass by hand.
type tlsCtFixture struct {
	t          *testing.T
	clock      *tlsCertTestClock
	transport  *tlsCtFixtureTransport
	client     *TlsCtClient
	store      SidecarStore
	settings   *SidecarTlsSettings
	identities *tlsCtTestIdentities
	watch      *tlsCtWatch

	stateLock    sync.Mutex
	rows         []*TlsCertRecord
	rowsErr      error
	namesErr     error
	noConfig     bool
	notListening bool
	customHosts  []string
	events       []SidecarEvent
	randValue    int64
}

func newTlsCtFixture(t *testing.T) *tlsCtFixture {
	t.Helper()
	instance, _, _, _ := newTlsTestSecrets(t)
	store, err := instance.Store(&testNetworkId).Directory(tlsComponentName, tlsComponentName)
	if err != nil {
		t.Fatal(err)
	}
	transport := newTlsCtFixtureTransport(t)
	fixture := &tlsCtFixture{
		t:          t,
		clock:      newTlsCertTestClock(),
		transport:  transport,
		client:     newTlsCtFixtureClient(t, transport, ""),
		store:      store,
		settings:   DefaultSidecarTlsSettings(),
		identities: &tlsCtTestIdentities{keys: map[Id][]byte{}, pinned: map[Id]time.Time{}},
	}
	fixture.watch = fixture.newWatch()
	return fixture
}

func (self *tlsCtFixture) args() *TlsCtWatchArgs {
	return &TlsCtWatchArgs{
		NetworkId: testNetworkId,
		Sources:   self.client.Sources(),
		Rows: func(ctx context.Context) (*TlsCertsResult, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.rowsErr != nil {
				return nil, self.rowsErr
			}
			return &TlsCertsResult{Certs: slices.Clone(self.rows)}, nil
		},
		Names: func(ctx context.Context) (*TlsCertNames, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.namesErr != nil {
				return nil, self.namesErr
			}
			return &TlsCertNames{Root: tlsCertTestRoot, Label: tlsCertTestLabel, CustomHosts: slices.Clone(self.customHosts)}, nil
		},
		Identities: func() TlsCtIdentities {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.noConfig {
				return nil
			}
			return self.identities
		},
		Listening: func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return !self.notListening
		},
		Store: self.store,
		Event: func(event SidecarEvent) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.events = append(self.events, event)
		},
		Settings: self.settings,
		Clock:    self.clock,
		Rand: func(n int64) int64 {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return min(self.randValue, n-1)
		},
		Log: NewNoopLogger(),
	}
}

// A watch over the fixture's store, as a restart makes one.
func (self *tlsCtFixture) newWatch() *tlsCtWatch {
	self.t.Helper()
	watch, err := newTlsCtWatch(self.t.Context(), self.args())
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(watch.Close)
	return watch
}

func (self *tlsCtFixture) pass() int {
	return self.watch.Pass(self.t.Context())
}

func (self *tlsCtFixture) set(change func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	change()
}

func (self *tlsCtFixture) eventsSoFar() []SidecarEvent {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.events)
}

// A fixture certificate's key, names and issuance.
func (self *tlsCtFixture) logged(index int) ([sha256.Size]byte, []string, time.Time) {
	self.t.Helper()
	issuance := self.transport.certSpotter[index]
	spkiSha256, ok := tlsCtParseSha256(issuance["pubkey_sha256"].(string))
	if !ok {
		self.t.Fatal("the fixture's key is no hash")
	}
	names := []string{}
	for _, name := range issuance["dns_names"].([]any) {
		names = append(names, name.(string))
	}
	notBefore, err := time.Parse(time.RFC3339, issuance["not_before"].(string))
	if err != nil {
		self.t.Fatal(err)
	}
	return spkiSha256, tlsCtCanonicalNames(names), notBefore
}

// The identity a label names, pinned long before any fixture certificate was issued.
func (self *tlsCtFixture) identity(label string) (Id, []byte) {
	seed := sha256.Sum256([]byte("ct watch identity " + label))
	sidecarId := tlsCertTestId("ct watch sidecar " + label)
	self.identities.stateLock.Lock()
	defer self.identities.stateLock.Unlock()
	if _, ok := self.identities.keys[sidecarId]; !ok {
		self.identities.keys[sidecarId] = ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
		self.identities.pinned[sidecarId] = time.Date(2026, time.January, 2, 0, 0, 0, 0, time.UTC)
	}
	return sidecarId, seed[:]
}

// A row in state for the fixture certificate at index, attested by label's identity.
func (self *tlsCtFixture) row(index int, label string, state TlsCertState) *TlsCertRecord {
	self.t.Helper()
	spkiSha256, names, notBefore := self.logged(index)
	identifierSetSha256, err := TlsIdentifierSetHash(names)
	if err != nil {
		self.t.Fatal(err)
	}
	sidecarId, seed := self.identity(label)
	attestation, err := SignTlsKeyAttestation(&protocol.TlsKeyAttestation{
		NetworkId:           testNetworkId[:],
		SidecarId:           sidecarId[:],
		SpkiSha256:          spkiSha256[:],
		IdentifierSetSha256: identifierSetSha256[:],
		IssueTimeMillis:     uint64(notBefore.Add(-time.Minute).UnixMilli()),
	}, testTlsSign(seed, sidecarId[:]))
	if err != nil {
		self.t.Fatal(err)
	}
	return &TlsCertRecord{
		CertId:              NewId(),
		NetworkId:           testNetworkId,
		SidecarId:           sidecarId,
		IdentifierSetSha256: identifierSetSha256[:],
		SpkiSha256:          spkiSha256[:],
		Attestation:         attestation,
		State:               state,
		// what a row with its chain kept holds; the watch reads only that there is one
		Chain: [][]byte{[]byte("a chain")},
	}
}

func (self *tlsCtFixture) setRows(rows ...*TlsCertRecord) {
	self.set(func() {
		self.rows = rows
	})
}

// The zone's two certificates, each attested by its own device.
func (self *tlsCtFixture) zoneRows() []*TlsCertRecord {
	return []*TlsCertRecord{
		self.row(tlsCtTestZoneCertificate, "desktop", TlsCertStateIssued),
		self.row(tlsCtTestSecondCertificate, "laptop", TlsCertStateIssued),
	}
}

func TestTlsCtWatchAnUnattestedCertificateAlarms(t *testing.T) {
	fixture := newTlsCtFixture(t)
	// the zone's own certificate is attested; a second, a test certificate, nobody asked for
	fixture.setRows(fixture.row(tlsCtTestZoneCertificate, "desktop", TlsCertStateIssued))
	if alarms := fixture.pass(); alarms != 1 {
		t.Fatalf("%d alarms", alarms)
	}
	events := fixture.eventsSoFar()
	if len(events) != 1 || events[0].Kind != SidecarEventCtAlarm || events[0].CtAlarm != SidecarCtAlarmUnattested || events[0].SidecarId != nil {
		t.Fatalf("events %+v", events)
	}
	status := fixture.watch.Status()
	spkiSha256, names, _ := fixture.logged(tlsCtTestSecondCertificate)
	if status.Degraded || len(status.Alarms) != 1 || !slices.Equal(status.Alarms[0].DnsNames, names) || hex.EncodeToString(status.Alarms[0].SpkiSha256) != hex.EncodeToString(spkiSha256[:]) {
		t.Errorf("status %+v", status)
	}
	if !status.PassTime.Equal(fixture.clock.Now()) {
		t.Errorf("pass time %s", status.PassTime)
	}
	// it stands at the next pass and is told once
	if alarms := fixture.pass(); alarms != 1 || len(fixture.eventsSoFar()) != 1 {
		t.Errorf("%d alarms and %d events at the second pass", alarms, len(fixture.eventsSoFar()))
	}
	// a row that arrives late withdraws it
	fixture.setRows(fixture.zoneRows()...)
	if alarms := fixture.pass(); alarms != 0 || len(fixture.watch.Status().Alarms) != 0 {
		t.Errorf("%d alarms once the row arrived", alarms)
	}
}

func TestTlsCtWatchAnAttestedCertificateDoesNotAlarm(t *testing.T) {
	fixture := newTlsCtFixture(t)
	fixture.setRows(fixture.zoneRows()...)
	if alarms := fixture.pass(); alarms != 0 {
		t.Fatalf("%d alarms", alarms)
	}
	if events := fixture.eventsSoFar(); len(events) != 0 {
		t.Errorf("events %+v", events)
	}
	if fixture.watch.Degraded() {
		t.Errorf("degraded with both sources answering")
	}
	// the certificate past its validity has no row and is not judged
	state, err := fixture.watch.readState()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Known) != 2 || len(state.Alarms) != 0 {
		t.Errorf("%d known and %d alarms kept", len(state.Known), len(state.Alarms))
	}
	// each source's cursor moved, so the next pass reads nothing again
	requests := fixture.transport.requestCount(TlsCtSourceCrtSh)
	fixture.pass()
	if fetched := fixture.transport.requestCount(TlsCtSourceCrtSh) - requests; fetched != 2 {
		t.Errorf("%d crt.sh requests at a pass with nothing new", fetched)
	}
}

func TestTlsCtWatchAnOrderInFlightDoesNotAlarm(t *testing.T) {
	// a CA logs the precertificate before certs learns the order finished
	for _, state := range []TlsCertState{TlsCertStateQueued, TlsCertStateOrdering, TlsCertStateRevoking} {
		fixture := newTlsCtFixture(t)
		fixture.setRows(fixture.row(tlsCtTestZoneCertificate, "desktop", state), fixture.row(tlsCtTestSecondCertificate, "laptop", TlsCertStateIssued))
		if alarms := fixture.pass(); alarms != 0 {
			t.Errorf("%d alarms with the row %s", alarms, state)
		}
	}
}

func TestTlsCtWatchCountsAPrecertificateAndItsCertificateOnce(t *testing.T) {
	fixture := newTlsCtFixture(t)
	// no row at all: Cert Spotter's issuance, crt.sh's precertificate and crt.sh's certificate are one alarm, and the
	// second certificate, which both sources show, another
	if alarms := fixture.pass(); alarms != 2 {
		t.Fatalf("%d alarms", alarms)
	}
	if events := fixture.eventsSoFar(); len(events) != 2 {
		t.Errorf("%d events", len(events))
	}
	keys := map[string]bool{}
	for _, alarm := range fixture.watch.Status().Alarms {
		keys[hex.EncodeToString(alarm.SpkiSha256)] = true
	}
	if len(keys) != 2 {
		t.Errorf("%d keys alarmed", len(keys))
	}
}

func TestTlsCtWatchSourcesDisagreeingIsNoAlarm(t *testing.T) {
	fixture := newTlsCtFixture(t)
	fixture.setRows(fixture.zoneRows()...)
	// crt.sh answers that it has logged nothing; Cert Spotter shows the certificates
	fixture.transport.fail(TlsCtSourceCrtSh, 0, "[]")
	if alarms := fixture.pass(); alarms != 0 || fixture.watch.Degraded() || len(fixture.eventsSoFar()) != 0 {
		t.Errorf("%d alarms, degraded %t", alarms, fixture.watch.Degraded())
	}
	// and an unattested certificate only one source shows still alarms
	other := newTlsCtFixture(t)
	other.setRows(other.row(tlsCtTestZoneCertificate, "desktop", TlsCertStateIssued))
	other.transport.fail(TlsCtSourceCertSpotter, 0, "[]")
	if alarms := other.pass(); alarms != 1 {
		t.Errorf("%d alarms for a certificate one source shows", alarms)
	}
}

func TestTlsCtWatchAlarmsOnAnIdentityPinnedUnder24Hours(t *testing.T) {
	fixture := newTlsCtFixture(t)
	fixture.setRows(fixture.zoneRows()...)
	sidecarId, _ := fixture.identity("desktop")
	_, _, notBefore := fixture.logged(tlsCtTestZoneCertificate)

	fixture.identities.stateLock.Lock()
	fixture.identities.pinned[sidecarId] = notBefore.Add(-23 * time.Hour)
	fixture.identities.stateLock.Unlock()
	if alarms := fixture.pass(); alarms != 1 {
		t.Fatalf("%d alarms for an identity pinned 23 h before issuance", alarms)
	}
	events := fixture.eventsSoFar()
	if len(events) != 1 || events[0].CtAlarm != SidecarCtAlarmRecentIdentity || events[0].SidecarId == nil || *events[0].SidecarId != sidecarId {
		t.Fatalf("events %+v", events)
	}

	fixture.identities.stateLock.Lock()
	fixture.identities.pinned[sidecarId] = notBefore.Add(-25 * time.Hour)
	fixture.identities.stateLock.Unlock()
	if alarms := fixture.pass(); alarms != 0 {
		t.Errorf("%d alarms for an identity pinned 25 h before issuance", alarms)
	}
}

func TestTlsCtWatchATamperedAttestationAlarms(t *testing.T) {
	tamper := []struct {
		name   string
		change func(fixture *tlsCtFixture, row *TlsCertRecord)
	}{
		{name: "a flipped byte", change: func(fixture *tlsCtFixture, row *TlsCertRecord) {
			row.Attestation = slices.Clone(row.Attestation)
			row.Attestation[len(row.Attestation)/2] ^= 0x01
		}},
		{name: "no attestation", change: func(fixture *tlsCtFixture, row *TlsCertRecord) {
			row.Attestation = nil
		}},
		{name: "another certificate's attestation", change: func(fixture *tlsCtFixture, row *TlsCertRecord) {
			row.Attestation = fixture.row(tlsCtTestSecondCertificate, "desktop", TlsCertStateIssued).Attestation
		}},
		{name: "another identity's key pinned for the sidecar", change: func(fixture *tlsCtFixture, row *TlsCertRecord) {
			_, seed := fixture.identity("an operator")
			fixture.identities.stateLock.Lock()
			defer fixture.identities.stateLock.Unlock()
			fixture.identities.keys[row.SidecarId] = ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		}},
		{name: "a sidecar verified config never admitted", change: func(fixture *tlsCtFixture, row *TlsCertRecord) {
			fixture.identities.stateLock.Lock()
			defer fixture.identities.stateLock.Unlock()
			delete(fixture.identities.keys, row.SidecarId)
		}},
		{name: "a row said to be another sidecar's", change: func(fixture *tlsCtFixture, row *TlsCertRecord) {
			row.SidecarId, _ = fixture.identity("laptop")
		}},
		{name: "a row of another network", change: func(fixture *tlsCtFixture, row *TlsCertRecord) {
			row.NetworkId = tlsCertTestId("another network")
		}},
		{name: "a row for other names", change: func(fixture *tlsCtFixture, row *TlsCertRecord) {
			otherSetSha256 := sha256.Sum256([]byte("another set"))
			row.IdentifierSetSha256 = otherSetSha256[:]
		}},
	}
	for _, c := range tamper {
		fixture := newTlsCtFixture(t)
		row := fixture.row(tlsCtTestZoneCertificate, "desktop", TlsCertStateIssued)
		second := fixture.row(tlsCtTestSecondCertificate, "laptop", TlsCertStateIssued)
		c.change(fixture, row)
		fixture.setRows(row, second)
		if alarms := fixture.pass(); alarms != 1 {
			t.Errorf("%s: %d alarms", c.name, alarms)
			continue
		}
		if events := fixture.eventsSoFar(); len(events) != 1 || events[0].CtAlarm != SidecarCtAlarmUnattested {
			t.Errorf("%s: events %+v", c.name, events)
		}
	}
}

func TestTlsCtWatchSourcesDownIsDegradedAndNoAlarm(t *testing.T) {
	fixture := newTlsCtFixture(t)
	// nothing attested, so anything read would alarm
	fixture.transport.fail(TlsCtSourceCertSpotter, 503, "")
	fixture.transport.fail(TlsCtSourceCrtSh, 429, "")
	if alarms := fixture.pass(); alarms != 0 {
		t.Fatalf("%d alarms with both sources down", alarms)
	}
	if !fixture.watch.Degraded() || len(fixture.eventsSoFar()) != 0 {
		t.Fatalf("degraded %t, %d events", fixture.watch.Degraded(), len(fixture.eventsSoFar()))
	}
	state, err := fixture.watch.readState()
	if err != nil || len(state.Cursors) != 0 {
		t.Errorf("a failed source moved a cursor: %v, %v", state, err)
	}

	// one source back: what it shows is judged, and the watch is still degraded
	fixture.transport.fail(TlsCtSourceCertSpotter, 0, "")
	if alarms := fixture.pass(); alarms != 2 || !fixture.watch.Degraded() {
		t.Errorf("%d alarms, degraded %t with one source down", alarms, fixture.watch.Degraded())
	}
	fixture.transport.fail(TlsCtSourceCrtSh, 0, "")
	if alarms := fixture.pass(); alarms != 2 || fixture.watch.Degraded() {
		t.Errorf("%d alarms, degraded %t with both sources back", alarms, fixture.watch.Degraded())
	}
}

func TestTlsCtWatchJudgesNothingWithoutRowsNamesOrConfig(t *testing.T) {
	blind := []struct {
		name   string
		change func(fixture *tlsCtFixture)
	}{
		{name: "the rows", change: func(fixture *tlsCtFixture) { fixture.rowsErr = ErrTlsCertsOffline }},
		{name: "the names", change: func(fixture *tlsCtFixture) { fixture.namesErr = errors.New("the zone is unreachable") }},
		{name: "verified config", change: func(fixture *tlsCtFixture) { fixture.noConfig = true }},
	}
	for _, c := range blind {
		fixture := newTlsCtFixture(t)
		fixture.set(func() {
			c.change(fixture)
		})
		if alarms := fixture.pass(); alarms != 0 || !fixture.watch.Degraded() || len(fixture.eventsSoFar()) != 0 {
			t.Errorf("without %s: %d alarms, degraded %t", c.name, alarms, fixture.watch.Degraded())
		}
		// nothing was asked of a source either, so no cursor passed a certificate unjudged
		if count := fixture.transport.requestCount(TlsCtSourceCertSpotter) + fixture.transport.requestCount(TlsCtSourceCrtSh); count != 0 {
			t.Errorf("without %s: %d requests", c.name, count)
		}
	}
}

func TestTlsCtWatchNotListeningWatchesNothing(t *testing.T) {
	fixture := newTlsCtFixture(t)
	fixture.set(func() {
		fixture.notListening = true
	})
	if alarms := fixture.pass(); alarms != 0 || fixture.watch.Degraded() {
		t.Errorf("%d alarms, degraded %t", alarms, fixture.watch.Degraded())
	}
	if count := fixture.transport.requestCount(TlsCtSourceCertSpotter) + fixture.transport.requestCount(TlsCtSourceCrtSh); count != 0 {
		t.Errorf("%d requests from a sidecar that is not listening", count)
	}
}

func TestTlsCtWatchJitterBounds(t *testing.T) {
	fixture := newTlsCtFixture(t)
	interval := fixture.settings.CtWatchInterval
	jitter := fixture.settings.CtWatchJitter
	if interval != 6*time.Hour || jitter != 30*time.Minute {
		t.Fatalf("interval %s, jitter %s", interval, jitter)
	}
	// the watch's own loop is parked on the earliest wait the jitter allows
	fixture.clock.awaitTimer(t, interval-jitter)
	// the latest: the pass runs at its time, and the next is set as far out as the jitter goes
	fixture.setRows(fixture.zoneRows()...)
	fixture.set(func() {
		fixture.randValue = int64(2*jitter) - 1
	})
	fixture.clock.advance(interval - jitter)
	fixture.clock.awaitTimer(t, interval+jitter-1)
	if status := fixture.watch.Status(); status.PassTime.IsZero() || status.Degraded {
		t.Errorf("the loop's pass %+v", status)
	}
	for _, value := range []int64{0, 1, int64(jitter), int64(2*jitter) - 1} {
		fixture.set(func() {
			fixture.randValue = value
		})
		if wait := fixture.watch.nextWait(); wait < interval-jitter || interval+jitter <= wait {
			t.Errorf("a wait of %s", wait)
		}
	}
	// a jitter that could reach zero is refused
	args := fixture.args()
	settings := *fixture.settings
	settings.CtWatchJitter = settings.CtWatchInterval
	args.Settings = &settings
	if _, err := newTlsCtWatch(t.Context(), args); !errors.Is(err, errInvalidSettings) {
		t.Errorf("a jitter as long as the interval: %v", err)
	}
}

func TestTlsCtWatchACustomRowThatIsACertificateDoesNotAlarm(t *testing.T) {
	// DESIGN-DETAILS 17.7: custom_issued, custom_revoking, and a row that ended with its chain kept
	for _, state := range []TlsCertState{TlsCertStateCustomIssued, TlsCertStateCustomRevoking, TlsCertStateRevoked, TlsCertStateExpired} {
		fixture := newTlsCtFixture(t)
		fixture.set(func() {
			fixture.customHosts = []string{tlsCtTestCustom}
		})
		fixture.setRows(append(fixture.zoneRows(), fixture.row(tlsCtTestCustomCertificate, "desktop", state))...)
		if alarms := fixture.pass(); alarms != 0 {
			t.Errorf("%d alarms with the custom row %s", alarms, state)
		}
		if fixture.watch.Degraded() {
			t.Errorf("degraded with the custom row %s", state)
		}
	}
}

func TestTlsCtWatchACustomCertificateOnAKeyNoRowHoldsAlarms(t *testing.T) {
	absent := []struct {
		name string
		rows func(fixture *tlsCtFixture) []*TlsCertRecord
	}{
		{name: "no row", rows: func(fixture *tlsCtFixture) []*TlsCertRecord { return nil }},
		{name: "only custom_queued", rows: func(fixture *tlsCtFixture) []*TlsCertRecord {
			return []*TlsCertRecord{fixture.row(tlsCtTestCustomCertificate, "desktop", TlsCertStateCustomQueued)}
		}},
		{name: "only custom_ordering", rows: func(fixture *tlsCtFixture) []*TlsCertRecord {
			return []*TlsCertRecord{fixture.row(tlsCtTestCustomCertificate, "desktop", TlsCertStateCustomOrdering)}
		}},
		{name: "queued and ordering both", rows: func(fixture *tlsCtFixture) []*TlsCertRecord {
			return []*TlsCertRecord{
				fixture.row(tlsCtTestCustomCertificate, "desktop", TlsCertStateCustomQueued),
				fixture.row(tlsCtTestCustomCertificate, "desktop", TlsCertStateCustomOrdering),
			}
		}},
		{name: "a row that ended with no chain", rows: func(fixture *tlsCtFixture) []*TlsCertRecord {
			row := fixture.row(tlsCtTestCustomCertificate, "desktop", TlsCertStateRevoked)
			row.Chain = nil
			return []*TlsCertRecord{row}
		}},
		{name: "a state from a later build", rows: func(fixture *tlsCtFixture) []*TlsCertRecord {
			return []*TlsCertRecord{fixture.row(tlsCtTestCustomCertificate, "desktop", TlsCertState("custom_later"))}
		}},
		{name: "an issued row on another key", rows: func(fixture *tlsCtFixture) []*TlsCertRecord {
			// the device's own custom_issued row, for the same host, on the key it holds
			row := fixture.row(tlsCtTestCustomCertificate, "desktop", TlsCertStateCustomIssued)
			otherSpkiSha256 := sha256.Sum256([]byte("the device's own key"))
			row.SpkiSha256 = otherSpkiSha256[:]
			return []*TlsCertRecord{row}
		}},
	}
	for _, c := range absent {
		fixture := newTlsCtFixture(t)
		fixture.set(func() {
			fixture.customHosts = []string{tlsCtTestCustom}
		})
		fixture.setRows(append(fixture.zoneRows(), c.rows(fixture)...)...)
		if alarms := fixture.pass(); alarms != 1 {
			t.Errorf("%s: %d alarms", c.name, alarms)
			continue
		}
		alarm := fixture.watch.Status().Alarms[0]
		if alarm.Reason != SidecarCtAlarmUnattested || !slices.Equal(alarm.DnsNames, []string{tlsCtTestCustom}) {
			t.Errorf("%s: alarm %+v", c.name, alarm)
		}
	}
	// a sidecar with no custom host asks about none
	fixture := newTlsCtFixture(t)
	fixture.setRows(fixture.zoneRows()...)
	if alarms := fixture.pass(); alarms != 0 {
		t.Errorf("%d alarms with no custom host watched", alarms)
	}
}

func TestTlsCtWatchKeepsACertificateKnownAfterItsRowIsDeleted(t *testing.T) {
	fixture := newTlsCtFixture(t)
	fixture.setRows(fixture.zoneRows()...)
	if alarms := fixture.pass(); alarms != 0 {
		t.Fatalf("%d alarms", alarms)
	}
	// certs deletes a revoked row 30 days on, while the certificate is still logged and inside its validity; the
	// sources show it again, as after a lost cursor
	fixture.setRows()
	state, err := fixture.watch.readState()
	if err != nil {
		t.Fatal(err)
	}
	state.Cursors = map[string]string{}
	if err := fixture.watch.writeState(state); err != nil {
		t.Fatal(err)
	}
	if alarms := fixture.pass(); alarms != 0 {
		t.Errorf("%d alarms for certificates found known before", alarms)
	}
	// a state that does not decode is a failed pass, never a forgotten one
	writeStoreFile(t, fixture.store, tlsCtStateFileName, []byte("not the watch's"))
	if alarms := fixture.pass(); alarms != 0 || !fixture.watch.Degraded() {
		t.Errorf("%d alarms, degraded %t over a state that does not decode", alarms, fixture.watch.Degraded())
	}
}

func TestTlsCtWatchARestartTellsAStandingAlarmAgain(t *testing.T) {
	fixture := newTlsCtFixture(t)
	fixture.setRows(fixture.row(tlsCtTestZoneCertificate, "desktop", TlsCertStateIssued))
	if alarms := fixture.pass(); alarms != 1 || len(fixture.eventsSoFar()) != 1 {
		t.Fatalf("%d alarms", alarms)
	}
	// the cursors are past the certificate; the alarm is the store's
	restarted := fixture.newWatch()
	if alarms := restarted.Pass(t.Context()); alarms != 1 {
		t.Fatalf("%d alarms after a restart", alarms)
	}
	if events := fixture.eventsSoFar(); len(events) != 2 || events[1].CtAlarm != SidecarCtAlarmUnattested {
		t.Errorf("events after a restart %+v", events)
	}
	restarted.Pass(t.Context())
	if events := fixture.eventsSoFar(); len(events) != 2 {
		t.Errorf("%d events after the restart's second pass", len(events))
	}
}

// An authority whose retained entries are timed an hour apart from start, each at its position.
type tlsCtTestAuthority struct {
	*testActAuthority
	start time.Time
	count uint64
}

func (self *tlsCtTestAuthority) ProposedSince(at time.Time) (uint64, time.Time, bool) {
	for n := uint64(1); n <= self.count; n += 1 {
		entryTime := self.start.Add(time.Duration(n) * time.Hour)
		if !entryTime.Before(at) {
			return n, entryTime, true
		}
	}
	return 0, time.Time{}, false
}

func TestTlsCtAuthorityIdentitiesReadThePinFromTheLog(t *testing.T) {
	if NewTlsCtAuthorityIdentities(nil) != nil {
		t.Fatalf("identities with no authority")
	}
	start := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	authority := &tlsCtTestAuthority{testActAuthority: newTestActAuthority(), start: start, count: 10}
	sidecarId := tlsCertTestId("an admitted sidecar")
	identityPublicKey := []byte("an identity public key, 32 bytes")
	authority.sidecars[sidecarId] = &AclSidecar{Row: &bridge.SidecarRow{SidecarId: sidecarId[:], AdmittedAt: 5, IdentityPublicKey: identityPublicKey}}
	identities := NewTlsCtAuthorityIdentities(authority)
	if string(identities.IdentityPublicKey(sidecarId)) != string(identityPublicKey) {
		t.Errorf("the pinned key")
	}
	unknown := tlsCertTestId("never admitted")
	if identities.IdentityPublicKey(unknown) != nil || !identities.PinnedSince(unknown, start) {
		t.Errorf("a sidecar the state never admitted reads as pinned long ago")
	}
	// admitted by entry 5, timed at start + 5 h
	if !identities.PinnedSince(sidecarId, start.Add(5*time.Hour)) || !identities.PinnedSince(sidecarId, start.Add(4*time.Hour+time.Minute)) {
		t.Errorf("an identity pinned at or after the instant reads as older")
	}
	if identities.PinnedSince(sidecarId, start.Add(5*time.Hour+time.Minute)) {
		t.Errorf("an identity pinned before the instant reads as newer")
	}
	// past the newest entry every pin is older
	if identities.PinnedSince(sidecarId, start.Add(100*time.Hour)) {
		t.Errorf("an identity reads as pinned after the log's newest entry")
	}
}

func TestSidecarStatusShowsTheCtWatchDegraded(t *testing.T) {
	fixture := newTlsCtFixture(t)
	sidecar := newTestSidecar(t)
	events := recordEvents(sidecar)
	if sidecar.Status().CtWatchDegraded {
		t.Fatalf("degraded with no watch")
	}
	sidecar.setTlsCtWatch(fixture.watch)
	fixture.transport.fail(TlsCtSourceCrtSh, 503, "")
	fixture.setRows(fixture.zoneRows()...)
	fixture.pass()
	if !sidecar.Status().CtWatchDegraded {
		t.Errorf("a degraded watch does not show in the status")
	}
	fixture.transport.fail(TlsCtSourceCrtSh, 0, "")
	fixture.pass()
	if sidecar.Status().CtWatchDegraded {
		t.Errorf("a recovered watch still shows degraded")
	}
	sidecar.setTlsCtWatch(nil)
	// the watch's alarm is one a component relays
	if err := sidecar.Alarm(SidecarEvent{Kind: SidecarEventCtAlarm, CtAlarm: SidecarCtAlarmUnattested}); err != nil {
		t.Fatal(err)
	}
	if len(*events) != 1 || (*events)[0].Kind != SidecarEventCtAlarm || (*events)[0].CtAlarm != SidecarCtAlarmUnattested {
		t.Errorf("events %+v", *events)
	}
}

func TestTlsComponentRunsTheCtWatch(t *testing.T) {
	fixture := newTlsCertFixture(t)
	fixture.manager.Close()
	ctFixture := newTlsCtFixture(t)
	var attached sidecarCtWatch
	closed := false
	watchArgs := ctFixture.args()
	// the manager's rows, names, store, settings and clock stand in where the watch names none
	watchArgs.NetworkId = Id{}
	watchArgs.Rows = nil
	watchArgs.Names = nil
	watchArgs.Store = nil
	watchArgs.Settings = nil
	watchArgs.Clock = nil
	component, err := NewTlsComponent(t.Context(), &TlsComponentArgs{
		Manager: &TlsCertManagerArgs{
			NetworkId: fixture.networkId,
			SidecarId: fixture.sidecarId,
			Settings:  fixture.settings,
			Keys:      fixture.keys,
			Sign:      testTlsSign(fixture.identity, fixture.sidecarId[:]),
			ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
				return "synthetic-service-token", nil
			},
			Names: fixture.names,
			Store: fixture.store,
			Clock: fixture.clock,
			Log:   NewNoopLogger(),
		},
		CtWatch: watchArgs,
		SetCtWatch: func(watch sidecarCtWatch) {
			attached = watch
		},
		CloseCtSources: func() {
			closed = true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if attached == nil {
		t.Fatalf("the watch was not attached to the status")
	}
	// with no generation attached the rows cannot be read: degraded, and no alarm
	if alarms := component.ctWatch.Pass(t.Context()); alarms != 0 || !component.CtWatchStatus().Degraded || !attached.Degraded() {
		t.Errorf("%d alarms, status %+v", alarms, component.CtWatchStatus())
	}
	component.manager.SetApi(fixture.api)
	if alarms := component.ctWatch.Pass(t.Context()); alarms != 2 || component.CtWatchStatus().Degraded {
		t.Errorf("%d alarms through the manager's rows, status %+v", alarms, component.CtWatchStatus())
	}
	component.Close()
	if attached != nil || !closed {
		t.Errorf("a closed component left its watch attached or its sources open")
	}
}
