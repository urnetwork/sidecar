// The conformance suite for socketsservice.SocketStore (§9.8; SOCK-M5-03): what store.go promises, run
// on FakeSocketStore here and on server's model store (SOCK-M5-04), so the fake stays honest (D-TEST-2).
// Every case runs through the interface alone, on a clock of its own and ids no other case shares, so one
// Redis serves the whole run and a shared database's other keys change no verdict.
//
// Leases, shares and reports live by the store's injected clock, which each case moves; a store's
// backing ttls run on real time and are never what a case reads. A case is a plain function returning
// its first failure, and RunSocketStoreSuite loops over them, since one store's cases are homogeneous
// variations (connect/CODESTYLE.md:216). A failure in one does not stop the next.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/socketsservice"
)

// How long one case may wait on a store before it fails. Real time, so only ever a failure's bound: no
// case sleeps.
const socketSuiteCaseTimeout = 60 * time.Second

// What a case is given: a store on its own fake clock.
type socketSuiteEnv struct {
	ctx      context.Context
	clock    *FakeClock
	settings *socketsservice.SocketStoreSettings
	store    socketsservice.SocketStore
}

type socketSuiteCase struct {
	name string
	run  func(env *socketSuiteEnv) error
}

// Makes a store for one case on clock with settings. Each case makes its own.
type SocketStoreFactory func(clock sidecar.Clock, settings *socketsservice.SocketStoreSettings) socketsservice.SocketStore

// Runs every case, each on a store newStore makes. t is a testing.TB so that server's T3 test can run it
// inside its test environment's callback.
func RunSocketStoreSuite(t testing.TB, newStore SocketStoreFactory) {
	t.Helper()
	for _, suiteCase := range socketSuiteCases() {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), socketSuiteCaseTimeout)
			defer cancel()
			clock := NewFakeClock(DefaultClockStart())
			settings := socketsservice.DefaultSocketStoreSettings()
			env := &socketSuiteEnv{ctx: ctx, clock: clock, settings: settings, store: newStore(clock, settings)}
			if err := suiteCase.run(env); err != nil {
				t.Errorf("%s: %v", suiteCase.name, err)
			}
		}()
	}
}

func socketSuiteCases() []socketSuiteCase {
	return []socketSuiteCase{
		{name: "a page writes its entries, which list and pick", run: caseSocketPageWrites},
		{name: "a page applied twice leaves what applying it once did", run: caseSocketPageRetryIdempotent},
		{name: "a page older than the stored set_version is refused and writes nothing", run: caseSocketPageStaleRefused},
		{name: "a page unlistens what it lacks in its range and nothing outside it", run: caseSocketPageRangeScoped},
		{name: "pages over consecutive ranges under one set_version build one set", run: caseSocketPagesBuildOneSet},
		{name: "a lease ends at exactly its 45 s", run: caseSocketLeaseExpires},
		{name: "a group takes one protocol", run: caseSocketOneProtocolPerGroup},
		{name: "an exclusive listener refuses later registrations until its lease ends", run: caseSocketExclusiveHeld},
		{name: "an exclusive registration into a shared group is taken", run: caseSocketExclusiveIntoSharedGroup},
		{name: "a pick answers no_listener and busy as the scheduler does", run: caseSocketPickOutcomes},
		{name: "a pick matches PickSocketListeners on what the store holds", run: caseSocketPickMatchesScheduler},
		{name: "a pick matches PickSocketListeners at load ties and at the clamp", run: caseSocketPickMatchesSchedulerAtItsEdges},
		{name: "a dialer adds at most c to est, and its share decays with the ticket", run: caseSocketIssuedShareDecays},
		{name: "a report excludes the listener for its dialer alone", run: caseSocketReportExcludes},
		{name: "ejection needs reporters from two networks and takes at most half a group", run: caseSocketEjection},
		{name: "a report for an earlier listen is ignored", run: caseSocketReportOldListenIgnored},
		{name: "a pair holds its grant expiry until replaced or removed", run: caseSocketServicePairs},
		{name: "removing a client ends its leases, its set and its pairs", run: caseSocketRemoveClient},
		{name: "removing entries ends those leases and the set forgets them", run: caseSocketRemoveEntries},
		{name: "a listing pages through every name", run: caseSocketListNamesPages},
		{name: "first and last listeners are reported on explicit transitions", run: caseSocketFirstAndLastListener},
		{name: "one name in two networks is two groups", run: caseSocketNetworksIsolated},
		{name: "a group past the sample size still picks", run: caseSocketSampledGroupPicks},
	}
}

// A random id no other case shares.
func socketSuiteId() connect.Id {
	return connect.Id(sidecar.NewId())
}

// Random bytes.
func socketSuiteBytes(byteCount int) []byte {
	value := make([]byte, byteCount)
	if _, err := rand.Read(value); err != nil {
		panic(err)
	}
	return value
}

// A tls/ name with a random host, lowercase and canonical.
func socketSuiteEdgeName() string {
	return fmt.Sprintf("tls/443/h%x", socketSuiteBytes(6))
}

// A registration with §9.5's defaults for an edge name, or a token path when name is empty.
func socketSuiteRegistration(name string) *sidecar.SocketRegistration {
	listenId := socketSuiteId()
	registration := &sidecar.SocketRegistration{
		ListenId:   &listenId,
		Protocol:   "tcp",
		Weight:     100,
		MaxStreams: 256,
		Serving:    true,
		Claim:      socketSuiteBytes(96),
	}
	if name != "" {
		registration.Name = name
	} else {
		registration.NameToken = socketSuiteBytes(32)
		registration.SealedName = socketSuiteBytes(152)
	}
	return registration
}

// Registrations sorted by name key, as a page holds them.
func socketSuiteSorted(registrations []*sidecar.SocketRegistration) []*sidecar.SocketRegistration {
	sorted := slices.Clone(registrations)
	slices.SortFunc(sorted, func(a *sidecar.SocketRegistration, b *sidecar.SocketRegistration) int {
		return bytes.Compare(a.NameKey(), b.NameKey())
	})
	return sorted
}

// One unbounded page of a client's whole set.
func (self *socketSuiteEnv) applyWhole(networkId connect.Id, clientId connect.Id, setVersion uint64, registrations ...*sidecar.SocketRegistration) (*socketsservice.SocketStorePageResult, error) {
	return self.store.ApplyPage(self.ctx, &socketsservice.SocketStorePage{
		NetworkId:        networkId,
		ListenerClientId: clientId,
		SetVersion:       setVersion,
		Registrations:    socketSuiteSorted(registrations),
	})
}

// Applies and requires every entry to hold a lease.
func (self *socketSuiteEnv) mustApplyWhole(networkId connect.Id, clientId connect.Id, setVersion uint64, registrations ...*sidecar.SocketRegistration) error {
	result, err := self.applyWhole(networkId, clientId, setVersion, registrations...)
	if err != nil {
		return err
	}
	if result.Stale {
		return errors.New("a fresh page was stale")
	}
	for index, outcome := range result.Outcomes {
		if outcome.Taken {
			return fmt.Errorf("entry %d was taken", index)
		}
	}
	return nil
}

// A pick by dialer with draws and nothing else asked.
func (self *socketSuiteEnv) pick(networkId connect.Id, nameKey []byte, dialerClientId connect.Id, firstDraw uint32, secondDraw uint32) (*socketsservice.SocketStorePickResult, error) {
	return self.store.Pick(self.ctx, &socketsservice.SocketStorePickRequest{
		NetworkId:       networkId,
		NameKey:         nameKey,
		DialerClientId:  dialerClientId,
		DialerNetworkId: networkId,
		FirstDraw:       firstDraw,
		SecondDraw:      secondDraw,
	})
}

// The listeners' client ids, in order.
func socketSuiteListenerIds(listeners []*socketsservice.SocketStoreListener) []connect.Id {
	listenerClientIds := []connect.Id{}
	for _, listener := range listeners {
		listenerClientIds = append(listenerClientIds, listener.Candidate.ListenerClientId)
	}
	return listenerClientIds
}

// Every name of a network's listing, paging count at a time.
func (self *socketSuiteEnv) listAll(networkId connect.Id, count int) ([]*sidecar.SocketListName, error) {
	names := []*sidecar.SocketListName{}
	seenNameKeys := map[string]bool{}
	cursor := ""
	for pageCount := 0; ; pageCount += 1 {
		if 10000 < pageCount {
			return nil, errors.New("the listing never ended")
		}
		page, nextCursor, err := self.store.ListNames(self.ctx, networkId, cursor, count)
		if err != nil {
			return nil, err
		}
		if count < len(page) {
			return nil, fmt.Errorf("a page of %d for a count of %d", len(page), count)
		}
		for _, name := range page {
			nameKey := name.Name
			if nameKey == "" {
				nameKey = string(name.NameToken)
			}
			if !seenNameKeys[nameKey] {
				seenNameKeys[nameKey] = true
				names = append(names, name)
			}
		}
		if nextCursor == "" {
			return names, nil
		}
		cursor = nextCursor
	}
}

func caseSocketPageWrites(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	clientId := socketSuiteId()
	edge := socketSuiteRegistration(socketSuiteEdgeName())
	blinded := socketSuiteRegistration("")
	result, err := env.applyWhole(networkId, clientId, 1, edge, blinded)
	if err != nil {
		return err
	}
	if result.Stale || result.SetVersion != 1 || len(result.Outcomes) != 2 || len(result.Removed) != 0 {
		return fmt.Errorf("result %+v", result)
	}
	for index, outcome := range result.Outcomes {
		if outcome.Taken || !outcome.FirstListener {
			return fmt.Errorf("outcome %d: %+v", index, outcome)
		}
	}
	for _, registration := range []*sidecar.SocketRegistration{edge, blinded} {
		listeners, err := env.store.ListListeners(env.ctx, networkId, registration.NameKey())
		if err != nil {
			return err
		}
		if len(listeners) != 1 || listeners[0].Candidate.ListenerClientId != clientId {
			return fmt.Errorf("%d listeners", len(listeners))
		}
		listener := listeners[0]
		if *listener.Registration.ListenId != *registration.ListenId || !bytes.Equal(listener.Registration.Claim, registration.Claim) ||
			listener.Registration.Name != registration.Name || !bytes.Equal(listener.Registration.NameToken, registration.NameToken) {
			return errors.New("the registration did not read back")
		}
		wantLease := env.clock.Now().UnixMilli() + env.settings.Lease.Milliseconds()
		if listener.Candidate.LeaseExpireMillis != wantLease || listener.Candidate.ReportMillis != env.clock.Now().UnixMilli() {
			return fmt.Errorf("lease %d, report %d", listener.Candidate.LeaseExpireMillis, listener.Candidate.ReportMillis)
		}
		pick, err := env.pick(networkId, registration.NameKey(), socketSuiteId(), 0, 0)
		if err != nil {
			return err
		}
		if pick.Outcome != socketsservice.SocketPickFound || pick.Primary.Candidate.ListenerClientId != clientId || pick.Backup != nil {
			return fmt.Errorf("pick %+v", pick)
		}
		if !bytes.Equal(pick.Primary.Registration.Claim, registration.Claim) {
			return errors.New("a pick did not carry the claim")
		}
	}
	names, err := env.listAll(networkId, 10)
	if err != nil {
		return err
	}
	if len(names) != 2 {
		return fmt.Errorf("%d names listed", len(names))
	}
	for _, name := range names {
		switch {
		case name.Name == edge.Name:
			if len(name.NameToken) != 0 || len(name.SealedName) != 0 {
				return errors.New("an edge name listed with a token")
			}
		case bytes.Equal(name.NameToken, blinded.NameToken):
			if !bytes.Equal(name.SealedName, blinded.SealedName) || name.Name != "" {
				return errors.New("a blinded name listed without its seal")
			}
		default:
			return errors.New("a name listed that was never registered")
		}
	}
	return nil
}

func caseSocketPageRetryIdempotent(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	clientId := socketSuiteId()
	registrations := []*sidecar.SocketRegistration{socketSuiteRegistration(""), socketSuiteRegistration(""), socketSuiteRegistration(socketSuiteEdgeName())}
	if err := env.mustApplyWhole(networkId, clientId, 7, registrations...); err != nil {
		return err
	}
	again, err := env.applyWhole(networkId, clientId, 7, registrations...)
	if err != nil {
		return err
	}
	if again.Stale || again.SetVersion != 7 || len(again.Removed) != 0 {
		return fmt.Errorf("the retry: %+v", again)
	}
	for index, outcome := range again.Outcomes {
		if outcome.Taken || outcome.FirstListener {
			return fmt.Errorf("the retry's outcome %d: %+v", index, outcome)
		}
	}
	for _, registration := range registrations {
		listeners, err := env.store.ListListeners(env.ctx, networkId, registration.NameKey())
		if err != nil {
			return err
		}
		if len(listeners) != 1 {
			return fmt.Errorf("%d listeners after a retry", len(listeners))
		}
	}
	return nil
}

func caseSocketPageStaleRefused(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	clientId := socketSuiteId()
	kept := socketSuiteRegistration("")
	if err := env.mustApplyWhole(networkId, clientId, 20, kept); err != nil {
		return err
	}
	late := socketSuiteRegistration("")
	result, err := env.applyWhole(networkId, clientId, 19, late)
	if err != nil {
		return err
	}
	if !result.Stale || result.SetVersion != 20 || len(result.Outcomes) != 0 || len(result.Removed) != 0 {
		return fmt.Errorf("an older page: %+v", result)
	}
	listeners, err := env.store.ListListeners(env.ctx, networkId, late.NameKey())
	if err != nil {
		return err
	}
	if len(listeners) != 0 {
		return errors.New("a stale page wrote")
	}
	listeners, err = env.store.ListListeners(env.ctx, networkId, kept.NameKey())
	if err != nil {
		return err
	}
	if len(listeners) != 1 {
		return errors.New("a stale page unlistened")
	}
	// a newer one replaces the set
	result, err = env.applyWhole(networkId, clientId, 21, late)
	if err != nil {
		return err
	}
	if result.Stale || result.SetVersion != 21 || len(result.Removed) != 1 || !bytes.Equal(result.Removed[0].NameKey, kept.NameKey()) {
		return fmt.Errorf("a newer page: %+v", result)
	}
	return nil
}

func caseSocketPageRangeScoped(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	clientId := socketSuiteId()
	registrations := []*sidecar.SocketRegistration{}
	for range 6 {
		registrations = append(registrations, socketSuiteRegistration(""))
	}
	registrations = socketSuiteSorted(registrations)
	split := registrations[3].NameKey()
	page := func(setVersion uint64, keyStart []byte, keyEnd []byte, entries ...*sidecar.SocketRegistration) (*socketsservice.SocketStorePageResult, error) {
		return env.store.ApplyPage(env.ctx, &socketsservice.SocketStorePage{
			NetworkId:        networkId,
			ListenerClientId: clientId,
			SetVersion:       setVersion,
			KeyStart:         keyStart,
			KeyEnd:           keyEnd,
			Registrations:    entries,
		})
	}
	if _, err := page(1, nil, split, registrations[:3]...); err != nil {
		return err
	}
	if _, err := page(1, split, nil, registrations[3:]...); err != nil {
		return err
	}
	// the first range again, lacking its middle entry
	result, err := page(1, nil, split, registrations[0], registrations[2])
	if err != nil {
		return err
	}
	if result.Stale || len(result.Removed) != 1 || !bytes.Equal(result.Removed[0].NameKey, registrations[1].NameKey()) || !result.Removed[0].LastListener {
		return fmt.Errorf("the second page: %+v", result)
	}
	for index, registration := range registrations {
		listeners, err := env.store.ListListeners(env.ctx, networkId, registration.NameKey())
		if err != nil {
			return err
		}
		if want := index != 1; (len(listeners) == 1) != want {
			return fmt.Errorf("entry %d listening: %d", index, len(listeners))
		}
	}
	// an empty page over the second range unlistens it all, and the first stays
	result, err = page(1, split, nil)
	if err != nil {
		return err
	}
	if len(result.Removed) != 3 {
		return fmt.Errorf("%d removed by an empty page", len(result.Removed))
	}
	for index, removed := range result.Removed {
		if !bytes.Equal(removed.NameKey, registrations[3+index].NameKey()) {
			return fmt.Errorf("removed %d out of order", index)
		}
	}
	listeners, err := env.store.ListListeners(env.ctx, networkId, registrations[0].NameKey())
	if err != nil {
		return err
	}
	if len(listeners) != 1 {
		return errors.New("a page touched what lay outside its range")
	}
	return nil
}

func caseSocketPagesBuildOneSet(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	clientId := socketSuiteId()
	registrations := []*sidecar.SocketRegistration{}
	for range 30 {
		registrations = append(registrations, socketSuiteRegistration(""))
	}
	registrations = socketSuiteSorted(registrations)
	bounds := [][]byte{nil, registrations[10].NameKey(), registrations[20].NameKey(), nil}
	for index := range 3 {
		result, err := env.store.ApplyPage(env.ctx, &socketsservice.SocketStorePage{
			NetworkId:        networkId,
			ListenerClientId: clientId,
			SetVersion:       5,
			KeyStart:         bounds[index],
			KeyEnd:           bounds[index+1],
			Registrations:    registrations[index*10 : index*10+10],
		})
		if err != nil {
			return err
		}
		if result.Stale || len(result.Removed) != 0 {
			return fmt.Errorf("page %d: %+v", index, result)
		}
	}
	names, err := env.listAll(networkId, 8)
	if err != nil {
		return err
	}
	if len(names) != 30 {
		return fmt.Errorf("%d names from three pages of ten", len(names))
	}
	return nil
}

func caseSocketLeaseExpires(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	registration := socketSuiteRegistration("")
	if err := env.mustApplyWhole(networkId, socketSuiteId(), 1, registration); err != nil {
		return err
	}
	env.clock.Advance(env.settings.Lease - time.Millisecond)
	pick, err := env.pick(networkId, registration.NameKey(), socketSuiteId(), 0, 0)
	if err != nil {
		return err
	}
	if pick.Outcome != socketsservice.SocketPickFound {
		return fmt.Errorf("a millisecond before the lease ends: %v", pick.Outcome)
	}
	env.clock.Advance(time.Millisecond)
	pick, err = env.pick(networkId, registration.NameKey(), socketSuiteId(), 0, 0)
	if err != nil {
		return err
	}
	if pick.Outcome != socketsservice.SocketPickNoListener {
		return fmt.Errorf("at the lease's end: %v", pick.Outcome)
	}
	listeners, err := env.store.ListListeners(env.ctx, networkId, registration.NameKey())
	if err != nil {
		return err
	}
	names, err := env.listAll(networkId, 10)
	if err != nil {
		return err
	}
	if len(listeners) != 0 || len(names) != 0 {
		return fmt.Errorf("an ended lease: %d listeners, %d names", len(listeners), len(names))
	}
	return nil
}

func caseSocketOneProtocolPerGroup(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	first := socketSuiteRegistration("")
	if err := env.mustApplyWhole(networkId, socketSuiteId(), 1, first); err != nil {
		return err
	}
	other := copySocketRegistration(first)
	otherListenId := socketSuiteId()
	other.ListenId = &otherListenId
	other.Protocol = "udp"
	result, err := env.applyWhole(networkId, socketSuiteId(), 1, other)
	if err != nil {
		return err
	}
	if !result.Outcomes[0].Taken {
		return errors.New("a second protocol joined the group")
	}
	other.Protocol = first.Protocol
	result, err = env.applyWhole(networkId, socketSuiteId(), 1, other)
	if err != nil {
		return err
	}
	if result.Outcomes[0].Taken {
		return errors.New("the group's own protocol was taken")
	}
	return nil
}

func caseSocketExclusiveHeld(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	holderId := socketSuiteId()
	holder := socketSuiteRegistration("")
	holder.Exclusive = true
	if err := env.mustApplyWhole(networkId, holderId, 1, holder); err != nil {
		return err
	}
	later := copySocketRegistration(holder)
	later.Exclusive = false
	laterId := socketSuiteId()
	result, err := env.applyWhole(networkId, laterId, 1, later)
	if err != nil {
		return err
	}
	if !result.Outcomes[0].Taken {
		return errors.New("an exclusive group took a later listener")
	}
	// the holder's own heartbeat keeps it
	if err := env.mustApplyWhole(networkId, holderId, 2, holder); err != nil {
		return fmt.Errorf("the holder's heartbeat: %w", err)
	}
	env.clock.Advance(env.settings.Lease)
	result, err = env.applyWhole(networkId, laterId, 2, later)
	if err != nil {
		return err
	}
	if result.Outcomes[0].Taken {
		return errors.New("an ended exclusive lease still held the group")
	}
	return nil
}

func caseSocketExclusiveIntoSharedGroup(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	first := socketSuiteRegistration("")
	if err := env.mustApplyWhole(networkId, socketSuiteId(), 1, first); err != nil {
		return err
	}
	exclusive := copySocketRegistration(first)
	exclusive.Exclusive = true
	result, err := env.applyWhole(networkId, socketSuiteId(), 1, exclusive)
	if err != nil {
		return err
	}
	if !result.Outcomes[0].Taken {
		return errors.New("an exclusive registration joined a shared group")
	}
	return nil
}

func caseSocketPickOutcomes(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	pick, err := env.pick(networkId, socketSuiteBytes(16), socketSuiteId(), 0, 0)
	if err != nil {
		return err
	}
	if pick.Outcome != socketsservice.SocketPickNoListener || pick.Primary != nil {
		return fmt.Errorf("no group: %+v", pick)
	}

	full := socketSuiteRegistration("")
	full.MaxStreams = 8
	full.Inflight = 8
	if err := env.mustApplyWhole(networkId, socketSuiteId(), 1, full); err != nil {
		return err
	}
	pick, err = env.pick(networkId, full.NameKey(), socketSuiteId(), 0, 0)
	if err != nil {
		return err
	}
	if pick.Outcome != socketsservice.SocketPickBusy || pick.Primary != nil {
		return fmt.Errorf("only a full listener: %+v", pick)
	}

	idle := socketSuiteRegistration("")
	idle.Serving = false
	draining := copySocketRegistration(idle)
	draining.Serving = true
	draining.Draining = true
	if err := env.mustApplyWhole(networkId, socketSuiteId(), 1, idle); err != nil {
		return err
	}
	if err := env.mustApplyWhole(networkId, socketSuiteId(), 1, draining); err != nil {
		return err
	}
	pick, err = env.pick(networkId, idle.NameKey(), socketSuiteId(), 0, 0)
	if err != nil {
		return err
	}
	if pick.Outcome != socketsservice.SocketPickNoListener {
		return fmt.Errorf("only listeners not serving or draining: %v", pick.Outcome)
	}

	versioned := socketSuiteRegistration("")
	versioned.Version = 2
	versioned.Alpn = []string{"h2"}
	if err := env.mustApplyWhole(networkId, socketSuiteId(), 1, versioned); err != nil {
		return err
	}
	for _, c := range []struct {
		protocol   string
		minVersion int
		alpns      []string
		want       socketsservice.SocketPickOutcome
	}{
		{want: socketsservice.SocketPickFound},
		{protocol: "tcp", minVersion: 2, alpns: []string{"http/1.1", "h2"}, want: socketsservice.SocketPickFound},
		{protocol: "udp", want: socketsservice.SocketPickNoListener},
		{minVersion: 3, want: socketsservice.SocketPickNoListener},
		{alpns: []string{"http/1.1"}, want: socketsservice.SocketPickNoListener},
	} {
		pick, err := env.store.Pick(env.ctx, &socketsservice.SocketStorePickRequest{
			NetworkId:      networkId,
			NameKey:        versioned.NameKey(),
			DialerClientId: socketSuiteId(),
			Protocol:       c.protocol,
			MinVersion:     c.minVersion,
			Alpns:          c.alpns,
		})
		if err != nil {
			return err
		}
		if pick.Outcome != c.want {
			return fmt.Errorf("protocol %q, version %d, alpns %v: %v", c.protocol, c.minVersion, c.alpns, pick.Outcome)
		}
	}
	return nil
}

func caseSocketPickMatchesScheduler(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	nameKey := socketSuiteBytes(48)
	random := mathrand.New(mathrand.NewPCG(1, 2))
	for index := range 9 {
		registration := socketSuiteRegistration("")
		registration.NameToken = nameKey
		registration.Weight = []int{1, 7, 100, 100, 250, 999, 1000, 3, 50}[index]
		registration.MaxStreams = []int{4, 16, 256, 40, 256, 1000, 10, 64, 30}[index]
		registration.Inflight = []int{0, 15, 120, 3, 256, 0, 9, 1, 29}[index]
		registration.Version = index % 3
		if index%2 == 0 {
			registration.Alpn = []string{"h2"}
		}
		registration.Draining = index == 7
		if err := env.mustApplyWhole(networkId, socketSuiteId(), 1, registration); err != nil {
			return err
		}
	}
	dialerClientIds := []connect.Id{socketSuiteId(), socketSuiteId(), socketSuiteId()}
	scheduler := env.settings.Scheduler
	for round := range 120 {
		request := &socketsservice.SocketStorePickRequest{
			NetworkId:       networkId,
			NameKey:         nameKey,
			DialerClientId:  dialerClientIds[round%len(dialerClientIds)],
			DialerNetworkId: networkId,
			FirstDraw:       random.Uint32(),
			SecondDraw:      random.Uint32(),
		}
		if round%4 == 1 {
			request.Alpns = []string{"h2"}
		}
		if round%5 == 2 {
			request.MinVersion = 1
		}
		listeners, err := env.store.ListListeners(env.ctx, networkId, nameKey)
		if err != nil {
			return err
		}
		candidates := []*socketsservice.SocketCandidate{}
		for _, listener := range listeners {
			candidates = append(candidates, listener.Candidate)
		}
		want := socketsservice.PickSocketListeners(candidates, &socketsservice.SocketPickRequest{
			DialerClientId: request.DialerClientId,
			Protocol:       request.Protocol,
			MinVersion:     request.MinVersion,
			Alpns:          request.Alpns,
			NowMillis:      env.clock.Now().UnixMilli(),
			FirstDraw:      request.FirstDraw,
			SecondDraw:     request.SecondDraw,
		}, scheduler)
		got, err := env.store.Pick(env.ctx, request)
		if err != nil {
			return err
		}
		if got.Outcome != want.Outcome {
			return fmt.Errorf("round %d: outcome %v, the scheduler's %v", round, got.Outcome, want.Outcome)
		}
		if want.Outcome == socketsservice.SocketPickFound {
			if got.Primary.Candidate.ListenerClientId != want.Primary.ListenerClientId {
				return fmt.Errorf("round %d: another primary", round)
			}
			if (got.Backup == nil) != (want.Backup == nil) || (want.Backup != nil && got.Backup.Candidate.ListenerClientId != want.Backup.ListenerClientId) {
				return fmt.Errorf("round %d: another backup", round)
			}
		}
		// at most 36 s over the run, inside one lease, so every round picks among live listeners
		env.clock.Advance(time.Duration(random.IntN(300)) * time.Millisecond)
	}
	listeners, err := env.store.ListListeners(env.ctx, networkId, nameKey)
	if err != nil {
		return err
	}
	if len(listeners) != 9 {
		return fmt.Errorf("%d of 9 leases lived through the run", len(listeners))
	}
	return nil
}

// Compares one store pick with PickSocketListeners on what ListListeners shows just before it.
func (self *socketSuiteEnv) pickAgainstScheduler(request *socketsservice.SocketStorePickRequest) (*socketsservice.SocketStorePickResult, error) {
	listeners, err := self.store.ListListeners(self.ctx, request.NetworkId, request.NameKey)
	if err != nil {
		return nil, err
	}
	candidates := []*socketsservice.SocketCandidate{}
	for _, listener := range listeners {
		candidates = append(candidates, listener.Candidate)
	}
	want := socketsservice.PickSocketListeners(candidates, &socketsservice.SocketPickRequest{
		DialerClientId: request.DialerClientId,
		Protocol:       request.Protocol,
		MinVersion:     request.MinVersion,
		Alpns:          request.Alpns,
		NowMillis:      self.clock.Now().UnixMilli(),
		FirstDraw:      request.FirstDraw,
		SecondDraw:     request.SecondDraw,
	}, self.settings.Scheduler)
	got, err := self.store.Pick(self.ctx, request)
	if err != nil {
		return nil, err
	}
	if got.Outcome != want.Outcome {
		return nil, fmt.Errorf("outcome %v, the scheduler's %v", got.Outcome, want.Outcome)
	}
	if want.Outcome == socketsservice.SocketPickFound {
		if got.Primary.Candidate.ListenerClientId != want.Primary.ListenerClientId {
			return nil, errors.New("another primary")
		}
		if (got.Backup == nil) != (want.Backup == nil) || (want.Backup != nil && got.Backup.Candidate.ListenerClientId != want.Backup.ListenerClientId) {
			return nil, errors.New("another backup")
		}
	}
	return got, nil
}

func caseSocketPickMatchesSchedulerAtItsEdges(env *socketSuiteEnv) error {
	// equal loads and weights: the first sampled stays the primary
	networkId := socketSuiteId()
	tiedNameKey := socketSuiteBytes(16)
	tiedListenerIds := []connect.Id{}
	tiedRegistrations := []*sidecar.SocketRegistration{}
	for range 4 {
		registration := socketSuiteRegistration("")
		registration.NameToken = tiedNameKey
		registration.Inflight = 10
		tiedListenerIds = append(tiedListenerIds, socketSuiteId())
		tiedRegistrations = append(tiedRegistrations, registration)
	}
	random := mathrand.New(mathrand.NewPCG(3, 4))
	for round := range 24 {
		// a heartbeat a millisecond on reports anew, so no earlier issue counts and every round starts
		// tied, its leases fresh
		env.clock.Advance(time.Millisecond)
		for index, registration := range tiedRegistrations {
			if err := env.mustApplyWhole(networkId, tiedListenerIds[index], uint64(round+1), registration); err != nil {
				return err
			}
		}
		pick, err := env.pickAgainstScheduler(&socketsservice.SocketStorePickRequest{
			NetworkId:       networkId,
			NameKey:         tiedNameKey,
			DialerClientId:  socketSuiteId(),
			DialerNetworkId: networkId,
			FirstDraw:       random.Uint32(),
			SecondDraw:      random.Uint32(),
		})
		if err != nil {
			return fmt.Errorf("tied round %d: %w", round, err)
		}
		if pick.Outcome != socketsservice.SocketPickFound || pick.Backup == nil {
			return fmt.Errorf("tied round %d: %v", round, pick.Outcome)
		}
	}

	// one dialer up to and past c on a listener whose last c slots are all it has left
	clampedNameKey := socketSuiteBytes(16)
	registration := socketSuiteRegistration("")
	registration.NameToken = clampedNameKey
	clampCount := socketsservice.SocketClampCount(registration.MaxStreams, env.settings.Scheduler)
	registration.Inflight = registration.MaxStreams - clampCount - 1
	if err := env.mustApplyWhole(networkId, socketSuiteId(), 1, registration); err != nil {
		return err
	}
	dialerId := socketSuiteId()
	for round := range clampCount + 5 {
		pick, err := env.pickAgainstScheduler(&socketsservice.SocketStorePickRequest{
			NetworkId:       networkId,
			NameKey:         clampedNameKey,
			DialerClientId:  dialerId,
			DialerNetworkId: networkId,
		})
		if err != nil {
			return fmt.Errorf("clamped round %d: %w", round, err)
		}
		if pick.Outcome != socketsservice.SocketPickFound {
			return fmt.Errorf("clamped round %d: one dialer's tickets filled the listener", round)
		}
	}
	return nil
}

func caseSocketIssuedShareDecays(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	listenerId := socketSuiteId()
	registration := socketSuiteRegistration("")
	registration.Inflight = 10
	if err := env.mustApplyWhole(networkId, listenerId, 1, registration); err != nil {
		return err
	}
	scheduler := env.settings.Scheduler
	clampCount := socketsservice.SocketClampCount(registration.MaxStreams, scheduler)
	est := func() (int, error) {
		listeners, err := env.store.ListListeners(env.ctx, networkId, registration.NameKey())
		if err != nil {
			return 0, err
		}
		if len(listeners) != 1 {
			return 0, fmt.Errorf("%d listeners", len(listeners))
		}
		return socketsservice.SocketEstimate(listeners[0].Candidate, env.clock.Now().UnixMilli(), scheduler), nil
	}
	firstDialerId := socketSuiteId()
	for range clampCount + 10 {
		pick, err := env.pick(networkId, registration.NameKey(), firstDialerId, 0, 0)
		if err != nil {
			return err
		}
		if pick.Outcome != socketsservice.SocketPickFound {
			// the clamp never refuses a ticket (D-SOCK-5)
			return fmt.Errorf("a pick under the clamp: %v", pick.Outcome)
		}
	}
	if value, err := est(); err != nil || value != registration.Inflight+clampCount {
		return fmt.Errorf("one dialer's est %d, want %d: %v", value, registration.Inflight+clampCount, err)
	}
	// a second dialer adds at most c of its own
	secondDialerId := socketSuiteId()
	for range 3 {
		if _, err := env.pick(networkId, registration.NameKey(), secondDialerId, 0, 0); err != nil {
			return err
		}
	}
	if value, err := est(); err != nil || value != registration.Inflight+clampCount+3 {
		return fmt.Errorf("two dialers' est %d: %v", value, err)
	}
	// each issue counts only for a ticket's life
	env.clock.Advance(scheduler.TicketLifetime)
	if value, err := est(); err != nil || value != registration.Inflight {
		return fmt.Errorf("est after a ticket's life %d: %v", value, err)
	}
	// and a report counts nothing issued before it
	for range 5 {
		if _, err := env.pick(networkId, registration.NameKey(), firstDialerId, 0, 0); err != nil {
			return err
		}
	}
	if value, err := est(); err != nil || value != registration.Inflight+5 {
		return fmt.Errorf("est before the report %d: %v", value, err)
	}
	env.clock.Advance(time.Millisecond)
	registration.Inflight = 40
	if err := env.mustApplyWhole(networkId, listenerId, 2, registration); err != nil {
		return err
	}
	if value, err := est(); err != nil || value != registration.Inflight {
		return fmt.Errorf("est after the report %d: %v", value, err)
	}
	return nil
}

func caseSocketReportExcludes(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	nameKey := socketSuiteBytes(16)
	listenerIds := []connect.Id{}
	listenIds := []connect.Id{}
	for range 2 {
		registration := socketSuiteRegistration("")
		registration.NameToken = nameKey
		listenerId := socketSuiteId()
		if err := env.mustApplyWhole(networkId, listenerId, 1, registration); err != nil {
			return err
		}
		listenerIds = append(listenerIds, listenerId)
		listenIds = append(listenIds, *registration.ListenId)
	}
	dialerId := socketSuiteId()
	pick, err := env.store.Pick(env.ctx, &socketsservice.SocketStorePickRequest{
		NetworkId:       networkId,
		NameKey:         nameKey,
		DialerClientId:  dialerId,
		DialerNetworkId: networkId,
		Reports:         []*socketsservice.SocketStoreReport{{ListenerClientId: listenerIds[0], ListenId: listenIds[0]}},
	})
	if err != nil {
		return err
	}
	if pick.ExclusionCount != 1 || pick.EjectionCount != 0 {
		return fmt.Errorf("one report: %d exclusions, %d ejections", pick.ExclusionCount, pick.EjectionCount)
	}
	for draw := range uint32(20) {
		pick, err := env.pick(networkId, nameKey, dialerId, draw*977, draw*31)
		if err != nil {
			return err
		}
		if pick.Outcome != socketsservice.SocketPickFound || pick.Primary.Candidate.ListenerClientId != listenerIds[1] || pick.Backup != nil {
			return errors.New("the excluded listener reached its reporter")
		}
	}
	// another dialer still reaches it
	reached := false
	for draw := range uint32(20) {
		pick, err := env.pick(networkId, nameKey, socketSuiteId(), draw*977, draw*31)
		if err != nil {
			return err
		}
		reached = reached || pick.Primary.Candidate.ListenerClientId == listenerIds[0] ||
			(pick.Backup != nil && pick.Backup.Candidate.ListenerClientId == listenerIds[0])
	}
	if !reached {
		return errors.New("an exclusion reached another dialer")
	}
	// an exclusion lasts one step
	env.clock.Advance(env.settings.Scheduler.EjectionStep)
	pick, err = env.pick(networkId, nameKey, dialerId, 0, 1)
	if err != nil {
		return err
	}
	if pick.Backup == nil {
		return errors.New("an ended exclusion still held")
	}
	return nil
}

func caseSocketEjection(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	nameKey := socketSuiteBytes(16)
	listenerIds := []connect.Id{}
	listenIds := []connect.Id{}
	for range 4 {
		registration := socketSuiteRegistration("")
		registration.NameToken = nameKey
		listenerId := socketSuiteId()
		if err := env.mustApplyWhole(networkId, listenerId, 1, registration); err != nil {
			return err
		}
		listenerIds = append(listenerIds, listenerId)
		listenIds = append(listenIds, *registration.ListenId)
	}
	report := func(index int, dialerNetworkId connect.Id) (*socketsservice.SocketStorePickResult, error) {
		return env.store.Pick(env.ctx, &socketsservice.SocketStorePickRequest{
			NetworkId:       networkId,
			NameKey:         nameKey,
			DialerClientId:  socketSuiteId(),
			DialerNetworkId: dialerNetworkId,
			Reports:         []*socketsservice.SocketStoreReport{{ListenerClientId: listenerIds[index], ListenId: listenIds[index]}},
		})
	}
	firstNetworkId := socketSuiteId()
	pick, err := report(0, firstNetworkId)
	if err != nil {
		return err
	}
	if pick.EjectionCount != 0 {
		return errors.New("one network ejected")
	}
	// the same network again is still one network
	if pick, err = report(0, firstNetworkId); err != nil || pick.EjectionCount != 0 {
		return fmt.Errorf("one network twice ejected: %v", err)
	}
	env.clock.Advance(env.settings.Scheduler.ReporterWindow)
	if pick, err = report(0, socketSuiteId()); err != nil || pick.EjectionCount != 1 {
		return fmt.Errorf("a second network within the window did not eject: %v", err)
	}
	ejected := func(index int) (bool, error) {
		listeners, err := env.store.ListListeners(env.ctx, networkId, nameKey)
		if err != nil {
			return false, err
		}
		for _, listener := range listeners {
			if listener.Candidate.ListenerClientId == listenerIds[index] {
				return listener.Candidate.Ejection.Active(env.clock.Now().UnixMilli(), env.settings.Scheduler), nil
			}
		}
		return false, errors.New("the listener is gone")
	}
	if out, err := ejected(0); err != nil || !out {
		return fmt.Errorf("the listener is not ejected: %v", err)
	}
	for draw := range uint32(20) {
		pick, err := env.pick(networkId, nameKey, socketSuiteId(), draw*7919, draw*104729)
		if err != nil {
			return err
		}
		if pick.Primary.Candidate.ListenerClientId == listenerIds[0] || pick.Backup.Candidate.ListenerClientId == listenerIds[0] {
			return errors.New("an ejected listener was picked")
		}
	}
	// a second listener of four may go, a third may not
	for _, index := range []int{1, 2} {
		if _, err := report(index, socketSuiteId()); err != nil {
			return err
		}
		pick, err := report(index, socketSuiteId())
		if err != nil {
			return err
		}
		if want := index == 1; (pick.EjectionCount == 1) != want {
			return fmt.Errorf("listener %d: %d ejections", index, pick.EjectionCount)
		}
	}
	return nil
}

func caseSocketReportOldListenIgnored(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	listenerId := socketSuiteId()
	registration := socketSuiteRegistration("")
	if err := env.mustApplyWhole(networkId, listenerId, 1, registration); err != nil {
		return err
	}
	oldListenId := *registration.ListenId
	newListenId := socketSuiteId()
	registration.ListenId = &newListenId
	if err := env.mustApplyWhole(networkId, listenerId, 2, registration); err != nil {
		return err
	}
	pick, err := env.store.Pick(env.ctx, &socketsservice.SocketStorePickRequest{
		NetworkId:       networkId,
		NameKey:         registration.NameKey(),
		DialerClientId:  socketSuiteId(),
		DialerNetworkId: networkId,
		Reports:         []*socketsservice.SocketStoreReport{{ListenerClientId: listenerId, ListenId: oldListenId}},
	})
	if err != nil {
		return err
	}
	if pick.ExclusionCount != 0 || pick.Outcome != socketsservice.SocketPickFound {
		return fmt.Errorf("a report for an earlier listen: %+v", pick)
	}
	return nil
}

func caseSocketServicePairs(env *socketSuiteEnv) error {
	listenerId := socketSuiteId()
	dialerId := socketSuiteId()
	if _, found, err := env.store.GetServicePair(env.ctx, listenerId, dialerId); err != nil || found {
		return fmt.Errorf("an unset pair: %v %v", found, err)
	}
	if err := env.store.SetServicePair(env.ctx, listenerId, dialerId, 12345, time.Hour); err != nil {
		return err
	}
	if value, found, err := env.store.GetServicePair(env.ctx, listenerId, dialerId); err != nil || !found || value != 12345 {
		return fmt.Errorf("a set pair: %d %v %v", value, found, err)
	}
	if _, found, err := env.store.GetServicePair(env.ctx, listenerId, socketSuiteId()); err != nil || found {
		return fmt.Errorf("another dialer's pair: %v %v", found, err)
	}
	if err := env.store.SetServicePair(env.ctx, listenerId, dialerId, 0, time.Hour); err != nil {
		return err
	}
	if value, found, err := env.store.GetServicePair(env.ctx, listenerId, dialerId); err != nil || !found || value != 0 {
		return fmt.Errorf("a replaced pair: %d %v %v", value, found, err)
	}
	if err := env.store.SetServicePair(env.ctx, listenerId, dialerId, 1, 0); err == nil {
		return errors.New("a pair with no ttl was set")
	}
	if err := env.store.RemoveServicePairs(env.ctx, listenerId); err != nil {
		return err
	}
	if _, found, err := env.store.GetServicePair(env.ctx, listenerId, dialerId); err != nil || found {
		return fmt.Errorf("a removed pair: %v %v", found, err)
	}
	return nil
}

func caseSocketRemoveClient(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	clientId := socketSuiteId()
	shared := socketSuiteRegistration("")
	registrations := []*sidecar.SocketRegistration{socketSuiteRegistration(""), socketSuiteRegistration(socketSuiteEdgeName()), shared}
	if err := env.mustApplyWhole(networkId, clientId, 1, registrations...); err != nil {
		return err
	}
	otherShared := copySocketRegistration(shared)
	otherListenId := socketSuiteId()
	otherShared.ListenId = &otherListenId
	if err := env.mustApplyWhole(networkId, socketSuiteId(), 1, otherShared); err != nil {
		return err
	}
	if err := env.store.SetServicePair(env.ctx, clientId, socketSuiteId(), 0, time.Hour); err != nil {
		return err
	}
	removed, err := env.store.RemoveClient(env.ctx, clientId)
	if err != nil {
		return err
	}
	if len(removed) != 3 {
		return fmt.Errorf("%d removed", len(removed))
	}
	for _, entry := range removed {
		if entry.ListenerClientId != clientId || entry.NetworkId != networkId {
			return errors.New("a removal named another lease")
		}
		if want := !bytes.Equal(entry.NameKey, shared.NameKey()); entry.LastListener != want {
			return errors.New("a shared group's removal was its last")
		}
	}
	names, err := env.listAll(networkId, 10)
	if err != nil {
		return err
	}
	if len(names) != 1 || !bytes.Equal(names[0].NameToken, shared.NameToken) {
		return fmt.Errorf("%d names after a removal", len(names))
	}
	listeners, err := env.store.ListListeners(env.ctx, networkId, shared.NameKey())
	if err != nil {
		return err
	}
	if len(listeners) != 1 || listeners[0].Candidate.ListenerClientId == clientId {
		return errors.New("the removed client still listens")
	}
	removed, err = env.store.RemoveClient(env.ctx, clientId)
	if err != nil || len(removed) != 0 {
		return fmt.Errorf("a second removal: %d, %v", len(removed), err)
	}
	// its set went with it, so a new page is no one's retry
	result, err := env.applyWhole(networkId, clientId, 0, registrations[0])
	if err != nil {
		return err
	}
	if result.Stale {
		return errors.New("a removed client's set survived")
	}
	return nil
}

func caseSocketRemoveEntries(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	shared := socketSuiteRegistration("")
	firstId := socketSuiteId()
	secondId := socketSuiteId()
	if err := env.mustApplyWhole(networkId, firstId, 1, shared); err != nil {
		return err
	}
	second := copySocketRegistration(shared)
	secondListenId := socketSuiteId()
	second.ListenId = &secondListenId
	if err := env.mustApplyWhole(networkId, secondId, 1, second); err != nil {
		return err
	}
	removed, err := env.store.RemoveEntries(env.ctx, networkId, []*socketsservice.SocketStoreEntryRef{{ListenerClientId: firstId, NameKey: shared.NameKey()}})
	if err != nil {
		return err
	}
	if len(removed) != 1 || removed[0].LastListener {
		return fmt.Errorf("the first removal: %+v", removed)
	}
	removed, err = env.store.RemoveEntries(env.ctx, networkId, []*socketsservice.SocketStoreEntryRef{
		{ListenerClientId: firstId, NameKey: shared.NameKey()},
		{ListenerClientId: secondId, NameKey: shared.NameKey()},
	})
	if err != nil {
		return err
	}
	if len(removed) != 1 || !removed[0].LastListener || removed[0].ListenerClientId != secondId {
		return fmt.Errorf("the second removal: %+v", removed)
	}
	// the set forgot it, so the client's next page does not unlisten it again
	result, err := env.applyWhole(networkId, firstId, 2)
	if err != nil {
		return err
	}
	if len(result.Removed) != 0 {
		return errors.New("a removed entry stayed in its client's set")
	}
	return nil
}

func caseSocketListNamesPages(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	registrations := []*sidecar.SocketRegistration{}
	for index := range 25 {
		if index%5 == 0 {
			registrations = append(registrations, socketSuiteRegistration(socketSuiteEdgeName()))
		} else {
			registrations = append(registrations, socketSuiteRegistration(""))
		}
	}
	if err := env.mustApplyWhole(networkId, socketSuiteId(), 1, registrations...); err != nil {
		return err
	}
	for _, count := range []int{1, 7, 25, 100} {
		names, err := env.listAll(networkId, count)
		if err != nil {
			return err
		}
		if len(names) != len(registrations) {
			return fmt.Errorf("a count of %d listed %d", count, len(names))
		}
	}
	if _, _, err := env.store.ListNames(env.ctx, networkId, "", 0); err == nil {
		return errors.New("a count of zero listed")
	}
	return nil
}

func caseSocketFirstAndLastListener(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	firstId := socketSuiteId()
	secondId := socketSuiteId()
	registration := socketSuiteRegistration(socketSuiteEdgeName())
	result, err := env.applyWhole(networkId, firstId, 1, registration)
	if err != nil || !result.Outcomes[0].FirstListener {
		return fmt.Errorf("the first listener: %v", err)
	}
	second := copySocketRegistration(registration)
	secondListenId := socketSuiteId()
	second.ListenId = &secondListenId
	result, err = env.applyWhole(networkId, secondId, 1, second)
	if err != nil || result.Outcomes[0].FirstListener {
		return fmt.Errorf("the second listener: %v", err)
	}
	result, err = env.applyWhole(networkId, firstId, 2)
	if err != nil || len(result.Removed) != 1 || result.Removed[0].LastListener {
		return fmt.Errorf("the first to leave: %v", err)
	}
	result, err = env.applyWhole(networkId, secondId, 2)
	if err != nil || len(result.Removed) != 1 || !result.Removed[0].LastListener {
		return fmt.Errorf("the last to leave: %v", err)
	}
	return nil
}

func caseSocketNetworksIsolated(env *socketSuiteEnv) error {
	firstNetworkId := socketSuiteId()
	secondNetworkId := socketSuiteId()
	registration := socketSuiteRegistration(socketSuiteEdgeName())
	firstId := socketSuiteId()
	if err := env.mustApplyWhole(firstNetworkId, firstId, 1, registration); err != nil {
		return err
	}
	pick, err := env.pick(secondNetworkId, registration.NameKey(), socketSuiteId(), 0, 0)
	if err != nil {
		return err
	}
	if pick.Outcome != socketsservice.SocketPickNoListener {
		return errors.New("a name reached across networks")
	}
	exclusive := copySocketRegistration(registration)
	exclusive.Exclusive = true
	if err := env.mustApplyWhole(secondNetworkId, socketSuiteId(), 1, exclusive); err != nil {
		return fmt.Errorf("the other network's group: %w", err)
	}
	names, err := env.listAll(secondNetworkId, 10)
	if err != nil || len(names) != 1 {
		return fmt.Errorf("the other network's listing: %d, %v", len(names), err)
	}
	return nil
}

func caseSocketSampledGroupPicks(env *socketSuiteEnv) error {
	networkId := socketSuiteId()
	nameKey := socketSuiteBytes(16)
	listenerIds := map[connect.Id]bool{}
	for range env.settings.SampleCount + 6 {
		registration := socketSuiteRegistration("")
		registration.NameToken = nameKey
		listenerId := socketSuiteId()
		if err := env.mustApplyWhole(networkId, listenerId, 1, registration); err != nil {
			return err
		}
		listenerIds[listenerId] = true
	}
	for draw := range uint32(10) {
		pick, err := env.store.Pick(env.ctx, &socketsservice.SocketStorePickRequest{
			NetworkId:       networkId,
			NameKey:         nameKey,
			DialerClientId:  socketSuiteId(),
			DialerNetworkId: networkId,
			FirstDraw:       draw * 7919,
			SecondDraw:      draw * 104729,
			SampleSeed:      draw,
		})
		if err != nil {
			return err
		}
		if pick.Outcome != socketsservice.SocketPickFound || pick.Backup == nil ||
			!listenerIds[pick.Primary.Candidate.ListenerClientId] || !listenerIds[pick.Backup.Candidate.ListenerClientId] {
			return fmt.Errorf("a sampled group's pick: %+v", pick)
		}
	}
	return nil
}
