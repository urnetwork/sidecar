// POST /socket/registrations at T2, on FakeSocketStore and FakeSocketGate (SOCK-M5-05): §22.5's pages, the
// refusals the registration path's rules name, and DESIGN-DETAILS 13.6's fences, each on a fake clock with no
// sleep. A revocation lands between a page's judgment and its write through the store's hook.

package socketsservice_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/socketsservice"
)

// A listener of a new network, enrolled at gate, allowed every name, and the position its state loaded at.
func testSocketEnrolledListener(world *testSocketWorld, process *testSocketProcess) *testSocketSidecar {
	listener := world.newSidecar(testSocketId())
	process.gate.SetIdentityKey(listener.networkId, listener.sidecarId, listener.publicKey())
	process.gate.AllowListenPrefix(listener.networkId, listener.sidecarId, nil, testSocketGrant("listen"))
	process.gate.Load(listener.networkId)
	return listener
}

// The name keys the store lists for networkId, sorted.
func testSocketListedNameKeys(t *testing.T, world *testSocketWorld, networkId connect.Id) [][]byte {
	t.Helper()
	nameKeys := [][]byte{}
	cursor := ""
	for {
		names, nextCursor, err := world.fakeStore.ListNames(world.ctx, networkId, cursor, 1024)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			if name.Name != "" {
				nameKeys = append(nameKeys, []byte(name.Name))
			} else {
				nameKeys = append(nameKeys, name.NameToken)
			}
		}
		if nextCursor == "" {
			break
		}
		cursor = nextCursor
	}
	slices.SortFunc(nameKeys, bytes.Compare)
	return nameKeys
}

// §22.5: a 3,000-name set goes as three pages under one set_version, none refused for its size, and a later
// round's page unlistens only the names in its own range.
func TestSocketRegistrationsPageAThreeThousandNameSet(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := testSocketEnrolledListener(world, process)

	registrations := []*sidecar.SocketRegistration{}
	for range 3000 {
		registrations = append(registrations, listener.blindedRegistration(t, testSocketTokenPath(t, 2)))
	}
	registrations = testSocketSortRegistrations(registrations)
	bounds := [][]byte{nil, registrations[1000].NameKey(), registrations[2000].NameKey(), nil}
	pageOf := func(index int, page []*sidecar.SocketRegistration, setVersion uint64) *sidecar.SocketRegistrationsArgs {
		return &sidecar.SocketRegistrationsArgs{SetVersion: setVersion, KeyStart: bounds[index], KeyEnd: bounds[index+1], Registrations: page}
	}
	for index := range 3 {
		code, result := process.register(listener.token, pageOf(index, registrations[index*1000:(index+1)*1000], 10))
		if code != http.StatusOK || result.Error != nil || len(result.Statuses) != 1000 {
			t.Fatalf("page %d answered %d, %+v", index, code, result.Error)
		}
		for entryIndex, status := range result.Statuses {
			if status != sidecar.SocketRegistrationStatusOk {
				t.Fatalf("page %d entry %d answered %s", index, entryIndex, status)
			}
		}
	}
	if listed := testSocketListedNameKeys(t, world, listener.networkId); len(listed) != 3000 {
		t.Fatalf("%d names listed", len(listed))
	}

	// the next round's middle page drops one name of its range, which alone unlistens
	dropped := registrations[1500]
	middle := slices.Concat(registrations[1000:1500], registrations[1501:2000])
	code, result := process.register(listener.token, pageOf(1, middle, 11))
	if code != http.StatusOK || result.Error != nil {
		t.Fatalf("answered %d, %+v", code, result)
	}
	listed := testSocketListedNameKeys(t, world, listener.networkId)
	if len(listed) != 2999 {
		t.Fatalf("%d names listed after the unlisten", len(listed))
	}
	if slices.ContainsFunc(listed, func(nameKey []byte) bool { return bytes.Equal(nameKey, dropped.NameKey()) }) {
		t.Fatal("the dropped name still listens")
	}
	// the first and last pages' names were outside the range, so none moved
	for _, registration := range slices.Concat(registrations[:1000], registrations[2000:]) {
		listeners, err := world.fakeStore.ListListeners(world.ctx, listener.networkId, registration.NameKey())
		if err != nil || len(listeners) != 1 {
			t.Fatalf("a name outside the page's range lost its lease: %d, %v", len(listeners), err)
		}
	}
}

// A page with an entry outside its range, out of order, past its size, or naming both a name and a token
// path is refused whole as invalid and writes nothing; an older set_version is refused as stale with the
// stored one.
func TestSocketRegistrationsRefuseAMalformedOrOlderPage(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := testSocketEnrolledListener(world, process)
	first := listener.blindedRegistration(t, testSocketTokenPath(t, 1))
	second := listener.blindedRegistration(t, testSocketTokenPath(t, 1))
	sorted := testSocketSortRegistrations([]*sidecar.SocketRegistration{first, second})

	both := listener.edgeRegistration(t, "tls/443/blog", "tls", "")
	both.NameToken = testSocketTokenPath(t, 1)
	tooMany := []*sidecar.SocketRegistration{}
	for range 1025 {
		tooMany = append(tooMany, listener.blindedRegistration(t, testSocketTokenPath(t, 1)))
	}
	shortSeal := listener.blindedRegistration(t, testSocketTokenPath(t, 1))
	shortSeal.SealedName = shortSeal.SealedName[:151]
	for index, args := range []*sidecar.SocketRegistrationsArgs{
		{SetVersion: 5, KeyEnd: sorted[0].NameKey(), Registrations: sorted},
		{SetVersion: 5, Registrations: []*sidecar.SocketRegistration{sorted[1], sorted[0]}},
		{SetVersion: 5, Registrations: testSocketSortRegistrations(tooMany)},
		{SetVersion: 5, Registrations: []*sidecar.SocketRegistration{both}},
		{SetVersion: 5, Registrations: []*sidecar.SocketRegistration{shortSeal}},
		{SetVersion: 5, KeyStart: []byte("b"), KeyEnd: []byte("a")},
	} {
		code, result := process.register(listener.token, args)
		if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeInvalid || len(result.Statuses) != 0 {
			t.Errorf("page %d answered %d, %+v", index, code, result)
		}
	}
	if count := world.fakeStore.OpCount("ApplyPage"); count != 0 {
		t.Fatalf("%d pages reached the store", count)
	}

	process.registerOk(listener, 7, first, second)
	code, result := process.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: 6, Registrations: sorted})
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeStale || result.SetVersion != 7 {
		t.Fatalf("an older page answered %d, %+v", code, result)
	}
}

// §22.5: after a store wipe, one interval of the client's pages rebuilds its set.
func TestSocketRegistrationsRebuildAfterAStoreWipe(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := testSocketEnrolledListener(world, process)
	registrations := []*sidecar.SocketRegistration{}
	for range 20 {
		registrations = append(registrations, listener.blindedRegistration(t, testSocketTokenPath(t, 3)))
	}
	process.registerOk(listener, 1, registrations...)
	world.fakeStore.Wipe()
	if listed := testSocketListedNameKeys(t, world, listener.networkId); len(listed) != 0 {
		t.Fatalf("%d names survived the wipe", len(listed))
	}
	world.clock.Advance(15 * time.Second)
	process.registerOk(listener, 2, registrations...)
	if listed := testSocketListedNameKeys(t, world, listener.networkId); len(listed) != 20 {
		t.Fatalf("%d names after one interval", len(listed))
	}
	// the gauge counts the newest page of each client range, so a heartbeat does not count its leases twice
	if leases := process.host.Metrics.Value("urnetwork_sockets_registrations"); leases != 20 {
		t.Fatalf("the registrations gauge reads %v", leases)
	}
	process.registerOk(listener, 3, registrations[:5]...)
	if leases := process.host.Metrics.Value("urnetwork_sockets_registrations"); leases != 5 {
		t.Fatalf("after a smaller page the gauge reads %v", leases)
	}
	world.clock.Advance(45 * time.Second)
	other := testSocketEnrolledListener(world, process)
	process.registerOk(other, 1, other.blindedRegistration(t, testSocketTokenPath(t, 1)))
	if leases := process.host.Metrics.Value("urnetwork_sockets_registrations"); leases != 1 {
		t.Fatalf("past the lease the gauge reads %v", leases)
	}
}

// §22.5: a client looping registrations is shed with unavailable once its burst is spent, and its next token
// comes at the bucket's rate.
func TestSocketRegistrationsShedALoopingClient(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := testSocketEnrolledListener(world, process)
	registration := listener.blindedRegistration(t, testSocketTokenPath(t, 1))
	args := &sidecar.SocketRegistrationsArgs{SetVersion: 1, Registrations: []*sidecar.SocketRegistration{registration}}
	for index := range 500 {
		if code, result := process.register(listener.token, args); code != http.StatusOK || result.Error != nil {
			t.Fatalf("call %d of the burst answered %d, %+v", index, code, result)
		}
	}
	code, result := process.register(listener.token, args)
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeUnavailable || result.Error.RetryAfterMs != 20 {
		t.Fatalf("a call past the burst answered %d, %+v", code, result)
	}
	applied := world.fakeStore.OpCount("ApplyPage")
	world.clock.Advance(20 * time.Millisecond)
	if code, result := process.register(listener.token, args); code != http.StatusOK || result.Error != nil {
		t.Fatalf("the next token's call answered %d, %+v", code, result)
	}
	if world.fakeStore.OpCount("ApplyPage") != applied+1 {
		t.Fatal("a shed call reached the store")
	}
}

// D-SOCK-13: a name outside tls/, smtp/ and ur/ in the clear is refused, as invalid, and never reaches the
// store; nor does a name in the clear that is not canonical.
func TestSocketRegistrationsRefuseAPlaintextApplicationName(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := testSocketEnrolledListener(world, process)
	for _, name := range []string{"db/primary", "share/aaaaaaaaaaaaaaaaaaaaaaaaaa", "sys/x", "TLS/443/blog"} {
		registration := listener.edgeRegistration(t, name, "tcp", "")
		code, result := process.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: 1, Registrations: []*sidecar.SocketRegistration{registration}})
		if code != http.StatusOK || result.Error != nil || len(result.Statuses) != 1 || result.Statuses[0] != sidecar.SocketRegistrationStatusInvalid {
			t.Errorf("%q answered %d, %+v", name, code, result)
		}
		if listeners, _ := world.fakeStore.ListListeners(world.ctx, listener.networkId, []byte(name)); len(listeners) != 0 {
			t.Errorf("%q holds a lease", name)
		}
	}
}

// A forged claim, one over another listen, another name or another network, and one of another sidecar are
// each refused; the sidecar's own claim over the entry passes.
func TestSocketRegistrationsRefuseAForgedOrMismatchedClaim(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := testSocketEnrolledListener(world, process)
	other := world.newSidecar(listener.networkId)
	nameToken := testSocketTokenPath(t, 2)

	forged := listener.blindedRegistration(t, nameToken)
	forged.Claim = bytes.Clone(forged.Claim)
	forged.Claim[len(forged.Claim)-3] ^= 0x01
	otherListen := listener.blindedRegistration(t, nameToken)
	otherListen.Claim = listener.blindedRegistration(t, nameToken).Claim
	otherName := listener.blindedRegistration(t, nameToken)
	otherName.Claim = listener.blindedRegistration(t, testSocketTokenPath(t, 2)).Claim
	otherSidecar := other.blindedRegistration(t, nameToken)
	none := listener.blindedRegistration(t, nameToken)
	none.Claim = nil
	for index, registration := range []*sidecar.SocketRegistration{forged, otherListen, otherName, otherSidecar, none} {
		code, result := process.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: uint64(index + 1), Registrations: []*sidecar.SocketRegistration{registration}})
		if code != http.StatusOK || result.Error != nil || result.Statuses[0] != sidecar.SocketRegistrationStatusDenied {
			t.Errorf("claim %d answered %d, %+v", index, code, result)
		}
	}
	process.registerOk(listener, 10, listener.blindedRegistration(t, nameToken))
}

// A heartbeat checks no claim it checked before: the memo holds what passed for the same client, bytes and key.
func TestSocketRegistrationsRememberAClaim(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := testSocketEnrolledListener(world, process)
	registrations := []*sidecar.SocketRegistration{}
	for range 30 {
		registrations = append(registrations, listener.blindedRegistration(t, testSocketTokenPath(t, 1)))
	}
	process.registerOk(listener, 1, registrations...)
	if count := process.service.ClaimVerifyCount(); count != 30 {
		t.Fatalf("the first page checked %d claims", count)
	}
	process.registerOk(listener, 2, registrations...)
	if count := process.service.ClaimVerifyCount(); count != 30 {
		t.Fatalf("the heartbeat checked %d more claims", count-30)
	}
	// a new identity key is a new memo key, so the old claims are checked again under it, and refused
	newKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	process.gate.SetIdentityKey(listener.networkId, listener.sidecarId, newKey)
	process.gate.Load(listener.networkId)
	code, result := process.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: 3, Registrations: testSocketSortRegistrations(registrations)})
	if code != http.StatusOK || result.Error != nil || result.Statuses[0] != sidecar.SocketRegistrationStatusRevoked {
		t.Fatalf("claims under a rotated key answered %d, %+v", code, result)
	}
}

// revoked once a grant the entry held is gone at the page's position: the lease ends for cause.
func TestSocketRegistrationsAnswerRevokedOnADroppedGrant(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := world.newSidecar(testSocketId())
	nameToken := testSocketTokenPath(t, 2)
	process.gate.SetIdentityKey(listener.networkId, listener.sidecarId, listener.publicKey())
	process.gate.AllowListen(listener.networkId, listener.sidecarId, nameToken, testSocketGrant("a"))
	process.gate.Load(listener.networkId)
	registration := listener.blindedRegistration(t, nameToken)
	process.registerOk(listener, 1, registration)

	process.gate.RevokeListen(listener.networkId, listener.sidecarId, nameToken)
	position := process.gate.Load(listener.networkId)
	code, result := process.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: 2, Registrations: []*sidecar.SocketRegistration{registration}})
	if code != http.StatusOK || result.Error != nil || result.Statuses[0] != sidecar.SocketRegistrationStatusRevoked {
		t.Fatalf("answered %d, %+v", code, result)
	}
	if listeners, _ := world.fakeStore.ListListeners(world.ctx, listener.networkId, nameToken); len(listeners) != 0 {
		t.Fatal("the revoked entry still holds its lease")
	}
	// the removal's tombstone fences a put admitted below its position (13.3's S2)
	stale := world.newProcess(nil)
	stale.gate.SetIdentityKey(listener.networkId, listener.sidecarId, listener.publicKey())
	stale.gate.AllowListen(listener.networkId, listener.sidecarId, nameToken, testSocketGrant("a"))
	stale.gate.LoadAt(listener.networkId, position-1)
	code, result = stale.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: 3, Registrations: []*sidecar.SocketRegistration{registration}})
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeUnavailable || result.Error.RetryAfterMs != 1000 {
		t.Fatalf("a stale process's put answered %d, %+v", code, result)
	}
	if observed := stale.gate.Observed(listener.networkId); !slices.Contains(observed, position) {
		t.Fatalf("the fence was not handed to the gate: %v", observed)
	}
}

// exclusive holds the group against every later registration, and lets go once its lease lapses (§9.5).
func TestSocketRegistrationsHoldExclusiveUntilItsLeaseLapses(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	holder := testSocketEnrolledListener(world, process)
	other := world.newSidecar(holder.networkId)
	process.gate.SetIdentityKey(holder.networkId, other.sidecarId, other.publicKey())
	process.gate.AllowListenPrefix(holder.networkId, other.sidecarId, nil, testSocketGrant("other"))
	process.gate.Load(holder.networkId)
	nameToken := testSocketTokenPath(t, 1)

	exclusive := holder.blindedRegistration(t, nameToken)
	exclusive.Exclusive = true
	process.registerOk(holder, 1, exclusive)
	args := &sidecar.SocketRegistrationsArgs{SetVersion: 1, Registrations: []*sidecar.SocketRegistration{other.blindedRegistration(t, nameToken)}}
	if code, result := process.register(other.token, args); code != http.StatusOK || result.Statuses[0] != sidecar.SocketRegistrationStatusTaken {
		t.Fatalf("a second listener answered %d, %+v", code, result)
	}
	world.clock.Advance(45 * time.Second)
	args.SetVersion = 2
	if code, result := process.register(other.token, args); code != http.StatusOK || result.Statuses[0] != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("after the lease lapsed the second listener answered %d, %+v", code, result)
	}
}

// DESIGN-DETAILS 13.6: a put stalled across a revocation and its sweep is fenced, answers unavailable and hands
// the gate the sweep's position; the retry, judged where the revocation is loaded, is refused.
func TestSocketRegistrationsFenceAPutStalledAcrossARevocation(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := world.newSidecar(testSocketId())
	nameToken := testSocketTokenPath(t, 2)
	process.gate.SetIdentityKey(listener.networkId, listener.sidecarId, listener.publicKey())
	process.gate.AllowListen(listener.networkId, listener.sidecarId, nameToken, testSocketGrant("a"))
	position := process.gate.Load(listener.networkId)
	registration := listener.blindedRegistration(t, nameToken)
	process.registerOk(listener, 1, registration)

	// the next heartbeat is judged at position and held before its write, while the revocation lands and
	// another process's sweep removes the lease for cause one position on
	entered := make(chan struct{})
	release := make(chan struct{})
	world.store.beforeApplyPage = func(page *socketsservice.SocketStorePage) {
		world.store.beforeApplyPage = nil
		close(entered)
		<-release
	}
	type answer struct {
		code   int
		result *sidecar.SocketRegistrationsResult
	}
	answers := make(chan answer, 1)
	go func() {
		code, result := process.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: 2, Registrations: []*sidecar.SocketRegistration{registration}})
		answers <- answer{code: code, result: result}
	}()
	<-entered
	removals, err := world.fakeStore.RemoveEntries(world.ctx, listener.networkId, socketsservice.SocketRemoveRefused, position+1,
		[]*socketsservice.SocketStoreEntryRef{{ListenerClientId: listener.clientId, NameKey: nameToken}})
	if err != nil || len(removals) != 1 || removals[0].Removed == nil {
		t.Fatalf("the sweep's removal: %v, %v", removals, err)
	}
	close(release)
	stalled := <-answers
	if stalled.code != http.StatusOK || stalled.result.Error == nil || stalled.result.Error.Code != sidecar.SocketErrorCodeUnavailable {
		t.Fatalf("the stalled put answered %d, %+v", stalled.code, stalled.result)
	}
	if listeners, _ := world.fakeStore.ListListeners(world.ctx, listener.networkId, nameToken); len(listeners) != 0 {
		t.Fatal("the stalled put wrote the lease back")
	}
	if observed := process.gate.Observed(listener.networkId); !slices.Contains(observed, position+1) {
		t.Fatalf("the fence was not handed to the gate: %v", observed)
	}

	// once the process holds the revocation, the retry is refused
	process.gate.RevokeListen(listener.networkId, listener.sidecarId, nameToken)
	process.gate.LoadAt(listener.networkId, position+1)
	code, result := process.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: 3, Registrations: []*sidecar.SocketRegistration{registration}})
	if code != http.StatusOK || result.Error != nil || result.Statuses[0] != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("the retry answered %d, %+v", code, result)
	}
}

// DESIGN-DETAILS 13.6 (TestOlderPageIsStale's engine half): an older page that lands after a newer page
// unlistened its entry is refused as stale, and writes the lease back nowhere.
func TestSocketRegistrationsOlderPageAfterAnUnlistenIsStale(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := testSocketEnrolledListener(world, process)
	registration := listener.blindedRegistration(t, testSocketTokenPath(t, 1))
	process.registerOk(listener, 1, registration)
	process.registerOk(listener, 2)
	code, result := process.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: 1, Registrations: []*sidecar.SocketRegistration{registration}})
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeStale || result.SetVersion != 2 {
		t.Fatalf("the older page answered %d, %+v", code, result)
	}
	if listeners, _ := world.fakeStore.ListListeners(world.ctx, listener.networkId, registration.NameKey()); len(listeners) != 0 {
		t.Fatal("the older page wrote the lease back")
	}

	// with the client's set gone, the unlisten's own fence refuses the older put
	process.registerOk(listener, 3, registration)
	process.registerOk(listener, 4)
	if err := world.fakeStore.LapseClientSet(world.ctx, listener.clientId); err != nil {
		t.Fatal(err)
	}
	code, result = process.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: 3, Registrations: []*sidecar.SocketRegistration{registration}})
	if code != http.StatusOK || result.Error == nil {
		t.Fatalf("an older put past its set answered %d, %+v", code, result)
	}
	if listeners, _ := world.fakeStore.ListListeners(world.ctx, listener.networkId, registration.NameKey()); len(listeners) != 0 {
		t.Fatal("the older put wrote the lease back past the unlisten's fence")
	}
}

// DESIGN-DETAILS 13.6: a refused entry that never held a lease leaves no tombstone, so a process whose state
// still allows it registers it.
func TestSocketRegistrationsRefusedEntryWithNoLeaseLeavesNoTombstone(t *testing.T) {
	world := newTestSocketWorld(t)
	fresh := world.newProcess(nil)
	stale := world.newProcess(nil)
	listener := world.newSidecar(testSocketId())
	nameToken := testSocketTokenPath(t, 2)
	for _, process := range []*testSocketProcess{fresh, stale} {
		process.gate.SetIdentityKey(listener.networkId, listener.sidecarId, listener.publicKey())
	}
	stale.gate.AllowListen(listener.networkId, listener.sidecarId, nameToken, testSocketGrant("a"))
	stale.gate.LoadAt(listener.networkId, 4)
	fresh.gate.LoadAt(listener.networkId, 5)

	registration := listener.blindedRegistration(t, nameToken)
	code, result := fresh.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: 1, Registrations: []*sidecar.SocketRegistration{registration}})
	if code != http.StatusOK || result.Error != nil || result.Statuses[0] != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("the fresh process answered %d, %+v", code, result)
	}
	stale.registerOk(listener, 2, registration)
}

// DESIGN-DETAILS 13.6: a page for a network the gate is behind on, past its grace, is unavailable and writes
// nothing; within the grace it serves.
func TestSocketRegistrationsUnavailableWhileBehind(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := testSocketEnrolledListener(world, process)
	registration := listener.blindedRegistration(t, testSocketTokenPath(t, 1))
	process.gate.NoteEvidence(listener.networkId, 9)
	process.registerOk(listener, 1, registration)
	applied := world.fakeStore.OpCount("ApplyPage")

	world.clock.Advance(process.gate.BehindGrace)
	code, result := process.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: 2, Registrations: []*sidecar.SocketRegistration{registration}})
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeUnavailable || result.Error.RetryAfterMs != 250 {
		t.Fatalf("a page past the grace answered %d, %+v", code, result)
	}
	if world.fakeStore.OpCount("ApplyPage") != applied {
		t.Fatal("a page past the grace reached the store")
	}
	// another network at the same process serves on
	other := testSocketEnrolledListener(world, process)
	process.registerOk(other, 1, other.blindedRegistration(t, testSocketTokenPath(t, 1)))
	// a load covering the evidence makes the network fresh again
	process.gate.LoadAt(listener.networkId, 9)
	process.registerOk(listener, 3, registration)

	// a network the gate never loaded is unavailable too
	unloaded := world.newSidecar(testSocketId())
	code, result = process.register(unloaded.token, &sidecar.SocketRegistrationsArgs{SetVersion: 1, Registrations: []*sidecar.SocketRegistration{unloaded.blindedRegistration(t, testSocketTokenPath(t, 1))}})
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeUnavailable {
		t.Fatalf("an unloaded network answered %d, %+v", code, result)
	}
}

// One view a page: however many entries, the gate's state is read once (13.2.3's step 4).
func TestSocketRegistrationsTakeOneViewAPage(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := testSocketEnrolledListener(world, process)
	registrations := []*sidecar.SocketRegistration{}
	for range 50 {
		registrations = append(registrations, listener.blindedRegistration(t, testSocketTokenPath(t, 1)))
	}
	before := process.gate.ViewCount(listener.networkId)
	process.registerOk(listener, 1, registrations...)
	if count := process.gate.ViewCount(listener.networkId) - before; count != 1 {
		t.Fatalf("a page took %d views", count)
	}
}

// Hooks that record what they were asked and answer what a test sets.
type testSocketRecordingHooks struct {
	validateErr   error
	validateCount int
	firstListens  []string
	lastUnlistens []string
}

func (self *testSocketRecordingHooks) ValidateListen(ctx context.Context, check *socketsservice.SocketListenCheck) error {
	self.validateCount += 1
	return self.validateErr
}

func (self *testSocketRecordingHooks) FirstListen(networkId connect.Id, name string) {
	self.firstListens = append(self.firstListens, name)
}

func (self *testSocketRecordingHooks) LastUnlisten(networkId connect.Id, name string) {
	self.lastUnlistens = append(self.lastUnlistens, name)
}

// An edge namespace nobody registered refuses its names; a registered one's ValidateListen decides, an
// undecided one making the page unavailable; FirstListen and LastUnlisten follow the transitions.
func TestSocketRegistrationsFollowTheNamespaceHooks(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := testSocketEnrolledListener(world, process)
	registration := listener.edgeRegistration(t, "tls/443/blog", "tls", "http")
	args := &sidecar.SocketRegistrationsArgs{SetVersion: 1, Registrations: []*sidecar.SocketRegistration{registration}}
	if code, result := process.register(listener.token, args); code != http.StatusOK || result.Statuses[0] != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("tls/ with no hooks answered %d, %+v", code, result)
	}

	hooks := &testSocketRecordingHooks{}
	if err := process.service.RegisterNamespace(sidecar.SocketNamespaceTls, hooks); err != nil {
		t.Fatal(err)
	}
	for _, refusal := range []struct {
		err    error
		status sidecar.SocketRegistrationStatus
		code   sidecar.SocketErrorCode
	}{
		{err: socketsservice.ErrSocketListenRefused, status: sidecar.SocketRegistrationStatusDenied},
		{err: socketsservice.ErrSocketListenUnavailable, code: sidecar.SocketErrorCodeUnavailable},
		{err: errors.New("anything else"), code: sidecar.SocketErrorCodeUnavailable},
	} {
		hooks.validateErr = refusal.err
		args.SetVersion += 1
		code, result := process.register(listener.token, args)
		switch {
		case code != http.StatusOK:
			t.Fatalf("answered %d", code)
		case refusal.code != "" && (result.Error == nil || result.Error.Code != refusal.code):
			t.Errorf("%v answered %+v", refusal.err, result)
		case refusal.code == "" && (result.Error != nil || result.Statuses[0] != refusal.status):
			t.Errorf("%v answered %+v", refusal.err, result)
		}
	}
	hooks.validateErr = nil
	process.registerOk(listener, 10, registration)
	process.registerOk(listener, 11, registration)
	process.registerOk(listener, 12)
	if !slices.Equal(hooks.firstListens, []string{"tls/443/blog"}) || !slices.Equal(hooks.lastUnlistens, []string{"tls/443/blog"}) {
		t.Fatalf("transitions %v, %v", hooks.firstListens, hooks.lastUnlistens)
	}
}

// QD-656: an accepted tls/ entry renews its client's pairs, at most once an interval; once the client's last
// tls/ entry leaves, its pairs go and a floor at the page's position refuses an older write.
func TestSocketRegistrationsKeepTheEdgePairs(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	if err := process.service.RegisterNamespace(sidecar.SocketNamespaceTls, &testSocketRecordingHooks{}); err != nil {
		t.Fatal(err)
	}
	listener := testSocketEnrolledListener(world, process)
	registration := listener.edgeRegistration(t, "tls/443/blog", "tls", "http")
	dialerClientId := testSocketId()
	if wrote, _, err := world.fakeStore.SetServicePair(world.ctx, listener.clientId, dialerClientId, 0, 15*time.Minute, 1); err != nil || !wrote {
		t.Fatalf("pair: %v, %v", wrote, err)
	}
	process.registerOk(listener, 1, registration)
	process.registerOk(listener, 2, registration)
	if count := world.fakeStore.OpCount("TouchServicePairs"); count != 1 {
		t.Fatalf("%d touches within one interval", count)
	}
	world.clock.Advance(5 * time.Minute)
	process.registerOk(listener, 3, registration)
	if count := world.fakeStore.OpCount("TouchServicePairs"); count != 2 {
		t.Fatalf("%d touches after an interval", count)
	}
	if _, found, _ := world.fakeStore.GetServicePair(world.ctx, listener.clientId, dialerClientId); !found {
		t.Fatal("the touched pair is gone")
	}

	position := uint64(1)
	process.registerOk(listener, 4)
	if _, found, _ := world.fakeStore.GetServicePair(world.ctx, listener.clientId, dialerClientId); found {
		t.Fatal("the pair outlived the client's last edge entry")
	}
	if wrote, floor, err := world.fakeStore.SetServicePair(world.ctx, listener.clientId, dialerClientId, 0, time.Minute, position-1); err != nil || wrote || floor != position {
		t.Fatalf("a write below the floor: %v, %d, %v", wrote, floor, err)
	}
}

// Who may register: a token with no sidecar outside urnetwork-edge is denied, a removed client and a refused
// token answer 401, §19.11's closed sockets gate answers 503 with Retry-After, and an unavailable authenticator
// answers unavailable.
func TestSocketRegistrationsRefuseWhoMayNot(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := testSocketEnrolledListener(world, process)
	args := &sidecar.SocketRegistrationsArgs{SetVersion: 1, Registrations: []*sidecar.SocketRegistration{listener.blindedRegistration(t, testSocketTokenPath(t, 1))}}

	noSidecar := world.authenticator.Issue(&sidecar.Principal{
		NetworkId: listener.networkId, ClientId: testSocketId(), Audience: socketsservice.SocketsAudience,
		IssuedAt: world.clock.Now(), ExpiresAt: world.clock.Now().Add(time.Hour),
	})
	if code, result := process.register(noSidecar, args); code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeDenied {
		t.Errorf("no sidecar answered %d, %+v", code, result)
	}
	otherAudience := world.authenticator.Issue(&sidecar.Principal{
		NetworkId: listener.networkId, ClientId: listener.clientId, SidecarId: &listener.sidecarId, Audience: "evs",
		IssuedAt: world.clock.Now(), ExpiresAt: world.clock.Now().Add(time.Hour),
	})
	for _, token := range []string{"", "not-a-token", otherAudience} {
		if code, _ := process.register(token, args); code != http.StatusUnauthorized {
			t.Errorf("a refused token answered %d", code)
		}
	}

	closed := world.newProcess(nil)
	if err := closed.host.Gates.Set("sidecar:\n  sockets: {enabled: false}\n"); err != nil {
		t.Fatal(err)
	}
	recorder := closed.call(http.MethodPost, "/socket/registrations", listener.token, args)
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") != "60" {
		t.Errorf("a closed gate answered %d, Retry-After %q", recorder.Code, recorder.Header().Get("Retry-After"))
	}

	if _, err := world.authFaults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "authenticator.Authenticate", Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	if code, result := process.register(listener.token, args); code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeUnavailable {
		t.Errorf("an unavailable authenticator answered %d, %+v", code, result)
	}

	process.service.NoteClientRemovedForTest(listener.clientId)
	if code, _ := process.register(listener.token, args); code != http.StatusUnauthorized {
		t.Errorf("a removed client answered %d", code)
	}
	world.clock.Advance(10 * time.Minute)
	if code, result := process.register(listener.token, args); code != http.StatusOK || result.Error != nil {
		t.Errorf("past the removed-client set's ttl the client answered %d, %+v", code, result)
	}
}

// §13.9's kill switch refuses a tls/ name it names, or every host of the network with *.
func TestSocketRegistrationsRefuseAKilledName(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	if err := process.service.RegisterNamespace(sidecar.SocketNamespaceTls, &testSocketRecordingHooks{}); err != nil {
		t.Fatal(err)
	}
	listener := testSocketEnrolledListener(world, process)
	blog := listener.edgeRegistration(t, "tls/443/blog", "tls", "http")
	shop := listener.edgeRegistration(t, "tls/443/shop", "tls", "http")
	process.service.SetKillsForTest(listener.networkId, []*sidecar.TlsKillEntry{{Host: "blog", Reason: "phishing"}})
	code, result := process.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: 1, Registrations: testSocketSortRegistrations([]*sidecar.SocketRegistration{blog, shop})})
	if code != http.StatusOK || result.Error != nil {
		t.Fatalf("answered %d, %+v", code, result)
	}
	if result.Statuses[0] != sidecar.SocketRegistrationStatusDenied || result.Statuses[1] != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("statuses %v", result.Statuses)
	}
	process.service.SetKillsForTest(listener.networkId, []*sidecar.TlsKillEntry{{Host: sidecar.TlsKillAllHosts, Reason: "takedown"}})
	code, result = process.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: 2, Registrations: []*sidecar.SocketRegistration{shop}})
	if code != http.StatusOK || result.Statuses[0] != sidecar.SocketRegistrationStatusRevoked {
		t.Fatalf("a network-wide kill answered %d, %+v", code, result)
	}
}

// The answer's fixed part: the stored set_version, the service's clock, the ticket keys, the urnetwork-edge
// network and whether §20 has stopped the network's new streams.
func TestSocketRegistrationsAnswerWhatAdmissionNeeds(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := testSocketEnrolledListener(world, process)
	process.gate.SetSpent(listener.networkId, true)
	code, result := process.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: 42, Registrations: []*sidecar.SocketRegistration{listener.blindedRegistration(t, testSocketTokenPath(t, 1))}})
	if code != http.StatusOK || result.Error != nil {
		t.Fatalf("answered %d, %+v", code, result)
	}
	switch {
	case result.SetVersion != 42:
		t.Errorf("set_version %d", result.SetVersion)
	case result.ServerTimeMillis != uint64(world.clock.Now().UnixMilli()):
		t.Errorf("server_time %d", result.ServerTimeMillis)
	case len(result.TicketKeys) != 1 || result.TicketKeys[0].KeyId != "k1":
		t.Errorf("ticket keys %+v", result.TicketKeys)
	case result.UrnetworkEdge == nil || *result.UrnetworkEdge != world.edgeNetworkId:
		t.Errorf("urnetwork_edge %v", result.UrnetworkEdge)
	case !result.StreamsStopped:
		t.Error("a spent network's streams are not stopped")
	}
}
