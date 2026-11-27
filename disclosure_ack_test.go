//go:build !ios_extension && !sidecar_http && !js

// The person's acknowledgment of a disclosure (CTRUST-M12-01) on the harness config store's test vault and authority
// (models_member_config_test.go) and the fixture policy: only the person's act records, at the version shown; the key
// keeps what it does not know and only rises; an acknowledgment covers every locale; Await ends only when the key holds
// the version, synced from another device included, never at a ui_response; and the changed marks.

package sidecar

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// The fixture policy's registry, the member's phone reading its harness config, the acknowledgments, the marks in a
// memory store and the check, on a clock the test moves.
type testDisclosureAckWorld struct {
	config   *testMemberConfigWorld
	source   *testDisclosureSource
	registry *ComputeDisclosureRegistry
	clock    *harnessTestClock
	acks     *ComputeDisclosureAcks
	marks    *computeDisclosureMarks
	check    *ComputeDisclosureCheck
}

func newTestDisclosureAckWorld(t *testing.T) *testDisclosureAckWorld {
	t.Helper()
	world := &testDisclosureAckWorld{
		config: newTestMemberConfigWorld(t),
		source: &testDisclosureSource{policy: testDisclosurePolicy(t)},
		clock:  newHarnessTestClock(),
	}
	world.registry = newTestDisclosureRegistry(t, world.source)
	world.acks = world.acksOf(t, world.config.store)
	store := newTestMemoryStore()
	world.marks = &computeDisclosureMarks{
		store:    func() (SidecarStore, error) { return store, nil },
		settings: world.registry.Settings(),
	}
	check, err := NewComputeDisclosureCheck(&ComputeDisclosureCheckArgs{
		Registry: world.registry, Acks: world.acks, marks: world.marks, Now: world.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	world.check = check
	return world
}

// Acknowledgments over store, the world's registry and clock.
func (self *testDisclosureAckWorld) acksOf(t *testing.T, store *MemberHarnessConfig) *ComputeDisclosureAcks {
	t.Helper()
	acks, err := NewComputeDisclosureAcks(&ComputeDisclosureAcksArgs{
		Store:    func() (*MemberHarnessConfig, error) { return store, nil },
		Registry: self.registry,
		Clock:    self.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return acks
}

// The person's confirmed act on the phone, for id at version.
func testDisclosureConfirmed(id string, version uint32) *ComputeDisclosureAckArgs {
	return &ComputeDisclosureAckArgs{Id: id, Version: version, Origin: SidecarActConfirmed}
}

// The newest version of the vault's file, empty for none.
func (self *testDisclosureAckWorld) file() string {
	versions := self.config.vault.versions
	if len(versions) == 0 {
		return ""
	}
	return string(versions[len(versions)-1].data)
}

// Refused: an MCP origin, a hook, an unconfirmed control call, a harness ancestor and a read-only device, none writing
// anything; the person's confirmed act on the phone lands as compute.disclosures' value.
func TestDisclosureAckOnlyByPerson(t *testing.T) {
	world := newTestDisclosureAckWorld(t)
	for name, args := range map[string]*ComputeDisclosureAckArgs{
		"an MCP origin":          {Id: "inference:engy", Version: 1, Origin: SidecarActMcp},
		"a hook":                 {Id: "inference:engy", Version: 1, Origin: SidecarActHook},
		"an unconfirmed call":    {Id: "inference:engy", Version: 1, Origin: SidecarActUnconfirmed},
		"no origin":              {Id: "inference:engy", Version: 1},
		"a harness ancestor":     {Id: "inference:engy", Version: 1, Origin: SidecarActConfirmed, HarnessAncestor: true},
		"no arguments, no actor": nil,
	} {
		if err := world.acks.Ack(t.Context(), args); !errors.Is(err, ErrDisclosureAckRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a device that is not approval-capable, though its person confirmed
	readOnly := world.acksOf(t, world.config.storeOf(t, world.config.readOnly))
	if err := readOnly.Ack(t.Context(), testDisclosureConfirmed("inference:engy", 1)); !errors.Is(err, ErrDisclosureAckRefused) {
		t.Errorf("a read-only device: %v", err)
	}
	// an enclave's sidecar, which the store never takes a write from
	enclave := world.acksOf(t, world.config.storeOf(t, world.config.enclave))
	if err := enclave.Ack(t.Context(), testDisclosureConfirmed("inference:engy", 1)); !errors.Is(err, ErrDisclosureAckRefused) {
		t.Errorf("an enclave: %v", err)
	}
	if world.config.vault.writeCount != 0 {
		t.Fatalf("a refused act wrote %d times", world.config.vault.writeCount)
	}

	if err := world.acks.Ack(t.Context(), testDisclosureConfirmed("inference:engy", 1)); err != nil {
		t.Fatal(err)
	}
	if want := `{"version":1,"compute":{"disclosures":{"inference:engy":1}}}`; world.file() != want {
		t.Fatalf("the file %s, want %s", world.file(), want)
	}
	read, err := world.acks.Read(t.Context())
	if err != nil || read.Versions["inference:engy"] != 1 || read.Gap != "" || read.Source != MemberHarnessConfigSourceFile {
		t.Fatalf("read back %+v, %v", read, err)
	}
	// an acknowledgment of an id the policy does not carry, or of no id of §2.8's, writes nothing
	if err := world.acks.Ack(t.Context(), testDisclosureConfirmed("inference:nobody", 1)); !errors.Is(err, ErrComputeDisclosureNotCarried) {
		t.Errorf("an id not carried: %v", err)
	}
	if err := world.acks.Ack(t.Context(), testDisclosureConfirmed("Inference:engy", 1)); !errors.Is(err, ErrComputeDisclosureIdInvalid) {
		t.Errorf("an id outside §2.8's: %v", err)
	}
	if world.config.vault.writeCount != 1 {
		t.Fatalf("%d writes, want 1", world.config.vault.writeCount)
	}
}

// A version shown older than the current one is disclosure_changed, writing nothing; with no verified policy nothing
// can be acknowledged.
func TestDisclosureAckChangedVersion(t *testing.T) {
	world := newTestDisclosureAckWorld(t)
	world.source.policy.Disclosure("inference:engy").Version = 2
	for _, shown := range []uint32{1, 3, 0} {
		if err := world.acks.Ack(t.Context(), testDisclosureConfirmed("inference:engy", shown)); !errors.Is(err, ErrDisclosureChanged) {
			t.Errorf("version %d shown: %v", shown, err)
		}
	}
	world.source.policy = nil
	if err := world.acks.Ack(t.Context(), testDisclosureConfirmed("inference:engy", 2)); !errors.Is(err, ErrComputeDisclosurePolicyUnavailable) {
		t.Errorf("no policy: %v", err)
	}
	if world.config.vault.writeCount != 0 {
		t.Fatalf("%d writes, want none", world.config.vault.writeCount)
	}
}

// The key keeps every other key's bytes and the ids it does not know, ignores a value that is no version with a gap,
// only rises, and a key that is no object is written whole.
func TestDisclosureAckKeyKeepsWhatItDoesNotKnow(t *testing.T) {
	world := newTestDisclosureAckWorld(t)
	world.config.vault.put(world.config.laptop, []byte(`{"version": 1, "models": {"tee_only": true},
 "compute": {"disclosures": {"weather:today": 4, "search:parallel": "1", "inference:engy": 2.0, "inference:saygm": 1}}}`))
	read, err := world.acks.Read(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if read.Versions["weather:today"] != 4 || read.Versions["inference:saygm"] != 1 || len(read.Versions) != 2 ||
		read.Gap != MemberHarnessConfigGapUnreadable || !strings.Contains(read.Reason, "2 of") {
		t.Fatalf("read %+v", read)
	}
	if err := world.acks.Ack(t.Context(), testDisclosureConfirmed("search:parallel", 1)); err != nil {
		t.Fatal(err)
	}
	want := `{"version": 1, "models": {"tee_only": true},
 "compute": {"disclosures": {"weather:today": 4, "search:parallel": 1, "inference:engy": 2.0, "inference:saygm": 1}}}`
	if world.file() != want {
		t.Fatalf("the file\n%s\nwant\n%s", world.file(), want)
	}
	// a version already held writes nothing
	writes := world.config.vault.writeCount
	if err := world.acks.Ack(t.Context(), testDisclosureConfirmed("inference:saygm", 1)); err != nil || world.config.vault.writeCount != writes {
		t.Fatalf("an acknowledgment held already: %v, %d writes", err, world.config.vault.writeCount-writes)
	}
	// a key that is no object is written whole
	world.config.vault.put(world.config.laptop, []byte(`{"version":1,"compute":{"disclosures":["search:parallel"],"other":true}}`))
	if err := world.acks.Ack(t.Context(), testDisclosureConfirmed("search:parallel", 1)); err != nil {
		t.Fatal(err)
	}
	if want := `{"version":1,"compute":{"disclosures":{"search:parallel":1},"other":true}}`; world.file() != want {
		t.Fatalf("the file %s, want %s", world.file(), want)
	}
	// a higher version held is never lowered
	world.config.vault.put(world.config.laptop, []byte(`{"version":1,"compute":{"disclosures":{"inference:engy":3}}}`))
	writes = world.config.vault.writeCount
	if err := world.acks.Ack(t.Context(), testDisclosureConfirmed("inference:engy", 1)); err != nil || world.config.vault.writeCount != writes {
		t.Fatalf("a lower version: %v, %d writes", err, world.config.vault.writeCount-writes)
	}
}

// An acknowledgment made after the German text was shown covers the version in English too: the key holds a version,
// never a locale.
func TestDisclosureAckCoversEveryLocale(t *testing.T) {
	world := newTestDisclosureAckWorld(t)
	// German shown: the policy carries engy in English alone, and local in German too
	world.source.policy.Disclosure("inference:engy").Locales = append(world.source.policy.Disclosure("inference:engy").Locales,
		&ComputePolicyDisclosureText{Locale: "de", Summary: "Nicht in einer TEE.", Exposed: []string{"Alles."}, Private: []string{"Nichts."}})
	view, err := world.registry.View("inference:engy", "de-AT")
	if err != nil || view.Locale != "de" {
		t.Fatalf("the German view %+v, %v", view, err)
	}
	if err := world.acks.Ack(t.Context(), testDisclosureConfirmed(view.Id, view.Version)); err != nil {
		t.Fatal(err)
	}
	for _, locale := range []string{"", "en", "de", "fr-CA"} {
		if err := world.check.Require(t.Context(), "inference:engy", locale); err != nil {
			t.Errorf("in %q: %v", locale, err)
		}
	}
	if want := `{"version":1,"compute":{"disclosures":{"inference:engy":1}}}`; world.file() != want {
		t.Errorf("the key holds more than a version: %s", world.file())
	}
}

// Await returns once the key holds the version: at once where it does; after another of the member's devices wrote it
// and the vault's change woke it, or the recheck read it; never at a ui_response's acknowledgment, which the Harness's
// broker refuses and which no store holds.
func TestDisclosureAwaitLandsFromOtherDevice(t *testing.T) {
	world := newTestDisclosureAckWorld(t)
	broker := NewHarnessUiBroker(&HarnessUiBrokerArgs{
		Emit:  func(agentId Id, event *HarnessEvent) error { return nil },
		Acks:  world.acks,
		Clock: world.clock,
	})
	runId, agentId := NewId(), NewId()
	defer broker.AttachPerson(runId)()
	type asked struct {
		response *HarnessUiResponse
		err      error
	}
	done := make(chan asked, 1)
	go func() {
		response, err := broker.Ask(t.Context(), runId, agentId, &HarnessUiRequest{Id: "ui_1", Method: HarnessUiDisclosure,
			DisclosureId: "inference:engy", DisclosureVersion: 1})
		done <- asked{response: response, err: err}
	}()
	// the request is pending, and the wait armed its recheck
	if err := world.clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if err := broker.Respond(&HarnessUiResponse{Id: "ui_1", Acknowledged: true}); !errors.Is(err, ErrHarnessUiAnswerRefused) {
		t.Fatalf("a ui_response's acknowledgment: %v", err)
	}
	// a recheck with nothing in the key keeps waiting
	world.clock.Advance(world.registry.Settings().AwaitRecheckInterval)
	if err := world.clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		t.Fatalf("answered with nothing in the key: %+v", result)
	default:
	}
	// the laptop's acknowledgment, synced into the vault, wakes it at the vault's change
	world.config.vault.put(world.config.laptop, []byte(`{"version":1,"compute":{"disclosures":{"inference:engy":1}}}`))
	world.acks.Notify()
	result := <-done
	if result.err != nil || result.response == nil || !result.response.Acknowledged {
		t.Fatalf("answered %+v, %v", result.response, result.err)
	}
	// held already: at once
	if err := world.acks.Await(t.Context(), "inference:engy", 1); err != nil {
		t.Fatal(err)
	}
	// a version the key does not reach waits until its context ends; each wait below is known armed by its own timer,
	// counted past the timers earlier waits left
	ctx, cancel := context.WithCancel(t.Context())
	waited := make(chan error, 1)
	armed := world.clock.TimerCount()
	go func() { waited <- world.acks.Await(ctx, "inference:engy", 2) }()
	if err := world.clock.AwaitTimers(t.Context(), armed+1); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-waited; !errors.Is(err, context.Canceled) {
		t.Fatalf("a wait whose context ended: %v", err)
	}
	// the recheck alone reads it again where no change was announced
	waited = make(chan error, 1)
	armed = world.clock.TimerCount()
	go func() { waited <- world.acks.Await(t.Context(), "search:parallel", 1) }()
	if err := world.clock.AwaitTimers(t.Context(), armed+1); err != nil {
		t.Fatal(err)
	}
	world.config.vault.put(world.config.laptop, []byte(`{"version":1,"compute":{"disclosures":{"inference:engy":1,"search:parallel":1}}}`))
	world.clock.Advance(world.registry.Settings().AwaitRecheckInterval)
	if err := <-waited; err != nil {
		t.Fatalf("the recheck: %v", err)
	}
}

// A version newer than the one first listed, acknowledged or opened marks the lines until the person opens the text;
// a revision marks nothing; a new install's first listing is new, not changed.
func TestDisclosureChangedMarks(t *testing.T) {
	world := newTestDisclosureAckWorld(t)
	changed := func(id string) bool {
		t.Helper()
		verdict, err := world.check.Check(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		return verdict.Changed
	}
	if changed("inference:engy") || changed("inference:chutes") {
		t.Fatal("version 1, first listed, is marked changed")
	}
	// a new version of a disclosure that asks nothing, and of one that asks
	world.source.policy = testDisclosurePolicy(t)
	world.source.policy.Version = 4
	world.source.policy.Disclosure("inference:chutes").Version = 2
	world.source.policy.Disclosure("inference:engy").Version = 2
	if !changed("inference:chutes") || !changed("inference:engy") || changed("inference:local") {
		t.Fatal("a new version is not marked changed")
	}
	// opening the text ends the mark, for that id alone
	if err := world.marks.opened("inference:chutes", 2, nil); err != nil {
		t.Fatal(err)
	}
	if changed("inference:chutes") || !changed("inference:engy") {
		t.Fatal("opening one text ended the wrong mark")
	}
	// a revision marks nothing
	world.source.policy = testDisclosurePolicy(t)
	world.source.policy.Version = 5
	world.source.policy.Disclosure("inference:chutes").Version = 2
	world.source.policy.Disclosure("inference:chutes").Revision = 1
	world.source.policy.Disclosure("inference:engy").Version = 2
	if changed("inference:chutes") {
		t.Fatal("a revision is marked changed")
	}
	// acknowledging the new version ends its mark too
	if err := world.acks.Ack(t.Context(), testDisclosureConfirmed("inference:engy", 2)); err != nil {
		t.Fatal(err)
	}
	if changed("inference:engy") {
		t.Fatal("an acknowledged version is marked changed")
	}
	// a store that cannot be reached keeps no marks: changed only past an older acknowledgment
	world.marks.store = func() (SidecarStore, error) { return nil, ErrSidecarStoreLocked }
	world.source.policy.Disclosure("inference:engy").Version = 3
	if !changed("inference:engy") || changed("inference:chutes") {
		t.Fatal("with no store, the marks are not the acknowledgment's alone")
	}
}

// The grace's clock: a test moves it past the instant the version took effect.
func testDisclosureSetVersion(policy *ComputePolicy, id string, version uint32, since time.Time, graceDays uint32) {
	disclosure := policy.Disclosure(id)
	disclosure.Version, disclosure.SinceMs, disclosure.GraceDays = version, since.UnixMilli(), graceDays
}

// The list Sidecar.ComputeDisclosures answers carries each id's acknowledgment from the same policy as its texts: the
// version held, whose, whether a use is covered, and its mark; acknowledgments that do not read leave what asks
// uncovered, with no scope, and what asks nothing covered.
func TestComputeDisclosuresListCarriesAcks(t *testing.T) {
	world := newTestDisclosureAckWorld(t)
	component := &computeDisclosureComponent{
		sidecar:  &Sidecar{log: NewNoopLogger()},
		settings: world.registry.Settings(),
		registry: world.registry,
		acks:     world.acks,
		marks:    world.marks,
		check:    world.check,
	}
	if err := world.acks.Ack(t.Context(), testDisclosureConfirmed("inference:engy", 1)); err != nil {
		t.Fatal(err)
	}
	list, err := component.list(t.Context(), "de")
	if err != nil {
		t.Fatal(err)
	}
	views := map[string]*ComputeDisclosureView{}
	for _, view := range list.Disclosures {
		views[view.Id] = view
	}
	if engy := views["inference:engy"]; engy.Scope != ComputeDisclosureScopePerson || engy.Acknowledged != 1 || !engy.Covered || engy.Changed {
		t.Errorf("engy %+v", engy)
	}
	if search := views["search:parallel"]; search.Acknowledged != 0 || search.Covered {
		t.Errorf("search %+v", search)
	}
	if local := views["inference:local"]; !local.Covered || local.Locale != "de" {
		t.Errorf("local %+v", local)
	}
	// a new version within its grace: covered, marked changed
	testDisclosureSetVersion(world.source.policy, "inference:engy", 2, world.clock.Now().Add(-time.Hour), 14)
	world.source.policy = testDisclosurePolicyCopy(world.source.policy)
	if list, err = component.list(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	if engy := list.Disclosures[2]; engy.Id != "inference:engy" || engy.Version != 2 || engy.Acknowledged != 1 || !engy.Covered || !engy.Changed {
		t.Errorf("engy at version 2 %+v", engy)
	}
	// unreadable acknowledgments: no scope, what asks not covered, what asks nothing covered
	world.config.vault.historyErr = errors.New("evs unreachable")
	if list, err = component.list(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	for _, view := range list.Disclosures {
		if view.Scope != "" || view.Acknowledged != 0 || view.Covered == view.Asks {
			t.Errorf("unreadable: %+v", view)
		}
	}
	// no policy: policy_unavailable, nothing listed
	world.source.policy = nil
	if list, err := component.list(t.Context(), ""); !errors.Is(err, ErrComputeDisclosurePolicyUnavailable) || list != nil {
		t.Errorf("no policy: %v, %v", list, err)
	}
}
