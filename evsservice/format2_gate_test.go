// EVS2-M10-05's tests of §19.11's format2 gate as evs reads it and of 5c's answer: the gate's table over the host's
// gates, its percent boundaries and its rereads; a push carrying format 2 from a network outside the gate refused
// 409 VERSIONING, recorded, and its push id answering that record after the gate opens (I-EVS-3); a push inside the
// gate with no format-2 rules supplied answering 503 and raising nothing; and a format-1 push untouched by the gate.

package evsservice

import (
	"fmt"
	"net/http"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The host's whole sidecar.yml with evs open to the fixture's network and format2 as given, since a file replaces
// every gate at once.
func (self *pushFixture) setFormat2(format2 string) {
	self.t.Helper()
	text := fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n  format2: %s\n", connect.Id(self.check.networkId).String(), format2)
	if err := self.host.Gates.Set(text); err != nil {
		self.t.Fatal(err)
	}
}

// The format2 gate open to the fixture's network, with rules that pass every format-2 push, as EVS2-M10-06's will
// once they land.
func (self *pushFixture) openFormat2() {
	self.t.Helper()
	self.setFormat2(fmt.Sprintf("{enabled: true, networks: [%q]}", connect.Id(self.check.networkId).String()))
	self.engine.deps.Format2Rules = func(view *PushView) *EvsCheckRefusal { return nil }
}

// A creation of path as a versionless file (versioning 1), which only format 2 takes.
func (self *pushFixture) createVersionless(plan *sidecar.EvsPushPlan, labels ...string) {
	self.t.Helper()
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsEntryVersion{
		Version: plan.BaseVersion + 1, PushId: plan.PushId.Bytes(), BaseVersion: plan.BaseVersion, TimeMs: plan.TimeMs,
		Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: 4096, SealedFields: []byte("sealed fields"),
		Versioning: uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS),
		Chain:      []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("inline record")}},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: checkTestPath(labels...), EntryVersion: entryBytes})
}

// plan's request body built as format 2 and signed by the fixture's writer.
func (self *pushFixture) bodyFormat2(plan *sidecar.EvsPushPlan) *protocol.EvsPushRequest {
	self.t.Helper()
	built, err := sidecar.NewEvsStatementBuilder(checkTestSign(self.check.signingKey, self.check.signerId)).BuildFormat2(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	return &protocol.EvsPushRequest{Statement: built.Statement.Bytes, Payload: built.Payload}
}

// repo/ as the cluster holds it, with its ETag.
func (self *pushFixture) repo() (*protocol.EvsRepoObject, string) {
	self.t.Helper()
	read, err := NewRepoCache(self.clock, self.settings).ReadFresh(self.ctx, self.cluster, self.check.repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	return read.Object, read.Etag
}

// A network id whose gate bucket is bucket.
func format2TestNetworkAt(t *testing.T, bucket int) sidecar.Id {
	t.Helper()
	for i := 0; i < 100*1000; i += 1 {
		networkId := testIdFrom(fmt.Sprintf("format2 gate network %d", i))
		if sidecar.ServiceGateBucket(connect.Id(networkId)) == bucket {
			return networkId
		}
	}
	t.Fatalf("no network id in bucket %d", bucket)
	return sidecar.Id{}
}

// §19.11's rule as the engine's gate answers it: in when enabled and listed, or enabled and the bucket is under the
// percent; an absent file and an absent block read as off, with purge and drop observe; a mode that is not exactly
// `on` reads observe.
func TestFormat2GateTable(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(t.Context(), clock, nil, nil, nil)
	gate := NewFormat2Gate(host.ServiceHost())
	listed, other := format2TestNetworkAt(t, 40), format2TestNetworkAt(t, 41)
	low, high := format2TestNetworkAt(t, 0), format2TestNetworkAt(t, 99)
	listedStr := connect.Id(listed).String()
	cases := []struct {
		name   string
		file   string
		admits []sidecar.Id
		out    []sidecar.Id
		purge  sidecar.Format2Mode
		drop   sidecar.Format2Mode
	}{
		{name: "an empty file", file: "", out: []sidecar.Id{listed, other, low, high}},
		{name: "no format2 block", file: "sidecar:\n  evs: {enabled: true, percent: 100}\n", out: []sidecar.Id{listed, other, low, high}},
		{name: "the design's default", file: "sidecar:\n  format2: {enabled: false, networks: [], percent: 0, purge: observe, drop: observe}\n", out: []sidecar.Id{listed, other, low, high}},
		{name: "listed and disabled", file: fmt.Sprintf("sidecar:\n  format2: {enabled: false, networks: [%q], percent: 100}\n", listedStr), out: []sidecar.Id{listed, other, low, high}},
		{name: "listed", file: fmt.Sprintf("sidecar:\n  format2: {enabled: true, networks: [%q]}\n", listedStr), admits: []sidecar.Id{listed}, out: []sidecar.Id{other, low, high}},
		{name: "percent 0", file: "sidecar:\n  format2: {enabled: true, percent: 0}\n", out: []sidecar.Id{listed, other, low, high}},
		{name: "percent 1", file: "sidecar:\n  format2: {enabled: true, percent: 1}\n", admits: []sidecar.Id{low}, out: []sidecar.Id{listed, other, high}},
		{name: "percent at a bucket", file: "sidecar:\n  format2: {enabled: true, percent: 40}\n", admits: []sidecar.Id{low}, out: []sidecar.Id{listed, other, high}},
		{name: "percent past a bucket", file: "sidecar:\n  format2: {enabled: true, percent: 41}\n", admits: []sidecar.Id{low, listed}, out: []sidecar.Id{other, high}},
		{name: "percent 99", file: "sidecar:\n  format2: {enabled: true, percent: 99}\n", admits: []sidecar.Id{low, listed, other}, out: []sidecar.Id{high}},
		{name: "percent 100", file: "sidecar:\n  format2: {enabled: true, percent: 100}\n", admits: []sidecar.Id{low, listed, other, high}},
		{name: "purge on", file: "sidecar:\n  format2: {enabled: true, purge: on}\n", out: []sidecar.Id{listed}, purge: sidecar.Format2On},
		{name: "drop on", file: "sidecar:\n  format2: {enabled: true, drop: \"on\"}\n", out: []sidecar.Id{listed}, drop: sidecar.Format2On},
		{name: "modes that are not on", file: "sidecar:\n  format2: {enabled: true, purge: \"On\", drop: delete}\n", out: []sidecar.Id{listed}},
		// the modes are the jobs' own switches, read apart from `enabled` (testdata/gates/table.yml): a gate closed again
		// admits no new push, and repos it raised stay format 2, their purge and drops still under these
		{name: "modes on while disabled", file: "sidecar:\n  format2: {enabled: false, purge: on, drop: on}\n", out: []sidecar.Id{listed}, purge: sidecar.Format2On, drop: sidecar.Format2On},
	}
	for _, c := range cases {
		if err := host.Gates.Set(c.file); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		for _, networkId := range c.admits {
			if !gate.Admits(networkId) {
				t.Errorf("%s: bucket %d refused", c.name, sidecar.ServiceGateBucket(connect.Id(networkId)))
			}
		}
		for _, networkId := range c.out {
			if gate.Admits(networkId) {
				t.Errorf("%s: bucket %d admitted", c.name, sidecar.ServiceGateBucket(connect.Id(networkId)))
			}
		}
		wantPurge, wantDrop := c.purge, c.drop
		if wantPurge == "" {
			wantPurge = sidecar.Format2Observe
		}
		if wantDrop == "" {
			wantDrop = sidecar.Format2Observe
		}
		if gate.PurgeMode() != wantPurge || gate.DropMode() != wantDrop {
			t.Errorf("%s: purge %s drop %s, want %s and %s", c.name, gate.PurgeMode(), gate.DropMode(), wantPurge, wantDrop)
		}
	}
}

// The engine's gate keeps no answer of its own: the host's next read moves it at once, a file the reader refuses
// leaves the last good one, and a host with no gates, or none at all, answers closed.
func TestFormat2GateFollowsTheHostAndFailsClosed(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(t.Context(), clock, nil, nil, nil)
	gate := NewFormat2Gate(host.ServiceHost())
	networkId := format2TestNetworkAt(t, 7)
	if gate.Admits(networkId) {
		t.Fatal("a gate nobody set admitted")
	}
	if err := host.Gates.Set("sidecar:\n  format2: {enabled: true, percent: 8, purge: on}\n"); err != nil {
		t.Fatal(err)
	}
	if !gate.Admits(networkId) || gate.PurgeMode() != sidecar.Format2On || gate.DropMode() != sidecar.Format2Observe {
		t.Fatal("the gate did not follow the host's read")
	}
	if err := host.Gates.Set("sidecar: [not, a, map"); err == nil {
		t.Fatal("the fake read a broken file")
	}
	if !gate.Admits(networkId) {
		t.Fatal("a broken later read moved the gate")
	}
	if err := host.Gates.Set("sidecar:\n  format2: {enabled: true, percent: 7}\n"); err != nil {
		t.Fatal(err)
	}
	if gate.Admits(networkId) || gate.PurgeMode() != sidecar.Format2Observe {
		t.Fatal("the gate kept an answer past the host's read")
	}

	for name, closed := range map[string]Format2Gate{
		"no host":            NewFormat2Gate(nil),
		"a host of no gates": NewFormat2Gate(&sidecar.ServiceHost{}),
		"the closed gate":    ClosedFormat2Gate{},
	} {
		if closed.Admits(networkId) || closed.PurgeMode() != sidecar.Format2Observe || closed.DropMode() != sidecar.Format2Observe {
			t.Errorf("%s: not closed", name)
		}
	}
}

// §11.6's format row at 5c (plan-EVS2-small-readings#3): a push carrying format 2 from a network outside the gate is
// 409 VERSIONING, recorded first, and raises nothing; once the gate opens, that push id still answers its record
// (I-EVS-3), while a new push id commits.
func TestPushOutsideTheFormat2GateIsRefusedVersioningAndRecorded(t *testing.T) {
	fixture := newPushFixture(t, nil)
	// rules given, so the gate alone refuses
	fixture.engine.deps.Format2Rules = func(view *PushView) *EvsCheckRefusal { return nil }
	plan := fixture.plan()
	fixture.createVersionless(plan, "a")
	body := fixture.bodyFormat2(plan)
	token := fixture.token(fixture.check.signerId)
	_, etag := fixture.repo()

	recorder := fixture.post(token, body)
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING)
	if refusalOf(t, recorder).GetRecorded() || refusalOf(t, recorder).GetNeedsFormat() != 0 {
		t.Fatalf("the recording attempt answered %v", refusalOf(t, recorder))
	}
	head := fixture.head()
	if head.Version() != 0 || len(head.Head.GetRefused()) != sidecar.EvsRefusalByteCount {
		t.Fatalf("the refusal was not recorded: %v", head.Head)
	}
	if object, after := fixture.repo(); object.GetFormat() != sidecar.EvsRepoFormat1 || after != etag {
		t.Fatalf("a refused push wrote repo/: format %d", object.GetFormat())
	}

	// a gate enabled for other networks, or by a percent under this network's bucket, still refuses it
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
	fixture.setFormat2(fmt.Sprintf("{enabled: true, networks: [%q], percent: %d}", connect.Id(testIdFrom("another network")).String(), sidecar.ServiceGateBucket(connect.Id(fixture.check.networkId))))
	other := fixture.plan()
	fixture.createVersionless(other, "b")
	requireRefusal(t, fixture.post(token, fixture.bodyFormat2(other)), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING)

	fixture.openFormat2()
	again := fixture.post(token, body)
	requireRefusal(t, again, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING)
	if !refusalOf(t, again).GetRecorded() {
		t.Fatal("the push id's later attempt, the gate open, answered without recorded: true")
	}
	if fixture.head().Version() != 0 {
		t.Fatal("a recorded push id committed once the gate opened")
	}
	if object, _ := fixture.repo(); object.GetFormat() != sidecar.EvsRepoFormat1 {
		t.Fatal("a recorded push id raised the repo once the gate opened")
	}
	fresh := fixture.plan()
	fixture.createVersionless(fresh, "c")
	fixture.requireCommitted(fixture.post(token, fixture.bodyFormat2(fresh)), 1)
	if object, _ := fixture.repo(); object.GetFormat() != sidecar.EvsRepoFormat2 {
		t.Fatal("the gate open, a new push id did not raise the repo")
	}
}

// Inside the gate with no format-2 rules supplied, EVS2-M10-06's seam, a format-2 push answers 503: nothing commits
// unchecked, nothing is recorded against the push, and the repo is not raised.
func TestPushInTheGateWithoutFormat2RulesCommitsNothing(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2()
	fixture.engine.deps.Format2Rules = nil
	plan := fixture.plan()
	fixture.createVersionless(plan, "a")
	_, etag := fixture.repo()
	requireRefusal(t, fixture.post(fixture.token(fixture.check.signerId), fixture.bodyFormat2(plan)), http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if !fixture.head().Absent() {
		t.Fatal("an unchecked format-2 push wrote the head")
	}
	if object, after := fixture.repo(); object.GetFormat() != sidecar.EvsRepoFormat1 || after != etag {
		t.Fatal("an unchecked format-2 push raised the repo")
	}
}

// The gate asks only of a push that carries format 2: a format-1 push commits whatever the gate says, and raises
// nothing inside it, as a body built by format 2's builder does when it holds no format-2 value.
func TestFormat1PushPassesTheFormat2GateAndRaisesNothing(t *testing.T) {
	fixture := newPushFixture(t, nil)
	_, etag := fixture.repo()
	closed := fixture.plan()
	fixture.create(closed, "a")
	fixture.requireCommitted(fixture.push(closed), 1)

	fixture.openFormat2()
	plain := fixture.plan()
	fixture.create(plain, "b")
	fixture.requireCommitted(fixture.push(plain), 2)
	built := fixture.plan()
	fixture.create(built, "c")
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), fixture.bodyFormat2(built)), 3)
	if object, after := fixture.repo(); object.GetFormat() != sidecar.EvsRepoFormat1 || after != etag {
		t.Fatalf("a format-1 push raised the repo: format %d", object.GetFormat())
	}
}
