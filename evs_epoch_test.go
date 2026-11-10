package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// One classification for evs and its clients: a shrink after the starting generation's pin is immediate, anything
// else batched (question evs1-m2-16-due-classification, option 1).
func TestEvsClassifyPathEpochDue(t *testing.T) {
	cases := []struct {
		holdersShrunkAt uint64
		fromAuthVersion uint64
		immediate       bool
	}{
		{holdersShrunkAt: 0, fromAuthVersion: 0, immediate: false},
		{holdersShrunkAt: 0, fromAuthVersion: 7, immediate: false},
		{holdersShrunkAt: 7, fromAuthVersion: 7, immediate: false},
		{holdersShrunkAt: 7, fromAuthVersion: 9, immediate: false},
		{holdersShrunkAt: 8, fromAuthVersion: 7, immediate: true},
		{holdersShrunkAt: 1, fromAuthVersion: 0, immediate: true},
	}
	for _, c := range cases {
		if immediate := EvsClassifyPathEpochDue(c.holdersShrunkAt, c.fromAuthVersion); immediate != c.immediate {
			t.Errorf("shrunk at %d from %d: immediate %t", c.holdersShrunkAt, c.fromAuthVersion, immediate)
		}
	}
}

// Creation blocks on shared and owned refs of general, config and mailcfg repos alone (plan-EVS1-epoch-kinds #1, #2).
func TestEvsRefBlocksCreation(t *testing.T) {
	blockingKinds := map[protocol.RepoKind]bool{
		protocol.RepoKind_REPO_KIND_GENERAL: true, protocol.RepoKind_REPO_KIND_CONFIG: true, protocol.RepoKind_REPO_KIND_MAILCFG: true,
	}
	blockingRefs := map[protocol.EvsRefKind]bool{protocol.EvsRefKind_EVS_REF_SHARED: true, protocol.EvsRefKind_EVS_REF_OWNED: true}
	for repoKindValue := range protocol.RepoKind_name {
		for refKindValue := range protocol.EvsRefKind_name {
			repoKind, refKind := protocol.RepoKind(repoKindValue), protocol.EvsRefKind(refKindValue)
			want := blockingKinds[repoKind] && blockingRefs[refKind]
			if got := EvsRefBlocksCreation(repoKind, refKind); got != want {
				t.Errorf("%s %s: blocks %t", repoKind, refKind, got)
			}
		}
	}
}

// path_map_sha256 is SHA-256 over the parts' signed bytes in part order (DESIGN-DETAILS 9.2.2): the hasher one part at
// a time equals the hash of the parts joined, and another order is another hash.
func TestEvsPathMapSha256(t *testing.T) {
	parts := [][]byte{[]byte("part one's signed bytes"), []byte("part two's"), []byte("and three")}
	joined := sha256.Sum256(bytes.Join(parts, nil))
	if got := EvsPathMapSha256(parts); !bytes.Equal(got, joined[:]) {
		t.Fatalf("the map's hash %x, want %x", got, joined)
	}
	hasher := NewEvsPathMapHasher()
	for _, part := range parts {
		hasher.Add(part)
	}
	if !bytes.Equal(hasher.Sum(), joined[:]) || hasher.PartCount() != 3 {
		t.Fatalf("the hasher %x over %d parts", hasher.Sum(), hasher.PartCount())
	}
	if bytes.Equal(EvsPathMapSha256([][]byte{parts[1], parts[0], parts[2]}), joined[:]) {
		t.Fatal("two orders of the parts hash alike")
	}
}

// 409 MAP_SOURCE reads as itself and as no other refusal, MAP_PARTS among them.
func TestIsEvsMapSource(t *testing.T) {
	mapSource := &EvsError{Status: 409, Code: protocol.EvsRefusalCode_EVS_REFUSAL_MAP_SOURCE}
	if !IsEvsMapSource(mapSource) || !IsEvsMapSource(fmt.Errorf("a PATH_EPOCH: %w", mapSource)) {
		t.Fatal("MAP_SOURCE not read as itself")
	}
	if IsEvsMapSource(&EvsError{Status: 409, Code: protocol.EvsRefusalCode_EVS_REFUSAL_MAP_PARTS}) || IsEvsMapSource(errors.New("other")) {
		t.Fatal("another answer read as MAP_SOURCE")
	}
	if status, ok := EvsRefusalStatus(protocol.EvsRefusalCode_EVS_REFUSAL_MAP_SOURCE); !ok || status != 409 ||
		EvsRefusalRecordable(protocol.EvsRefusalCode_EVS_REFUSAL_MAP_SOURCE) || EvsRefusalRefusesNothing(protocol.EvsRefusalCode_EVS_REFUSAL_MAP_SOURCE) {
		t.Fatalf("MAP_SOURCE's row: %d %t", status, ok)
	}
}

// The two token rules (DESIGN-DETAILS 9.2.3) as a table over (floor, cur, sources, the record's PinEpoch, the
// verifier's asks, quiet, fresh): a path with a floor is named in cur and each source, PinEpoch and ask at or above
// it, never below; one with none is named in cur alone on a fresh state with no source standing and no immediate
// pressure, else looked up, and waits for a fresh state where only freshness is missing.
func TestEvsEpochTokensRules(t *testing.T) {
	epochOf := func(current uint64, sources ...uint64) *protocol.EvsPathEpoch {
		epoch := &protocol.EvsPathEpoch{Current: current}
		for _, source := range sources {
			epoch.Sources = append(epoch.Sources, &protocol.EvsEpochSource{Epoch: source})
		}
		return epoch
	}
	cases := []struct {
		name      string
		epoch     *protocol.EvsPathEpoch
		floor     uint64
		pinEpoch  uint64
		more      []uint64
		quiet     bool
		fresh     bool
		epochs    []uint64
		lookup    bool
		needFresh bool
	}{
		{name: "a new name, no source, quiet, fresh", epoch: epochOf(1), quiet: true, fresh: true, epochs: []uint64{1}},
		{name: "a new name on a stale state", epoch: epochOf(1), quiet: true, needFresh: true},
		{name: "a new name while a source stands", epoch: epochOf(2, 1), quiet: true, fresh: true, lookup: true},
		{name: "a new name under immediate pressure", epoch: epochOf(1), fresh: true, lookup: true},
		{name: "a floor at the current epoch", epoch: epochOf(3, 2, 1), floor: 3, quiet: true, epochs: []uint64{3}},
		{name: "a floor in a source", epoch: epochOf(3, 2, 1), floor: 2, epochs: []uint64{3, 2}},
		{name: "a floor below every source", epoch: epochOf(3, 2, 1), floor: 1, epochs: []uint64{3, 2, 1}},
		{name: "a record's pin epoch at the floor", epoch: epochOf(4), floor: 1, pinEpoch: 1, epochs: []uint64{4, 1}},
		{name: "a record's pin epoch below the floor", epoch: epochOf(4), floor: 2, pinEpoch: 1, epochs: []uint64{4}},
		{name: "asks for epochs, one below the floor", epoch: epochOf(4), floor: 2, more: []uint64{1, 3}, epochs: []uint64{4, 3}},
	}
	for _, c := range cases {
		epochs, lookup, needFresh := evsEpochTokens(c.epoch, c.floor, c.pinEpoch, c.more, c.quiet, c.fresh)
		if !slices.Equal(epochs, c.epochs) || lookup != c.lookup || needFresh != c.needFresh {
			t.Errorf("%s: epochs %v lookup %t fresh %t", c.name, epochs, lookup, needFresh)
		}
	}
	if evsLowerFloor(0, 2) != 2 || evsLowerFloor(3, 2) != 2 || evsLowerFloor(1, 2) != 1 || evsLowerFloor(2, 0) != 2 {
		t.Error("a floor fell other than to the lower epoch")
	}
}

// A ref's state as noted from a head of version, generation and epoch.
func evsTestRefEpoch(version uint64, generation uint64, epoch *protocol.EvsPathEpoch) *evsRefEpoch {
	return &evsRefEpoch{refId: evsTestId("pressure ref"), epoch: epoch, version: version, generation: generation, refKind: protocol.EvsRefKind_EVS_REF_SHARED}
}

// pressure as evs classifies the same crossing (EvsClassifyPathEpochDue, question evs1-m2-16-due-classification
// option 1): a recorded due by its block; else the newest REMOVE generation this device holds above the head's,
// immediate unless the state's holders shrank at or below the auth pin of the generation crossed from; none for a
// REQUEST rotation or a ref with no head; and quiet holds new names only on a blocking ref under immediate pressure.
func TestEvsPressureMatchesEvsClassification(t *testing.T) {
	writer := newEvsTestWriter(t)
	repo := writer.repo
	ctx := context.Background()
	writer.gkm.auths[1] = 3
	due := func(blocks bool) *protocol.EvsPathEpoch {
		return &protocol.EvsPathEpoch{Current: 1, DueGeneration: 2, DueBlocksCreation: blocks, DueByMs: 1}
	}
	cases := []struct {
		name     string
		state    *evsRefEpoch
		newest   uint64
		cause    GkmCause
		shrunkAt uint64
		pressure evsPressure
	}{
		{name: "a due recorded that blocks", state: evsTestRefEpoch(4, 2, due(true)), newest: 2, pressure: evsPressureImmediate},
		{name: "a due recorded that does not", state: evsTestRefEpoch(4, 2, due(false)), newest: 2, pressure: evsPressureBatched},
		{name: "no newer generation", state: evsTestRefEpoch(4, 1, &protocol.EvsPathEpoch{Current: 1}), newest: 1},
		{name: "a REMOVE after a shrink", state: evsTestRefEpoch(4, 1, &protocol.EvsPathEpoch{Current: 1}), newest: 2,
			cause: GkmCauseRemove, shrunkAt: 5, pressure: evsPressureImmediate},
		{name: "a REMOVE of expiries alone", state: evsTestRefEpoch(4, 1, &protocol.EvsPathEpoch{Current: 1}), newest: 2,
			cause: GkmCauseRemove, shrunkAt: 3, pressure: evsPressureBatched},
		{name: "a REQUEST rotation", state: evsTestRefEpoch(4, 1, &protocol.EvsPathEpoch{Current: 1}), newest: 2, cause: GkmCauseRequest},
		{name: "a ref with no head", state: evsTestRefEpoch(0, 0, &protocol.EvsPathEpoch{Current: 1}), newest: 2,
			cause: GkmCauseRemove, shrunkAt: 5},
	}
	for _, c := range cases {
		writer.gkm.newest = c.newest
		writer.gkm.causes[2] = c.cause
		writer.world.config.repo.HoldersShrunkAt = c.shrunkAt
		pressure, _, err := repo.pressure(ctx, c.state)
		if err != nil || pressure != c.pressure {
			t.Errorf("%s: pressure %d %v", c.name, pressure, err)
		}
		if c.cause == GkmCauseRemove && c.state.version != 0 {
			if immediate := EvsClassifyPathEpochDue(c.shrunkAt, 3); immediate != (c.pressure == evsPressureImmediate) {
				t.Errorf("%s: evs classes it immediate %t", c.name, immediate)
			}
		}
		quiet, err := repo.quiet(ctx, c.state)
		if err != nil || quiet != (c.pressure != evsPressureImmediate) {
			t.Errorf("%s: quiet %t %v", c.name, quiet, err)
		}
	}
	// a mailbox never holds creation (plan-EVS1-epoch-kinds #1)
	writer.world.config.repo.Kind = protocol.RepoKind_REPO_KIND_MAILBOX
	if quiet, err := repo.quiet(ctx, evsTestRefEpoch(4, 2, due(true))); err != nil || !quiet {
		t.Errorf("a mailbox ref under a due: quiet %t %v", quiet, err)
	}
}

// Notes head as the client's verified head of the world's main ref.
func (self *evsTestWriter) noteHead(head *protocol.EvsHeadSummary) {
	self.test.client.noteVerifiedHead(self.world.repoId, self.world.refId, head)
}

// PathEpochStatus's states and ur status's line (DESIGN-DETAILS 9.2.8).
func TestEvsPathEpochStatus(t *testing.T) {
	writer := newEvsTestWriter(t)
	ctx := context.Background()
	now := writer.test.clock.Now()
	writer.gkm.newest = 2
	head := func(epoch *protocol.EvsPathEpoch) *protocol.EvsHeadSummary {
		return &protocol.EvsHeadSummary{Version: 5, Generation: 2, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, PathEpoch: epoch}
	}
	sources := func(epochs ...uint64) []*protocol.EvsEpochSource {
		listed := []*protocol.EvsEpochSource{}
		for _, epoch := range epochs {
			listed = append(listed, &protocol.EvsEpochSource{Epoch: epoch})
		}
		return listed
	}
	cases := []struct {
		name  string
		epoch *protocol.EvsPathEpoch
		state string
		class string
	}{
		{name: "no due", epoch: &protocol.EvsPathEpoch{Current: 2}, state: EvsPathEpochStateNone},
		{name: "an immediate due", epoch: &protocol.EvsPathEpoch{Current: 1, DueGeneration: 2, DueBlocksCreation: true, DueByMs: now.UnixMilli()},
			state: EvsPathEpochStateWaitingMapper, class: "immediate"},
		{name: "an overdue one", epoch: &protocol.EvsPathEpoch{Current: 1, DueGeneration: 2, DueBlocksCreation: true, DueByMs: now.Add(-2 * time.Hour).UnixMilli()},
			state: EvsPathEpochStateOverdue, class: "immediate"},
		{name: "three sources standing", epoch: &protocol.EvsPathEpoch{Current: 4, Sources: sources(3, 2, 1), DueGeneration: 5, DueBlocksCreation: true, DueByMs: now.UnixMilli()},
			state: EvsPathEpochStateWaitingSources, class: "immediate"},
		{name: "a batched due and two sources", epoch: &protocol.EvsPathEpoch{Current: 3, Sources: sources(2, 1), DueGeneration: 4, DueByMs: now.UnixMilli()},
			state: EvsPathEpochStateWaitingSources, class: "batched"},
	}
	for _, c := range cases {
		writer.noteHead(head(c.epoch))
		status, err := writer.repo.PathEpochStatus(ctx, nil)
		if err != nil || status.State != c.state || status.Class != c.class {
			t.Errorf("%s: %+v %v", c.name, status, err)
		}
	}
	status := &EvsPathEpochStatus{Current: 1, DueGeneration: 2, DueBy: time.Date(2026, time.November, 8, 9, 0, 0, 0, time.UTC), Class: "immediate", State: EvsPathEpochStateOverdue}
	if line := status.StatusLine("work", "main"); line != "work main: path epoch 1 -> 2, due 2026-11-08T09:00:00Z (immediate): overdue" {
		t.Errorf("ur status's line %q", line)
	}
}

// The epoch_overdue alarms a writer's verified heads raise.
func (self *evsTestWriter) overdueAlarms() int {
	count := 0
	for _, event := range self.test.eventsOf(SidecarEventEvsAlarm) {
		if event.EvsAlarm == SidecarEvsAlarmEpochOverdue {
			count += 1
		}
	}
	return count
}

// The writer's overdue alarm (DESIGN-DETAILS 9.2.8): once an hour past due_by_ms, once per due generation in 24 h; not
// while a batched due waits on two sources, nor within the hour after the head first lists fewer; and from when this
// device first held a REMOVE generation no head records.
func TestEvsEpochOverdueAlarm(t *testing.T) {
	writer := newEvsTestWriter(t)
	now := writer.test.clock.Now()
	head := func(version uint64, epoch *protocol.EvsPathEpoch) *protocol.EvsHeadSummary {
		return &protocol.EvsHeadSummary{Version: version, Generation: 2, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, PathEpoch: epoch}
	}
	immediate := &protocol.EvsPathEpoch{Current: 1, DueGeneration: 2, DueBlocksCreation: true, DueByMs: now.Add(-30 * time.Minute).UnixMilli()}
	writer.noteHead(head(1, immediate))
	if writer.overdueAlarms() != 0 {
		t.Fatal("an alarm under an hour past due")
	}
	writer.test.clock.advance(31 * time.Minute)
	writer.noteHead(head(2, immediate))
	writer.noteHead(head(3, immediate))
	if writer.overdueAlarms() != 1 {
		t.Fatalf("%d alarms an hour past due", writer.overdueAlarms())
	}
	writer.test.clock.advance(24 * time.Hour)
	writer.noteHead(head(4, immediate))
	if writer.overdueAlarms() != 2 {
		t.Fatalf("%d alarms a day later", writer.overdueAlarms())
	}

	// a batched due waiting on two sources, then the hour after the head lists fewer
	writer = newEvsTestWriter(t)
	now = writer.test.clock.Now()
	twoSources := &protocol.EvsPathEpoch{Current: 3, Sources: []*protocol.EvsEpochSource{{Epoch: 2}, {Epoch: 1}}, DueGeneration: 4, DueByMs: now.Add(-48 * time.Hour).UnixMilli()}
	writer.noteHead(head(1, twoSources))
	oneSource := &protocol.EvsPathEpoch{Current: 3, Sources: []*protocol.EvsEpochSource{{Epoch: 2}}, DueGeneration: 4, DueByMs: twoSources.GetDueByMs()}
	writer.noteHead(head(2, oneSource))
	writer.test.clock.advance(59 * time.Minute)
	writer.noteHead(head(3, oneSource))
	if writer.overdueAlarms() != 0 {
		t.Fatalf("%d alarms in the deferral or the hour after it", writer.overdueAlarms())
	}
	writer.test.clock.advance(2 * time.Minute)
	writer.noteHead(head(4, oneSource))
	if writer.overdueAlarms() != 1 {
		t.Fatalf("%d alarms past the hour after the deferral", writer.overdueAlarms())
	}

	// a REMOVE generation this device holds and no head records
	writer = newEvsTestWriter(t)
	writer.test.client.epochs.noteHeldRemoval(writer.world.repoId, 2, writer.test.clock.Now())
	unrecorded := &protocol.EvsPathEpoch{Current: 1}
	writer.noteHead(head(1, unrecorded))
	writer.test.clock.advance(61 * time.Minute)
	writer.noteHead(&protocol.EvsHeadSummary{Version: 2, Generation: 1, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, PathEpoch: unrecorded})
	if writer.overdueAlarms() != 1 {
		t.Fatalf("%d alarms an hour after holding an unrecorded removal", writer.overdueAlarms())
	}
}
