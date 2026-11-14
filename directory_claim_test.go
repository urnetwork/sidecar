//go:build !sidecar_http && !ios_extension

// RECORD-M6-16's claims as state of a run's item: four claims raising the version, a fifth refused, a release and a
// handoff, the end reading handed_off; claims off refusing both kinds and announcing nothing; prompt announcing at the
// first claim; a claim's expiry capped by the run's; a session no run binds refused; and through RecordProjection in
// a team network, claim and handoff reaching the run's item while ask goes to the writer's own route.

package sidecar_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A claim on runId's item, of paths, text and expiry.
func testRunsClaim(t *testing.T, runs *sidecar.DirectoryRuns, runId sidecar.Id, paths []string, expiresMillis int64) (*sidecar.RecordAppendResult, error) {
	t.Helper()
	return runs.Coordinate(t.Context(), &sidecar.RecordAppendArgs{Kind: sidecar.RecordKindClaim, RunId: &runId, ExpiresMillis: expiresMillis},
		&sidecar.RecordTargets{Paths: paths}, &protocol.CoordinationBody{Text: "taking it", Targets: paths})
}

// Four claims each raise the version, source agent; a fifth is refused; a release sets its claim released; a handoff
// sets the handoff and its claim handed_off; the end then reads handed_off.
func TestDirectoryRunFifthClaimRefused(t *testing.T) {
	env := newTestRunsEnv(t)
	start := env.start(sidecar.DirectoryRunClaimsAuto)
	env.clock.Advance(10 * time.Second)
	for i := 0; i < sidecar.DirectoryClaimCount; i += 1 {
		result, err := testRunsClaim(t, env.runs, start.RunId, []string{"src/"}, 0)
		if err != nil {
			t.Fatal(err)
		}
		if result.Version != uint64(i+2) || result.AnnouncementId == nil {
			t.Fatalf("claim %d: %+v", i, result)
		}
	}
	if _, err := testRunsClaim(t, env.runs, start.RunId, []string{"src/"}, 0); !errors.Is(err, sidecar.ErrDirectoryRunClaimsFull) {
		t.Fatalf("a fifth claim: %v", err)
	}
	items := env.writer.items(t)
	claims := items[len(items)-1].GetClaims()
	if len(claims) != sidecar.DirectoryClaimCount {
		t.Fatalf("%d claims", len(claims))
	}
	sources := env.writer.sources()
	if sources[0] != sidecar.RecordSourceHook || sources[len(sources)-1] != sidecar.RecordSourceAgent {
		t.Fatalf("sources %v", sources)
	}
	runId := start.RunId
	released := sidecar.Id(claims[0].GetClaimId())
	if _, err := env.runs.Coordinate(t.Context(), &sidecar.RecordAppendArgs{Kind: sidecar.RecordKindClaim, RunId: &runId, ExpiresMillis: env.clock.Now().UnixMilli() - 1},
		&sidecar.RecordTargets{ClaimIds: []sidecar.Id{released}, Release: true}, &protocol.CoordinationBody{}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.runs.Coordinate(t.Context(), &sidecar.RecordAppendArgs{Kind: sidecar.RecordKindClaim, RunId: &runId, ExpiresMillis: env.clock.Now().UnixMilli() - 1},
		&sidecar.RecordTargets{ClaimIds: []sidecar.Id{sidecar.NewId()}, Release: true}, &protocol.CoordinationBody{}); !errors.Is(err, sidecar.ErrRecordTargetsInvalid) {
		t.Fatalf("a release of no claim: %v", err)
	}
	handed := sidecar.Id(claims[1].GetClaimId())
	toMember := sidecar.NewId()
	if _, err := env.runs.Coordinate(t.Context(), &sidecar.RecordAppendArgs{Kind: sidecar.RecordKindHandoff, RunId: &runId},
		&sidecar.RecordTargets{ClaimIds: []sidecar.Id{handed}, MemberIds: []sidecar.Id{toMember}, AgentLabels: []string{"reviewer"}},
		&protocol.CoordinationBody{Text: "yours now"}); err != nil {
		t.Fatal(err)
	}
	if err := env.runs.Ended(start.RunId); err != nil {
		t.Fatal(err)
	}
	items = env.writer.items(t)
	last := items[len(items)-1]
	states := map[string]uint32{}
	for _, claim := range last.GetClaims() {
		states[string(claim.GetClaimId())] = claim.GetState()
	}
	if last.GetState() != uint32(sidecar.DirectoryAnnouncementStateHandedOff) || last.GetVersion() != 8 ||
		states[string(released.Bytes())] != uint32(sidecar.DirectoryClaimStateReleased) ||
		states[string(handed.Bytes())] != uint32(sidecar.DirectoryClaimStateHandedOff) ||
		!bytes.Equal(last.GetHandoff().GetToMemberId(), toMember.Bytes()) || last.GetHandoff().GetToAgentLabel() != "reviewer" ||
		last.GetHandoff().GetNote() != "yours now" {
		t.Fatalf("the end %v", last)
	}
}

// Under claims off a claim and a handoff are refused naming the setting, and nothing is announced, at the start or
// after.
func TestDirectoryRunClaimsOffRefusesBoth(t *testing.T) {
	env := newTestRunsEnv(t)
	start := env.start(sidecar.DirectoryRunClaimsOff)
	env.clock.Advance(time.Minute)
	if _, err := testRunsClaim(t, env.runs, start.RunId, []string{"src/"}, 0); !errors.Is(err, sidecar.ErrDirectoryRunsClaimsOff) {
		t.Fatalf("a claim: %v", err)
	}
	runId := start.RunId
	if _, err := env.runs.Coordinate(t.Context(), &sidecar.RecordAppendArgs{Kind: sidecar.RecordKindHandoff, RunId: &runId},
		&sidecar.RecordTargets{AgentLabels: []string{"reviewer"}}, &protocol.CoordinationBody{}); !errors.Is(err, sidecar.ErrDirectoryRunsClaimsOff) {
		t.Fatalf("a handoff: %v", err)
	}
	env.runs.Moved(start.RunId)
	env.clock.Advance(2 * time.Hour)
	if err := env.runs.Ended(start.RunId); err != nil {
		t.Fatal(err)
	}
	if items := env.writer.items(t); len(items) != 0 {
		t.Fatalf("claims off announced %d items", len(items))
	}
}

// Under prompt nothing is announced at the start, and the first claim announces the run at version 1, the claim in
// it, source agent, its expiry capped by the run's.
func TestDirectoryRunPromptAnnouncesAtFirstClaim(t *testing.T) {
	env := newTestRunsEnv(t)
	start := env.start(sidecar.DirectoryRunClaimsPrompt)
	env.clock.Advance(time.Minute)
	if items := env.writer.items(t); len(items) != 0 {
		t.Fatalf("prompt announced %d items at the start", len(items))
	}
	result, err := testRunsClaim(t, env.runs, start.RunId, []string{"src/retry/"}, env.clock.Now().Add(48*time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	items := env.writer.items(t)
	if len(items) != 1 || result.Version != 1 {
		t.Fatalf("%d items, version %d", len(items), result.Version)
	}
	item := items[0]
	if item.GetVersion() != 1 || len(item.GetClaims()) != 1 || item.GetClaims()[0].GetTargets()[0] != "src/retry/" ||
		item.GetClaims()[0].GetExpiresMillis() != item.GetExpiresMillis() || env.writer.sources()[0] != sidecar.RecordSourceAgent {
		t.Fatalf("the first claim's item %v", item)
	}
}

// A session no run binds, and a run that ended, have no item to change.
func TestDirectoryRunUnboundSessionRefused(t *testing.T) {
	env := newTestRunsEnv(t)
	if _, err := env.runs.Coordinate(t.Context(), &sidecar.RecordAppendArgs{Kind: sidecar.RecordKindClaim},
		&sidecar.RecordTargets{}, &protocol.CoordinationBody{}); !errors.Is(err, sidecar.ErrDirectoryRunUnknown) {
		t.Fatalf("no run: %v", err)
	}
	if _, err := testRunsClaim(t, env.runs, sidecar.NewId(), nil, 0); !errors.Is(err, sidecar.ErrDirectoryRunUnknown) {
		t.Fatalf("an unknown run: %v", err)
	}
	start := env.start(sidecar.DirectoryRunClaimsAuto)
	env.clock.Advance(10 * time.Second)
	if err := env.runs.Ended(start.RunId); err != nil {
		t.Fatal(err)
	}
	if _, err := testRunsClaim(t, env.runs, start.RunId, nil, 0); !errors.Is(err, sidecar.ErrDirectoryRunUnknown) {
		t.Fatalf("an ended run: %v", err)
	}
}

// Every entry of writerId's stream in repoId, each body opened: storedEntries' read of any repo.
func testStreamEntries(world *testRecordWorld, repoId sidecar.Id, writerId sidecar.Id) []*testRecordStored {
	world.t.Helper()
	reader := world.streams.For(world.readerId)
	versions, err := reader.ReadStream(world.t.Context(), repoId, writerId, 0)
	if err != nil {
		world.t.Fatal(err)
	}
	stored := []*testRecordStored{}
	for _, version := range versions {
		slot, err := reader.ReadSlot(world.t.Context(), repoId, version.SlotId)
		if err != nil {
			world.t.Fatal(err)
		}
		for _, streamEntry := range version.Entries {
			entry := &protocol.RecordEntry{}
			if err := proto.Unmarshal(streamEntry.Entry, entry); err != nil {
				world.t.Fatal(err)
			}
			header, err := sidecar.ParseStoredRecordHeader(entry.GetHeader().GetBody())
			if err != nil {
				world.t.Fatal(err)
			}
			item := &testRecordStored{version: version.Version, path: streamEntry.Path, entry: entry, header: header.Header}
			for _, row := range slot.Rows {
				if row.KeyIndex == entry.GetKeyIndex() {
					key, salt, err := sidecar.RecordSlotRowSplit(row.Row)
					if err != nil {
						world.t.Fatal(err)
					}
					if item.body, err = sidecar.RecordOpen(header, entry.GetSealedBody(), key, salt); err != nil {
						world.t.Fatal(err)
					}
				}
			}
			stored = append(stored, item)
		}
	}
	return stored
}

// Through RecordProjection in a team network with a directory: a claim and a handoff change the calling run's item,
// written to this sidecar's own stream in the directory, an ask goes there as the writer routes it, and under claims
// off a claim is refused, writing nothing.
func TestRecordAppendTeamRoutes(t *testing.T) {
	world := newTestRecordWorld(t)
	directoryId, err := world.streams.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := world.streams.Grant(directoryId, world.readerId, sidecartest.RecordStreamsScope{Read: true}); err != nil {
		t.Fatal(err)
	}
	device := world.device(true)
	world.fixture.Repos[directoryId] = &sidecartest.FakeRecordRepoAuth{
		Readers: []sidecar.Id{world.readerId, device.sidecarId},
		Writers: []sidecar.Id{device.sidecarId},
	}
	if err := world.streams.Grant(directoryId, device.sidecarId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	world.fixture.Logs = &sidecar.RecordLogIds{Team: true, DirectoryId: &directoryId}
	world.publish()
	record := device.open()
	directoryAuth := sidecartest.NewFakeDirectoryAuth()
	memberId := world.memberId
	directoryAuth.Append(&sidecartest.FakeDirectoryAuthFixture{
		Sidecars:    map[sidecar.Id]*sidecartest.FakeDirectorySidecar{device.sidecarId: {MemberId: &memberId}},
		DirectoryId: &directoryId,
	})
	client, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId: device.sidecarId,
		Store:     sidecartest.NewFakeStore().Root(),
		Auth:      func() sidecar.DirectoryAuthView { return directoryAuth.Tip() },
		Clock:     world.clock,
		Settings:  sidecar.DefaultSidecarSettings().Directory,
		Writer:    record.Writer(),
		Runs:      world.runs,
	})
	if err != nil {
		t.Fatal(err)
	}
	projection, err := sidecar.NewRecordProjection(&sidecar.RecordProjectionArgs{Record: record, Directory: func() *sidecar.DirectoryClient { return client }})
	if err != nil {
		t.Fatal(err)
	}
	runId, offRunId := sidecar.NewId(), sidecar.NewId()
	world.runs.StartRun(runId)
	world.runs.StartRun(offRunId)
	for _, start := range []*sidecar.DirectoryRunStart{
		{RunId: runId, Claims: sidecar.DirectoryRunClaimsAuto, Harness: "claude-code", Title: "fix the retry path", Project: "app"},
		{RunId: offRunId, Claims: sidecar.DirectoryRunClaimsOff, Harness: "claude-code", Title: "quiet", Project: "app"},
	} {
		if err := client.Runs().Started(start); err != nil {
			t.Fatal(err)
		}
	}
	claimed, err := projection.Append(t.Context(), &sidecar.RecordAppendArgs{Kind: sidecar.RecordKindClaim, RunId: &runId, Targets: []string{"src/retry/"}, Text: "mine"})
	if err != nil {
		t.Fatal(err)
	}
	if claimed.AnnouncementId == nil || claimed.Version != 1 || claimed.LogId != directoryId {
		t.Fatalf("the claim: %+v", claimed)
	}
	if _, err := projection.Append(t.Context(), &sidecar.RecordAppendArgs{Kind: sidecar.RecordKindHandoff, RunId: &runId, Targets: []string{"agent:reviewer"}, Text: "yours"}); err != nil {
		t.Fatal(err)
	}
	asked, err := projection.Append(t.Context(), &sidecar.RecordAppendArgs{Kind: sidecar.RecordKindAsk, RunId: &runId, Targets: []string{"agent:reviewer"}, Text: "who owns retry?"})
	if err != nil || asked.LogId != directoryId {
		t.Fatalf("the ask: %+v, %v", asked, err)
	}
	if _, err := projection.Append(t.Context(), &sidecar.RecordAppendArgs{Kind: sidecar.RecordKindClaim, RunId: &offRunId, Targets: []string{"src/"}}); !errors.Is(err, sidecar.ErrDirectoryRunsClaimsOff) {
		t.Fatalf("a claim under off: %v", err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	kinds := []sidecar.RecordKind{}
	for _, stored := range testStreamEntries(world, directoryId, device.sidecarId) {
		kinds = append(kinds, sidecar.RecordKind(stored.header.GetKind()))
		if sidecar.RecordKind(stored.header.GetKind()) == sidecar.RecordKindAnnounce {
			item := &protocol.Announcement{}
			if err := proto.Unmarshal(stored.body, item); err != nil {
				t.Fatal(err)
			}
			if len(item.GetClaims()) != 1 || item.GetClaims()[0].GetTargets()[0] != "src/retry/" {
				t.Fatalf("an announced item %v", item)
			}
		}
	}
	if len(kinds) != 3 || kinds[0] != sidecar.RecordKindAnnounce || kinds[1] != sidecar.RecordKindAnnounce || kinds[2] != sidecar.RecordKindAsk {
		t.Fatalf("the directory stream's kinds %v", kinds)
	}
	for _, stored := range world.storedEntries(device.sidecarId) {
		if kind := sidecar.RecordKind(stored.header.GetKind()); kind == sidecar.RecordKindClaim || kind == sidecar.RecordKindHandoff {
			t.Fatalf("a %s entry in the vault in team mode", kind)
		}
	}
}

// The text forms of the claims values parse to the values whose numbers SidecarClaims shares, and nothing else does.
func TestDirectoryRunClaimsParse(t *testing.T) {
	for text, want := range map[string]sidecar.DirectoryRunClaims{"auto": 3, "prompt": 2, "off": 1} {
		value, err := sidecar.ParseDirectoryRunClaims(text)
		if err != nil || value != want || value.String() != text {
			t.Errorf("%s: %d, %v", text, value, err)
		}
	}
	for _, text := range []string{"", "Auto", "on", "none"} {
		if _, err := sidecar.ParseDirectoryRunClaims(text); !errors.Is(err, sidecar.ErrDirectoryFormatInvalid) {
			t.Errorf("%q: %v", text, err)
		}
	}
	if sidecar.DirectoryRunClaims(0).String() != "off" || sidecar.DirectoryRunClaims(9).String() != "off" {
		t.Error("a value off < prompt < auto does not name reads other than off")
	}
}
