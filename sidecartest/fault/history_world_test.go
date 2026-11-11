//go:build sidecar_testhooks

// An evs world's history (history.go's EvsWorld.History), read from FS-1's and FS-58's runs on T2: each instance's
// attempt one operation by the device that posted it, the unanswered and the unknown open, the refused aborted, what
// refuses nothing left out, and every committed version of main named by exactly one push id, as the head holds it.
// The schedules hold evs instances at barriers, so they need the sidecar_testhooks tag.

package fault

import (
	"context"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One fixed run of builder's schedule alone, refusal or not, on a T2 Net, and the history its world left.
func historyWorldRun(t *testing.T, builder Builder) (*EvsWorld, *History, uint64) {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	schedule := builder(net)
	schedule.Twin = nil
	schedule.Refuses = ""
	if result := Run(t.Context(), schedule, net); result.Err != nil {
		t.Fatalf("%s", result)
	}
	world := EvsWorldOf(net)
	if world == nil {
		t.Fatalf("%s made no evs world", schedule.Id)
	}
	head, err := world.Head(context.Background())
	if err != nil || head == nil {
		t.Fatalf("main's head: %v, %v", head, err)
	}
	return world, world.History(schedule.Id), head.GetVersion()
}

// Every operation names main; no version is named by two push ids, nor a push id at two versions; and each version of
// main through headVersion is named by a committed operation, or is one an unknown push id that never answered a
// commit can have taken, one version each.
func historyWorldCheckVersions(t *testing.T, world *EvsWorld, history *History, headVersion uint64) {
	t.Helper()
	if err := history.Validate(); err != nil {
		t.Fatal(err)
	}
	main := HistoryRef{RepoId: world.RepoId, RefId: world.RefId()}
	if refs := history.Refs(); len(refs) != 1 || refs[0] != main {
		t.Fatalf("refs %v, want main's alone (%s)", refs, main)
	}
	versionPushIds := map[uint64]sidecar.Id{}
	pushIdVersions := map[sidecar.Id]uint64{}
	unknownPushIds := map[sidecar.Id]bool{}
	for _, operation := range history.Operations() {
		switch operation.Outcome {
		case OutcomeUnknown:
			unknownPushIds[operation.PushId] = true
			continue
		case OutcomeCommitted:
		default:
			continue
		}
		if headVersion < operation.Version {
			t.Fatalf("%s commits above main's head at v%d", operation, headVersion)
		}
		if seen, ok := versionPushIds[operation.Version]; ok && seen != operation.PushId {
			t.Fatalf("v%d named by %s and by %s", operation.Version, seen, operation.PushId)
		}
		if seen, ok := pushIdVersions[operation.PushId]; ok && seen != operation.Version {
			t.Fatalf("%s committed at v%d and at v%d", operation.PushId, seen, operation.Version)
		}
		versionPushIds[operation.Version] = operation.PushId
		pushIdVersions[operation.PushId] = operation.Version
	}
	openCount := 0
	for pushId := range unknownPushIds {
		if _, ok := pushIdVersions[pushId]; !ok {
			openCount += 1
		}
	}
	unnamedCount := 0
	for version := uint64(1); version <= headVersion; version += 1 {
		if _, ok := versionPushIds[version]; !ok {
			unnamedCount += 1
		}
	}
	if openCount < unnamedCount {
		t.Fatalf("main holds %d versions no committed operation names, and %d unknown push ids answered no commit", unnamedCount, openCount)
	}
}

// FS-1's registered case: P's attempt on evs1, killed at its applied CAS, is unknown with no return, and its attempt
// on evs2 commits at P's original version; every other attempt is writerB's commit.
func TestEvsWorldHistoryOfFs1(t *testing.T) {
	world, history, headVersion := historyWorldRun(t, Fs1LostAnswerRetriedOnEvs2)
	historyWorldCheckVersions(t, world, history, headVersion)
	version, pushId, err := world.CommittedVersion("writerA", "p.bin")
	if err != nil {
		t.Fatal(err)
	}
	unknownCount := 0
	for _, operation := range history.Operations() {
		switch {
		case operation.Outcome == OutcomeUnknown:
			unknownCount += 1
			if operation.PushId != pushId || operation.Actor != "writerA" || operation.Instance != "evs1" || operation.Return != 0 {
				t.Errorf("an unknown operation other than P's killed attempt: %s", operation)
			}
		case operation.PushId == pushId:
			if operation.Actor != "writerA" || operation.Instance != "evs2" || operation.Outcome != OutcomeCommitted || operation.Version != version {
				t.Errorf("P's retry: %s, want writerA's commit at v%d on evs2", operation, version)
			}
		case operation.Actor != "writerB" || operation.Instance != "evs3" || operation.Outcome != OutcomeCommitted:
			t.Errorf("an operation that is no writerB commit on evs3: %s", operation)
		}
	}
	if unknownCount != 1 {
		t.Fatalf("%d unknown operations, want P's killed attempt alone", unknownCount)
	}
	if count := len(history.Operations()); count != int(headVersion)+1 {
		t.Fatalf("%d operations for %d versions, want one each and P's retry", count, headVersion)
	}
}

// FS-1's unknown clause: P's attempt whose CAS applied and whose rereads all failed answers 503 {outcome: unknown},
// unknown with its return kept; every retry that read nothing refuses nothing and is no operation.
func TestEvsWorldHistoryOfAnUnknownAnswer(t *testing.T) {
	world, history, headVersion := historyWorldRun(t, Fs1UnknownDeletesNothing)
	historyWorldCheckVersions(t, world, history, headVersion)
	pushes := world.DevicePushes("writerA")
	push := pushes[len(pushes)-1]
	if answers := push.InstanceAnswers(); len(answers) < 2 {
		t.Fatalf("P was answered %v, and the clause retries it", answers)
	}
	operations := []*Operation{}
	for _, operation := range history.Operations() {
		if operation.PushId == push.PushId {
			operations = append(operations, operation)
		}
	}
	if len(operations) != 1 {
		t.Fatalf("P is %d operations, want its unknown attempt alone: %v", len(operations), operations)
	}
	operation := operations[0]
	if operation.Outcome != OutcomeUnknown || operation.Return == 0 || operation.Instance != "evs1" || !strings.Contains(operation.Answer, "unknown") {
		t.Fatalf("P's attempt: %s, want evs1's answered unknown", operation)
	}
}

// FS-58's registered case: A's change of x.txt, refused 409 naming it, is one aborted operation.
func TestEvsWorldHistoryOfARefusal(t *testing.T) {
	world, history, headVersion := historyWorldRun(t, Fs58FoldBetweenReadAndRerun)
	historyWorldCheckVersions(t, world, history, headVersion)
	pushes := world.DevicePushes("writerA")
	refused := pushes[len(pushes)-1]
	abortedCount := 0
	for _, operation := range history.Operations() {
		if operation.Outcome == OutcomeUnknown {
			t.Errorf("an unknown operation in a run that lost no answer: %s", operation)
		}
		if operation.Outcome != OutcomeAborted {
			continue
		}
		abortedCount += 1
		if operation.PushId != refused.PushId || operation.Actor != "writerA" || operation.Instance != "evs1" || !strings.Contains(operation.Answer, "PATH_CONFLICT") {
			t.Errorf("an aborted operation other than A's refusal: %s", operation)
		}
	}
	if abortedCount != 1 {
		t.Fatalf("%d aborted operations, want A's refusal alone", abortedCount)
	}
}
