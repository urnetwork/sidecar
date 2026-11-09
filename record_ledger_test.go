// D-MCP-11's ledger (record_ledger.go): each use reserved once and never given back, the retry path, the restart
// list, a Failed file refusing every spend, and retention on a fake clock.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A clock a record test moves by hand. Its timers never fire: nothing here waits.
type recordTestClock struct {
	stateLock sync.Mutex
	at        time.Time
}

// A fixed date, so a test repeats.
func newRecordTestClock() *recordTestClock {
	return &recordTestClock{at: time.Date(2026, time.November, 8, 9, 10, 11, 0, time.UTC)}
}

// See Clock.
func (self *recordTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.at
}

// See Clock.
func (self *recordTestClock) After(timeout time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

// See Clock.
func (self *recordTestClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}

// Moves the clock.
func (self *recordTestClock) advance(by time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.at = self.at.Add(by)
}

// An enrolled, unlocked instance, its medium, and a ledger on it.
func newTestLedger(t *testing.T) (*SidecarInstance, SidecarStoreBackend, *ApprovalLedger, *recordTestClock) {
	t.Helper()
	instance, backend, _ := enrolledInstance(t)
	clock := newRecordTestClock()
	ledger, err := NewApprovalLedger(instance.Store(&testNetworkId), defaultSidecarMcpSettings(), clock)
	if err != nil {
		t.Fatal(err)
	}
	return instance, backend, ledger, clock
}

// A 32-byte value named by label, for an action id, a payload hash or an effect key.
func ledgerTestHash(label string) []byte {
	sum := sha256.Sum256([]byte(label))
	return sum[:]
}

// Reserves action's use under a hold, as spend steps 1 to 4 do.
func reserveTestUse(t *testing.T, ledger *ApprovalLedger, approvalId Id, action string, uses uint32) (*ApprovalReserve, bool, error) {
	t.Helper()
	hold := ledger.Hold(approvalId)
	defer hold.Release()
	return hold.Reserve(ledgerTestHash("action "+action), ledgerTestHash("payload "+action), ledgerTestHash("effect "+action), uses)
}

func TestReserveTakesTheNextUse(t *testing.T) {
	_, _, ledger, _ := newTestLedger(t)
	approvalId := NewId()
	for i, action := range []string{"a", "b", "c"} {
		reserve, created, err := reserveTestUse(t, ledger, approvalId, action, 3)
		if err != nil || !created {
			t.Fatalf("use %d: created %v, err %v", i, created, err)
		}
		if reserve.UseIndex != uint32(i) || !bytes.Equal(reserve.EffectKey, ledgerTestHash("effect "+action)) {
			t.Errorf("use %d: %+v", i, reserve)
		}
	}
	if uses, err := ledger.Uses(approvalId); err != nil || uses != 3 {
		t.Errorf("uses %d, err %v", uses, err)
	}
	if _, _, err := reserveTestUse(t, ledger, approvalId, "d", 3); !errors.Is(err, ErrApprovalSpent) {
		t.Errorf("a fourth use answered %v", err)
	}
}

// Spend step 2: the same action again finds its Reserve and takes no new use.
func TestReserveRetryFindsTheSameUse(t *testing.T) {
	_, _, ledger, _ := newTestLedger(t)
	approvalId := NewId()
	first, _, err := reserveTestUse(t, ledger, approvalId, "a", 1)
	if err != nil {
		t.Fatal(err)
	}
	again, created, err := reserveTestUse(t, ledger, approvalId, "a", 1)
	if err != nil || created || again.UseIndex != first.UseIndex {
		t.Errorf("retry: created %v, err %v, %+v", created, err, again)
	}
	if uses, _ := ledger.Uses(approvalId); uses != 1 {
		t.Errorf("uses %d after a retry", uses)
	}
	found, err := ledger.FindReserve(approvalId, ledgerTestHash("action a"))
	if err != nil || found == nil || found.UseIndex != 0 {
		t.Errorf("found %+v, err %v", found, err)
	}
}

// A use stays consumed whatever its outcome, so no other action takes it (AU3).
func TestReserveNeverRemoved(t *testing.T) {
	_, _, ledger, _ := newTestLedger(t)
	approvalId := NewId()
	if _, _, err := reserveTestUse(t, ledger, approvalId, "a", 1); err != nil {
		t.Fatal(err)
	}
	for _, state := range []ApprovalOutcomeState{ApprovalOutcomeUncertain, ApprovalOutcomeNotDone} {
		err := ledger.Append(approvalId, &ApprovalOutcome{ActionId: ledgerTestHash("action a"), State: state, Millis: 1})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := reserveTestUse(t, ledger, approvalId, "b", 1); !errors.Is(err, ErrApprovalSpent) {
			t.Errorf("after %s another action answered %v", state, err)
		}
	}
	state, err := ledger.State(approvalId)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Reserves) != 1 || state.Outcome(ledgerTestHash("action a")).State != ApprovalOutcomeNotDone {
		t.Errorf("state %+v", state)
	}
	// a done after a not_done changes nothing: the first final outcome stands
	err = ledger.Append(approvalId, &ApprovalOutcome{ActionId: ledgerTestHash("action a"), State: ApprovalOutcomeDone, Millis: 2})
	if err != nil {
		t.Fatal(err)
	}
	if state, _ := ledger.State(approvalId); state.Outcome(ledgerTestHash("action a")).State != ApprovalOutcomeNotDone {
		t.Error("a later outcome replaced a final one")
	}
}

func TestReserveRefusesCancelled(t *testing.T) {
	_, _, ledger, _ := newTestLedger(t)
	approvalId := NewId()
	if _, _, err := reserveTestUse(t, ledger, approvalId, "a", 3); err != nil {
		t.Fatal(err)
	}
	hold := ledger.Hold(approvalId)
	if err := hold.Cancel(NewId()); err != nil {
		t.Fatal(err)
	}
	hold.Release()
	if _, _, err := reserveTestUse(t, ledger, approvalId, "b", 3); !errors.Is(err, ErrApprovalCancelled) {
		t.Errorf("a use after a cancel answered %v", err)
	}
	// the use reserved before the cancel still completes, by its retry path
	if reserve, created, err := reserveTestUse(t, ledger, approvalId, "a", 3); err != nil || created || reserve == nil {
		t.Errorf("retry after cancel: created %v, err %v", created, err)
	}
}

// An outcome only follows a Reserve, and a Reserve or a Cancel only goes through a hold.
func TestLedgerRowsKeepTheirOrder(t *testing.T) {
	_, _, ledger, _ := newTestLedger(t)
	approvalId := NewId()
	if err := ledger.Append(approvalId, &ApprovalOutcome{ActionId: ledgerTestHash("x"), State: ApprovalOutcomeDone}); err == nil {
		t.Error("an outcome for no reserve was taken")
	}
	if err := ledger.Append(approvalId, &ApprovalReserve{}); err == nil {
		t.Error("a reserve outside a hold was taken")
	}
	if err := ledger.Append(approvalId, &ApprovalCancelRow{}); err == nil {
		t.Error("a cancel outside a hold was taken")
	}
}

func TestUnresolvedListsReserveWithoutOutcome(t *testing.T) {
	_, _, ledger, _ := newTestLedger(t)
	first := NewId()
	second := NewId()
	for _, action := range []string{"done", "uncertain", "none"} {
		if _, _, err := reserveTestUse(t, ledger, first, action, 3); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := reserveTestUse(t, ledger, second, "other", 1); err != nil {
		t.Fatal(err)
	}
	appendOutcome := func(action string, state ApprovalOutcomeState) {
		err := ledger.Append(first, &ApprovalOutcome{ActionId: ledgerTestHash("action " + action), State: state, Millis: 5})
		if err != nil {
			t.Fatal(err)
		}
	}
	appendOutcome("done", ApprovalOutcomeDone)
	appendOutcome("uncertain", ApprovalOutcomeUncertain)
	unresolved, err := ledger.Unresolved()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, item := range unresolved {
		if item.Err != nil {
			t.Fatal(item.Err)
		}
		for _, action := range []string{"done", "uncertain", "none", "other"} {
			if bytes.Equal(item.Reserve.ActionId, ledgerTestHash("action "+action)) {
				got[action] = item.Uncertain
			}
		}
	}
	if len(got) != 3 || !got["uncertain"] || got["none"] || got["other"] {
		t.Errorf("unresolved %v", got)
	}
	if _, listed := got["done"]; listed {
		t.Error("a done use is listed")
	}
}

// A file whose bytes fail reads Failed, and nothing spends from it: State, Reserve and the restart list all say so.
func TestLedgerFailedRefusesToSpend(t *testing.T) {
	_, backend, ledger, _ := newTestLedger(t)
	approvalId := NewId()
	if _, _, err := reserveTestUse(t, ledger, approvalId, "a", 2); err != nil {
		t.Fatal(err)
	}
	path := networkFilePath(testNetworkId, approvalLedgerDirectoryName+"/"+approvalLedgerName(approvalId))
	content := readBackend(t, backend, path)
	content[len(content)-1] ^= 0x01
	putBackendFile(t, backend, path, content)
	if _, err := ledger.State(approvalId); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("state answered %v", err)
	}
	if _, _, err := reserveTestUse(t, ledger, approvalId, "b", 2); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("reserve answered %v", err)
	}
	unresolved, err := ledger.Unresolved()
	if err != nil || len(unresolved) != 1 || !errors.Is(unresolved[0].Err, ErrSidecarStoreFailed) {
		t.Errorf("unresolved %+v, err %v", unresolved, err)
	}
}

// A row of a kind this build does not know, as RECORD's Decide, is kept and read back whole.
type ledgerTestDecideRow struct {
	RequestId      Id    `json:"request_id"`
	Step           int   `json:"step"`
	NotAfterMillis int64 `json:"not_after_millis"`
}

// See ApprovalLedgerRowBody.
func (self *ledgerTestDecideRow) ApprovalLedgerRowKind() ApprovalLedgerRowKind {
	return "decide"
}

func TestLedgerKeepsRowsOfOtherKinds(t *testing.T) {
	_, _, ledger, _ := newTestLedger(t)
	requestId := NewId()
	row := &ledgerTestDecideRow{RequestId: requestId, Step: 2, NotAfterMillis: 1234}
	if err := ledger.Append(requestId, row); err != nil {
		t.Fatal(err)
	}
	state, err := ledger.State(requestId)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Rows) != 1 || state.Rows[0].Kind != "decide" {
		t.Fatalf("rows %+v", state.Rows)
	}
	got := &ledgerTestDecideRow{}
	if err := json.Unmarshal(state.Rows[0].Body, got); err != nil || *got != *row {
		t.Errorf("read back %+v, err %v", got, err)
	}
	if notAfterMillis, ok := state.NotAfterMillis(); !ok || notAfterMillis != 1234 {
		t.Errorf("not_after %d, %v", notAfterMillis, ok)
	}
}

// The request and each decision are kept as stored, and their expiry dates the file.
func TestLedgerKeepsRequestAndDecisionBytes(t *testing.T) {
	_, _, ledger, clock := newTestLedger(t)
	approvalId := NewId()
	notAfter := clock.Now().Add(time.Hour)
	request, err := proto.Marshal(&protocol.ApprovalRequest{ApprovalId: approvalId.Bytes(), NotAfterMillis: notAfter.UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Append(approvalId, &ApprovalRequestRow{Request: request}); err != nil {
		t.Fatal(err)
	}
	decision := []byte("synthetic signed decision bytes")
	if err := ledger.Append(approvalId, &ApprovalDecisionRow{Decision: decision}); err != nil {
		t.Fatal(err)
	}
	state, err := ledger.State(approvalId)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(state.Request, request) || len(state.Decisions) != 1 || !bytes.Equal(state.Decisions[0], decision) {
		t.Errorf("state %+v", state)
	}
	if notAfterMillis, ok := state.NotAfterMillis(); !ok || notAfterMillis != notAfter.UnixMilli() {
		t.Errorf("not_after %d, %v", notAfterMillis, ok)
	}
}

// Files go 30 days after their not_after, and not before; one with no expiry stays.
func TestLedgerRetention(t *testing.T) {
	_, _, ledger, clock := newTestLedger(t)
	dated := NewId()
	undated := NewId()
	notAfter := clock.Now().Add(time.Hour)
	request, err := proto.Marshal(&protocol.ApprovalRequest{ApprovalId: dated.Bytes(), NotAfterMillis: notAfter.UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Append(dated, &ApprovalRequestRow{Request: request}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reserveTestUse(t, ledger, undated, "a", 1); err != nil {
		t.Fatal(err)
	}
	clock.advance(time.Hour + 30*24*time.Hour - time.Minute)
	if removed, err := ledger.Sweep(context.Background()); err != nil || removed != 0 {
		t.Fatalf("early sweep removed %d, err %v", removed, err)
	}
	clock.advance(2 * time.Minute)
	if removed, err := ledger.Sweep(context.Background()); err != nil || removed != 1 {
		t.Fatalf("sweep removed %d, err %v", removed, err)
	}
	if state, err := ledger.State(dated); err != nil || len(state.Rows) != 0 {
		t.Errorf("the swept file still reads %+v, err %v", state, err)
	}
	if uses, err := ledger.Uses(undated); err != nil || uses != 1 {
		t.Errorf("the undated file: uses %d, err %v", uses, err)
	}
}

// Racers for an approval's last use, each holding the mutex in turn: exactly one reserves it (AU1).
func TestRacingReservesTakeOneUse(t *testing.T) {
	_, _, ledger, _ := newTestLedger(t)
	approvalId := NewId()
	var group sync.WaitGroup
	var stateLock sync.Mutex
	createdCount := 0
	spentCount := 0
	for i := 0; i < 8; i += 1 {
		group.Add(1)
		go func() {
			defer group.Done()
			hold := ledger.Hold(approvalId)
			defer hold.Release()
			action := string(rune('a' + i))
			_, created, err := hold.Reserve(ledgerTestHash(action), ledgerTestHash("p"+action), ledgerTestHash("e"+action), 1)
			stateLock.Lock()
			defer stateLock.Unlock()
			if created {
				createdCount += 1
			}
			if errors.Is(err, ErrApprovalSpent) {
				spentCount += 1
			}
		}()
	}
	group.Wait()
	if createdCount != 1 || spentCount != 7 {
		t.Errorf("created %d, spent %d", createdCount, spentCount)
	}
}

// A Sidecar keeps one ledger, so every spend of an approval takes the same mutex, and none before enrollment.
func TestSidecarKeepsOneLedger(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	sidecar := &Sidecar{instance: instance, settings: validSidecarSettings()}
	if _, err := sidecar.ApprovalLedger(); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("before enrollment the ledger answered %v", err)
	}
	if _, err := OpenSidecarStoreLog(sidecar.LocalStore(), "x"); !errors.Is(err, ErrSidecarStoreNoClass) {
		t.Errorf("before enrollment a store's log answered %v", err)
	}
	networkId := testNetworkId
	sidecar.networkId = &networkId
	first, err := sidecar.ApprovalLedger()
	if err != nil {
		t.Fatal(err)
	}
	second, err := sidecar.ApprovalLedger()
	if err != nil || first != second {
		t.Errorf("a second ledger: %v", err)
	}
	if _, _, err := reserveTestUse(t, first, NewId(), "a", 1); err != nil {
		t.Error(err)
	}
}
