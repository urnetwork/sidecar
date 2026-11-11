// The history's own contract (history.go): one clock for what recorders stamp and what they record whole, copies in
// and out, and every malformed operation kept and named rather than dropped.

package fault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

func historyTestRef() HistoryRef {
	return HistoryRef{RepoId: sidecar.NewId(), RefId: sidecar.NewId()}
}

func TestHistoryStampsAndRecordsOnOneClock(t *testing.T) {
	history := NewHistory("one clock")
	ref := historyTestRef()
	pushId := sidecar.NewId()
	call := history.Now()
	operation := &Operation{Kind: OperationPush, Actor: "writerA", Ref: ref, PushId: pushId, Call: call, Return: history.Now(), Outcome: OutcomeCommitted, Version: 1}
	history.Record(operation)
	if operation.Call != 1 || operation.Return != 2 {
		t.Fatalf("the first stamps were %d and %d", operation.Call, operation.Return)
	}
	// an operation recorded whole keeps its times, and the clock moves past them
	history.Record(&Operation{Kind: OperationPush, Actor: "writerB", Ref: ref, PushId: sidecar.NewId(), Call: 10, Outcome: OutcomeUnknown})
	history.Record(&Operation{Kind: OperationRead, Actor: "reader", Ref: ref, PushId: pushId, Call: 12, Return: 20, Outcome: OutcomeCommitted, Version: 1})
	if now := history.Now(); now != 21 {
		t.Fatalf("the clock read %d after a return at 20", now)
	}
	// recording an older time does not move the clock back
	history.Record(&Operation{Kind: OperationRead, Actor: "reader", Ref: ref, Call: 3, Return: 4, Outcome: OutcomeCommitted})
	if now := history.Now(); now != 22 {
		t.Fatalf("the clock read %d after recording times below it", now)
	}

	// copies in and out
	operation.Version = 7
	operations := history.Operations()
	if len(operations) != 4 || operations[0].Version != 1 {
		t.Fatalf("a change to a recorded operation reached the history: %v", operations)
	}
	operations[1].Outcome = OutcomeAborted
	if history.Operations()[1].Outcome != OutcomeUnknown {
		t.Fatal("a change to a returned operation reached the history")
	}
	if err := history.Validate(); err != nil {
		t.Fatal(err)
	}
	if refs := history.Refs(); len(refs) != 1 || refs[0] != ref {
		t.Fatalf("refs %v, want the one ref", refs)
	}
}

func TestHistoryRefsInTheOrderFirstRecorded(t *testing.T) {
	history := NewHistory("refs")
	first := historyTestRef()
	second := historyTestRef()
	for index, ref := range []HistoryRef{first, second, first, second} {
		history.Record(&Operation{Kind: OperationRead, Actor: "reader", Ref: ref, Call: int64(2*index + 1), Return: int64(2*index + 2), Outcome: OutcomeCommitted})
	}
	refs := history.Refs()
	if len(refs) != 2 || refs[0] != first || refs[1] != second {
		t.Fatalf("refs %v, want %v then %v", refs, first, second)
	}
}

// Each malformed operation is kept and named by its place, so a check fails on it rather than reading a history that
// quietly lacks it.
func TestHistoryKeepsAMalformedOperationAndNamesIt(t *testing.T) {
	ref := historyTestRef()
	pushId := sidecar.NewId()
	valid := []*Operation{
		{Kind: OperationPush, Actor: "writerA", Instance: "evs1", Ref: ref, PushId: pushId, Call: 1, Return: 2, Outcome: OutcomeCommitted, Version: 1},
		{Kind: OperationPush, Actor: "writerA", Instance: "evs2", Ref: ref, PushId: pushId, Call: 3, Outcome: OutcomeUnknown},
		{Kind: OperationPush, Actor: "writerA", Instance: "evs2", Ref: ref, PushId: pushId, Call: 3, Return: 4, Outcome: OutcomeUnknown},
		{Kind: OperationPush, Actor: "writerB", Ref: ref, PushId: sidecar.NewId(), Call: 5, Return: 5, Outcome: OutcomeAborted},
		{Kind: OperationRead, Actor: "reader", Ref: ref, Call: 6, Return: 7, Outcome: OutcomeCommitted},
		{Kind: OperationRead, Actor: "reader", Ref: ref, PushId: pushId, Call: 6, Return: 7, Outcome: OutcomeCommitted, Version: 1},
		{Kind: OperationRead, Actor: "reader", Ref: ref, Call: 8, Outcome: OutcomeUnknown},
	}
	for _, operation := range valid {
		if err := operation.Validate(); err != nil {
			t.Errorf("a well-formed operation refused: %v", err)
		}
	}
	type malformed struct {
		operation *Operation
		problem   string
	}
	cases := []malformed{
		{operation: &Operation{Kind: OperationPush, Ref: ref, Call: 1, Return: 2, Outcome: OutcomeCommitted, Version: 1}, problem: "no push id"},
		{operation: &Operation{Kind: OperationPush, Ref: ref, PushId: pushId, Call: 1, Return: 2, Outcome: OutcomeCommitted}, problem: "version 0"},
		{operation: &Operation{Kind: OperationPush, Ref: ref, PushId: pushId, Call: 1, Return: 2, Outcome: OutcomeAborted, Version: 3}, problem: "names none"},
		{operation: &Operation{Kind: OperationPush, Ref: ref, PushId: pushId, Call: 1, Outcome: OutcomeUnknown, Version: 1}, problem: "names none"},
		{operation: &Operation{Kind: OperationPush, Ref: ref, PushId: pushId, Call: 1, Return: 2}, problem: "no outcome"},
		{operation: &Operation{Kind: OperationRead, Ref: ref, Call: 1, Return: 2, Outcome: OutcomeAborted}, problem: "aborted read"},
		{operation: &Operation{Kind: OperationRead, Ref: ref, PushId: pushId, Call: 1, Return: 2, Outcome: OutcomeCommitted}, problem: "absent ref naming a push"},
		{operation: &Operation{Kind: OperationRead, Ref: ref, Call: 1, Outcome: OutcomeUnknown, Version: 2}, problem: "unknown outcome naming"},
		{operation: &Operation{Ref: ref, PushId: pushId, Call: 1, Return: 2, Outcome: OutcomeCommitted, Version: 1}, problem: "no kind"},
		{operation: &Operation{Kind: OperationPush, PushId: pushId, Call: 1, Return: 2, Outcome: OutcomeCommitted, Version: 1}, problem: "no ref"},
		{operation: &Operation{Kind: OperationPush, Ref: HistoryRef{RepoId: ref.RepoId}, PushId: pushId, Call: 1, Return: 2, Outcome: OutcomeCommitted, Version: 1}, problem: "no ref"},
		{operation: &Operation{Kind: OperationPush, Ref: ref, PushId: pushId, Return: 2, Outcome: OutcomeCommitted, Version: 1}, problem: "before the history's clock starts"},
		{operation: &Operation{Kind: OperationPush, Ref: ref, PushId: pushId, Call: 1, Outcome: OutcomeCommitted, Version: 1}, problem: "only an unknown outcome may lack"},
		{operation: &Operation{Kind: OperationPush, Ref: ref, PushId: pushId, Call: 4, Return: 3, Outcome: OutcomeAborted}, problem: "before its call"},
	}
	history := NewHistory("malformed")
	for _, operation := range valid {
		history.Record(operation)
	}
	for _, c := range cases {
		err := c.operation.Validate()
		if err == nil || !strings.Contains(err.Error(), c.problem) {
			t.Errorf("%s: %v, want %q", c.operation, err, c.problem)
		}
		history.Record(c.operation)
	}
	if count := len(history.Operations()); count != len(valid)+len(cases) {
		t.Fatalf("the history holds %d operations of %d recorded", count, len(valid)+len(cases))
	}
	err := history.Validate()
	if err == nil {
		t.Fatal("a history of malformed operations validated")
	}
	for index := range cases {
		if place := fmt.Sprintf("operation %d:", len(valid)+index); !strings.Contains(err.Error(), place) {
			t.Errorf("the history's error does not name %q: %v", place, err)
		}
	}
	for index := range valid {
		if place := fmt.Sprintf("operation %d:", index); strings.Contains(err.Error(), place) {
			t.Errorf("the history's error names a well-formed %q", place)
		}
	}
}
