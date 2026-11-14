// §22.8's history rule (TEST-M2-02; D-TEST-10, FI-2): "Porcupine checks T3 histories per ref with §11.8's commit
// rule; an unknown outcome has an open end time and matches any result". A History is the record that rule reads,
// kept here as plain data: the operations clients made against refs, each with its actor, its push id and ref, its
// call and return on the history's clock, and how it ended, committed at a version, aborted or unknown. It sits one
// level above the store record behind FI-30 (sidecartest.BlobRecorder): what clients asked of evs and were answered,
// not what evs asked of the store. server's sidecart3.CheckLinearizable runs Porcupine over it, so Porcupine enters
// no sidecar go.mod (plan-TEST-small-readings reading 2, QD-303), and FI-2's oracle (TEST-M2-04) reads the same
// record.
//
// Time is the schedule's order, never wall time: barriers decide what ran first, and a clock that read the time of
// day would order two operations by the scheduler's luck. A history's clock is a counter, which Now moves at every
// call and return a recorder stamps; an operation recorded whole keeps the times it carries, and the clock moves
// past them, so a later stamp follows every time recorded.
//
// What an operation is:
//
//	push  one attempt of a push id, as the instance that took it answered: a client's retry and the lb's re-send of
//	      one request to a second instance are each an attempt of their own, since each may commit (§11.8's retry id
//	      row). An answer that says nothing of its push's fate is no operation, and a recorder leaves it out: a 400,
//	      401 or 429, a 503 that names no unknown outcome, and 409 PARTS_MISSING, which records and refuses nothing
//	      (§11.8's seal row). Its step would be the same in every state, so it constrains nothing.
//	read  one read of a ref's head from its cluster, answering the version it was served at and, where the read
//	      says, the push that committed there. A read through a cache that may lag is no linearizable read, and is
//	      not recorded as one.
//
// An evs world's history (EvsWorld.History) holds every attempt its instances took, from the world's own record of
// them and on its logical clock. The world keeps no record of what its devices read, so that history holds no read.
//
// Safe for concurrent use.

package fault

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// What an operation did: see the file header.
type OperationKind int

const (
	OperationPush OperationKind = iota + 1
	OperationRead
)

// "push" or "read".
func (self OperationKind) String() string {
	switch self {
	case OperationPush:
		return "push"
	case OperationRead:
		return "read"
	}
	return fmt.Sprintf("OperationKind(%d)", int(self))
}

// How an operation ended (FI-2: committed, aborted or unknown).
type Outcome int

const (
	// A push committed at Version, as its answer named, or a read was served Version.
	OutcomeCommitted Outcome = iota + 1
	// A push's answer refused its push id, so no attempt of it ever commits (I-EVS-3). A read is never aborted.
	OutcomeAborted
	// Nothing says what became of it: its answer was lost, it answered 503 {outcome: unknown}, or its instance never
	// answered, killed or still holding it at the end. Its end is open, and it matches any result.
	OutcomeUnknown
)

// "committed", "aborted" or "unknown".
func (self Outcome) String() string {
	switch self {
	case OutcomeCommitted:
		return "committed"
	case OutcomeAborted:
		return "aborted"
	case OutcomeUnknown:
		return "unknown"
	}
	return fmt.Sprintf("Outcome(%d)", int(self))
}

// A ref of a repo: what a check partitions a history by, since each ref has its own commit point.
type HistoryRef struct {
	RepoId sidecar.Id
	RefId  sidecar.Id
}

// The repo's and the ref's key ids, as evs's keys spell them.
func (self HistoryRef) String() string {
	return sidecar.EvsKeyId(self.RepoId) + "/" + sidecar.EvsKeyId(self.RefId)
}

// One operation a client made against a ref, as plain data.
type Operation struct {
	Kind OperationKind
	// Who made it: the client's actor, such as "writerA".
	Actor string
	// Who answered it, such as "evs2", or empty when the client's own answer is all that is known.
	Instance string
	Ref      HistoryRef
	// A push's id. For a read, the push the version it was served names, or zero where the read did not say.
	PushId sidecar.Id
	// When it was called and when it returned, on the history's clock. An unknown outcome's Return is when its answer
	// came, or 0 when none came, and a check takes its end as open either way.
	Call   int64
	Return int64
	// How it ended.
	Outcome Outcome
	// A commit's version, or the version a read was served, 0 naming the ref absent. 0 for any other outcome.
	Version uint64
	// An aborted push's refusal code, as evs answered it, or zero where the recorder does not know it. SHREDDING binds
	// less than the rest: FI-2 lets an attempt validated before its repo's shred began commit after another's
	// SHREDDING refusal, since the shred destroys what it commits (I-EVS-3).
	Code protocol.EvsRefusalCode
	// What answered it, for a person reading a failing check: "evs2 200 v63".
	Answer string
	// How many store requests the Net's blob history held when it was called, so every request at that index or
	// later came after it: what FI-2 orders an attempt against a store write by, such as the repo/ CAS that began a
	// shred (TEST-M2-04). 0 where the recorder does not know it, which no check takes as before anything.
	StoreArrival int
}

// nil for an operation a check can read; otherwise what is wrong with it.
func (self *Operation) Validate() error {
	problems := []string{}
	switch self.Kind {
	case OperationPush:
		if self.PushId == (sidecar.Id{}) {
			problems = append(problems, "a push with no push id")
		}
		switch self.Outcome {
		case OutcomeCommitted:
			if self.Version == 0 {
				problems = append(problems, "a commit at version 0, which is no version")
			}
		case OutcomeAborted, OutcomeUnknown:
			if self.Version != 0 {
				problems = append(problems, fmt.Sprintf("a version, %d, on an outcome that names none", self.Version))
			}
		default:
			problems = append(problems, fmt.Sprintf("no outcome (%v)", self.Outcome))
		}
		if self.Code != protocol.EvsRefusalCode(0) && self.Outcome != OutcomeAborted {
			problems = append(problems, fmt.Sprintf("a refusal code, %s, on a push that was not refused", self.Code))
		}
	case OperationRead:
		if self.Code != protocol.EvsRefusalCode(0) {
			problems = append(problems, fmt.Sprintf("a refusal code, %s, on a read", self.Code))
		}
		switch self.Outcome {
		case OutcomeCommitted:
			if self.Version == 0 && self.PushId != (sidecar.Id{}) {
				problems = append(problems, "a read of an absent ref naming a push")
			}
		case OutcomeUnknown:
			if self.Version != 0 || self.PushId != (sidecar.Id{}) {
				problems = append(problems, "a read of unknown outcome naming what it was served")
			}
		case OutcomeAborted:
			problems = append(problems, "an aborted read: a read has no refusal that binds a push")
		default:
			problems = append(problems, fmt.Sprintf("no outcome (%v)", self.Outcome))
		}
	default:
		problems = append(problems, fmt.Sprintf("no kind (%v)", self.Kind))
	}
	if self.Ref.RepoId == (sidecar.Id{}) || self.Ref.RefId == (sidecar.Id{}) {
		problems = append(problems, "no ref")
	}
	if self.Call <= 0 {
		problems = append(problems, fmt.Sprintf("a call at %d, before the history's clock starts", self.Call))
	}
	switch {
	case self.Return == 0 && self.Outcome != OutcomeUnknown:
		problems = append(problems, "no return, which only an unknown outcome may lack")
	case self.Return != 0 && self.Return < self.Call:
		problems = append(problems, fmt.Sprintf("a return at %d before its call at %d", self.Return, self.Call))
	}
	if 0 < len(problems) {
		return fmt.Errorf("%s: %s", self, strings.Join(problems, "; "))
	}
	return nil
}

// "[3, 5] writerA push <id> at evs1: committed v1 (evs1 200 v1)".
func (self *Operation) String() string {
	var text strings.Builder
	if self.Return == 0 {
		fmt.Fprintf(&text, "[%d, open] ", self.Call)
	} else {
		fmt.Fprintf(&text, "[%d, %d] ", self.Call, self.Return)
	}
	fmt.Fprintf(&text, "%s %s", self.Actor, self.Kind)
	if self.Kind == OperationPush {
		fmt.Fprintf(&text, " %s", self.PushId)
	}
	if self.Instance != "" {
		fmt.Fprintf(&text, " at %s", self.Instance)
	}
	fmt.Fprintf(&text, ": %s", self.Outcome)
	if self.Outcome == OutcomeCommitted {
		fmt.Fprintf(&text, " v%d", self.Version)
		if self.Kind == OperationRead && self.PushId != (sidecar.Id{}) {
			fmt.Fprintf(&text, " by %s", self.PushId)
		}
	}
	if self.Answer != "" {
		fmt.Fprintf(&text, " (%s)", self.Answer)
	}
	return text.String()
}

// See the file header.
type History struct {
	name string

	stateLock sync.Mutex
	// the latest time stamped or recorded
	clock      int64
	operations []*Operation
}

// An empty history, named for what it records, such as its schedule's id.
func NewHistory(name string) *History {
	return &History{name: name}
}

// What the history records, as NewHistory named it.
func (self *History) Name() string {
	return self.name
}

// A time after every time the history has stamped or recorded: what a recorder stamps a call or a return with.
func (self *History) Now() int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.clock += 1
	return self.clock
}

// Appends a copy of operation, as given: a malformed one is kept, and fails every check that reads it (Validate),
// rather than being left out. The clock moves past its times.
func (self *History) Record(operation *Operation) {
	copied := *operation
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.clock = max(self.clock, copied.Call, copied.Return)
	self.operations = append(self.operations, &copied)
}

// Every operation, in the order recorded, each a copy.
func (self *History) Operations() []*Operation {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	operations := make([]*Operation, 0, len(self.operations))
	for _, operation := range self.operations {
		copied := *operation
		operations = append(operations, &copied)
	}
	return operations
}

// Each ref an operation names, in the order first recorded.
func (self *History) Refs() []HistoryRef {
	refs := []HistoryRef{}
	for _, operation := range self.Operations() {
		if !slices.Contains(refs, operation.Ref) {
			refs = append(refs, operation.Ref)
		}
	}
	return refs
}

// nil when every operation is one a check can read; otherwise each that is not, with its place in the history.
func (self *History) Validate() error {
	errs := []error{}
	for index, operation := range self.Operations() {
		if err := operation.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s's operation %d: %w", self.name, index, err))
		}
	}
	return errors.Join(errs...)
}

// The world's pushes as a history named name: each attempt an instance took (Attempts), with its times on the world's
// logical clock, made by the device that posted its push id, at main, which is the one ref a world's devices write.
// An attempt its instance never answered, and one answered 503 {outcome: unknown}, is unknown; a 200 commits at the
// version it names; an answer that refuses aborts its push id; and an answer that refuses nothing is left out (the
// file header). A device's own view of each push, the lb's answer, repeats an instance's answer, or reports that
// none came, which the instances' unanswered attempts already hold, so it adds no operation.
func (self *EvsWorld) History(name string) *History {
	history := NewHistory(name)
	pushIdDevices := map[sidecar.Id]string{}
	for _, push := range self.Pushes() {
		pushIdDevices[push.PushId] = push.Device
	}
	ref := HistoryRef{RepoId: self.RepoId, RefId: self.RefId()}
	for _, attempt := range self.Attempts() {
		operation := &Operation{
			Kind:         OperationPush,
			Actor:        pushIdDevices[attempt.PushId],
			Instance:     attempt.Instance,
			Ref:          ref,
			PushId:       attempt.PushId,
			Call:         attempt.Call,
			Return:       attempt.Return,
			StoreArrival: attempt.StoreArrival,
		}
		answer := attempt.Answer
		switch {
		case answer == nil:
			operation.Outcome = OutcomeUnknown
			operation.Return = 0
			operation.Answer = attempt.Instance + " never answered"
		case answer.Unknown:
			operation.Outcome = OutcomeUnknown
			operation.Answer = answer.String()
		case answer.Status == http.StatusOK:
			operation.Outcome = OutcomeCommitted
			operation.Version = answer.Version
			operation.Answer = answer.String()
		case answer.Refuses() && answer.Code != protocol.EvsRefusalCode_EVS_REFUSAL_PARTS_MISSING:
			operation.Outcome = OutcomeAborted
			operation.Code = answer.Code
			operation.Answer = answer.String()
		default:
			continue
		}
		history.Record(operation)
	}
	return history
}
