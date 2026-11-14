// fault.Ledger (TEST-M2-04; FI-2, D-TEST-10): the running record of every operation a schedule's clients made and
// how each ended, kept per Net as the run goes, and what evs served each read. FI-2 reads it against the stores; it
// is the client's view of the same operations FI-1 and FI-6 read from durable state, so an oracle that must not call
// an operation done, or reclaimable, while some client still waits on it asks the ledger which are unknown.
//
//	sources   a world that keeps its own record of attempts adds itself as a source (AddSource), and the ledger
//	          reads it whole at each look: an evs world's instances' attempts, as EvsWorld.History gives them. A
//	          source's times are on its own clock, so the ledger orders one source's operations by time and never
//	          compares two sources' times; StoreArrival, the Net's blob history index at the call, is the one order
//	          every source shares
//	records   a recorder with no record of its own records each operation as it ends (Record), its times from the
//	          ledger's own clock (Now) and its StoreArrival from the Net (StoreArrival)
//	pushes    one push id's attempts together (Pushes): committed once any attempt answered 200, aborted once any
//	          answered a refusal that binds (every refusal but PUSH_ID_REUSED, which refuses another statement under a
//	          committed push id), and unknown while neither holds. Unknown is the running set (Unknown): pushes no
//	          client knows the end of, which may still commit, so nothing may clean up after them
//	reads     each read reply evs served, by head (RecordRead, LedgerReadsOf): the head version it was served at and
//	          every path it answered, which FI-15 holds to the head history
//	holdings  each generation a key holder reported as its current one (RecordKeyHolding), which FI-4 holds to
//	          the store's gen/ objects
//
// Safe for concurrent use. A ledger goes with its Net.

package fault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"weak"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// See the file header.
type Ledger struct {
	net *Net

	stateLock sync.Mutex
	// operations recorded directly, on the ledger's own clock
	direct *History
	// recorders read whole at each look, in the order added
	sources []*ledgerSource
	reads   []*LedgerRead
	// what key holders reported holding, in order (FI-4)
	keyHoldings []*KeyHolding
}

type ledgerSource struct {
	name       string
	operations func() []*Operation
}

var ledgers sync.Map

// The Net's ledger, made at first use; it goes with the Net.
func LedgerOf(net *Net) *Ledger {
	return netMemoryOf(&ledgers, net, func() *Ledger {
		return &Ledger{net: net, direct: NewHistory("ledger")}
	})
}

// One value per Net in memories, made by build at first use and dropped when the Net closes: an oracle's memory of
// what it saw at earlier checks, or the ledger. Keyed weakly, so a memory never keeps its Net alive.
func netMemoryOf[T any](memories *sync.Map, net *Net, build func() *T) *T {
	key := weak.Make(net)
	if memory, ok := memories.Load(key); ok {
		return memory.(*T)
	}
	actual, loaded := memories.LoadOrStore(key, build())
	if !loaded {
		context.AfterFunc(net.Context(), func() { memories.Delete(key) })
	}
	return actual.(*T)
}

// Adds a recorder the ledger reads whole at each look: operations gives copies of every operation it holds so far.
func (self *Ledger) AddSource(name string, operations func() []*Operation) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sources = append(self.sources, &ledgerSource{name: name, operations: operations})
}

// A time on the ledger's own clock, after every time it has stamped or recorded: what a recorder stamps a call or a
// return with.
func (self *Ledger) Now() int64 {
	return self.direct.Now()
}

// How many store requests the Net's blob history holds now: what a recorder stamps an operation's StoreArrival with
// at its call.
func (self *Ledger) StoreArrival() int {
	return self.net.BlobHistoryCount()
}

// Records operation, a copy, as given: a malformed one is kept and fails FI-2, never left out.
func (self *Ledger) Record(operation *Operation) {
	self.direct.Record(operation)
}

// Every operation, each a copy: each source's in the order added, then those recorded directly.
func (self *Ledger) Operations() []*Operation {
	self.stateLock.Lock()
	sources := slices.Clone(self.sources)
	self.stateLock.Unlock()
	operations := []*Operation{}
	for _, source := range sources {
		operations = append(operations, source.operations()...)
	}
	return append(operations, self.direct.Operations()...)
}

// One push id's attempts as the ledger holds them, and what they say of its end.
type LedgerPush struct {
	PushId sidecar.Id
	Ref    HistoryRef
	// In the order the ledger holds them.
	Attempts []*Operation
}

// Whether a refusal code binds its push id: every refusal but PUSH_ID_REUSED, which answers another statement under a
// push id that committed (§11.8's 5a), so it says nothing of that push's end.
func ledgerRefusalBinds(code protocol.EvsRefusalCode) bool {
	return code != protocol.EvsRefusalCode_EVS_REFUSAL_PUSH_ID_REUSED
}

// The versions its committed attempts answered, each once, in the order first answered.
func (self *LedgerPush) Versions() []uint64 {
	versions := []uint64{}
	for _, attempt := range self.Attempts {
		if attempt.Outcome == OutcomeCommitted && !slices.Contains(versions, attempt.Version) {
			versions = append(versions, attempt.Version)
		}
	}
	return versions
}

// Its attempts answered a refusal that binds.
func (self *LedgerPush) Refusals() []*Operation {
	refusals := []*Operation{}
	for _, attempt := range self.Attempts {
		if attempt.Outcome == OutcomeAborted && ledgerRefusalBinds(attempt.Code) {
			refusals = append(refusals, attempt)
		}
	}
	return refusals
}

// Committed once an attempt answered 200, aborted once one answered a refusal that binds, else unknown. A push both
// committed and aborted reads committed here; FI-2 names it.
func (self *LedgerPush) Outcome() Outcome {
	if 0 < len(self.Versions()) {
		return OutcomeCommitted
	}
	if 0 < len(self.Refusals()) {
		return OutcomeAborted
	}
	return OutcomeUnknown
}

// Every push id the ledger holds an attempt of, in the order first held, its attempts together.
func (self *Ledger) Pushes() []*LedgerPush {
	return ledgerPushesOf(self.Operations())
}

func ledgerPushesOf(operations []*Operation) []*LedgerPush {
	pushes := []*LedgerPush{}
	byPushId := map[sidecar.Id]*LedgerPush{}
	for _, operation := range operations {
		if operation.Kind != OperationPush {
			continue
		}
		push := byPushId[operation.PushId]
		if push == nil {
			push = &LedgerPush{PushId: operation.PushId, Ref: operation.Ref}
			byPushId[operation.PushId] = push
			pushes = append(pushes, push)
		}
		push.Attempts = append(push.Attempts, operation)
	}
	return pushes
}

// The running set of unknown operations: every push no client knows the end of, which may still commit.
func (self *Ledger) Unknown() []*LedgerPush {
	unknown := []*LedgerPush{}
	for _, push := range self.Pushes() {
		if push.Outcome() == OutcomeUnknown {
			unknown = append(unknown, push)
		}
	}
	return unknown
}

// One read reply's answer for one ref: the head it was served at and every path it answered, as evs sent them.
type LedgerRead struct {
	// Who read, and the instance that answered.
	Actor    string
	Instance string
	Ref      HistoryRef
	// The head version the reply was served at, and the head's ref mode.
	HeadVersion uint64
	RefMode     protocol.EvsRefMode
	// The head's path epochs: its current one, and the sources it listed.
	CurrentEpoch uint64
	SourceEpochs []uint64
	Paths        []*protocol.EvsReadPathReply
}

// Records a read reply's answer, a copy.
func (self *Ledger) RecordRead(read *LedgerRead) {
	copied := *read
	copied.SourceEpochs = slices.Clone(read.SourceEpochs)
	copied.Paths = []*protocol.EvsReadPathReply{}
	for _, path := range read.Paths {
		copied.Paths = append(copied.Paths, proto.Clone(path).(*protocol.EvsReadPathReply))
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.reads = append(self.reads, &copied)
}

// Every read recorded, in order.
func (self *Ledger) Reads() []*LedgerRead {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.reads)
}

// What one key holder reported holding of a group, as its client answered (FI-4, fi4.go): the generation it holds
// as its current one and that generation's commitment.
type KeyHolding struct {
	// The holder's actor, such as "readerB".
	Holder     string
	GroupId    sidecar.Id
	Generation uint64
	Commitment []byte
}

// Records a key holder's report, a copy.
func (self *Ledger) RecordKeyHolding(holding *KeyHolding) {
	copied := *holding
	copied.Commitment = bytes.Clone(holding.Commitment)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.keyHoldings = append(self.keyHoldings, &copied)
}

// Every key holding recorded, in order.
func (self *Ledger) KeyHoldings() []*KeyHolding {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.keyHoldings)
}

// A read reply's body, u32be(length) | EvsReadFrame frames, as one LedgerRead per head it names, the paths after a
// head answering for that head's ref. A reply that ends in an error frame or does not parse is an error, and records
// nothing a reader was not served whole.
func LedgerReadsOf(actor string, instance string, repoId sidecar.Id, body []byte) ([]*LedgerRead, error) {
	frames := sidecar.NewEvsReadFrames(bytes.NewReader(body))
	reads := []*LedgerRead{}
	var current *LedgerRead
	for {
		frame, err := frames.Next()
		if errors.Is(err, io.EOF) {
			return reads, nil
		}
		if err != nil {
			return nil, err
		}
		if head := frame.GetHead(); head != nil {
			refId, err := sidecar.IdFromBytes(head.GetRefId())
			if err != nil {
				return nil, fmt.Errorf("a head that names no ref: %w", err)
			}
			current = &LedgerRead{
				Actor: actor, Instance: instance, Ref: HistoryRef{RepoId: repoId, RefId: refId},
				HeadVersion: head.GetVersion(), RefMode: head.GetRefMode(),
				CurrentEpoch: max(1, head.GetPathEpoch().GetCurrent()),
			}
			for _, source := range head.GetPathEpoch().GetSources() {
				current.SourceEpochs = append(current.SourceEpochs, source.GetEpoch())
			}
			reads = append(reads, current)
		}
		if path := frame.GetPath(); path != nil {
			if current == nil {
				return nil, errors.New("a path frame before any head")
			}
			current.Paths = append(current.Paths, path)
		}
	}
}
