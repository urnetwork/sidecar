// The record's narrow surface of evs (§11), of §7.9's and §8's verified state, and of §16.6's run file, so the
// record's M3 tasks build and test with none of them: RecordStreams stands in for EvsRepo, RecordAuthView for
// ConfigState and AclState at a pin, and RecordRunView for the run file. RECORD-M3-12 binds RecordStreams to EvsRepo,
// TEAM's ConfigState and ACL's AclState bind RecordAuthView, and MCP-M3-04's Sidecar.RunTainted fills RecordRunView;
// sidecartest's fakes stand in until then, and each seam here has a value that fails closed while nothing is bound.
//
// A seam, not a second evs: what crosses it is the record's own bytes, its entries with their bodies sealed already
// and its slot rows and deposit batches as plaintext the binding seals, so nothing here encodes, seals or opens. A
// refusal is evs's, by §11.8's code (EVS-FORMAT.md). On every leg: nothing here names a connect type.

package sidecar

import (
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// No RecordStreams is bound yet: nothing was written or read (RECORD-M3-12 binds one).
	ErrRecordStreamsUnavailable = errors.New("record streams unavailable")
	// The pin is above this state's: wait until the log reaches it.
	ErrRecordAuthAhead = errors.New("record auth pin ahead of the state")
	// The pin is before what this state retains (§7.9's retain row): not judged, and held against no one.
	ErrRecordAuthNotRetained = errors.New("record auth pin not retained")
	// The pin's chain value is not this chain's at its position: a fork (§5.4's head_alarm).
	ErrRecordAuthOffChain = errors.New("record auth pin off the chain")
)

// What evs answered instead of a commit, by §11.8's code. A recordable code (1 to 63) is recorded against the push
// id, so a retry of that id gets the same refusal and never a commit (I-EVS-3); a final one (64 to 127) is not, and a
// code from 128 refuses nothing, so the same statement may go again.
type RecordStreamRefusal struct {
	Code protocol.EvsRefusalCode
	// Whether evs recorded it against the push id.
	Recorded bool
}

// Names the code and its status, nothing of the push.
func (self *RecordStreamRefusal) Error() string {
	status, _ := EvsRefusalStatus(self.Code)
	return fmt.Sprintf("record stream refused: %d %s", status, self.Code)
}

// The refusal code err carries, and false for an error that is no refusal, such as an unreachable evs.
func RecordStreamRefusalCode(err error) (protocol.EvsRefusalCode, bool) {
	var refusal *RecordStreamRefusal
	if errors.As(err, &refusal) {
		return refusal.Code, true
	}
	return protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED, false
}

// One row of a slot object: the key_index an entry names, and the row's plaintext, key || salt (RECORD.md section
// 5.2), which the binding wraps under fek_g and a reader gets back unwrapped. A row is a key, so it never reaches a
// log or an error.
type RecordSlotRow struct {
	KeyIndex uint32
	Row      []byte
}

// A slot key an ERASE names: an entry's (key_slot_id, key_index).
type RecordSlotKey struct {
	SlotId   Id
	KeyIndex uint32
}

// One entry file a push creates: RECORD.md section 5.2's stream path, which the caller builds, and the RecordEntry's
// bytes, its body sealed already and its key_slot_id and key_index naming this push's slot.
type RecordStreamEntry struct {
	Path  string
	Entry []byte
}

// One push to a sidecar's own stream in a record-class repo, which §11.8's refs table lets only that sidecar write,
// and only by creating paths.
type RecordStreamPush struct {
	// Drawn per push statement: a retry of this push keeps it, and a push rebuilt after a refusal draws another.
	PushId Id
	// The stream's writer, which must be the caller itself: evs refuses another's (§11.8's refs table).
	WriterSidecarId Id
	// The push's one slot object, drawn as PushId is: a retry keeps it, and a rebuilt push draws another and re-signs
	// no entry, since key_slot_id and key_index lie outside the signed header (§16.8).
	SlotId Id
	// At most 64, in ascending key_index (§11.8's slot bound).
	SlotRows []*RecordSlotRow
	// In the push's order, each creating its path.
	Entries []*RecordStreamEntry
	// §7.9's pin the push declares, at which readers judge the writer's right (RECORD.md section 5.5's right step).
	AuthPin *bridge.AuthPin
}

// What a committed push answers: its ref's new version, and evs's time for it, the push time readers take, which evs
// signs and bounds where an entry's time_millis is only its writer's word (RECORD.md section 5.5's push time).
type RecordStreamCommit struct {
	Version    uint64
	TimeMillis int64
}

// One ref of a log: a writer's stream, or a depositor's deposit ref.
type RecordStreamHead struct {
	SidecarId Id
	// The newest committed version, 0 before the first push.
	Version uint64
}

// One committed push of a stream, as a reader replays it. The binding returns only pushes whose statements verify by
// §11.8's replay (RECORD.md section 5.5's push step).
type RecordStreamVersion struct {
	Version    uint64
	PushId     Id
	TimeMillis int64
	AuthPin    *bridge.AuthPin
	SlotId     Id
	Entries    []*RecordStreamEntry
}

// A slot object as it stands: its live rows in ascending key_index, an erased row gone and no index shifted (§11.6).
type RecordSlot struct {
	SlotId Id
	Rows   []*RecordSlotRow
}

// One deposit to a log's drop key: a RecordDepositBatch's bytes, which the binding seals under the deposit's one
// object key, held in a slot HPKE-wrapped to the drop key (§11.12, RECORD.md section 5.4).
type RecordStreamDeposit struct {
	// Drawn per push statement, as RecordStreamPush's.
	PushId Id
	// The deposit ref's depositor, which must be the caller itself: evs refuses another's (§11.8's refs table).
	DepositorSidecarId Id
	// The deposit's random id in its ref, drawn as PushId is.
	DepositId Id
	Batch     []byte
	// §7.9's pin the deposit's push declares, at which the ingester judges the depositor (RECORD.md section 5.4's
	// right step).
	AuthPin *bridge.AuthPin
}

// One unconsumed deposit, as an ingester reads its ref in version order.
type RecordStreamDepositVersion struct {
	Version    uint64
	PushId     Id
	TimeMillis int64
	AuthPin    *bridge.AuthPin
	DepositId  Id
	Batch      []byte
}

// A CONSUME: deposits of one depositor's ref, ingested or refused, deleted with their slots (§11.12).
type RecordStreamConsume struct {
	PushId             Id
	DepositorSidecarId Id
	DepositIds         []Id
}

// An ERASE push on the repo's erasure ref (§11.12): the slot keys it destroys, and its note, which the caller seals.
type RecordStreamErase struct {
	PushId Id
	Keys   []*RecordSlotKey
	// §11.12's sealed note: the erasure's id and what the keys covered, opaque here.
	SealedNote []byte
}

// One committed ERASE, as readers and later erasers read it.
type RecordStreamErasure struct {
	Version         uint64
	PushId          Id
	TimeMillis      int64
	EraserSidecarId Id
	Keys            []*RecordSlotKey
	SealedNote      []byte
}

// One sidecar's reach into its network's record-class repos (§11.8, §11.12), evs's part of the record. Calls carry
// this sidecar's token, so evs, never the caller, says what it may do: push its own stream at rw, deposit to its own
// deposit ref at deposit, read streams, slots and erasures at read, read deposits and CONSUME at rw, ERASE at admin,
// and a receipt-only depositor only within §11.12's receipt budget. Safe for concurrent use.
type RecordStreams interface {
	// Commits one push to this sidecar's own stream of repo. A retry with the same push id and statement answers the
	// commit it made, or the refusal recorded against it; another statement under that id is PUSH_ID_REUSED.
	Append(ctx context.Context, repoId Id, push *RecordStreamPush) (*RecordStreamCommit, error)
	// The repo's streams, one a writer, with their versions.
	Streams(ctx context.Context, repoId Id) ([]*RecordStreamHead, error)
	// A stream's committed pushes after afterVersion, oldest first.
	ReadStream(ctx context.Context, repoId Id, writerSidecarId Id, afterVersion uint64) ([]*RecordStreamVersion, error)
	// A slot object's live rows. NOT_FOUND for a slot the repo never held.
	ReadSlot(ctx context.Context, repoId Id, slotId Id) (*RecordSlot, error)
	// Commits one deposit to this sidecar's own deposit ref of repo, as Append does a push.
	Deposit(ctx context.Context, repoId Id, deposit *RecordStreamDeposit) (*RecordStreamCommit, error)
	// The repo's deposit refs, one a depositor, with their versions.
	DepositRefs(ctx context.Context, repoId Id) ([]*RecordStreamHead, error)
	// A deposit ref's unconsumed deposits, in version order.
	ReadDeposits(ctx context.Context, repoId Id, depositorSidecarId Id) ([]*RecordStreamDepositVersion, error)
	// Commits a CONSUME. A deposit already gone is PATH_CONFLICT, which an ingester takes as consumed.
	Consume(ctx context.Context, repoId Id, consume *RecordStreamConsume) (*RecordStreamCommit, error)
	// Commits an ERASE, after which no slot holds its keys. NOTHING_TO_ERASE, recorded, when it names no key a slot
	// still holds.
	Erase(ctx context.Context, repoId Id, erase *RecordStreamErase) (*RecordStreamCommit, error)
	// The repo's committed ERASEs after afterVersion of its erasure ref, oldest first.
	ReadErasures(ctx context.Context, repoId Id, afterVersion uint64) ([]*RecordStreamErasure, error)
	// Calls back, with no lock held, each time a ref of repo moves, until unsubscribe runs: a hint to read again,
	// carrying nothing (§11.10).
	Subscribe(repoId Id, callback func(repoId Id)) (unsubscribe func())
}

// The streams a sidecar holds until RECORD-M3-12 binds EvsRepo: every call refuses with ErrRecordStreamsUnavailable,
// and a subscription never fires, so nothing reads as written, deposited, consumed or erased.
type RecordStreamsUnavailable struct{}

// Refuses.
func (self RecordStreamsUnavailable) Append(ctx context.Context, repoId Id, push *RecordStreamPush) (*RecordStreamCommit, error) {
	return nil, ErrRecordStreamsUnavailable
}

// Refuses.
func (self RecordStreamsUnavailable) Streams(ctx context.Context, repoId Id) ([]*RecordStreamHead, error) {
	return nil, ErrRecordStreamsUnavailable
}

// Refuses.
func (self RecordStreamsUnavailable) ReadStream(ctx context.Context, repoId Id, writerSidecarId Id, afterVersion uint64) ([]*RecordStreamVersion, error) {
	return nil, ErrRecordStreamsUnavailable
}

// Refuses.
func (self RecordStreamsUnavailable) ReadSlot(ctx context.Context, repoId Id, slotId Id) (*RecordSlot, error) {
	return nil, ErrRecordStreamsUnavailable
}

// Refuses.
func (self RecordStreamsUnavailable) Deposit(ctx context.Context, repoId Id, deposit *RecordStreamDeposit) (*RecordStreamCommit, error) {
	return nil, ErrRecordStreamsUnavailable
}

// Refuses.
func (self RecordStreamsUnavailable) DepositRefs(ctx context.Context, repoId Id) ([]*RecordStreamHead, error) {
	return nil, ErrRecordStreamsUnavailable
}

// Refuses.
func (self RecordStreamsUnavailable) ReadDeposits(ctx context.Context, repoId Id, depositorSidecarId Id) ([]*RecordStreamDepositVersion, error) {
	return nil, ErrRecordStreamsUnavailable
}

// Refuses: no deposit may read as consumed here.
func (self RecordStreamsUnavailable) Consume(ctx context.Context, repoId Id, consume *RecordStreamConsume) (*RecordStreamCommit, error) {
	return nil, ErrRecordStreamsUnavailable
}

// Refuses: an erasure must not read as done here.
func (self RecordStreamsUnavailable) Erase(ctx context.Context, repoId Id, erase *RecordStreamErase) (*RecordStreamCommit, error) {
	return nil, ErrRecordStreamsUnavailable
}

// Refuses.
func (self RecordStreamsUnavailable) ReadErasures(ctx context.Context, repoId Id, afterVersion uint64) ([]*RecordStreamErasure, error) {
	return nil, ErrRecordStreamsUnavailable
}

// Never fires.
func (self RecordStreamsUnavailable) Subscribe(repoId Id, callback func(repoId Id)) func() {
	return func() {}
}

// The logs a network holds, as RECORD.md section 4.2 routes by them.
type RecordLogIds struct {
	// A team network. A personal network routes every kind to the vault.
	Team bool
	// The team record and the team directory: nil while either does not exist, and in a personal network.
	TeamRecordId *Id
	DirectoryId  *Id
}

// What the record reads of §7.9's and §8's verified state at one pin (§16.8's matrix, §8.5's kinds and consent): who
// may read, write or deposit each log, who signs as whom, and which logs a network holds. RECORD.md section 4.2's
// routing and section 6.3's columns are the record's own, over these answers. A verdict at a past position, a
// deposit's or a push's own pin, comes from At, never from this state's tip (RECORD.md sections 5.4 and 5.5).
//
// Answers never change for one view, and a view is safe for concurrent use.
type RecordAuthView interface {
	// (n, A_n).
	Pin() *bridge.AuthPin
	// The state at an earlier pin on this chain: ErrRecordAuthAhead, ErrRecordAuthNotRetained or
	// ErrRecordAuthOffChain otherwise.
	At(pin *bridge.AuthPin) (RecordAuthView, error)
	// The identity key the log admits for a sidecar, nil for none. A revoked sidecar keeps it, for what it signed
	// while admitted.
	IdentityKey(sidecarId Id) []byte
	// The member an untagged sidecar belongs to; false for a tagged one or one the state does not admit.
	Member(sidecarId Id) (Id, bool)
	// A tagged sidecar's sponsor; false once it has none (§7.10).
	Sponsor(sidecarId Id) (Id, bool)
	// Whether the sidecar is a consented device of the repo's owner (§8.5): ACL's one predicate, never re-derived.
	Consented(repoId Id, sidecarId Id) bool
	// Whether the sidecar reads the repo (§8.6).
	Reads(repoId Id, sidecarId Id) bool
	// Whether it writes a stream of its own there: §16.8's matrix's writers, read_only devices and parked ones never.
	Writes(repoId Id, sidecarId Id) bool
	// Whether it deposits there.
	Deposits(repoId Id, sidecarId Id) bool
	// Whether its deposits there are read receipts alone: a reader of an owner-bound repo that is not its writer
	// (§8.5, §11.12), whose other kinds an ingester consumes unrecorded (RECORD.md section 5.4's class step).
	ReceiptOnly(repoId Id, sidecarId Id) bool
	// The since_n of a compromise revocation of the sidecar (§7.10), false for none: nothing it filed at or after
	// that position stands.
	CompromisedSince(sidecarId Id) (uint64, bool)
	// The network's logs.
	Logs() *RecordLogIds
	// A member's vault: its live vault repo whose RepoCreate has the lowest log position
	// (plan-RECORD-small-readings#3); false while it has none.
	Vault(memberId Id) (Id, bool)
}

// The state a sidecar reads until TEAM's and ACL's states bind RecordAuthView: no pin, no key, no right and no log,
// so every check that asks it refuses.
type RecordAuthUnavailable struct{}

// None.
func (self RecordAuthUnavailable) Pin() *bridge.AuthPin {
	return nil
}

// Ahead of every pin, so a caller waits rather than judges.
func (self RecordAuthUnavailable) At(pin *bridge.AuthPin) (RecordAuthView, error) {
	return nil, ErrRecordAuthAhead
}

// None.
func (self RecordAuthUnavailable) IdentityKey(sidecarId Id) []byte {
	return nil
}

// None.
func (self RecordAuthUnavailable) Member(sidecarId Id) (Id, bool) {
	return Id{}, false
}

// None.
func (self RecordAuthUnavailable) Sponsor(sidecarId Id) (Id, bool) {
	return Id{}, false
}

// Never.
func (self RecordAuthUnavailable) Consented(repoId Id, sidecarId Id) bool {
	return false
}

// Never.
func (self RecordAuthUnavailable) Reads(repoId Id, sidecarId Id) bool {
	return false
}

// Never.
func (self RecordAuthUnavailable) Writes(repoId Id, sidecarId Id) bool {
	return false
}

// Never.
func (self RecordAuthUnavailable) Deposits(repoId Id, sidecarId Id) bool {
	return false
}

// Always, so a depositor it judges files nothing but receipts.
func (self RecordAuthUnavailable) ReceiptOnly(repoId Id, sidecarId Id) bool {
	return true
}

// Compromised from the first position, so nothing anyone filed stands on this state.
func (self RecordAuthUnavailable) CompromisedSince(sidecarId Id) (uint64, bool) {
	return 0, true
}

// A personal network with no team logs.
func (self RecordAuthUnavailable) Logs() *RecordLogIds {
	return &RecordLogIds{}
}

// None.
func (self RecordAuthUnavailable) Vault(memberId Id) (Id, bool) {
	return Id{}, false
}

// §16.6's run file as the record reads it at sealing: whether a run is tainted (RECORD.md section 5.3's tainted row).
// MCP-M3-04's Sidecar.RunTainted fills it. Safe for concurrent use.
type RecordRunView interface {
	// Whether the run is tainted now: true for a run with no readable run file, and on any error reading one, so the
	// answer fails closed (D-MCP-16). A run's taint never clears.
	RunTainted(runId Id) bool
}

// The run view until MCP-M3-04 fills it: no run file is readable, so every run reads tainted.
type RecordRunViewMissing struct{}

// Always tainted.
func (self RecordRunViewMissing) RunTainted(runId Id) bool {
	return true
}
