//go:build !ios_extension

// A re-seed of one repo from this device's mirror (§11.13's re-seed row, §19.10's repos step, D-EVS-17; EVSB-M2-20;
// QD-725): after a site loss, while evs runs with reseed on, a repo admin's device sends evs back what its sealed
// mirror holds (evs_mirror_layout.go), through POST .../reseed, never re-signed:
//
//	order     the repo's erasure ref first, so evs holds every ERASE this device kept before any slot returns; then
//	          each other ref's history in version order; and last, after every ref's history, the slots
//	version   its new segments from seg/ through PUT .../segments, which takes re-seed uploads while reseed is on, then
//	          its statement as the mirror's stmt/ holds it with, from rec/, a one-part push's payload in one reseed
//	          call, or a push in parts' every part, each in its own call in part order, and then its seal naming the
//	          places those calls answered (QD-818, QD-836), as the push route's sender posts parts and a seal, so no
//	          call carries more than one part; a version evs already holds answers its version (§11.8's 5a), at its
//	          first part call for a push in parts, and the walk goes on
//	slot      each slot the mirror holds, under the statement of the last re-seeded version that names it, which is
//	          what evs takes a slot by; evs strips what its ERASEs cover (QD-096)
//	statement with SignReseed, for each ref re-seeded as far as the mirror holds it, a Signed EvsReseed over that
//	          head, which a reader whose pin lies above it accepts the shorter history under (§11.6)
//
// Every call is retried with the same bytes while evs answers a refusal that refuses nothing or nothing at all. A part
// call retried after an answer it lost leaves evs a second record of the part, and the seal names the one the last
// answer gave; a seal answered 409 PARTS_MISSING, which records and refuses nothing (a part's record gone to
// evacuation, say), sends the parts again and seals again, at most PartsMissingRetryCount times, as the push route's
// sender does (evs_push_parts.go).
//
// A ref stops at the first version the mirror cannot send or evs does not take, and says why: a version past it cannot
// chain. So does a PATH_EPOCH push whose map evs does not hold, whose parts this walk does not send. One ref's stop
// never ends the walk: the other refs and the slots go on, and the result names each.
//
// Nothing here reads evs: a head below this device's pin is what a re-seed mends, and the verifier refuses it until
// the EvsReseed is filed. The walk starts each ref at version 1 and lets 5a answer what evs already holds.
//
// A format-2 repo, on a client whose format-2 reader is installed (§11.13's re-seed row; EVS2-M10-13): a versionless
// path re-seeds content only for versions this device holds. A version whose path a later version the mirror holds
// writes or removes is replaced: its kind-5 content the mirror no longer holds is not sent, and the version goes as its
// statement and entry versions, which read `collected`, as do its staged segments, which no later version cites. A
// version no held version replaces sends its kind-5 content, and a kind-5 segment the mirror lacks for it stops the ref
// as any missing segment does; its staged segments, which ride its record's tail in the mirror and in no reseed call,
// go first through PUT .../segments as ordinary kind-5 uploads. A stale mirror's upload of what another device's
// re-seed replaced is refused by evs at the version's call, 409 VERSIONING, and that ref stops there: such a mirror
// holds nothing past that version that evs lacks.
//
// Before a repo's walk comes its groups step (§19.10's groups row; QD-1062), EvsRepo.ReseedPlace, which the repo's
// first admin device to reach the new site runs once:
//
//	place     PUT /evs/v1/repos/<id>, as a create resuming its id sends it. In a recovery evs writes repo/ keying for
//	          a repo its projection lists live, and deleted{deletion_id, its entry's time, signer} for one whose
//	          projection ends in an unrestored RepoDelete inside the restore window, so such a repo is deleted from
//	          its first object and the walk's segment uploads, which come before a version's first reseed call, meet
//	          the deleted repo/ that §11.12's re-seed exception takes them into (QD-977); one past restoring answers
//	          409 SHREDDING, and the step ends with it. 409 REPO_PLACED says another admin's device placed the repo:
//	          that device re-forms it and activates or deletes it, and this one goes on to its walk
//	group     the re-form (GkmGroupClient.ReformGroup), for a repo re-seeded as deleted its form and ladder alone,
//	          which is all gkm takes while repo/ reads deleted
//	activate  POST .../activate, which takes a live repo from keying to active, and is sent for a repo re-seeded as
//	          deleted too, whose expected answer is then 409 REPO_DELETED, the one refused call the honest order
//	          costs: repo/ stands deleted from its creation, nothing activates, and it stays deleted until its
//	          RepoRestore, after which a second ReformGroup finishes its group. A 200 there says the place created
//	          repo/ keying, as it does where the reseed gate was off at the place or evs's projection did not yet hold
//	          the RepoDelete this device's state shows (one filed after the log resumed, within §8.9's 5 s), and that
//	          repo/ is now active, which delete mends (owner decision 602; QD-1064)
//	delete    for that repo alone, DELETE /evs/v1/repos/<id>, the route with no statement of its own, which moves
//	          active to deleted{deletion_id, its entry's time, signer} under the RepoDelete evs's projection holds and
//	          answers a repo/ already deleted under it 200; while the projection trails this device's state, its 409
//	          STATEMENT_MISSING is asked again after ReseedDeleteWait, at most ReseedDeleteWaitCount times, and past
//	          them is the step's error with repo/ left active, which the step run again moves on, as taskworker's
//	          reconciler does once the projection holds the RepoDelete. Where the gate's state holds the RepoDelete,
//	          it gives the repo's admin admin alone (QD-880), so repo/ reading active between the two calls opens no
//	          read or write there
//
// Which of the two a repo is, the step reads from this device's verified config state, the newest RepoDelete of the
// repo's row with no RepoRestore of it, as Restore reads it; whether the deletion is still inside the restore window
// is evs's to judge, at place. A repo whose RepoDelete carries now is never placed. A repo re-seeded as deleted takes
// only §11.12's own transitions, keying to active by activate and active to deleted by DELETE, and no statement is
// filed for it.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A version the mirror does not hold whole: its statement, its records or a segment it introduces.
	ErrEvsReseedMirrorPartial = errors.New("evs: the mirror does not hold the version whole")
	// evs answered a version another than the one the mirror holds the statement at.
	ErrEvsReseedVersion = errors.New("evs: a re-seeded push committed at another version")
	// A repo this device's verified state shows no re-seed can return: one it does not hold, or one shredded by a
	// RepoDelete with now.
	ErrEvsReseedNotRestorable = errors.New("evs: the repo is not one a re-seed returns")
)

// What a repo's groups step is asked.
type EvsReseedPlaceArgs struct {
	// Re-forms the repo's group once the repo is placed: GkmGroupClient.ReformGroup, asked with Reseed for a repo
	// re-seeded as deleted. Nil re-forms through the client's key client where that re-forms groups, and where it
	// does not the step stops after the place with ErrGkmUnavailable, activating nothing.
	ReformGroup func(ctx context.Context, args *GkmReformArgs) (Id, error)
}

// What a repo's groups step did.
type EvsReseedPlaced struct {
	// The repo is re-seeded as deleted: placed, its group's form and ladder returned, and left with repo/ deleted.
	Deleted bool
	// For a repo re-seeded as deleted, the place created repo/ keying, and activate and DELETE moved it through active
	// to deleted (owner decision 602; QD-1064).
	Mended bool
	// Another admin's device placed the repo first, so this one re-formed and activated nothing.
	PlacedByAnother bool
	// The re-formed group; the zero id when another device placed the repo.
	GroupId Id
}

// A key client that re-forms a repo's group after a site loss: GkmGroupClient.
type evsReseedGroupReformer interface {
	ReformGroup(ctx context.Context, args *GkmReformArgs) (Id, error)
}

// What a re-seed is asked.
type EvsReseedArgs struct {
	// The recovery's incident id, which each EvsReseed names (§19.10).
	IncidentId []byte
	// Sign and file an EvsReseed over each ref's re-seeded head: a repo admin's statement that the history evs now
	// serves is all that survived.
	SignReseed bool
}

// One ref of a re-seed.
type EvsReseedRef struct {
	RefId Id
	// The version the mirror holds the ref through.
	MirrorVersion uint64
	// The version evs holds the ref through after the walk, and its chain: 0 when not even version 1 went.
	Version uint64
	Chain   [32]byte
	// Why the walk stopped below MirrorVersion; nil when the ref went whole.
	Stopped error
	// The Signed EvsReseed filed over Version, and why none was when SignReseed asked for one.
	Filed     bool
	FileError error
}

// One slot evs did not take.
type EvsReseedSlot struct {
	SlotId Id
	// evs's refusal, or nil for a slot no version this walk re-seeded names.
	Refused error
}

// What a re-seed did.
type EvsReseedResult struct {
	Refs []*EvsReseedRef
	// Segments sent, staged ones among them, and slots evs took or dropped as wholly erased.
	SegmentCount int
	SlotCount    int
	// Of format 2: the staged segments sent as uploads, and the replaced versions' kind-5 and staged segments not
	// sent, which those versions read `collected` without.
	StagedCount    int
	CollectedCount int
	// Slots evs did not take.
	Slots []*EvsReseedSlot
}

// Whether every ref went as far as the mirror holds it and every slot was taken.
func (self *EvsReseedResult) Whole() bool {
	for _, ref := range self.Refs {
		if ref.Stopped != nil || ref.FileError != nil {
			return false
		}
	}
	return len(self.Slots) == 0
}

// The repo's groups step, before its walk: placed afresh, its group re-formed, and activated, or for a repo re-seeded
// as deleted left with repo/ deleted, through activate and DELETE where the place created it keying. See the file
// header. ErrEvsNoConfig with no verified state; ErrEvsReseedNotRestorable, with nothing sent, for a repo the state
// does not hold or whose RepoDelete carries now. evs's refusal of the place, 409 SHREDDING for a repo past its restore
// window among them, is the error, as is a DELETE still refused past its waits. A step cut short runs again whole: the
// place answers its creator's retry as the first did, a re-form under way resumes from the keychain's record, and
// activate answers a repo/ already active 200 and one already deleted 409 REPO_DELETED.
func (self *EvsRepo) ReseedPlace(ctx context.Context, args *EvsReseedPlaceArgs) (*EvsReseedPlaced, error) {
	if args == nil {
		args = &EvsReseedPlaceArgs{}
	}
	client := self.client
	if client.args.Config == nil {
		return nil, ErrEvsNoConfig
	}
	state := client.args.Config()
	if state == nil {
		return nil, ErrEvsNoConfig
	}
	repo := state.Repo(self.repoId)
	if repo == nil {
		return nil, fmt.Errorf("%w: this device's verified state holds no such repo", ErrEvsReseedNotRestorable)
	}
	deletion := repo.GetDeletion()
	deleted := deletion != nil && deletion.GetDeletedAt() != 0 && deletion.GetRestoredAt() == 0
	if deleted && deletion.GetNow() {
		// evs's projection may trail this device's state: never placed on the chance it still reads the repo live
		return nil, fmt.Errorf("%w: its RepoDelete carries now", ErrEvsReseedNotRestorable)
	}
	placed := &EvsReseedPlaced{Deleted: deleted}
	if err := self.callLifecycle(ctx, evsPlaceCall(self.repoId)); err != nil {
		if IsEvsRepoPlaced(err) {
			placed.PlacedByAnother = true
			return placed, nil
		}
		return nil, err
	}
	reformGroup := args.ReformGroup
	if reformGroup == nil {
		reformer, ok := client.args.Gkm.(evsReseedGroupReformer)
		if !ok {
			return placed, fmt.Errorf("%w: this key client re-forms no group", ErrGkmUnavailable)
		}
		reformGroup = reformer.ReformGroup
	}
	groupId, err := reformGroup(ctx, &GkmReformArgs{RepoId: self.repoId, Reseed: deleted})
	if err != nil {
		return placed, fmt.Errorf("evs: the repo's group: %w", err)
	}
	placed.GroupId = groupId
	err = self.callLifecycle(ctx, evsActivateCall(self.repoId))
	switch {
	case !deleted:
		return placed, err
	case IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED):
		// the honest order: repo/ stands deleted from its creation, and the refused call activated nothing
		return placed, nil
	case err != nil:
		return placed, err
	}
	// repo/ stood keying and is now active: the projected RepoDelete takes it to deleted, the route alone
	deleteCall := &evsCall{
		route:  "DELETE /evs/v1/repos/{repo_id}",
		method: http.MethodDelete,
		path:   "/evs/v1/repos/" + evsUrlId(self.repoId),
		repoId: self.repoId,
		role:   evsScopeAdmin,
		retry:  true,
	}
	for waits := 0; ; waits += 1 {
		err = client.http.callMessage(ctx, deleteCall, nil)
		if err == nil {
			break
		}
		if !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING) || client.settings.ReseedDeleteWaitCount <= waits {
			return placed, fmt.Errorf("evs: the DELETE that takes the activated repo/ to deleted: %w", err)
		}
		// evs's projection trails this device's state
		select {
		case <-ctx.Done():
			return placed, ctx.Err()
		case <-client.clock.After(client.settings.ReseedDeleteWait):
		}
	}
	placed.Mended = true
	return placed, nil
}

// One walk.
type evsReseedRun struct {
	repo   *EvsRepo
	store  *EvsMirrorStore
	result *EvsReseedResult
	// by slot id in hex, the statement of the last re-seeded version that names the slot
	slotStatements map[string][]byte
	// the client reads format 2, so the mirror may hold a format-2 repo
	format2 bool
}

// Re-seeds the repo from this device's mirror. See the file header. An error is the mirror's or the context's; what
// evs refused is in the result.
func (self *EvsRepo) Reseed(ctx context.Context, args *EvsReseedArgs) (*EvsReseedResult, error) {
	if args == nil {
		args = &EvsReseedArgs{}
	}
	store, err := self.client.Mirror(self.repoId)
	if err != nil {
		return nil, err
	}
	refs, err := store.Refs()
	if err != nil {
		return nil, err
	}
	erasureRefId := EvsErasureRefId(self.repoId)
	slices.SortFunc(refs, func(a *EvsMirrorRef, b *EvsMirrorRef) int {
		// the erasure ref first, then by id
		if (a.RefId == erasureRefId) != (b.RefId == erasureRefId) {
			if a.RefId == erasureRefId {
				return -1
			}
			return 1
		}
		return a.RefId.Cmp(b.RefId)
	})
	run := &evsReseedRun{repo: self, store: store, result: &EvsReseedResult{}, slotStatements: map[string][]byte{}, format2: self.client.format2Reader() != nil}
	for _, ref := range refs {
		refResult := &EvsReseedRef{RefId: ref.RefId, MirrorVersion: ref.Version, Chain: EvsChainStart(self.repoId, ref.RefId)}
		run.result.Refs = append(run.result.Refs, refResult)
		refResult.Stopped = run.reseedRef(ctx, refResult)
		if err := ctx.Err(); err != nil {
			return run.result, err
		}
	}
	if err := run.reseedSlots(ctx); err != nil {
		return run.result, err
	}
	if args.SignReseed {
		for _, refResult := range run.result.Refs {
			if refResult.Version == 0 {
				continue
			}
			refResult.FileError = run.fileReseed(ctx, refResult, args.IncidentId)
			refResult.Filed = refResult.FileError == nil
			if err := ctx.Err(); err != nil {
				return run.result, err
			}
		}
	}
	return run.result, nil
}

// What the mirror holds under key, ErrEvsReseedMirrorPartial when it holds nothing there.
func (self *evsReseedRun) held(key EvsMirrorKey) ([]byte, error) {
	reader, err := self.store.Open(key)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		name, _ := key.Name()
		return nil, fmt.Errorf("%w: no %s", ErrEvsReseedMirrorPartial, name)
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// One reseed call, the same bytes until evs answers anything but a 429, a 503 or nothing.
func (self *evsReseedRun) post(ctx context.Context, request *protocol.EvsReseedRequest) (*protocol.EvsPushReply, error) {
	repo := self.repo
	call := &evsCall{
		route:  "POST /evs/v1/repos/{repo_id}/reseed",
		method: http.MethodPost,
		path:   "/evs/v1/repos/" + evsUrlId(repo.repoId) + "/reseed",
		repoId: repo.repoId,
		role:   evsScopeAdmin,
		body:   request,
	}
	reply := &protocol.EvsPushReply{}
	err := repo.client.retryRefusingNothing(ctx, func() error {
		reply = &protocol.EvsPushReply{}
		return repo.client.http.callMessage(ctx, call, reply)
	})
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// The ref's versions from 1 through the mirror's, in order, raising ref's version and chain with each evs holds. The
// answer is why the walk stopped short, nil when it did not.
func (self *evsReseedRun) reseedRef(ctx context.Context, ref *EvsReseedRef) error {
	var lastChanges map[string]uint64
	if self.format2 {
		lastChanges = self.lastChanges(ref)
	}
	for version := uint64(1); version <= ref.MirrorVersion; version += 1 {
		if err := ctx.Err(); err != nil {
			return err
		}
		statementBytes, statement, pushId, records, err := self.heldVersion(ref, version)
		if err != nil {
			return err
		}
		checked, err := evsMirrorCheckRecordsOf(statement, records, self.format2)
		if err != nil {
			return err
		}
		payload, parts, err := evsReseedBodiesOf(records, self.format2)
		if err != nil {
			return err
		}
		content := newEvsReseedContent(version, checked, lastChanges)
		for _, object := range checked.NewObjects {
			switch object.Kind {
			case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT:
				err := self.sendSegment(ctx, object.Id, pushId)
				if errors.Is(err, ErrEvsReseedMirrorPartial) && content.collected(object.Id) {
					// a replaced versionless version's content, gone from the mirror with its replacement
					self.result.CollectedCount += 1
					continue
				}
				if err != nil {
					return err
				}
			case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT:
				if content.collected(object.Id) {
					self.result.CollectedCount += 1
					continue
				}
				if err := self.sendStaged(ctx, checked.Staged, object.Id, pushId); err != nil {
					return err
				}
			}
		}
		var reply *protocol.EvsPushReply
		if parts == nil {
			reply, err = self.post(ctx, &protocol.EvsReseedRequest{Statement: statementBytes, Payload: payload})
		} else {
			reply, err = self.sendParts(ctx, statementBytes, parts)
		}
		if err != nil {
			return err
		}
		if reply.GetVersion() != version {
			return fmt.Errorf("%w: %d, held at %d", ErrEvsReseedVersion, reply.GetVersion(), version)
		}
		ref.Version = version
		ref.Chain = EvsChainNext(ref.Chain, pushId, statement.Sha256)
		self.noteSlots(statementBytes, checked)
	}
	return nil
}

// The statement the mirror holds at the ref's version, its push id and its records: part 0, the push's record or a
// push in parts' seal, and then each part's record.
func (self *evsReseedRun) heldVersion(ref *EvsReseedRef, version uint64) ([]byte, *EvsStatement, Id, [][]byte, error) {
	statementBytes, err := self.held(EvsMirrorStatementKey(ref.RefId, version))
	if err != nil {
		return nil, nil, Id{}, nil, err
	}
	statement, err := ParseEvsStatement(statementBytes)
	if err != nil && self.format2 && errors.Is(err, ErrEvsFormatUnsupported) {
		statement, err = ParseEvsStatementFormat2(statementBytes)
	}
	if err != nil {
		return nil, nil, Id{}, nil, err
	}
	push := statement.Push
	if !bytes.Equal(push.GetRepoId(), self.repo.repoId.Bytes()) || !bytes.Equal(push.GetRefId(), ref.RefId.Bytes()) {
		return nil, nil, Id{}, nil, fmt.Errorf("%w: a statement of another ref at version %d", ErrEvsMirrorRecordInvalid, version)
	}
	pushId, err := IdFromBytes(push.GetPushId())
	if err != nil {
		return nil, nil, Id{}, nil, err
	}
	records := make([][]byte, push.GetPartCount()+1)
	for part := range records {
		if records[part], err = self.held(EvsMirrorRecordKey(pushId, uint32(part))); err != nil {
			return nil, nil, Id{}, nil, err
		}
	}
	return statementBytes, statement, pushId, records, nil
}

// For a format-2 mirror: by token path's KeyString, the newest version the mirror holds of the ref that writes or
// removes the path, read before the walk as far as the mirror holds the ref whole.
func (self *evsReseedRun) lastChanges(ref *EvsReseedRef) map[string]uint64 {
	lastChanges := map[string]uint64{}
	for version := uint64(1); version <= ref.MirrorVersion; version += 1 {
		_, statement, _, records, err := self.heldVersion(ref, version)
		if err != nil {
			break
		}
		checked, err := evsMirrorCheckRecordsOf(statement, records, true)
		if err != nil {
			break
		}
		for _, change := range checked.Changes {
			lastChanges[change.TokenPath.KeyString()] = version
		}
	}
	return lastChanges
}

// What one version's kind-5 content is to its walk: see the file header.
type evsReseedContent struct {
	version     uint64
	lastChanges map[string]uint64
	// by segment id: the token paths whose versions name it by a kind-5 locator, staged or not, and whether any
	// version names it by a kind-1 one
	kind5Paths map[string][]string
	kind1      map[string]bool
}

func newEvsReseedContent(version uint64, checked *EvsCheckedPayload, lastChanges map[string]uint64) *evsReseedContent {
	content := &evsReseedContent{version: version, lastChanges: lastChanges, kind5Paths: map[string][]string{}, kind1: map[string]bool{}}
	for _, change := range checked.Changes {
		if !change.WritesEntry() {
			continue
		}
		entry := &protocol.EvsEntryVersion{}
		if proto.Unmarshal(change.EntryVersion, entry) != nil {
			continue
		}
		for _, locator := range entry.GetChain() {
			switch protocol.EvsLocatorKind(locator.GetKind()) {
			case protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT:
				id := string(locator.GetId())
				content.kind5Paths[id] = append(content.kind5Paths[id], change.TokenPath.KeyString())
			case protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT:
				content.kind1[string(locator.GetId())] = true
			}
		}
	}
	return content
}

// Whether segmentId is content only replaced versionless versions of this version name: kind-5 locators alone name
// it, each of a path a later version the mirror holds writes or removes.
func (self *evsReseedContent) collected(segmentId []byte) bool {
	paths := self.kind5Paths[string(segmentId)]
	if self.lastChanges == nil || len(paths) == 0 || self.kind1[string(segmentId)] {
		return false
	}
	for _, path := range paths {
		if self.lastChanges[path] <= self.version {
			return false
		}
	}
	return true
}

// What the reseed calls of a version whose records the mirror holds, already held to its statement, carry: a one-part
// push's payload as its record keeps it, with no parts, or a push in parts' every part as its record keeps it, in part
// order (QD-818), with no payload; never re-signed or rebuilt. With format2, a record's format-2 tail, its staged
// segments and its purge list, stays out of every call: staged content goes as uploads, and evs lists its own.
func evsReseedBodiesOf(records [][]byte, format2 bool) ([]byte, [][]byte, error) {
	parse := func(recordBytes []byte) (*EvsBatchRecord, error) {
		if format2 {
			record, _, err := ParseEvsBatchRecordFormat2(recordBytes)
			return record, err
		}
		return ParseEvsBatchRecord(recordBytes)
	}
	if len(records) == 1 {
		record, err := parse(records[0])
		if err != nil {
			return nil, nil, err
		}
		_, payload, err := ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return nil, nil, err
		}
		return payload, nil, nil
	}
	parts := make([][]byte, 0, len(records)-1)
	for _, recordBytes := range records[1:] {
		record, err := parse(recordBytes)
		if err != nil {
			return nil, nil, err
		}
		_, part, _, _, err := ParseEvsSealPartRecord(record)
		if err != nil {
			return nil, nil, err
		}
		parts = append(parts, part)
	}
	return nil, parts, nil
}

// A push in parts' reseed calls (QD-836): each part in its own call, in part order, then the seal naming the places
// those calls answered, each the same bytes on every try. A part call answered with a version found the push committed
// (§11.8's 5a), which answers the push with no seal. A seal answered 409 PARTS_MISSING sends every part again and seals
// again, at most PartsMissingRetryCount times. See the file header.
func (self *evsReseedRun) sendParts(ctx context.Context, statementBytes []byte, parts [][]byte) (*protocol.EvsPushReply, error) {
	for tries := 0; ; tries += 1 {
		places := make([]*protocol.EvsPlace, len(parts))
		for index, part := range parts {
			reply, err := self.post(ctx, &protocol.EvsReseedRequest{Statement: statementBytes, Parts: [][]byte{part}, PartNumber: uint32(index + 1)})
			if err != nil {
				return nil, err
			}
			if reply.GetPlace() == nil {
				if 0 < reply.GetVersion() {
					// the push stands committed
					return reply, nil
				}
				return nil, fmt.Errorf("%w: a reseed part answered with no place", ErrEvsReplyInvalid)
			}
			places[index] = reply.GetPlace()
		}
		reply, err := self.post(ctx, &protocol.EvsReseedRequest{Statement: statementBytes, PartPlaces: places})
		if IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_PARTS_MISSING) && tries < self.repo.client.settings.PartsMissingRetryCount {
			continue
		}
		return reply, err
	}
}

// One segment from the mirror's seg/ to evs, under the push that introduces it. evs answers a segment it already holds
// as it answers a new one.
func (self *evsReseedRun) sendSegment(ctx context.Context, segmentId []byte, pushId Id) error {
	body, err := self.held(EvsMirrorSegmentKey(segmentId))
	if err != nil {
		return err
	}
	return self.putSegment(ctx, segmentId, pushId, body)
}

// PUT .../segments of body under pushId, counted once evs answers it.
func (self *evsReseedRun) putSegment(ctx context.Context, segmentId []byte, pushId Id, body []byte) error {
	repo := self.repo
	call := &evsCall{
		route:   "PUT /evs/v1/repos/{repo_id}/segments/{segment_id}",
		method:  http.MethodPut,
		path:    "/evs/v1/repos/" + evsUrlId(repo.repoId) + "/segments/" + hex.EncodeToString(segmentId) + "?push=" + evsUrlId(pushId),
		repoId:  repo.repoId,
		role:    evsScopeAdmin,
		rawBody: body,
	}
	receipt := &protocol.EvsUploadReceipt{}
	if err := repo.client.retryRefusingNothing(ctx, func() error { return repo.client.http.callMessage(ctx, call, receipt) }); err != nil {
		return err
	}
	self.result.SegmentCount += 1
	return nil
}

// One staged segment of a format-2 version, from its record's tail as the mirror holds it, to evs as an ordinary
// kind-5 upload under the push that stages it, which its header names (§11.13's re-seed row).
func (self *evsReseedRun) sendStaged(ctx context.Context, staged []*EvsStagedSegment, segmentId []byte, pushId Id) error {
	var segment *EvsStagedSegment
	for _, candidate := range staged {
		if bytes.Equal(candidate.Id[:], segmentId) {
			segment = candidate
			break
		}
	}
	if segment == nil {
		return fmt.Errorf("%w: no staged segment %x in its record", ErrEvsReseedMirrorPartial, segmentId[:8])
	}
	if err := self.putSegment(ctx, segmentId, pushId, segment.Bytes); err != nil {
		return err
	}
	self.result.StagedCount += 1
	return nil
}

// The slots a re-seeded version names: those its new-objects section introduces and those its entry versions name.
func (self *evsReseedRun) noteSlots(statementBytes []byte, checked *EvsCheckedPayload) {
	for _, object := range checked.NewObjects {
		if object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT {
			self.slotStatements[hex.EncodeToString(object.Id)] = statementBytes
		}
	}
	for _, change := range checked.Changes {
		if !change.WritesEntry() {
			continue
		}
		entry := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
			continue
		}
		for _, slotId := range entry.GetSlotIds() {
			self.slotStatements[hex.EncodeToString(slotId)] = statementBytes
		}
	}
}

// Every slot the mirror holds, after every ref's history. A slot no re-seeded version names is not sent, since evs
// takes none without one, and is reported; so is one evs refuses.
func (self *evsReseedRun) reseedSlots(ctx context.Context) error {
	keys, err := self.store.List(EvsMirrorSlots, nil)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return err
		}
		slotId, err := IdFromBytes(key.ObjectId)
		if err != nil {
			continue
		}
		statementBytes := self.slotStatements[hex.EncodeToString(key.ObjectId)]
		if statementBytes == nil {
			self.result.Slots = append(self.result.Slots, &EvsReseedSlot{SlotId: slotId})
			continue
		}
		slotBytes, err := self.held(key)
		if err != nil {
			return err
		}
		if _, err := self.post(ctx, &protocol.EvsReseedRequest{Statement: statementBytes, SlotId: slotId.Bytes(), Slot: slotBytes}); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			self.result.Slots = append(self.result.Slots, &EvsReseedSlot{SlotId: slotId, Refused: err})
			continue
		}
		self.result.SlotCount += 1
	}
	return nil
}

// Signs and files the EvsReseed over ref's re-seeded head.
func (self *evsReseedRun) fileReseed(ctx context.Context, ref *EvsReseedRef, incidentId []byte) error {
	client := self.repo.client
	signedBytes, err := SignEvsReseed(client.args.Sign, self.repo.repoId, ref.RefId, ref.Version, ref.Chain, incidentId)
	if err != nil {
		return err
	}
	reply, err := self.post(ctx, &protocol.EvsReseedRequest{Statement: signedBytes})
	if err != nil {
		return err
	}
	if reply.GetVersion() != ref.Version {
		return fmt.Errorf("%w: a reseed filed at %d, signed over %d", ErrEvsReseedVersion, reply.GetVersion(), ref.Version)
	}
	return nil
}
