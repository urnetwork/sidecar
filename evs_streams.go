//go:build !ios_extension

// EvsRepo.ReadStreams and ListRefs (§11.9's streams and moved rows; §16.11's daemons; D-EVS-61, FI-25; EVS1-M6-01):
// a record-class repo's owned streams read up to 64 to a request, each after the version its reader holds, and the
// refs whose last commit moved the repo's push sequence past a value.
//
//	read     POST .../read {refs}: one framed reply, each stream's head summary first, then its statements after its
//	         pin, each with its push record and the segment ranges and slots its entries name; `more` where the
//	         reply's 4 MiB ran out, with the stream's next version; `behind` where its pin is older than the window,
//	         which the caller pages with GET .../log and then reads again from where it holds
//	verify   each stream's statements walked from the caller's pin (its version and C there) by the verifying
//	         reader's rules, every signature, ref rule and chain step, so a head that does not extend the pin is
//	         refused (ErrEvsHeadForked, ErrEvsChainBroken); each push's record held to its statement and its payload
//	         checked as a record keeps it, with no slot body (EvsCheckRecordPayload, QD-806; a sealed push's parts
//	         EvsCheckStoredSeal), each key taken from a slot the reply carried; each file a version creates rebuilt
//	         from the ranges and slots the reply carried, through the receipt gate, and held to its sealed fields;
//	         a stream read to its head is pinned, as a head read is, before any file is rebuilt
//	pins     each stream's head is held to this device's pin of its ref as the read asked at it, not as another call
//	         of the client raised it since, and raised with the walk from the caller's pin, judged against the pin as
//	         it then stands (evs_pin_walk.go): a head another raise passed stands where that raise's walk places it,
//	         and where nothing does the whole read is read again, at most EvsSettings.ReadStaleRetryCount times, before
//	         it answers ErrEvsReadStale; a stream that stops short of its head, more, is a page, judged against what
//	         the pin store holds and raising nothing
//	erased   a file whose every slot came back emptied reads as erased only where a committed ERASE on the repo's
//	         erasure ref names each of them, judged on the ERASEs read after the slots (evs_read_erased.go: read once a
//	         call at the first emptied slot, and again before a slot the list in hand does not name alarms); an
//	         emptied slot no ERASE names is a key evs withheld, which alarms as tampering and refuses the read. A key
//	         gone from a slot the reply did not carry is judged so by the reconstruction that reads the slot
//	moved    GET .../refs?moved_after=<the sequence the caller last listed at>: the refs past it, or every ref with
//	         All set where evs cannot place the value (a sequence restart, a ref its cache lacks); a caller lists every
//	         ref, MovedAfter nil, at its first sync each UTC day, since a commit whose raise a crash lost shows only at
//	         its ref's next commit
//
// Contents are held in memory a file at a time, a stream's entries being small; the reply's objects spill to the
// sealed store past DeltaBaseMemoryByteCount (QD-641). evs sees no path: the writer rules on what a stream holds stay
// the caller's (§16.11).
//
// On every leg but the ios_extension legs. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// One stream ReadStreams reads.
type EvsStreamRead struct {
	// The stream's ref by its name's bytes (RecordStreamRefName), whose id the read resolves into RefId, or by RefId
	// when RefName is nil.
	RefName []byte
	RefId   Id
	// The version the caller holds and C there; 0 with a zero chain for none, read from C_0.
	PinVersion uint64
	PinChain   [sha256.Size]byte
}

// What a read answered for one stream.
type EvsStreamVersions struct {
	RefId Id
	// The stream's head as evs gave it, which the versions reach when More and Behind are 0.
	Head *protocol.EvsHeadSummary
	// The versions after the pin, oldest first, each verified from the pin.
	Versions []*EvsStreamVersion
	// The reply's frame ran out here: read again from the last version given.
	More uint64
	// The pin is older than the window: the first version evs could not give, which GET .../log pages.
	Behind uint64
	// The bytes the reply carried for this stream: its frames' statements, records, ranges and slots.
	ByteCount int64
}

// One committed push of a stream.
type EvsStreamVersion struct {
	Version   uint64
	Statement *EvsVerifiedStatement
	Payload   *EvsCheckedPayload
	// Each file the push creates, its content rebuilt and checked.
	Files []*EvsStreamFileRead
	// The slot objects the push introduces, as stored (EvsSlotObject bytes), which a record binding opens.
	Slots []*EvsStreamSlot
}

// One file a stream's push creates.
type EvsStreamFileRead struct {
	TokenPath  EvsTokenPath
	EntryBytes []byte
	Entry      *protocol.EvsEntryVersion
	// Its content, nil when Erased.
	Content []byte
	// Every slot its chain's keys lie in was emptied by an ERASE (§11.12): the file reads as erased, nothing to open.
	Erased bool
}

// A slot object a push introduced.
type EvsStreamSlot struct {
	Id   Id
	Body []byte
}

// One stream's part of a streams reply as it arrived.
type evsStreamGroup struct {
	read       *EvsStreamRead
	head       *protocol.EvsHeadSummary
	statements []*protocol.EvsReadStatement
	more       uint64
	behind     uint64
	objects    *evsReadObjects
	byteCount  int64
}

// Reads streams after their pins in one request: see the file header. The answer holds one entry a read, in order.
func (self *EvsRepo) ReadStreams(ctx context.Context, reads []*EvsStreamRead) ([]*EvsStreamVersions, error) {
	request, err := self.streamsRequest(ctx, reads)
	if err != nil {
		return nil, err
	}
	// each stream's read in flight from its first ask to its raise, so another raise meanwhile keeps the chains that
	// place its head
	for _, read := range reads {
		done := self.client.pins.beginRead(self.repoId, read.RefId)
		defer done()
	}
	for staleCount := 0; ; staleCount += 1 {
		answers, err := self.readStreamsOnce(ctx, request, reads)
		if !errors.Is(err, ErrEvsReadStale) || self.client.settings.ReadStaleRetryCount <= staleCount {
			return answers, err
		}
	}
}

// The request ReadStreams sends for reads, each stream's ref id resolved into its read.
func (self *EvsRepo) streamsRequest(ctx context.Context, reads []*EvsStreamRead) (*protocol.EvsReadRequest, error) {
	formats := DefaultEvsFormatSettings()
	if len(reads) == 0 || formats.ReadStreamMaxRefCount < len(reads) {
		return nil, fmt.Errorf("%w: a streams read of %d refs", ErrEvsWriteInvalid, len(reads))
	}
	request := &protocol.EvsReadRequest{}
	seen := map[Id]bool{}
	for _, read := range reads {
		if read == nil {
			return nil, fmt.Errorf("%w: no stream", ErrEvsWriteInvalid)
		}
		if read.RefName != nil {
			refId, err := self.resolveRefId(ctx, read.RefName, nil)
			if err != nil {
				return nil, err
			}
			read.RefId = refId
		}
		if seen[read.RefId] {
			return nil, fmt.Errorf("%w: a stream named twice", ErrEvsWriteInvalid)
		}
		seen[read.RefId] = true
		request.Refs = append(request.Refs, &protocol.EvsReadRef{RefId: read.RefId.Bytes(), PinVersion: read.PinVersion})
	}
	return request, nil
}

// One ReadStreams request, each stream judged against the pin its ref held as the request was sent.
func (self *EvsRepo) readStreamsOnce(ctx context.Context, request *protocol.EvsReadRequest, reads []*EvsStreamRead) ([]*EvsStreamVersions, error) {
	asks := make([]*evsPinAsk, len(reads))
	for i, read := range reads {
		ask, err := self.client.pins.ask(self.repoId, read.RefId)
		if err != nil {
			return nil, err
		}
		asks[i] = ask
	}
	groups, err := self.client.postReadStreams(ctx, self.repoId, request, reads)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, group := range groups {
			group.objects.close()
		}
	}()
	answers := []*EvsStreamVersions{}
	// one judge of emptied slots for the whole call, every group's reconstructions judging by it too
	erasures := &evsErasedKeys{}
	for i, group := range groups {
		answer, err := self.streamVersions(ctx, group, asks[i], erasures)
		if err != nil {
			return nil, err
		}
		answers = append(answers, answer)
	}
	return answers, nil
}

// One stream's versions from its group, judged against the pin its ref held at ask: see the file header's verify and
// pins rows.
func (self *EvsRepo) streamVersions(ctx context.Context, group *evsStreamGroup, ask *evsPinAsk, erasures *evsErasedKeys) (*EvsStreamVersions, error) {
	read := group.read
	answer := &EvsStreamVersions{RefId: read.RefId, Head: group.head, More: group.more, Behind: group.behind, ByteCount: group.byteCount}
	if group.behind != 0 {
		// the caller pages the log from its pin: nothing after it verifies without the statements between
		return answer, nil
	}
	fromChain := read.PinChain
	if read.PinVersion == 0 {
		fromChain = EvsChainStart(self.repoId, read.RefId)
	}
	headVersion := group.head.GetVersion()
	if headVersion < read.PinVersion {
		return nil, fmt.Errorf("%w: a stream's head below the version read from", ErrEvsHeadForked)
	}
	through := headVersion
	if group.more != 0 {
		through = group.more - 1
	}
	if through < read.PinVersion || headVersion < through {
		return nil, fmt.Errorf("%w: more past the stream's head", ErrEvsReplyInvalid)
	}
	walked, err := self.client.verifier.walk(ctx, self.repoId, read.RefId, read.PinVersion, fromChain, group.statements, through)
	if err != nil {
		return nil, err
	}
	headChain, err := EvsChainFromBytes(group.head.GetChain())
	if err != nil {
		return nil, fmt.Errorf("%w: the head's chain", ErrEvsReplyInvalid)
	}
	verified := &EvsVerifiedHead{
		RepoId: self.repoId, RefId: read.RefId, Head: group.head, Version: headVersion, Chain: headChain,
		Statements: walked, FromVersion: read.PinVersion, ask: ask, fromChain: fromChain, ownStart: true,
	}
	if group.more == 0 {
		switch {
		case 0 < len(walked) && walked[len(walked)-1].Chain != headChain:
			return nil, fmt.Errorf("%w: the statements do not chain to the head", ErrEvsChainBroken)
		case len(walked) == 0 && fromChain != headChain:
			return nil, fmt.Errorf("%w: a head at the pin's version with another chain", ErrEvsHeadForked)
		}
		if err := self.client.verifier.checkAsked(self.repoId, read.RefId, ask, headVersion, headChain); err != nil {
			return nil, err
		}
		if 0 < len(walked) {
			if err := self.client.verifier.Pin(verified); err != nil {
				return nil, err
			}
		}
	} else if 0 < len(walked) {
		// a page short of the head: held to what the pin store holds, raising nothing
		page := &EvsVerifiedHead{
			RepoId: self.repoId, RefId: read.RefId, Head: group.head, Version: through, Chain: walked[len(walked)-1].Chain,
			Statements: walked, FromVersion: read.PinVersion, ask: ask, fromChain: fromChain, ownStart: true, page: true,
		}
		if _, err := self.client.verifier.judgeHead(page, nil); err != nil {
			return nil, err
		}
	}
	keys := newEvsReadKeys(self)
	keys.erasures = erasures
	result := &evsReadResult{refId: read.RefId, head: verified, keys: keys, objects: group.objects}
	for _, statement := range walked {
		version, err := self.streamVersion(ctx, result, group, statement, erasures)
		if err != nil {
			return nil, err
		}
		answer.Versions = append(answer.Versions, version)
	}
	return answer, nil
}

// One verified statement's version: its payload from the record the reply carried, its files rebuilt.
func (self *EvsRepo) streamVersion(ctx context.Context, result *evsReadResult, group *evsStreamGroup, statement *EvsVerifiedStatement, erasures *evsErasedKeys) (*EvsStreamVersion, error) {
	push := statement.Statement.Push
	record, ok := group.record(push.GetPushId(), 0)
	if !ok {
		return nil, fmt.Errorf("%w: the push record of version %d", ErrEvsObjectMissing, statement.Version)
	}
	batchRecord, tail, err := self.parseReadBatchRecord(record)
	if err != nil {
		return nil, fmt.Errorf("%w: a push record that does not parse", ErrEvsEntryRefused)
	}
	var payload *EvsCheckedPayload
	switch {
	case push.GetPartCount() == 0:
		if payload, err = self.checkReadPushPayload(statement.Statement, batchRecord, tail); err != nil {
			return nil, err
		}
	case batchRecord.Type == protocol.EvsBatchRecordType_EVS_BATCH_SEAL && 0 < push.GetPartCount():
		signed, places, err := ParseEvsSealRecordBody(batchRecord.Body)
		if err != nil || !bytes.Equal(signed, statement.Statement.Bytes) || len(places) != int(push.GetPartCount()) {
			return nil, fmt.Errorf("%w: a seal record of another statement or part count", ErrEvsEntryRefused)
		}
		parts := make([][]byte, push.GetPartCount())
		for part := range parts {
			partRecord, ok := group.record(push.GetPushId(), uint64(part+1))
			if !ok {
				return nil, fmt.Errorf("%w: part %d of version %d", ErrEvsObjectMissing, part+1, statement.Version)
			}
			parsed, _, err := self.parseReadBatchRecord(partRecord)
			if err != nil {
				return nil, fmt.Errorf("%w: a part record that is not one part's", ErrEvsEntryRefused)
			}
			// a part record, or a re-seeded push's part, a reseed record holding a part's body (QD-818)
			statementBytes, partBytes, _, _, err := ParseEvsSealPartRecord(parsed)
			if err != nil {
				return nil, fmt.Errorf("%w: a part record that is not one part's", ErrEvsEntryRefused)
			}
			if !bytes.Equal(statementBytes, statement.Statement.Bytes) {
				return nil, fmt.Errorf("%w: a part record of another statement", ErrEvsEntryRefused)
			}
			parts[part] = partBytes
		}
		if payload, err = self.checkReadSeal(statement.Statement, parts); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: a record of type %d for a push of %d parts", ErrEvsEntryRefused, batchRecord.Type, push.GetPartCount())
	}
	version := &EvsStreamVersion{Version: statement.Version, Statement: statement, Payload: payload}
	reader := self.client.format2Reader()
	for _, change := range payload.Changes {
		if !change.WritesEntry() {
			continue
		}
		entry := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
			return nil, fmt.Errorf("%w: an entry that does not parse", ErrEvsEntryRefused)
		}
		if reader != nil && EvsEntryVersionNeedsFormat2(entry) {
			// Owned record streams keep every version. Apply the writer's pinned rules before using the entry.
			if err := reader.verifyVersion(self.client.verifier, self.repoId, result.refId, statement.Statement, nil, EvsReservedRefNone, entry); err != nil {
				return nil, err
			}
		}
		if entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE) {
			continue
		}
		if evsStreamFileEmptied(result.objects, entry) {
			named, err := erasures.namesSlots(ctx, self, entry)
			if err != nil {
				return nil, err
			}
			if !named {
				// evs served the file's slots empty and no committed ERASE names them: a key withheld, no erasure
				self.client.alarm(self.repoId, result.refId, SidecarEvsAlarmTamper, "", nil)
				return nil, fmt.Errorf("%w: a file's slots served empty with no ERASE naming them", ErrEvsSealInvalid)
			}
			version.Files = append(version.Files, &EvsStreamFileRead{TokenPath: change.TokenPath, EntryBytes: change.EntryVersion, Entry: entry, Erased: true})
			continue
		}
		verified := &EvsVerifiedPath{
			TokenPath: change.TokenPath, EntryBytes: change.EntryVersion, Entry: entry, Statement: statement.Statement,
			CommitVersion: statement.Version,
		}
		content, err := func() ([]byte, error) {
			spill, _, _, err := self.reconstructContent(ctx, result, verified, nil)
			if err != nil {
				return nil, err
			}
			defer spill.close()
			return io.ReadAll(spill.reader())
		}()
		if errors.Is(err, ErrEvsErased) {
			// a key a committed ERASE destroyed, in a slot the reply did not carry, which the reconstruction read
			version.Files = append(version.Files, &EvsStreamFileRead{TokenPath: change.TokenPath, EntryBytes: change.EntryVersion, Entry: entry, Erased: true})
			continue
		}
		if err != nil {
			return nil, err
		}
		version.Files = append(version.Files, &EvsStreamFileRead{TokenPath: change.TokenPath, EntryBytes: change.EntryVersion, Entry: entry, Content: content})
	}
	for _, object := range payload.NewObjects {
		if object.Kind != protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT {
			continue
		}
		slotId, err := IdFromBytes(object.Id)
		if err != nil {
			return nil, fmt.Errorf("%w: a slot id of %d bytes", ErrEvsEntryRefused, len(object.Id))
		}
		body, ok := result.objects.slot(object.Id)
		if !ok {
			// a slot an erasure has emptied since, or one evs did not serve: the binding asks for it alone
			continue
		}
		version.Slots = append(version.Slots, &EvsStreamSlot{Id: slotId, Body: body})
	}
	return version, nil
}

// Whether every slot a file's chain keeps its keys in came back emptied, as an ERASE leaves it (§11.12's slots row),
// which reads as an erased file once a committed ERASE names each (evsErasedKeys.namesSlots). A slot the reply did not
// carry is no proof of it, and reconstruction asks for that one.
func evsStreamFileEmptied(objects *evsReadObjects, entry *protocol.EvsEntryVersion) bool {
	if len(entry.GetSlotIds()) == 0 {
		return false
	}
	for _, slotId := range entry.GetSlotIds() {
		slotBytes, ok := objects.slot(slotId)
		if !ok {
			return false
		}
		slot, err := EvsDecodeSlotObject(slotBytes)
		if err != nil || 0 < len(slot.GetKeys()) {
			return false
		}
	}
	return true
}

// A record the group carried, by its push id and number: 0 the push or seal record, else a part's.
func (self *evsStreamGroup) record(pushId []byte, number uint64) ([]byte, bool) {
	for key, spill := range self.objects.objects {
		if key.kind == protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD && key.id == hex.EncodeToString(pushId) && key.number == number {
			recordBytes, err := io.ReadAll(spill.reader())
			return recordBytes, err == nil
		}
	}
	return nil, false
}

// POST .../read {refs}: the reply's frames read one at a time into one group a stream, each beginning at its head
// summary, in the order the request named them.
func (self *EvsClient) postReadStreams(ctx context.Context, repoId Id, request *protocol.EvsReadRequest, reads []*EvsStreamRead) ([]*evsStreamGroup, error) {
	response, err := self.http.send(ctx, &evsCall{
		route:  "POST /evs/v1/repos/{repo_id}/read",
		method: http.MethodPost,
		path:   "/evs/v1/repos/" + evsUrlId(repoId) + "/read",
		repoId: repoId,
		role:   evsScopeRead,
		body:   request,
		retry:  true,
	})
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	groups := []*evsStreamGroup{}
	fail := func(err error) ([]*evsStreamGroup, error) {
		for _, group := range groups {
			group.objects.close()
		}
		return nil, err
	}
	frames := NewEvsReadFrames(response.Body)
	ended := false
	for {
		frame, err := frames.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(err)
		}
		if frame.GetEnd() {
			ended = true
			continue
		}
		if head := frame.GetHead(); head != nil {
			if len(reads) <= len(groups) || !bytes.Equal(head.GetRefId(), reads[len(groups)].RefId.Bytes()) {
				return fail(fmt.Errorf("%w: a head of a stream not asked for, or out of order", ErrEvsReplyInvalid))
			}
			groups = append(groups, &evsStreamGroup{read: reads[len(groups)], head: head, objects: newEvsReadObjects(self)})
			continue
		}
		if len(groups) == 0 {
			return fail(fmt.Errorf("%w: a frame before any head", ErrEvsReplyInvalid))
		}
		group := groups[len(groups)-1]
		if statement := frame.GetStatement(); statement != nil {
			group.statements = append(group.statements, statement)
			group.byteCount += int64(len(statement.GetStatement()))
		}
		if frame.GetMore() != 0 {
			group.more = frame.GetMore()
		}
		if frame.GetBehind() != 0 {
			group.behind = frame.GetBehind()
		}
		if frame.GetPath() != nil {
			return fail(fmt.Errorf("%w: a path in a streams reply", ErrEvsReplyInvalid))
		}
		if object := frame.GetObject(); object != nil {
			if err := group.objects.add(object); err != nil {
				return fail(err)
			}
			group.byteCount += int64(len(object.GetBody()))
		}
	}
	if !ended || len(groups) != len(reads) {
		return fail(fmt.Errorf("%w: a streams reply short of its end", ErrEvsReplyInvalid))
	}
	return groups, nil
}

// What ListRefs lists.
type EvsListRefsArgs struct {
	// The push sequence the caller last listed at; nil lists every ref.
	MovedAfter *uint64
}

// GET .../refs[?moved_after=]'s answer.
type EvsRefsListing struct {
	// repo/'s object format, and the repo's push sequence now: the next listing's moved_after.
	Format       uint32
	PushSequence uint64
	// Every ref is listed: no moved_after, a value evs cannot place, or a ref its cache lacks.
	All bool
	// Each ref's head as evs gives it, unverified, with the push sequence its last commit raised.
	Refs []*protocol.EvsHeadSummary
}

// Lists the repo's refs, or those moved past args.MovedAfter: see the file header's moved row.
func (self *EvsRepo) ListRefs(ctx context.Context, args *EvsListRefsArgs) (*EvsRefsListing, error) {
	path := "/evs/v1/repos/" + evsUrlId(self.repoId) + "/refs"
	if args != nil && args.MovedAfter != nil {
		path += "?moved_after=" + strconv.FormatUint(*args.MovedAfter, 10)
	}
	reply := &protocol.EvsRefsReply{}
	err := self.client.http.callMessage(ctx, &evsCall{
		route:  "GET /evs/v1/repos/{repo_id}/refs",
		method: http.MethodGet,
		path:   path,
		repoId: self.repoId,
		role:   evsScopeRead,
		retry:  true,
	}, reply)
	if err != nil {
		return nil, err
	}
	listing := &EvsRefsListing{Format: reply.GetFormat(), PushSequence: reply.GetPushSequence(), All: reply.GetAll(), Refs: reply.GetRefs()}
	if args == nil || args.MovedAfter == nil {
		listing.All = true
	}
	return listing, nil
}

// The id of a ref's name bytes under the repo's K_ref (§11.6), which any reader of the repo derives.
func (self *EvsRepo) RefIdOf(ctx context.Context, refName []byte) (Id, error) {
	return self.resolveRefId(ctx, refName, nil)
}
