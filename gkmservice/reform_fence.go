// The fence a re-form puts on the group it re-forms (QD-1186; §10.6's checks row, §10.8's re-form rows). §10.6 has
// gkm refuse a claim of a group the repo's newest GroupForm no longer names, but that check reads the forms and then
// creates gen/<g> under the old group's prefix, and the form is created under gkm/repo/<repo_id>/, so with nothing
// conditioning both a claim checked just before a re-form's form lands is created just after it: the repo holds two
// generations of one number, and the rotator, pinning the old group's, refuses the new group for good (I-16). So:
//
//   - the forms route writes, after the new group's owner marker and before its form, the old group's closing marker,
//     gkm/<old>/closed, If-None-Match, holding the re-form's Signed GroupForm byte for byte, which names the new group
//     and the generation its ladder carries. It then reads the old group's gen/<form.generation+1>: one there means
//     the old group moved past what the form carries, by a claim that may have been answered 201 before the marker
//     stood, so the form is refused 409 with that generation, which its re-former takes before it forms again; none
//     there and the form is filed. Which of the two a closing came to, its verdict, is recorded once, by an
//     If-None-Match create of gkm/<old>/closing/<h>, the form's bytes for sealed and nothing for void, so two tries of
//     one request, a resend beside an original whose answer was lost, never come to both: a try that loses the create
//     follows the verdict that won it. A void closing empties the marker by If-Match, opening the group again, and a
//     generation a claim wrote while the marker stood is then one of the group's like any other, its claimer taking it
//     at its next rotation from its draft;
//   - a claim, a wrap batch and a recovery-wrap batch in the old group write as they did and then read the marker,
//     since the store cannot condition a create on another object: a marker that stands answers 409 with its bytes,
//     naming the new group, whatever the write left, and the rotator follows the form. A claim reads it before its
//     create too, so one that starts once the marker stands writes nothing: a generation a refused claim wrote past
//     the form's makes the re-form's own read find the group moved past it, and void it, so only a claim already past
//     that read when the marker landed can cost a re-form its closing. An epoch commit reads it before its PUT alone,
//     since a commit answered 409 is a loser its committer discards (KF6), and one whose epoch stands must not be;
//   - GET gen and the drop-key route read the marker after their LIST and serve no generation past the closing form's,
//     so what a claim wrote after the marker stood reaches no member;
//   - another re-form finding a marker that closes the group answers 409 with it, which its client reads as another
//     re-form standing (ErrGkmWait), unless that closing is void, or has no verdict yet while the old group holds a
//     generation past its form's, when it is voided here as its own try would void it, or has no verdict yet and a
//     marker older than ReformClosingStallAge while this re-form's generation is at least its own (QD-1188), when it
//     is voided too: its re-former stopped between its marker and its verdict, and without this the group stayed
//     closed for good. Then the marker is taken by If-Match. A void recorded here races the stalled request, if it
//     still runs, on the verdict's one create, and the loser follows the winner, so a takeover is safe at any age;
//     the bound only keeps two live re-forms from voiding each other in turn. A closing voided so, its form's
//     generation the group's newest, refuses its own request with the marker that took over, or 503 while none has.

package gkmservice

import (
	"bytes"
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A group's closing marker as one read found it.
type gkmGroupClosing struct {
	// the marker's bytes as stored: the closing form's, which a 409 carries, or empty once a void closing opened the
	// group again
	raw  []byte
	etag string
	// when the store wrote the marker, by its own clock, for a marker a read found; zero for one this request wrote
	lastModified time.Time
	// the closing form's new group, and the newest generation its ladder carries
	newGroupId sidecar.Id
	generation uint64
}

// Whether the marker closes its group: one that stands and that no void closing emptied.
func (self *gkmGroupClosing) closes() bool {
	return self != nil && 0 < len(self.raw)
}

// A closing marker's bytes held to their shape: empty, or a Signed GroupForm re-forming groupId into another group at
// a generation; errGkmStoreFault for anything else, which gkm never writes.
func parseGkmGroupClosing(groupId sidecar.Id, objectBytes []byte, etag string) (*gkmGroupClosing, error) {
	closing := &gkmGroupClosing{raw: objectBytes, etag: etag}
	if len(objectBytes) == 0 {
		return closing, nil
	}
	fault := errors.Join(errGkmStoreFault, errors.New("a closing marker that is no GroupForm re-forming its group"))
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(objectBytes, signed); err != nil || signed.GetType() != uint32(bridge.SignedType_SIGNED_GROUP_FORM) {
		return nil, fault
	}
	body := &protocol.GroupForm{}
	if err := proto.Unmarshal(signed.GetBody(), body); err != nil || !bytes.Equal(body.GetPreviousGroupId(), groupId.Bytes()) || body.GetGeneration() == 0 {
		return nil, fault
	}
	newGroupId, err := sidecar.IdFromBytes(body.GetGroupId())
	if err != nil || newGroupId == (sidecar.Id{}) || newGroupId == groupId {
		return nil, fault
	}
	closing.newGroupId = newGroupId
	closing.generation = body.GetGeneration()
	return closing, nil
}

// groupId's closing marker as the store holds it now, never from a cache, since the fence judges by this read what a
// write it could not condition on the marker left: nil for none.
func (self *GkmEngine) readGroupClosing(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id) (*gkmGroupClosing, error) {
	objectBytes, info, err := readGkmObject(ctx, cluster, GkmGroupClosedKey(groupId), self.settings.StatementMaxByteCount)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	closing, err := parseGkmGroupClosing(groupId, objectBytes, info.Etag)
	if err != nil {
		return nil, err
	}
	closing.lastModified = info.LastModified
	return closing, nil
}

// The fence's read after a write to groupId: false once it has answered, 409 with the marker of a group a re-form
// closed, naming the new group, whatever the write left, or 503.
func (self *GkmEngine) checkGroupOpen(request *GkmRequest, groupId sidecar.Id) bool {
	closing, err := self.readGroupClosing(request.Ctx, request.Cluster, groupId)
	if err != nil {
		self.answerStoreError(request, err)
		return false
	}
	if closing.closes() {
		request.Conflict(closing.raw)
		return false
	}
	return true
}

// Of the generations a listing of groupId's gen/ found, ascending, those a reader is served: in a group a re-form
// closed none past the closing form's generation, which only a claim answered 409 can have written. The marker is read
// after the listing, so every generation listed while it stood is held to it.
func (self *GkmEngine) servedGenerations(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, generations []uint64) ([]uint64, error) {
	if len(generations) == 0 {
		return generations, nil
	}
	closing, err := self.readGroupClosing(ctx, cluster, groupId)
	if err != nil {
		return nil, err
	}
	if !closing.closes() {
		return generations, nil
	}
	for index, generation := range generations {
		if closing.generation < generation {
			return generations[:index], nil
		}
	}
	return generations, nil
}

// Creates key holding body, If-None-Match, as createGkmObject does, and answers the bytes that then stand there with
// what the store says of them: body itself, with only its etag, when this call wrote it, and as a read found them
// otherwise, an earlier try of the same bytes included. errGkmObjectGone for a key that existed and is gone, which
// only a shred leaves.
func createGkmObjectHeld(ctx context.Context, cluster sidecar.BlobCluster, key string, body []byte, maxByteCount int64) (held []byte, info *sidecar.BlobInfo, err error) {
	if err := checkGkmWriteClass(ctx); err != nil {
		return nil, nil, err
	}
	for writeCount := 1; ; writeCount += 1 {
		newEtag, err := cluster.PutIfNoneMatch(ctx, key, body, nil)
		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			return body, &sidecar.BlobInfo{Key: key, Etag: newEtag}, nil
		case errors.Is(err, sidecar.ErrBlobPrecondition), errors.As(err, &unknown):
			objectBytes, info, readErr := readGkmObject(ctx, cluster, key, maxByteCount)
			switch {
			case readErr == nil:
				return objectBytes, info, nil
			case !errors.Is(readErr, sidecar.ErrBlobNotFound) && unknown != nil:
				// the read could not tell, so the create's outcome stays unknown
				return nil, nil, err
			case !errors.Is(readErr, sidecar.ErrBlobNotFound):
				return nil, nil, readErr
			case unknown == nil:
				return nil, nil, errGkmObjectGone
			case gkmCreateWriteCount <= writeCount:
				return nil, nil, err
			}
			// it never landed, and by the settle rule it never will: send the same bytes again
		default:
			return nil, nil, err
		}
	}
}

// Replaces the bytes key holds at etag with body, If-Match, and answers the etag body then stands at: "" when another
// write moved the key first, which the caller judges by reading it again. A lost answer is read back.
func replaceGkmObjectHeld(ctx context.Context, cluster sidecar.BlobCluster, key string, etag string, body []byte, maxByteCount int64) (string, error) {
	if err := checkGkmWriteClass(ctx); err != nil {
		return "", err
	}
	newEtag, err := cluster.PutIfMatch(ctx, key, etag, body, nil)
	var unknown *sidecar.BlobUnknownError
	switch {
	case err == nil:
		return newEtag, nil
	case errors.Is(err, sidecar.ErrBlobPrecondition):
		return "", nil
	case errors.As(err, &unknown):
		held, info, readErr := readGkmObject(ctx, cluster, key, maxByteCount)
		switch {
		case readErr == nil && bytes.Equal(held, body):
			return info.Etag, nil
		case readErr == nil || errors.Is(readErr, sidecar.ErrBlobNotFound):
			return "", nil
		}
	}
	return "", err
}

// The fence's writes at a re-form of the repo's newest group, between the new group's owner marker and its form: the
// old group's closing marker, then the closing's verdict (the file header). true once the form may be filed, its
// closing sealed; false once it has answered: 409 with the marker of another re-form that stands or is under way, 409
// with the old group's generation past the form's, which the form does not carry, or 503.
func (self *GkmEngine) closeGroupForReform(request *GkmRequest, form *gkmFormUpload) bool {
	oldGroupId, err := sidecar.IdFromBytes(form.body.GetPreviousGroupId())
	if err != nil {
		request.BadRequest()
		return false
	}
	// a form whose closing an earlier try voided closes the group no more: it is refused as that try was
	sealed, found, ok := self.readClosingVerdict(request, oldGroupId, form.raw)
	if !ok {
		return false
	}
	if found && !sealed {
		return self.refuseVoidClosing(request, oldGroupId, form)
	}
	closing, ok := self.takeGroupClosing(request, oldGroupId, form)
	if !ok {
		return false
	}
	return self.settleGroupClosing(request, oldGroupId, form, closing)
}

// The old group's gen/<generation+1> as stored, the one generation past a form's generation that can stand there,
// since a claim needs its parent: nil for none. false once it has answered 503.
func (self *GkmEngine) newerGeneration(request *GkmRequest, groupId sidecar.Id, generation uint64) ([]byte, bool) {
	newer, err := self.readGeneration(request.Ctx, request.Cluster, groupId, generation+1)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, true
	}
	if err != nil {
		self.answerStoreError(request, err)
		return nil, false
	}
	return newer, true
}

// Writes the old group's closing marker with form's bytes, or finds them there from an earlier try, taking over a
// marker a void closing emptied, or one whose closing is void or can be voided since the old group moved past its
// form. Answers the marker as it then stands, this form's; false once it has answered: 409 with another re-form's
// marker that stands or is under way, or 503.
func (self *GkmEngine) takeGroupClosing(request *GkmRequest, oldGroupId sidecar.Id, form *gkmFormUpload) (*gkmGroupClosing, bool) {
	key := GkmGroupClosedKey(oldGroupId)
	barrierKey := gkmBarrierGroupKey(oldGroupId)
	maxByteCount := self.settings.StatementMaxByteCount
	for writeCount := 0; writeCount < self.settings.ReformCloseWriteCount; writeCount += 1 {
		if !request.CheckRepoWritable() {
			return nil, false
		}
		testHookBarrier(BarrierGroupCloseBefore, barrierKey)
		held, info, err := createGkmObjectHeld(request.Ctx, request.Cluster, key, form.raw, maxByteCount)
		testHookBarrier(BarrierGroupCloseAfter, barrierKey)
		if errors.Is(err, errGkmObjectGone) {
			continue
		}
		if err != nil {
			self.answerStoreError(request, err)
			return nil, false
		}
		standing, err := parseGkmGroupClosing(oldGroupId, held, info.Etag)
		if err != nil {
			self.answerStoreError(request, err)
			return nil, false
		}
		standing.lastModified = info.LastModified
		if bytes.Equal(held, form.raw) {
			return standing, true
		}
		if standing.closes() {
			// another re-form's closing, which stands, is under way, stalled, or came to nothing
			displaceable, ok := self.closingDisplaceable(request, oldGroupId, standing, form)
			if !ok {
				return nil, false
			}
			if !displaceable {
				request.Conflict(standing.raw)
				return nil, false
			}
		}
		if !request.CheckRepoWritable() {
			return nil, false
		}
		testHookBarrier(BarrierGroupCloseBefore, barrierKey)
		newEtag, err := replaceGkmObjectHeld(request.Ctx, request.Cluster, key, standing.etag, form.raw, maxByteCount)
		testHookBarrier(BarrierGroupCloseAfter, barrierKey)
		if err != nil {
			self.answerStoreError(request, err)
			return nil, false
		}
		if newEtag != "" {
			closing, err := parseGkmGroupClosing(oldGroupId, form.raw, newEtag)
			if err != nil {
				self.answerStoreError(request, err)
				return nil, false
			}
			return closing, true
		}
		// another write moved the marker since this one read it: judged again from what stands
	}
	request.Unavailable()
	return nil, false
}

// Whether another re-form's closing of the old group gives way to form's: void; or with no verdict yet, either the old
// group holding a generation past its form's, which voids it here as its own try's verdict would, or its marker older
// than ReformClosingStallAge while form's generation is at least its own (QD-1188), its re-former having stopped
// between its marker and its verdict. false in ok once it has answered.
func (self *GkmEngine) closingDisplaceable(request *GkmRequest, oldGroupId sidecar.Id, standing *gkmGroupClosing, form *gkmFormUpload) (displaceable bool, ok bool) {
	sealed, found, ok := self.readClosingVerdict(request, oldGroupId, standing.raw)
	if !ok {
		return false, false
	}
	if found {
		return !sealed, true
	}
	newer, ok := self.newerGeneration(request, oldGroupId, standing.generation)
	if !ok {
		return false, false
	}
	stalled := !standing.lastModified.IsZero() && self.settings.ReformClosingStallAge <= request.Now().Sub(standing.lastModified) &&
		standing.generation <= form.body.GetGeneration()
	if newer == nil && !stalled {
		// under way, and the group has not moved past its form
		return false, true
	}
	sealed, ok = self.recordClosingVerdict(request, oldGroupId, standing.raw, false)
	if !ok {
		return false, false
	}
	return !sealed, true
}

// A closing verdict's bytes: the closing form's for sealed, nothing for void; errGkmStoreFault for anything else.
func gkmClosingVerdictSealed(objectBytes []byte, formRaw []byte) (bool, error) {
	switch {
	case len(objectBytes) == 0:
		return false, nil
	case bytes.Equal(objectBytes, formRaw):
		return true, nil
	}
	return false, errors.Join(errGkmStoreFault, errors.New("a closing's verdict that is neither its form nor empty"))
}

// The verdict of the old group's closing by the form whose bytes are formRaw: found false while none is recorded.
// false in ok once it has answered 503.
func (self *GkmEngine) readClosingVerdict(request *GkmRequest, oldGroupId sidecar.Id, formRaw []byte) (sealed bool, found bool, ok bool) {
	key := GkmGroupClosingKey(oldGroupId, sha256Of(formRaw))
	objectBytes, _, err := readGkmObject(request.Ctx, request.Cluster, key, self.settings.StatementMaxByteCount)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return false, false, true
	}
	if err == nil {
		sealed, err = gkmClosingVerdictSealed(objectBytes, formRaw)
	}
	if err != nil {
		self.answerStoreError(request, err)
		return false, false, false
	}
	return sealed, true, true
}

// Records the verdict of the old group's closing by the form whose bytes are formRaw, If-None-Match, and answers the
// one that stands: a try that loses the create follows the verdict another recorded first. false in ok once it has
// answered.
func (self *GkmEngine) recordClosingVerdict(request *GkmRequest, oldGroupId sidecar.Id, formRaw []byte, seal bool) (sealed bool, ok bool) {
	verdict := []byte{}
	if seal {
		verdict = formRaw
	}
	if !request.CheckRepoWritable() {
		return false, false
	}
	key := GkmGroupClosingKey(oldGroupId, sha256Of(formRaw))
	barrierKey := gkmBarrierGroupKey(oldGroupId)
	testHookBarrier(BarrierGroupClosingBefore, barrierKey)
	held, _, err := createGkmObjectHeld(request.Ctx, request.Cluster, key, verdict, self.settings.StatementMaxByteCount)
	testHookBarrier(BarrierGroupClosingAfter, barrierKey)
	if err == nil {
		sealed, err = gkmClosingVerdictSealed(held, formRaw)
	}
	if err != nil {
		self.answerStoreError(request, err)
		return false, false
	}
	return sealed, true
}

// Settles this form's closing: the verdict already recorded, else sealed while the old group holds nothing past the
// form's generation and void once it does, recorded If-None-Match. true once sealed. A void closing empties the
// marker, opening the group again, and answers 409 with the generation past the form's. false once it has answered.
func (self *GkmEngine) settleGroupClosing(request *GkmRequest, oldGroupId sidecar.Id, form *gkmFormUpload, closing *gkmGroupClosing) bool {
	sealed, found, ok := self.readClosingVerdict(request, oldGroupId, form.raw)
	if !ok {
		return false
	}
	if !found {
		newer, ok := self.newerGeneration(request, oldGroupId, closing.generation)
		if !ok {
			return false
		}
		sealed, ok = self.recordClosingVerdict(request, oldGroupId, form.raw, newer == nil)
		if !ok {
			return false
		}
	}
	if sealed {
		return true
	}
	return self.refuseVoidClosing(request, oldGroupId, form)
}

// Refuses a form whose closing came to void: empties the old group's marker where it still holds the form, opening
// the group again, and answers 409 with the generation past the form's, which its re-former takes before it forms
// again. A closing another re-form took over as stalled (QD-1188) may have none past it: then the 409 carries the
// marker that took over, which its client reads as another re-form standing, and with none standing yet the answer is
// 503, so a resend finds what came of it. Always false, once it has answered.
func (self *GkmEngine) refuseVoidClosing(request *GkmRequest, oldGroupId sidecar.Id, form *gkmFormUpload) bool {
	if !self.openGroup(request, oldGroupId, form.raw) {
		return false
	}
	newer, ok := self.newerGeneration(request, oldGroupId, form.body.GetGeneration())
	if !ok {
		return false
	}
	if newer != nil {
		request.Conflict(newer)
		return false
	}
	closing, err := self.readGroupClosing(request.Ctx, request.Cluster, oldGroupId)
	if err != nil {
		self.answerStoreError(request, err)
		return false
	}
	if closing.closes() && !bytes.Equal(closing.raw, form.raw) {
		request.Conflict(closing.raw)
		return false
	}
	request.Unavailable()
	return false
}

// Empties the old group's closing marker where it still holds formRaw, If-Match, so the group takes writes again; a
// marker another write moved since is left as it stands. false once it has answered.
func (self *GkmEngine) openGroup(request *GkmRequest, oldGroupId sidecar.Id, formRaw []byte) bool {
	key := GkmGroupClosedKey(oldGroupId)
	barrierKey := gkmBarrierGroupKey(oldGroupId)
	for writeCount := 0; writeCount < self.settings.ReformCloseWriteCount; writeCount += 1 {
		closing, err := self.readGroupClosing(request.Ctx, request.Cluster, oldGroupId)
		if err != nil {
			self.answerStoreError(request, err)
			return false
		}
		if closing == nil || !bytes.Equal(closing.raw, formRaw) {
			return true
		}
		if !request.CheckRepoWritable() {
			return false
		}
		testHookBarrier(BarrierGroupCloseBefore, barrierKey)
		newEtag, err := replaceGkmObjectHeld(request.Ctx, request.Cluster, key, closing.etag, []byte{}, self.settings.StatementMaxByteCount)
		testHookBarrier(BarrierGroupCloseAfter, barrierKey)
		if err != nil {
			self.answerStoreError(request, err)
			return false
		}
		if newEtag != "" {
			return true
		}
	}
	request.Unavailable()
	return false
}
