// Format 2 at POST .../reseed (§11.13's re-seed row; R-EVS-17, D-EVS-17, D-EVS-37, FI-5, FI-12, FI-16, FS-70, FS-96;
// EVS2-M10-13). At a format-2 instance the reseed mode takes a format-2 push as its record stored it, read by format
// 2's parsers (EvsCheckStoredPayload, EvsCheckStoredPart, EvsCheckStoredSeal), with format 2's rules beside the mode's
// own (reseed.go). A format-1 instance answers it 409 FORMAT_UNSUPPORTED {needs_format: 2}, recording nothing.
//
//	gate      §19.11's format2 gate admits the repo's network, else 409 VERSIONING, refusing nothing
//	refs      format 2's 5c as the push route runs it (check_versioning.go, check_cut.go, check_drop.go), at the
//	          statement's own auth pin, and a DROP's consent and a cancel's window at the statement's time less 5b's
//	          bound, the earliest evs could have judged it, so no DROP or cancel that committed is refused when
//	          replayed
//	content   a versionless version's content comes back only where a device holds it: its kind-5 uploads and its
//	          staged segments, which a re-seeded record never carries in a tail, by PUT .../segments as ordinary
//	          kind-5 uploads before its first reseed call. A kind-5 upload or a staged item seg/ does not hold commits
//	          with the version, which reads `collected` once replaced; one seg/ holds is of its item's padded size,
//	          and an upload a kind-5 locator names is a kind-5 segment naming this push by its header. A segment only
//	          kind-1 locators name is format 1's: seg/ holds it, else 409 SEGMENT_GONE
//	citation  5h's citation rule (check_citation.go) over the push's own new-objects list in place of the receipts
//	          and staged bytes a re-seed does not carry: its staged items, and the uploads a kind-5 locator names
//	purge     a re-seeded replacement's record lists its candidates and step 8 hands them to the purge as a commit's
//	          (push_purge.go); a re-seeded push in parts lists them at its seal over every part's changes, since no
//	          re-seeded part's record carries a replaced list
//	replaced  5a's answer for a one-part push evs already holds is refused 409 VERSIONING while seg/ holds kind-5
//	          content of a version of it that the re-seeded history replaces and its path's newest version does not
//	          name: a stale mirror's upload, which went in before the call. That content is handed to the purge, as
//	          the replacing commit's list named it, so a stale mirror resurrects nothing (FS-70)
//	fence     5h's DROPPED fence is not run: a re-seed replays, ref after ref, a history the fence already held, so a
//	          version of one ref citing what another ref's DROP lists is kept by the re-run job's mark, never refused
//
// DROP pushes replay with the rest of history: step 8 appends each to the drop table as a commit does, and the job
// runs again from its signed state (EVSB-M10-03).
//
// Not built, each leaving the content where it is: the replaced rule at a seal's or a part call's 5a, which step 4
// has not read the paths for, and for a path whose head moved to another path epoch since the push.
//
// Not safe for concurrent use: it lives on its attempt.

package evsservice

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A re-seeded format-2 push's new segments as seg/ holds them.
type reseedFormat2Segments struct {
	// the new-objects SEGMENT items a kind-5 locator of a new version names, and those a kind-1 locator names
	kind5Named map[[sha256.Size]byte]bool
	kind1Named map[[sha256.Size]byte]bool
	// each STAGED_SEGMENT item
	staged map[[sha256.Size]byte]bool
	// of the kind-5-named uploads seg/ holds, those whose header is a kind-5 header naming this push
	kind5Headers map[[sha256.Size]byte]bool
}

// The format-2 rules of the reseed mode's 5 (b-h), after reseed.go's own: see the file header. view is the reseed
// mode's view, its auth the statement's own state.
func (self *pushAttempt) checkReseedFormat2(view *PushView) *EvsCheckRefusal {
	if !self.needsFormat2 {
		return nil
	}
	if !self.engine.format2Instance() {
		refusal := newEvsCheckRefusal(EvsCheckReasonFormatUnsupported, "a format-2 re-seed at a format-1 instance")
		refusal.NeedsFormat = sidecar.EvsRepoFormat2
		return refusal
	}
	if !self.engine.format2.Admits(self.networkId) {
		return newEvsCheckRefusal(EvsCheckReasonFormat2Gate, "a format-2 re-seed from a network outside the format2 gate")
	}
	judged := *view
	judged.Format2Rules = nil
	judged.NeedsFormat2 = true
	// a DROP's consent and a cancel's window at the earliest time evs could have judged the statement
	judged.Now = time.UnixMilli(view.Statement.Push.GetTimeMs()).Add(-self.settings.PushTimeBound)
	for _, check := range []func(view *PushView) *EvsCheckRefusal{CheckDropRefs, checkFormat2Refs} {
		if refusal := check(&judged); refusal != nil {
			return refusal
		}
	}
	return nil
}

// The format-2 rules of the reseed mode's 5h, after checkReseedObjects: the citation rule over the push's own new
// objects, then a DROP's boundary. See the file header.
func (self *pushAttempt) checkReseedFormat2Objects(view *PushView) *EvsCheckRefusal {
	if !self.needsFormat2 {
		return nil
	}
	if view.Stage != PushStagePart {
		if refusal := self.checkReseedCitation(view); refusal != nil {
			return refusal
		}
	}
	judged := *view
	judged.Format2Rules = nil
	return CheckDropBoundary(&judged)
}

// 5h's citation rule for a re-seeded push: the sources a re-seed carries are its new-objects list, its staged items
// and the uploads a kind-5 locator names standing in for its staged bytes and its receipts marked versionless. An
// upload seg/ holds counts only where its header is a kind-5 header naming this push.
func (self *pushAttempt) checkReseedCitation(view *PushView) *EvsCheckRefusal {
	segments := self.reseed.format2
	if segments == nil {
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "a re-seed's new segments not read")
	}
	uploads := map[[sha256.Size]byte]bool{}
	for segmentId := range segments.kind5Named {
		if _, held := self.reseed.segments[segmentId]; held && !segments.kind5Headers[segmentId] {
			// held at seg/ under a header that is not this push's kind-5 one: no versionless upload of it
			continue
		}
		uploads[segmentId] = true
	}
	citations, sources, refusal := evsCitationsWith(view, segments.staged, uploads)
	if refusal != nil {
		return refusal
	}
	err := sidecar.EvsCheckCitation(citations, sources)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sidecar.ErrEvsVersioning):
		return newEvsCheckRefusal(EvsCheckReasonCitation, err.Error())
	}
	return newEvsCheckRefusal(EvsCheckReasonInvalid, err.Error())
}

// Which new segments of a re-seeded format-2 push a kind-5 or a kind-1 locator names, and its staged items; and of
// the kind-5-named ones seg/ holds, whose header names this push. Once per attempt, after readReseedSegments.
func (self *pushAttempt) readReseedFormat2Segments(segmentCluster func() (sidecar.BlobCluster, error)) *EvsCheckRefusal {
	reseed := self.reseed
	if reseed.format2 != nil || !self.needsFormat2 {
		return nil
	}
	segments := &reseedFormat2Segments{
		kind5Named:   map[[sha256.Size]byte]bool{},
		kind1Named:   map[[sha256.Size]byte]bool{},
		staged:       map[[sha256.Size]byte]bool{},
		kind5Headers: map[[sha256.Size]byte]bool{},
	}
	newSegments := map[[sha256.Size]byte]bool{}
	for _, object := range self.payload.NewObjects {
		if len(object.Id) != sha256.Size {
			continue
		}
		switch object.Kind {
		case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT:
			newSegments[[sha256.Size]byte(object.Id)] = true
		case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT:
			segments.staged[[sha256.Size]byte(object.Id)] = true
		}
	}
	for _, change := range self.payload.Changes {
		if !change.WritesEntry() {
			continue
		}
		entry, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil {
			return newEvsCheckRefusal(EvsCheckReasonInvalid, "an entry version that does not parse")
		}
		for _, locator := range entry.GetChain() {
			if len(locator.GetId()) != sha256.Size || !newSegments[[sha256.Size]byte(locator.GetId())] {
				continue
			}
			switch protocol.EvsLocatorKind(locator.GetKind()) {
			case protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT:
				if !locator.GetStaged() {
					segments.kind5Named[[sha256.Size]byte(locator.GetId())] = true
				}
			case protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT:
				segments.kind1Named[[sha256.Size]byte(locator.GetId())] = true
			}
		}
	}
	for segmentId := range segments.kind5Named {
		if _, held := reseed.segments[segmentId]; !held {
			continue
		}
		cluster, err := segmentCluster()
		if err != nil {
			return newEvsCheckRefusal(EvsCheckReasonUnchecked, "no segment cluster")
		}
		header, err := readKind5Header(self.ctx, cluster, SegmentKey(self.repoId, segmentId))
		switch {
		case errors.Is(err, sidecar.ErrBlobNotFound):
		case errors.Is(err, sidecar.ErrEvsSegmentInvalid):
		case err != nil:
			return newEvsCheckRefusal(EvsCheckReasonUnchecked, "a segment's header that did not read")
		default:
			segments.kind5Headers[segmentId] = header.PushId == self.pushId && header.RepoId == self.repoId
		}
	}
	reseed.format2 = segments
	return nil
}

// A stored segment's kind-5 header: one ranged GET of its first 48 bytes.
func readKind5Header(ctx context.Context, cluster sidecar.BlobCluster, key string) (*sidecar.EvsKind5SegmentHeader, error) {
	object, err := cluster.GetRange(ctx, key, 0, sidecar.EvsKind5SegmentHeaderByteCount)
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	headerBytes := make([]byte, sidecar.EvsKind5SegmentHeaderByteCount)
	if _, err := io.ReadFull(object.Body, headerBytes); err != nil {
		return nil, err
	}
	return sidecar.ParseEvsKind5SegmentHeader(headerBytes)
}

// Whether a re-seeded format-2 push's new segment may stand absent from seg/: an upload only kind-5 locators name,
// or a staged item, which reads `collected` once replaced.
func (self *reseedFormat2Segments) mayBeAbsent(segmentId [sha256.Size]byte) bool {
	if self == nil {
		return false
	}
	return (self.kind5Named[segmentId] && !self.kind1Named[segmentId]) || self.staged[segmentId]
}

// 5a's answer in the reseed mode of a one-part format-2 push evs already holds: see the file header's replaced row.
// The outcome as it is for any other push, attempt or answer.
func (self *pushAttempt) reseedSettled(outcome *pushOutcome) *pushOutcome {
	if !outcome.committed || outcome.ownCommit != nil || !self.needsFormat2 || self.seal != nil || self.part != nil ||
		self.payload == nil || self.reads == nil || self.reads.view == nil {
		return outcome
	}
	view := self.reads.view
	push := self.statement.Push
	pathEpoch := max(1, push.GetPathEpoch())
	commits := []*PurgeCommit{}
	var segmentCluster sidecar.BlobCluster
	for _, change := range self.payload.Changes {
		if !change.WritesEntry() {
			continue
		}
		entry, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil || entry.GetVersioning() != uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS) {
			continue
		}
		read := view.Paths[change.TokenPath.KeyString()]
		if read == nil || read.Newest == nil || read.Newest.CommitVersion <= outcome.committedVersion ||
			(read.Epoch != 0 && read.Epoch != pathEpoch) {
			// still its path's newest, or read in another epoch: nothing here judges it replaced
			continue
		}
		newest, refusal := evsPathNewestEntry(view, change.TokenPath)
		if refusal != nil {
			return outcome
		}
		named := map[string]bool{}
		if newest != nil {
			for _, locator := range newest.GetChain() {
				named[string(locator.GetId())] = true
			}
		}
		candidate := &protocol.EvsPurgeCandidate{TokenPath: change.TokenPath.Components(), ReplacedVersion: entry.GetVersion()}
		for _, locator := range entry.GetChain() {
			if protocol.EvsLocatorKind(locator.GetKind()) != protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT ||
				len(locator.GetId()) != sha256.Size || named[string(locator.GetId())] {
				continue
			}
			if segmentCluster == nil {
				cluster, err := self.engine.blobs.SegmentCluster()
				if err != nil {
					return outcome
				}
				segmentCluster = cluster
			}
			ctx, cancel := context.WithTimeout(self.engine.ctx, self.settings.PushAttemptTimeout)
			_, err := segmentCluster.Head(ctx, SegmentKey(self.repoId, [sha256.Size]byte(locator.GetId())))
			cancel()
			switch {
			case errors.Is(err, sidecar.ErrBlobNotFound):
				continue
			case err != nil:
				// unread: the answer stays 5a's, and the content where it is
				return outcome
			}
			if locator.GetStaged() {
				candidate.StagedSegmentIds = append(candidate.StagedSegmentIds, locator.GetId())
			} else {
				candidate.SegmentIds = append(candidate.SegmentIds, locator.GetId())
			}
		}
		if len(candidate.GetSegmentIds()) == 0 && len(candidate.GetStagedSegmentIds()) == 0 {
			continue
		}
		commits = append(commits, &PurgeCommit{
			ClusterId: self.cluster.ClusterId(),
			RepoId:    self.repoId,
			RefId:     self.refId,
			NetworkId: self.networkId,
			PushId:    read.Newest.PushId,
			Version:   read.Newest.CommitVersion,
			PathEpoch: push.GetPathEpoch(),
			List:      &protocol.EvsPurgeList{Candidates: []*protocol.EvsPurgeCandidate{candidate}},
			Replaced:  []*PurgeReplaced{{TokenPath: change.TokenPath, Version: entry}},
		})
	}
	if len(commits) == 0 {
		return outcome
	}
	for _, commit := range commits {
		self.engine.handPurge(commit)
	}
	refusal := newEvsCheckRefusal(EvsCheckReasonReseedReplaced, "kind-5 content for a version the re-seeded history replaces")
	return refusedOutcome(refusal.Reply(self.pushId))
}

// evsCitationsOf's input with the given staged items and versionless uploads in place of the view's staged bytes and
// receipts.
func evsCitationsWith(view *PushView, staged map[[sha256.Size]byte]bool, uploads map[[sha256.Size]byte]bool) ([]*sidecar.EvsCitation, *sidecar.EvsCitationSources, *EvsCheckRefusal) {
	citations, sources, refusal := evsCitationsOf(view)
	if refusal != nil {
		return nil, nil, refusal
	}
	sources.Staged = staged
	sources.VersionlessUploads = uploads
	return citations, sources, nil
}
