// Format 2's 5h on evs (§11.7's content, kind 5, staged and cite rows, §11.8's 5h; I-EVS-10, FI-17, FS-64; EVS2-M10-06):
// sidecar.EvsCheckCitation over what step 4 read, the one rule replaying readers run too, answering 409 VERSIONING,
// recorded (§11.8's refuse row), for a kind-5 locator a versioned version names, one naming neither a staged segment
// of this push, an upload of this push whose receipt is marked versionless, nor an unstaged kind-5 locator of its
// path's base or of a path the push removes, a staged segment past its introducing version, a versionless version's
// kind-1 locator from anywhere but its base or a removed path, a kind-2 locator in a versionless version, a slot
// another path's version names, and a kind-5 segment or a removed versionless path's slot named twice.
//
// What it is told, from the view: the push's staged segments (the payload checks matched each to its new-objects item
// and its header to this push); its receipts that verify for this repo and signer and are marked versionless; each
// change's base, its path's newest version at step 4's head when that is the version the change names; each removed
// path's newest version; and each reuse source. A push in parts is checked at its seal, over every part's changes,
// staged segments and receipts, so a rename across parts is judged whole and the at-most-one rules hold across parts.
//
// Package-level functions are safe for concurrent use.

package evsservice

import (
	"crypto/sha256"
	"errors"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Format 2's 5h for a push carrying format 2, after format 1's 5h: the citation rule. A seam's rules, when the view
// carries one, ran at 5c instead. A part's citations wait for its seal, whose view holds every part's changes,
// staged segments, receipts and reads: a rename's removal and its target may sit in two parts, and the at-most-one
// rules count over the whole push, so only the seal can judge them, and only the seal commits.
func checkFormat2Objects(view *PushView) *EvsCheckRefusal {
	if !view.NeedsFormat2 || view.Format2Rules != nil || view.Stage == PushStagePart {
		return nil
	}
	return CheckCitation(view)
}

// 5h's citation rule: see the file header.
func CheckCitation(view *PushView) *EvsCheckRefusal {
	citations, sources, refusal := evsCitationsOf(view)
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

// The newest version step 4 read of a changed path, nil when it stands removed, was never written, or is a directory.
func evsPathNewestEntry(view *PushView, tokenPath sidecar.EvsTokenPath) (*protocol.EvsEntryVersion, *EvsCheckRefusal) {
	read := view.Paths[tokenPath.KeyString()]
	if read == nil || read.Newest == nil || !read.Newest.Exists || read.Newest.Directory {
		return nil, nil
	}
	var entryBytes []byte
	switch {
	case read.Newest.IndexVersion != nil:
		entryBytes = read.Newest.IndexVersion.GetEntryVersion()
	case read.Newest.Change != nil:
		entryBytes = read.Newest.Change.EntryVersion
	}
	if len(entryBytes) == 0 {
		return nil, nil
	}
	entry, err := parseEvsEntryVersion(entryBytes)
	if err != nil {
		return nil, newEvsCheckRefusal(EvsCheckReasonUnchecked, "a read version that does not parse")
	}
	return entry, nil
}

// The rule's input from the view: the new versions with their bases, and what they may cite.
func evsCitationsOf(view *PushView) ([]*sidecar.EvsCitation, *sidecar.EvsCitationSources, *EvsCheckRefusal) {
	push := view.Statement.Push
	sources := &sidecar.EvsCitationSources{
		RefId:              sidecar.Id(push.GetRefId()),
		Staged:             map[[sha256.Size]byte]bool{},
		VersionlessUploads: map[[sha256.Size]byte]bool{},
	}
	for _, staged := range view.Payload.Staged {
		sources.Staged[staged.Id] = true
	}
	signerId := sidecar.Id(push.GetSignerSidecarId())
	for _, receipt := range view.Receipts {
		if !receipt.GetVersionless() || len(receipt.GetSegmentId()) != sha256.Size || view.ReceiptKeys == nil {
			continue
		}
		// only a receipt that verifies marks its segment, as 5h's receipt row holds them
		if CheckUploadReceipt(view.ReceiptKeys, receipt, view.RepoId, signerId, view.Now) != nil {
			continue
		}
		sources.VersionlessUploads[[sha256.Size]byte(receipt.GetSegmentId())] = true
	}
	citations := []*sidecar.EvsCitation{}
	for _, change := range view.Payload.Changes {
		newest, refusal := evsPathNewestEntry(view, change.TokenPath)
		if refusal != nil {
			return nil, nil, refusal
		}
		if !change.WritesEntry() {
			if newest != nil {
				sources.Removed = append(sources.Removed, &sidecar.EvsCitedVersion{RefId: sources.RefId, TokenPath: change.TokenPath, Entry: newest})
			}
			continue
		}
		entry, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil {
			return nil, nil, newEvsCheckRefusal(EvsCheckReasonInvalid, "an entry version that does not parse")
		}
		var base *protocol.EvsEntryVersion
		if change.Change.GetBaseEntryVersion() != 0 && newest != nil && newest.GetVersion() == change.Change.GetBaseEntryVersion() {
			base = newest
		}
		citations = append(citations, &sidecar.EvsCitation{TokenPath: change.TokenPath, Version: entry, Base: base})
	}
	for _, reuse := range view.Reuses {
		if reuse == nil || reuse.Reuse == nil || reuse.EntryVersion == nil {
			// format 1's 5h refuses a reuse source step 4 found no version of
			continue
		}
		sources.Reuse = append(sources.Reuse, &sidecar.EvsCitedVersion{RefId: reuse.Reuse.RefId, TokenPath: reuse.Reuse.TokenPath, Entry: reuse.EntryVersion})
	}
	return citations, sources, nil
}
