//go:build !ios_extension

// List (§11.7's name row, §11.9's newest row): a directory's children at the newest committed version, the folded
// table evs keeps with, in version order, each verified delta after it applied: a delta adds or replaces rows and
// removes the tokens it lists. Every row opens under its own epoch's keys and AAD and is checked against its token,
// recomputed from the directory's token in that epoch, since evs folds the table itself and only the token ties a row
// to a path; a carried row keeps its source epoch's token and AAD (§11.6). Any failure refuses the whole listing.
//
// A ref's root has no entry in format 1, so List of the root refuses until question
// evs1-m2-24-root-directory-names is answered.
//
// On every leg. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// A directory's children, verified.
func (self *EvsRepo) List(ctx context.Context, args *EvsReadArgs) (*EvsListing, error) {
	refId, err := self.resolveRefId(ctx, args.RefName, args.RefId)
	if err != nil {
		return nil, err
	}
	result, err := self.read(ctx, refId, []string{args.Path}, args.Version, args.Fresh)
	if err != nil {
		return nil, err
	}
	defer result.objects.close()
	verified := result.replies[0]
	switch {
	case verified.Base != nil:
		return nil, ErrEvsOverlayBase
	case verified.Removal != nil, verified.Absent:
		return nil, ErrEvsPathAbsent
	case verified.Entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY):
		return nil, fmt.Errorf("%w: a file, which ReadHead reads", ErrEvsTokenInvalid)
	}
	if err := self.client.preDecrypt(ctx, self.repoId, refId, nil); err != nil {
		return nil, err
	}
	names := result.paths[0].names
	epochKeys := func(epoch uint64) (*EvsManifestKey, *EvsPathKey, EvsToken, error) {
		manifest, err := result.keys.manifest(ctx, epoch)
		if err != nil {
			return nil, nil, EvsToken{}, err
		}
		pathKey, err := result.keys.path(ctx, epoch)
		if err != nil {
			return nil, nil, EvsToken{}, err
		}
		tokenPath, err := EvsPathTokens(pathKey, names)
		if err != nil {
			return nil, nil, EvsToken{}, err
		}
		return manifest, pathKey, tokenPath.Last(), nil
	}
	children := map[EvsToken]*EvsOpenedName{}
	apply := func(table *protocol.EvsNameTable, tableEpoch uint64) error {
		if table == nil {
			return nil
		}
		opened, err := EvsOpenNameTable(table, tableEpoch, epochKeys)
		if err != nil {
			self.client.alarm(self.repoId, refId, SidecarEvsAlarmTamper, args.Path, nil)
			return err
		}
		for _, removed := range table.GetRemovedTokens() {
			delete(children, EvsToken(removed))
		}
		for _, name := range opened {
			children[name.Token] = name
		}
		return nil
	}
	headEpoch := max(1, result.head.Head.GetPathEpoch().GetCurrent())
	if verified.Names != nil {
		if err := apply(verified.Names, headEpoch); err != nil {
			return nil, err
		}
	} else if err := apply(verified.Entry.GetNames(), max(1, verified.Statement.Push.GetPathEpoch())); err != nil {
		return nil, err
	}
	for _, delta := range verified.Deltas {
		// a delta below the pin has no statement here, and its rows are in the head's epoch
		deltaEpoch := headEpoch
		if delta.Statement != nil {
			deltaEpoch = max(1, delta.Statement.Push.GetPathEpoch())
		}
		if err := apply(delta.Entry.GetNames(), deltaEpoch); err != nil {
			return nil, err
		}
	}
	listing := &EvsListing{RefId: refId, Path: args.Path, HeadVersion: result.head.Version}
	for _, name := range children {
		listing.Entries = append(listing.Entries, &EvsListEntry{Name: name.Name, Kind: name.Kind, CarriedEpoch: name.Epoch})
	}
	slices.SortFunc(listing.Entries, func(a *EvsListEntry, b *EvsListEntry) int { return bytes.Compare(a.Name, b.Name) })
	return listing, nil
}
