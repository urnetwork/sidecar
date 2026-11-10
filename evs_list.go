//go:build !ios_extension

// List (§11.7's name row, §11.9's newest row): a directory's children at the newest committed version, the folded
// table evs keeps with, in version order, each verified delta after it applied: a delta adds or replaces rows and
// removes the tokens it lists. Every row opens under its own epoch's keys and AAD and is checked against its token,
// recomputed from the directory's token in that epoch, since evs folds the table itself and only the token ties a row
// to a path (EvsRepo.openListing, evs_epoch_read.go): the folded table's untagged rows under the epoch whose copy
// served it (entry_epoch), a carried row under its source epoch's, a delta's under its statement's epoch (§11.6;
// DESIGN-DETAILS 9.2.4). Any failure refuses the whole listing. A listing of the newest version is cached for its head
// version, where each row is its child's floor (9.2.3's E2) and what a lookup reads.
//
// The root, path "", is a directory like any other whose token path is empty in every epoch, its rows the top-level
// names sealed under parent t_0 (question evs1-m2-24-root-directory-names, option 1; DESIGN-DETAILS 9.2.8): a ref
// nothing was written to lists it empty.
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
	case args.Path == "" && verified.Absent:
		// a ref no top-level name was written to: an empty root
		return &EvsListing{RefId: refId, Path: args.Path, HeadVersion: result.head.Version}, nil
	case verified.Removal != nil, verified.Absent:
		return nil, ErrEvsPathAbsent
	case verified.Entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY):
		return nil, fmt.Errorf("%w: a file, which ReadHead reads", ErrEvsTokenInvalid)
	}
	if err := self.client.preDecrypt(ctx, self.repoId, refId, nil); err != nil {
		return nil, err
	}
	opened, err := self.openListing(ctx, result, 0)
	if err != nil {
		return nil, err
	}
	listing := &EvsListing{RefId: refId, Path: args.Path, HeadVersion: result.head.Version}
	cached := &evsListedDirectory{headVersion: result.head.Version, rows: map[string]*evsListedRow{}}
	for token, row := range opened {
		listing.Entries = append(listing.Entries, &EvsListEntry{Name: row.name, Kind: row.kind, CarriedEpoch: row.carried})
		cached.rows[string(row.name)] = &evsListedRow{kind: row.kind, epoch: row.epoch, token: token}
	}
	slices.SortFunc(listing.Entries, func(a *EvsListEntry, b *EvsListEntry) int { return bytes.Compare(a.Name, b.Name) })
	if args.Version == 0 {
		self.client.epochs.cacheListing(self.repoId, refId, args.Path, cached, self.client.settings.ListingCacheCount)
	}
	return listing, nil
}
