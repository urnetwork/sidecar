//go:build !ios_extension

// Reads of versionless content (EVS2-M10-18; §11.7's reads row, §11.9's collected row, §18.5; R-EVS-8, R-EVS-14,
// D-EVS-38, I-EVS-4, FI-16, FS-64, FS-66): what a reader does when a versionless version's content is gone, ReadVersion,
// and a listing's settings.
//
//	content   a kind-5 or staged record opens and verifies as kind 1 (evs_reconstruct.go), then the whole plaintext's
//	          SHA-256 against the sealed content_sha256 and the git oid; a round that fetches a versionless version's
//	          ranges names the path at that version, which is how evs finds a staged segment in its push's record and
//	          how it answers `collected`
//	gone      `collected`, or a 404 of the content, decides nothing by itself: the reader reads the path's newest
//	          version with fresh set. The same version still newest is a missing segment, alarmed; a newer version, a
//	          removal or no path is a replacement, with no alarm: ErrEvsCollected, on which ReadHead reads again from
//	          the new head, at most EvsSettings.ReadReplacedRestartCount times, since a path overwritten faster than it
//	          downloads is a real outcome, and ReadVersion answers it to its caller
//	settings  List reads each file child's versioning when asked (EvsReadArgs.Settings), ReadMaxPathCount paths a
//	          round, and hides the index files' root unless asked (EvsReadArgs.IndexFiles; §16.2)
//
//	head mode a mobile or wasm client fetches versionless content only on an explicit open (§11.11's mobile row): head
//	          mode has no local tier and no pass that fetches content, so only ReadHead and ReadVersion ask for a
//	          versionless file's ranges; List, its settings and History read entries alone
//
// Not built: `dropped` and `drop_pending` are EVS2-M10-22's, and a path in either state is refused before it gets
// here (evs_proof.go). The search index's fetch policy, the aside to the head-mode rule, is SEARCH's.
//
// Not on the ios_extension leg, which reads format 1. Safe for concurrent use.

package sidecar

import (
	"context"
	"fmt"
	"io"

	"github.com/urnetwork/sidecar/protocol"
)

// The gone row (see the file header): what a versionless version's `collected` or missing content comes to, after a
// fresh read of its path's newest version. Never nil.
func (self *evsFormat2Rules) contentGone(ctx context.Context, repo *EvsRepo, result *evsReadResult, verified *EvsVerifiedPath) error {
	version := verified.Entry.GetVersion()
	read := result.pathOf(verified)
	if read == nil {
		// no path to ask again by: nothing shows a replacement
		repo.client.alarm(repo.repoId, result.refId, SidecarEvsAlarmMissingSegment, "", nil)
		return fmt.Errorf("%w: version %d of a versionless path", ErrEvsObjectMissing, version)
	}
	fresh, err := repo.readPaths(ctx, result.refId, []*evsReadPath{{path: read.path, token: read.token}}, true)
	if err != nil {
		return err
	}
	fresh.objects.close()
	newest := fresh.replies[0]
	if newest.Base == nil && !newest.Absent && newest.Removal == nil && newest.Entry != nil &&
		newest.Entry.GetVersion() == version && newest.CommitVersion == verified.CommitVersion {
		repo.client.alarm(repo.repoId, result.refId, SidecarEvsAlarmMissingSegment, read.path, nil)
		return fmt.Errorf("%w: version %d is its path's newest and its content is gone", ErrEvsObjectMissing, version)
	}
	return fmt.Errorf("%w: version %d was replaced", ErrEvsCollected, version)
}

// Reads an older version of a file by its number (§18.5), verified and reconstructed as ReadHead's is. A replaced
// versionless version answers ErrEvsCollected, after the fresh read that shows its replacement.
func (self *EvsRepo) ReadVersion(ctx context.Context, args *EvsReadArgs, out io.Writer) (*EvsFileInfo, error) {
	if args.Version == 0 {
		return nil, fmt.Errorf("%w: ReadVersion reads a version by its number", ErrEvsTokenInvalid)
	}
	refId, err := self.resolveRefId(ctx, args.RefName, args.RefId)
	if err != nil {
		return nil, err
	}
	return self.readFile(ctx, refId, args, args.Fresh, out)
}

// Each listed file's versioning, read from its newest version, ReadMaxPathCount paths a round. A child with no
// version the reader takes, one removed since the listing or one whose version the rules ignore, keeps 0.
func (self *EvsRepo) listSettings(ctx context.Context, refId Id, directory string, listing *EvsListing) error {
	files := []*EvsListEntry{}
	for _, entry := range listing.Entries {
		if entry.Kind == protocol.EvsEntryKind_EVS_ENTRY_FILE {
			files = append(files, entry)
		}
	}
	batchCount := DefaultEvsFormatSettings().ReadMaxPathCount
	for start := 0; start < len(files); start += batchCount {
		batch := files[start:min(len(files), start+batchCount)]
		paths := make([]string, 0, len(batch))
		for _, entry := range batch {
			path := string(entry.Name)
			if directory != "" {
				path = directory + "/" + path
			}
			paths = append(paths, path)
		}
		result, err := self.read(ctx, refId, paths, 0, false)
		if err != nil {
			return err
		}
		result.objects.close()
		for index, verified := range result.replies {
			if verified.Base == nil && !verified.Absent && verified.Removal == nil && verified.Entry != nil {
				batch[index].Versioning = verified.Entry.GetVersioning()
			}
		}
	}
	return nil
}
