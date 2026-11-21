//go:build !ios_extension

// The names and signed writes of every document-bearing file the index ref has held (§11.14's erase row).
// A live listing cannot give the names of files a roll-up removed. Walk to the verified head from the ref's
// first statement, opening only the index's signed directory deltas. Keep names across removals and retokenize
// them at each path epoch. Retained checks each path's History against the commits found here.

package sidecar

import (
	"context"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Every signed file write under a document-bearing index path, by its name and commit version.
func (self *indexEvsStore) retainedFileWrites(ctx context.Context, head *EvsVerifiedHead) (map[string]map[uint64]bool, error) {
	writes := map[string]map[uint64]bool{}
	if head.Version == 0 {
		return writes, nil
	}
	verified, err := self.repo.verifiedHistory(ctx, head)
	if err != nil {
		return nil, err
	}
	if err := self.repo.client.preDecrypt(ctx, self.repo.repoId, head.RefId, nil); err != nil {
		return nil, err
	}
	root := self.rootDirectory()
	rootNames, err := evsReadPathNames(root)
	if err != nil {
		return nil, err
	}
	names := map[string][][]byte{root: rootNames}
	var epoch uint64
	var pathKey *EvsPathKey
	var rootTokens EvsTokenPath
	var byToken map[string]string
	keys := newEvsReadKeys(self.repo)
	for _, statement := range verified.Statements {
		signed := statement.Statement
		if next := max(1, signed.Push.GetPathEpoch()); epoch != next {
			epoch = next
			pathKey, err = keys.path(ctx, epoch)
			if err != nil {
				return nil, err
			}
			byToken = map[string]string{}
			for path, components := range names {
				tokens, err := EvsPathTokens(pathKey, components)
				if err != nil {
					return nil, err
				}
				byToken[string(tokens.Bytes())] = path
				if path == root {
					rootTokens = tokens
				}
			}
		}
		// An inline change gives its exact path. A signed covering prefix of a multipart change may be
		// above the index root. Only its checked parts then tell whether it reached the index.
		touches := slices.ContainsFunc(signed.Changes, func(change *EvsCheckedChange) bool {
			return change.TokenPath.HasPrefix(rootTokens)
		}) || slices.ContainsFunc(signed.ChangedPrefixes, func(prefix EvsTokenPath) bool {
			return prefix.HasPrefix(rootTokens) || rootTokens.HasPrefix(prefix)
		})
		if !touches {
			continue
		}
		payload, err := self.repo.pushContent(ctx, head, statement)
		if err != nil {
			return nil, err
		}
		for _, change := range payload.Changes {
			if !change.WritesEntry() || !change.TokenPath.HasPrefix(rootTokens) {
				continue
			}
			path, ok := byToken[string(change.TokenPath.Bytes())]
			if !ok {
				return nil, fmt.Errorf("%w: an index entry with no signed name", ErrEvsEntryRefused)
			}
			entry := &protocol.EvsEntryVersion{}
			if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
				return nil, fmt.Errorf("%w: an index entry that does not parse", ErrEvsEntryRefused)
			}
			switch protocol.EvsEntryKind(entry.GetKind()) {
			case protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY:
				parent := names[path]
				rows, err := EvsOpenNameTable(entry.GetNames(), epoch, func(source uint64) (*EvsManifestKey, *EvsPathKey, EvsToken, error) {
					manifest, err := keys.manifest(ctx, source)
					if err != nil {
						return nil, nil, EvsToken{}, err
					}
					sourceKey, err := keys.path(ctx, source)
					if err != nil {
						return nil, nil, EvsToken{}, err
					}
					sourcePath, err := EvsPathTokens(sourceKey, parent)
					return manifest, sourceKey, sourcePath.Last(), err
				})
				if err != nil {
					self.repo.client.alarm(self.repo.repoId, head.RefId, SidecarEvsAlarmTamper, path, nil)
					return nil, err
				}
				for _, row := range rows {
					child := string(row.Name)
					if path != "" {
						child = path + "/" + child
					}
					components := append(slices.Clone(parent), row.Name)
					tokens, err := EvsPathTokens(pathKey, components)
					if err != nil {
						return nil, err
					}
					names[child] = components
					byToken[string(tokens.Bytes())] = child
				}
			case protocol.EvsEntryKind_EVS_ENTRY_FILE:
				if parsed, ok := indexParsePath(path, self.companion); ok && indexPathHoldsDocuments(parsed.kind) {
					if writes[path] == nil {
						writes[path] = map[uint64]bool{}
					}
					writes[path][statement.Version] = true
				}
			default:
				return nil, fmt.Errorf("%w: an unknown index entry kind", ErrEvsEntryRefused)
			}
		}
	}
	return writes, nil
}
