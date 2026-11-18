//go:build sidecar_testhooks && !ios_extension && !js

// The index on real engines, for SEARCH-M10-35's rows on sidecartest/fault's evs world (FS-74 on T2 and, through
// server's evshost, T3): an in-ref writer installed on an EvsClient as a composition will install one (none does yet,
// SEARCH-M10-13's note), writing its head beside each content push through the push builder's plan hook; and the index
// of a file-mode ref read back through EvsRepo's verifying reader, as every index builder reads it
// (evs_index_store_evs.go). Only the sidecar_testhooks build has it (§22.4).

package sidecar

import (
	"context"
	"errors"
)

// What an installed index writer judges and may do.
type SearchTestIndexWriterArgs struct {
	// Whether a settings or erasure set version's signer was one of the repo's admins when it signed: the composition's
	// AclState judge (indexAclAdmins). Required.
	IsAdmin func(signer Id) bool
	// Whether the device may merge now; nil never.
	MayMerge func() bool
}

// Installs an in-ref index writer on client: each format-2 content push of a file-mode ref carries the writer's head
// (IndexWriter.Prepare as the client's write plan hook). The function returned removes it.
func InstallSearchTestIndexWriter(client *EvsClient, args *SearchTestIndexWriterArgs) (func(), error) {
	if client == nil || args == nil || args.IsAdmin == nil {
		return nil, errors.New("search test index writer: a client and an admin judge")
	}
	writer, err := newIndexWriter(&indexWriterArgs{
		client: client,
		store: func(repo *EvsRepo, refName []byte) indexRefStore {
			return newIndexEvsStore(repo, refName, false)
		},
		isAdmin: func(repoId Id) func(file *indexFileVersion) bool {
			return func(file *indexFileVersion) bool { return args.IsAdmin(file.signerSidecarId) }
		},
		mayMerge: args.MayMerge,
		settings: DefaultIndexFormatSettings(),
		clock:    client.clock,
		log:      client.log,
	})
	if err != nil {
		return nil, err
	}
	return writer.Install(), nil
}

// What a file-mode ref's index holds at its head, read through repo as every index builder reads it.
type SearchTestEvsIndex struct {
	// The ref version read, its index files by path, and the documents its files hold live, by doc_key, at their
	// versions.
	Version uint64
	Files   map[string]uint64
	Live    map[[indexIdByteCount]byte]uint64
	// The start days of its buckets, ascending, and all's rolled_through_day and shards; 0 and none before a roll-up.
	Buckets          []uint32
	RolledThroughDay uint32
	AllShardCount    int
}

// Reads the index of repo's file-mode ref refName (nil: main) at its head, judging settings by isAdmin.
func ReadSearchTestEvsIndex(ctx context.Context, repo *EvsRepo, refName []byte, isAdmin func(signer Id) bool) (*SearchTestEvsIndex, error) {
	store := newIndexEvsStore(repo, refName, false)
	refId, err := store.refId(ctx)
	if err != nil {
		return nil, err
	}
	kind, err := repo.repoKind()
	if err != nil {
		return nil, err
	}
	view, err := indexLoadView(ctx, &indexViewArgs{
		store: store, repoId: repo.repoId, refId: refId, repoKind: kind,
		isAdmin:  func(file *indexFileVersion) bool { return isAdmin(file.signerSidecarId) },
		settings: DefaultIndexFormatSettings(),
	})
	if err != nil {
		return nil, err
	}
	index := &SearchTestEvsIndex{Version: view.head.version, Files: map[string]uint64{}, Live: map[[indexIdByteCount]byte]uint64{}}
	listing, err := store.List(ctx, view.head.version)
	if err != nil {
		return nil, err
	}
	for _, file := range listing.files {
		index.Files[file.path] = file.version
	}
	root := view.writeRoot()
	for _, bucket := range root.buckets {
		index.Buckets = append(index.Buckets, bucket.window.startDay)
	}
	if root.allManifest != nil {
		index.RolledThroughDay = root.allManifest.RolledThroughDay
	}
	index.AllShardCount = len(root.allShards)
	held, err := indexLoadHeldKeys(ctx, view, root)
	if err != nil {
		return nil, err
	}
	for key, newest := range held.keyNewests {
		if newest.live {
			index.Live[key] = newest.version
		}
	}
	return index, nil
}

// path's doc_key on repo's ref refId, chunk 0, under K_ref of the repo's RK_1 as gkm answers it to the device.
func SearchTestEvsDocKey(ctx context.Context, repo *EvsRepo, refId Id, path string) ([indexIdByteCount]byte, error) {
	repoKey, err := repo.client.args.Gkm.CurrentRepoKey(ctx, repo.repoId)
	if err != nil {
		return [indexIdByteCount]byte{}, err
	}
	refKey, err := indexRefKey(repoKey)
	if err != nil {
		return [indexIdByteCount]byte{}, err
	}
	return indexDocKey(refKey, refId, []byte(path), 0)
}

// One roll-up of the oldest expired bucket of repo's file-mode ref refName (nil: main), by runner, the device repo's
// client is, on that client's clock, through EvsRepo as every index builder reaches evs (SEARCH-M10-11's roller over
// indexEvsStore). K_index_g is the repo's newest generation's, as the device's gkm answers it.
func RollUpSearchTestEvs(ctx context.Context, repo *EvsRepo, refName []byte, runner Id, isAdmin func(signer Id) bool) (*SearchTestRollUp, error) {
	store := newIndexEvsStore(repo, refName, false)
	refId, err := store.refId(ctx)
	if err != nil {
		return nil, err
	}
	kind, err := repo.repoKind()
	if err != nil {
		return nil, err
	}
	repoKey, err := repo.client.args.Gkm.CurrentRepoKey(ctx, repo.repoId)
	if err != nil {
		return nil, err
	}
	padKey, err := indexNewPadKey(repoKey)
	if err != nil {
		return nil, err
	}
	roller, err := indexNewRoller(&indexRollerArgs{
		store: store, repoId: repo.repoId, refId: refId, repoKind: kind,
		isAdmin: func(file *indexFileVersion) bool { return isAdmin(file.signerSidecarId) },
		format:  DefaultIndexFormatSettings(),
		padKey:  func(ctx context.Context) (*indexPadKey, error) { return padKey, nil },
		tables:  indexLinkedTables(),
		clock:   repo.client.clock,
		runner:  runner,
	})
	if err != nil {
		return nil, err
	}
	outcome, err := roller.Roll(ctx, indexRootNumber)
	return searchTestRollUpOf(outcome, runner), searchTestErr(err)
}
