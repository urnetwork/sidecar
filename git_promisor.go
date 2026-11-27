//go:build !ios_extension && !sidecar_http

// The promisor (DESIGN-COMPUTE §13.4's clone row, D-GIT-2; GIT-M13-02): the blobs a sparse worktree has not fetched,
// as a promisor remote's are, each fetched from evs the first time a command reads it.
//
//	table    .git/ur/promised/xx/<rest of the oid>, one locator a blob (EvsGitBlobLocator): the ref and version whose
//	         push carries it, the chains before and at that version, and whether it is one of the push's entries or
//	         history records. The store holds a promised blob for every check a replay makes (HasGitObject), so trees
//	         and commits build over it; only a read fetches it
//	fetch    the blobs asked for, by version: the statement read from the log and walked from the kept chain before
//	         it, held to the kept chain at it, so it is the very push the replay took; its record read and its sealed
//	         metadata opened; its provenance judged and the run tainted first where it is untrusted (§13.6), before any
//	         blob is written; then each blob reconstructed as export reconstructs it, an entry's held to its sealed oid
//	         and a history record's to its size and oid, before it is written to the store; its locator dropped
//	         after. A blob a history record carries as a diff reads its base through the store, fetched in turn where
//	         that base is promised too
//	missing  a blob neither held nor promised is ErrEvsGitObjectMissing, as in any store; a promised one with no evs
//	         connected is ErrGitNotConnected, so a command run offline says why
//
// Not safe for concurrent use: one command's.

package sidecar

import (
	"cmp"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The promisor table's directory.
const gitPromisedDirectory = ".git/ur/promised"

// A locator as the table keeps it, hex for ids and chains.
type gitLocatorFile struct {
	Size        uint64 `json:"size"`
	RefId       string `json:"ref_id"`
	Version     uint64 `json:"version"`
	ChainBefore string `json:"chain_before"`
	Chain       string `json:"chain"`
	History     bool   `json:"history,omitempty"`
}

// The table of promised blobs on a worktree's file system.
type gitPromisorTable struct {
	fileSystem GitFileSystem
	settings   *GitSettings
}

// The table's file for oid.
func gitLocatorName(oid EvsGitOid) string {
	hexOid := hex.EncodeToString(oid[:])
	return gitPromisedDirectory + "/" + hexOid[:2] + "/" + hexOid[2:]
}

// Keeps a blob's locator.
func (self *gitPromisorTable) record(locator *EvsGitBlobLocator) error {
	content, err := json.Marshal(&gitLocatorFile{
		Size: locator.Size, RefId: locator.RefId.String(), Version: locator.Version,
		ChainBefore: hex.EncodeToString(locator.ChainBefore[:]), Chain: hex.EncodeToString(locator.Chain[:]),
		History: locator.History,
	})
	if err != nil {
		return err
	}
	name := gitLocatorName(locator.Oid)
	if err := self.fileSystem.MkdirAll(path.Dir(name), 0o755); err != nil {
		return err
	}
	return gitWriteFileAtomic(self.fileSystem, gitUrDirectory, name, content, 0o644, false)
}

// A blob's locator, nil where none is kept.
func (self *gitPromisorTable) read(oid EvsGitOid) (*EvsGitBlobLocator, error) {
	content, err := gitReadFile(self.fileSystem, gitLocatorName(oid), self.settings.StateFileByteCount)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	refused := fmt.Errorf("%w: a promisor locator that does not read", ErrGitObjectCorrupt)
	file := &gitLocatorFile{}
	if err := json.Unmarshal(content, file); err != nil {
		return nil, refused
	}
	refId, err := ParseId(file.RefId)
	if err != nil {
		return nil, refused
	}
	chainBefore, err := hex.DecodeString(file.ChainBefore)
	if err != nil || len(chainBefore) != len([32]byte{}) {
		return nil, refused
	}
	chain, err := hex.DecodeString(file.Chain)
	if err != nil || len(chain) != len([32]byte{}) || file.Version == 0 {
		return nil, refused
	}
	return &EvsGitBlobLocator{
		Oid: oid, Size: file.Size, RefId: refId, Version: file.Version, ChainBefore: [32]byte(chainBefore),
		Chain: [32]byte(chain), History: file.History,
	}, nil
}

// Drops a fetched blob's locator.
func (self *gitPromisorTable) remove(oid EvsGitOid) {
	self.fileSystem.Remove(gitLocatorName(oid))
}

// The repository's promisor table.
func (self *GitRepository) promisorTable() *gitPromisorTable {
	return &gitPromisorTable{fileSystem: self.fileSystem, settings: self.settings}
}

// The store's promisor: the table, and the repository's evs connection for a fetch.
type gitEvsPromisor struct {
	repository *GitRepository
	table      *gitPromisorTable
}

// Whether the table keeps a locator for oid.
func (self *gitEvsPromisor) promised(oid EvsGitOid) bool {
	_, err := self.table.fileSystem.Lstat(gitLocatorName(oid))
	return err == nil
}

// The store with only what it holds counting as held: what a lazy fetch's reconstruction writes into, so a promised
// blob is fetched rather than passed over as held.
type gitLocalObjects struct {
	*GitObjectStore
}

// Whether the store holds oid as a loose object.
func (self *gitLocalObjects) HasGitObject(oid EvsGitOid) bool {
	return self.GitObjectStore.Local(oid)
}

// Fetches the promised blobs among oids: see the file header's fetch row.
func (self *gitEvsPromisor) fetch(ctx context.Context, store *GitObjectStore, oids []EvsGitOid) error {
	locators := []*EvsGitBlobLocator{}
	for _, oid := range oids {
		if store.Local(oid) {
			continue
		}
		locator, err := self.table.read(oid)
		if err != nil {
			return err
		}
		if locator != nil && !slices.ContainsFunc(locators, func(held *EvsGitBlobLocator) bool { return held.Oid == oid }) {
			locators = append(locators, locator)
		}
	}
	if len(locators) == 0 {
		return nil
	}
	evsArgs, repo, err := self.repository.connected()
	if err != nil {
		return err
	}
	gate := self.repository.gate(evsArgs, repo.repoId)
	// one round of reads a version, its blobs together
	slices.SortFunc(locators, func(a *EvsGitBlobLocator, b *EvsGitBlobLocator) int {
		if order := a.RefId.Cmp(b.RefId); order != 0 {
			return order
		}
		return cmp.Compare(a.Version, b.Version)
	})
	replayer := newEvsGitReplayer(repo, &gitLocalObjects{GitObjectStore: store})
	for start := 0; start < len(locators); {
		end := start + 1
		for end < len(locators) && locators[end].RefId == locators[start].RefId && locators[end].Version == locators[start].Version {
			end += 1
		}
		if err := gitFetchVersion(ctx, replayer, gate, locators[start:end]); err != nil {
			return err
		}
		start = end
	}
	for _, locator := range locators {
		if !store.Local(locator.Oid) {
			return fmt.Errorf("%w: a promised blob its push did not carry", ErrEvsGitObjectMissing)
		}
		self.table.remove(locator.Oid)
	}
	return nil
}

// The fetch gate a lazy fetch judges through: the one this command's fetches share, so one taint covers both.
func (self *GitRepository) gate(evsArgs *GitEvsArgs, repoId Id) *gitFetchGate {
	if self.fetchGate == nil {
		self.fetchGate = newGitFetchGate(evsArgs, repoId)
	}
	return self.fetchGate
}

// Fetches the blobs one version's push carries, all of one ref and version: see the file header's fetch row.
func gitFetchVersion(ctx context.Context, replayer *evsGitExport, gate *gitFetchGate, locators []*EvsGitBlobLocator) error {
	repo := replayer.repo
	client := repo.client
	first := locators[0]
	done := client.pins.beginRead(repo.repoId, first.RefId)
	defer done()
	head, err := repo.pinnedHead(ctx, first.RefId)
	if err != nil {
		return err
	}
	if head.Version < first.Version {
		return fmt.Errorf("%w: the version that carried a promised blob is past the ref's head", ErrEvsGitObjectMissing)
	}
	statements, err := client.readLog(ctx, repo.repoId, first.RefId, first.Version, first.Version)
	if err != nil {
		return err
	}
	walked, err := client.verifier.walk(ctx, repo.repoId, first.RefId, first.Version-1, first.ChainBefore, statements, first.Version)
	if err != nil {
		return err
	}
	if len(walked) != 1 || walked[0].Chain != first.Chain {
		return fmt.Errorf("%w: the push that carried a promised blob is not the one replayed", ErrEvsChainBroken)
	}
	statement := walked[0]
	payload, err := repo.pushContent(ctx, head, statement)
	if err != nil {
		return err
	}
	manifest, err := replayer.keys.manifest(ctx, statement.Statement.Push.GetGeneration())
	if err != nil {
		return err
	}
	metadata, err := EvsOpenMetadata(manifest, payload.SealedMetadata)
	if err != nil {
		client.alarm(repo.repoId, first.RefId, SidecarEvsAlarmTamper, "", nil)
		return err
	}
	// the run is tainted before a byte of this push lands where it is untrusted (§13.6)
	if err := gate.see(ctx, first.RefId, statement.Statement, metadata); err != nil {
		return err
	}
	wanted := map[EvsGitOid]bool{}
	history := []*protocol.EvsSealedBlob{}
	for _, locator := range locators {
		if !locator.History {
			wanted[locator.Oid] = true
		}
	}
	for _, change := range payload.Changes {
		if len(wanted) == 0 {
			break
		}
		if !change.WritesEntry() {
			continue
		}
		file, err := replayer.entryFields(ctx, first.RefId, statement, change)
		if err != nil {
			return err
		}
		if file == nil || !wanted[file.oid] {
			continue
		}
		written, err := repo.exportBlob(ctx, replayer.objects, head, replayer.keys, statement, change, "")
		if err != nil {
			return err
		}
		if written == nil || written.oid != file.oid {
			return fmt.Errorf("%w: a promised blob that is not its oid", ErrEvsSealInvalid)
		}
		delete(wanted, file.oid)
	}
	git := metadata.GetGit()
	for _, blob := range git.GetBlobs() {
		oid := EvsGitOid(blob.GetGitOid())
		if slices.ContainsFunc(locators, func(locator *EvsGitBlobLocator) bool { return locator.History && locator.Oid == oid }) {
			history = append(history, blob)
		}
	}
	if 0 < len(history) {
		carried := proto.Clone(git).(*protocol.EvsGitUpdate)
		carried.Blobs = history
		if err := replayer.historyBlobs(ctx, head, statement, carried); err != nil {
			return err
		}
	}
	return nil
}
