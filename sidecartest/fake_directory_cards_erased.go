// The cards ref's index erasure set on FakeDirectoryCards (QD-1144; sidecar.DirectoryCardsErasureSet): what a card's
// return reads. The fake keeps no index, so a test lists a document as a directory admin's CUT would (ListErased),
// naming it by its plaintext name as every other path of the fake is named. The set's version is the last CUT's
// signer's, which a read holds to the caller's IsAdmin as evs's reader holds the set's version; a read a test fails
// (FailErasedReads) is a set that does not read. Each read is counted (FakeDirectoryCardsCounts.ErasedReads) and takes
// read, by the world's scopes.

package sidecartest

import (
	"context"
	"fmt"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var (
	_ sidecar.DirectoryCardsErasureSet = (*fakeDirectoryCardsClient)(nil)
	_ sidecar.DirectoryCardsErasureSet = (*FakeDirectoryPhone)(nil)
)

// One repo's cards ref index erasure set as CUTs left it.
type fakeDirectoryCardsErasure struct {
	// each document's highest version listed, by name; nil while no CUT wrote the set
	versions map[string]uint64
	// the last CUT's signer, whose version the set is
	signerId sidecar.Id
	// reads to fail before one answers
	failCount int
}

// The repo's erasure set, made on first use. The caller holds stateLock.
func (self *FakeDirectoryCards) erasureWithLock(repoId sidecar.Id) *fakeDirectoryCardsErasure {
	repo := self.repoWithLock(repoId)
	if repo.erasure == nil {
		repo.erasure = &fakeDirectoryCardsErasure{}
	}
	return repo.erasure
}

// Lists name in repoId's cards ref index erasure set at version, as signerId's CUT does: a version below the one listed
// lowers nothing, and the set's version is signerId's from then.
func (self *FakeDirectoryCards) ListErased(repoId sidecar.Id, signerId sidecar.Id, name []byte, version uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	erasure := self.erasureWithLock(repoId)
	if erasure.versions == nil {
		erasure.versions = map[string]uint64{}
	}
	erasure.versions[string(name)] = max(erasure.versions[string(name)], version)
	erasure.signerId = signerId
}

// Fails the next count reads of repoId's erasure set, as a set that does not read.
func (self *FakeDirectoryCards) FailErasedReads(repoId sidecar.Id, count int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.erasureWithLock(repoId).failCount = count
}

// sidecar.DirectoryCardsErasureSet over the fake's set: 0 for a name it lists nowhere, every 0 where no CUT wrote it.
func (self *fakeDirectoryCardsClient) CardsErasedVersions(ctx context.Context, repoId sidecar.Id, args *sidecar.DirectoryCardsErasedArgs) ([]uint64, error) {
	if args == nil || args.IsAdmin == nil {
		return nil, fakeRecordReadRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED)
	}
	if err := self.checkRead(repoId); err != nil {
		return nil, err
	}
	listed, signerId, failed := func() (map[string]uint64, sidecar.Id, bool) {
		self.fake.stateLock.Lock()
		defer self.fake.stateLock.Unlock()
		self.fake.counts.ErasedReads += 1
		erasure := self.fake.erasureWithLock(repoId)
		if 0 < erasure.failCount {
			erasure.failCount -= 1
			return nil, sidecar.Id{}, true
		}
		var listed map[string]uint64
		if erasure.versions != nil {
			listed = make(map[string]uint64, len(erasure.versions))
			for name, version := range erasure.versions {
				listed[name] = version
			}
		}
		return listed, erasure.signerId, false
	}()
	if failed {
		return nil, fmt.Errorf("%w: the fake's set does not read", sidecar.ErrDirectoryCardReturnUnchecked)
	}
	versions := make([]uint64, len(args.Names))
	if listed == nil {
		return versions, nil
	}
	if !args.IsAdmin(signerId) {
		return nil, fmt.Errorf("%w: a set version no directory admin signed", sidecar.ErrDirectoryCardReturnUnchecked)
	}
	for index, name := range args.Names {
		versions[index] = listed[string(name)]
	}
	return versions, nil
}

// The phone's reach into the fake's set, counted as the fake's.
func (self *FakeDirectoryPhone) CardsErasedVersions(ctx context.Context, repoId sidecar.Id, args *sidecar.DirectoryCardsErasedArgs) ([]uint64, error) {
	return self.inner.CardsErasedVersions(ctx, repoId, args)
}
