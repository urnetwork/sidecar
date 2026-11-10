//go:build !sidecar_http

// The bridge the group flows' external tests reach a client's keychain records through: what a device holds of a
// repo, seeded as a join would leave it and read back as a flow left it. Tests only.

package sidecar

import (
	"errors"
)

// Keeps generation with key as this client holds one it opened and judged, and moves the repo's pins to it.
func (self *GkmGroupClient) TestHoldGeneration(repoId Id, groupId Id, generation *GkmGeneration, key *EvsRepoKey) error {
	if err := self.putHeldGeneration(repoId, &gkmHeldGeneration{generation: generation, key: key}); err != nil {
		return err
	}
	return self.advancePins(repoId, func(pins *gkmRepoPins) {
		pins.groupId = groupId
		if pins.generation <= generation.Rotate.GetGeneration() {
			pins.generation = generation.Rotate.GetGeneration()
			pins.commitment = generation.Rotate.GetCommitment()
		}
	})
}

// Moves the repo's epoch pin to an epoch this client's engine adopted, with its header.
func (self *GkmGroupClient) TestHoldEpoch(repoId Id, group MlsGroup, header []byte) error {
	return self.advancePins(repoId, func(pins *gkmRepoPins) {
		pins.groupId = group.GroupId()
		pins.epoch = group.Epoch()
		pins.epochAuthenticator = group.EpochAuthenticator()
		pins.epochHeader = header
	})
}

// What this client holds of generation g: its key, nil for one it never opened, and whether it holds it as poisoned;
// found false for none.
func (self *GkmGroupClient) TestHeldGeneration(repoId Id, generation uint64) (key *EvsRepoKey, poisoned bool, found bool, err error) {
	held, err := self.heldGeneration(repoId, generation)
	if errors.Is(err, ErrGkmKeyMissing) {
		return nil, false, false, nil
	}
	if err != nil {
		return nil, false, false, err
	}
	return held.key, held.poisoned, true, nil
}

// The repo's pins as this client keeps them: its group, its newest adopted epoch and its newest generation.
func (self *GkmGroupClient) TestPins(repoId Id) (groupId Id, epoch uint64, generation uint64, err error) {
	pins, err := self.repoPins(repoId)
	if err != nil {
		return Id{}, 0, 0, err
	}
	return pins.groupId, pins.epoch, pins.generation, nil
}

// Whether the keychain holds a rotation draft for the repo.
func (self *GkmGroupClient) TestHasRotateDraft(repoId Id) bool {
	_, err := self.args.Secrets.Get(gkmRepoRecordName(repoId, "draft"))
	return err == nil
}
