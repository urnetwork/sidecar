//go:build ios_extension

// The forwarding role reads the config repo. It keeps no search observations and never plans an EVS write.

package sidecar

import (
	"context"

	"github.com/urnetwork/sidecar/protocol"
)

// The extension never opens mailbox content.
func (self *EvsRepo) checkMailRead(ctx context.Context, result *evsReadResult, verified *EvsVerifiedPath, content *evsSpill) error {
	return nil
}

// A config read retains no file names for local search.
func (self *EvsRepo) searchReadObserver(args *EvsReadArgs) func(*EvsFileInfo) {
	return nil
}

// The forwarding role reads no erasure ref and cannot authorize a checkpoint over a destroyed key.
func (self *EvsRepo) erasedBaseFields(ctx context.Context, result *evsReadResult, verified *EvsVerifiedPath) (*protocol.EvsSealedFields, error) {
	return nil, ErrEvsErased
}
