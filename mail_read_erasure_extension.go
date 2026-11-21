//go:build ios_extension

// The packet-forwarding extension has no mailbox or mail readers.

package sidecar

import "context"

// The extension never opens mailbox content.
func (self *EvsRepo) checkMailRead(ctx context.Context, result *evsReadResult, verified *EvsVerifiedPath, content *evsSpill) error {
	return nil
}
