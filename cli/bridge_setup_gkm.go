// The daemon's forwarding setup uses the GKM group client of the network whose config follower admitted it.
package main

import "context"

// Uploads the component's public reader key after the signed forwarding Delegation lands.
func (self *urNetworkGkm) UploadDelegationKey(ctx context.Context, delegationId []byte, readerKey []byte) error {
	group, err := self.group()
	if err != nil {
		return err
	}
	return group.UploadDelegationKey(ctx, delegationId, readerKey)
}

// Delivers the config group's current key under that public key.
func (self *urNetworkGkm) DeliverDelegationWraps(ctx context.Context, delegationId []byte) error {
	group, err := self.group()
	if err != nil {
		return err
	}
	return group.DeliverDelegationWraps(ctx, delegationId)
}
