package main

import (
	"context"

	"github.com/urnetwork/sidecar"
)

// The writer uses the same verified, per-network config ref as the daemon's follower.
var _ sidecar.ConfigHeadRef = (*urNetworkConfigHeads)(nil)

func (self *urNetworkConfigHeads) CurrentConfigHeadTip(ctx context.Context) (*sidecar.ConfigHeadTip, error) {
	ref, err := self.clients.headReader(nil)
	if err != nil {
		return nil, err
	}
	return ref.CurrentConfigHeadTip(ctx)
}

func (self *urNetworkConfigHeads) PrepareConfigHead(ctx context.Context, head *sidecar.ConfigHead, version uint64) (*sidecar.ConfigHeadPush, error) {
	ref, err := self.clients.headReader(nil)
	if err != nil {
		return nil, err
	}
	return ref.PrepareConfigHead(ctx, head, version)
}

func (self *urNetworkConfigHeads) CommitConfigHead(ctx context.Context, push *sidecar.ConfigHeadPush) error {
	ref, err := self.clients.headReader(nil)
	if err != nil {
		return err
	}
	return ref.CommitConfigHead(ctx, push)
}

func (self *urNetworkConfigHeads) ConfigHeadPushes(ctx context.Context, after uint64, through uint64) ([][]byte, error) {
	ref, err := self.clients.headReader(nil)
	if err != nil {
		return nil, err
	}
	return ref.ConfigHeadPushes(ctx, after, through)
}
