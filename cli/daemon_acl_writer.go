package main

import (
	"context"

	"github.com/urnetwork/sidecar"
)

// The stock follower is a reader. Only explicit ACL confirmation selects this writer.
func (self *urNetworkConfigHeads) ConfirmedAclConfigRef() sidecar.ConfigHeadRef {
	return &urConfirmedAclConfigRef{self}
}

type urConfirmedAclConfigRef struct {
	*urNetworkConfigHeads
}

func (self *urNetworkConfigHeads) CurrentConfigHeadTip(ctx context.Context) (*sidecar.ConfigHeadTip, error) {
	ref, err := self.clients.headReader(nil)
	if err != nil {
		return nil, err
	}
	return ref.CurrentConfigHeadTip(ctx)
}

func (self *urConfirmedAclConfigRef) PrepareConfigHead(ctx context.Context, head *sidecar.ConfigHead, version uint64) (*sidecar.ConfigHeadPush, error) {
	ref, err := self.clients.headReader(nil)
	if err != nil {
		return nil, err
	}
	return ref.ConfirmedAclConfigRef().PrepareConfigHead(ctx, head, version)
}

func (self *urConfirmedAclConfigRef) CommitConfigHead(ctx context.Context, push *sidecar.ConfigHeadPush) error {
	ref, err := self.clients.headReader(nil)
	if err != nil {
		return err
	}
	return ref.ConfirmedAclConfigRef().CommitConfigHead(ctx, push)
}

func (self *urConfirmedAclConfigRef) ConfigHeadPushes(ctx context.Context, after uint64, through uint64) ([][]byte, error) {
	ref, err := self.clients.headReader(nil)
	if err != nil {
		return nil, err
	}
	return ref.ConfirmedAclConfigRef().ConfigHeadPushes(ctx, after, through)
}
