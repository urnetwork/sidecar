//go:build !ios_extension

// A member replica's record reader shares its EVS client, receipt gate and fully published config on native and HTTP.

package sidecar

import (
	"bytes"
	"context"
	"fmt"
)

// Binds the member's EVS client and published config to the record and installs its write-ahead read receipts.
// A joining client's unpublished replay cannot authorize a read.
func (self *SidecarRecord) BindMemberReplica(config *ConfigClient, evs *EvsClient) error {
	return self.bindMemberReplica(config, evs, func() bool { return true })
}

// The follower supplies its live standing check so a refused, closed or replaced follower stops authorizing immediately.
func (self *SidecarRecord) bindMemberReplica(config *ConfigClient, evs *EvsClient, active func() bool) error {
	if config == nil || config.args == nil || evs == nil || evs.args == nil || evs.args.Identity == nil || config.NetworkId() != evs.NetworkId() {
		return fmt.Errorf("%w: record and replica need one network", ErrRecordDraftInvalid)
	}
	networkId := evs.NetworkId()
	sameIdentity := func() bool {
		identity := evs.args.Identity()
		return identity != nil && identity.NetworkId == networkId && identity.SidecarId == self.writer.sidecarId &&
			bytes.Equal(identity.IdentityPublicKey, self.writer.identityPublicKey)
	}
	if !sameIdentity() {
		return fmt.Errorf("%w: record and replica need one identity", ErrRecordDraftInvalid)
	}
	streams, err := NewRecordEvsStreams(&RecordEvsStreamsArgs{Client: evs, Store: self.writer.store})
	if err != nil {
		return err
	}
	auth := func() RecordAuthView {
		state := config.State()
		if !active() || (config.ctx != nil && config.ctx.Err() != nil) || state == nil || state.NetworkId() != networkId ||
			!sameIdentity() || !bytes.Equal(state.IdentityKey(self.writer.sidecarId), self.writer.identityPublicKey) {
			return RecordAuthUnavailable{}
		}
		return newConfigRecordAuth(state, self.writer.clock.Now())
	}
	open, err := NewRecordEvsEraseIndex(&RecordEvsEraseIndexArgs{Client: evs, Auth: auth})
	if err != nil {
		return err
	}
	self.SetEraseIndex(func(ctx context.Context, logId Id) (RecordEraseIndex, error) {
		if auth().Pin() == nil {
			return nil, ErrEvsNoConfig
		}
		return open(ctx, logId)
	})
	evs.SetRecordReceipts(self.receipts)
	self.Bind(streams, auth)
	return nil
}

// Binds both read authorization and erasure before the anchored client is published. The native record component
// belongs to this follower's authority and drains the durable writer and erasure journals on each generation.
func (self *SidecarConfigFollower) bindRecord(config *ConfigClient) (func(), error) {
	evs, err := self.args.RecordEvs()
	if err != nil {
		return nil, err
	}
	record, err := self.sidecar.Record()
	if err != nil {
		return nil, err
	}
	active := func() bool {
		if self.ctx.Err() != nil || self.Client() != config {
			return false
		}
		state, _ := self.sidecar.instance.State()
		return state == SidecarInstanceOpen
	}
	if err := record.bindMemberReplica(config, evs, active); err != nil {
		return nil, err
	}
	return self.attachRecord(record)
}
