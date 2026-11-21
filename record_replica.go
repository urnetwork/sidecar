//go:build !ios_extension

// A member replica's record reader shares its EVS client, receipt gate and fully published config on native and HTTP.

package sidecar

import (
	"bytes"
	"fmt"
)

// Binds the member's EVS client and published config to the record and installs its write-ahead read receipts.
// A joining client's unpublished replay cannot authorize a read.
func (self *SidecarRecord) BindMemberReplica(config *ConfigClient, evs *EvsClient) error {
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
	self.Bind(streams, func() RecordAuthView {
		state := config.State()
		if state == nil || state.NetworkId() != networkId || !sameIdentity() || !bytes.Equal(state.IdentityKey(self.writer.sidecarId), self.writer.identityPublicKey) {
			return RecordAuthUnavailable{}
		}
		return newConfigRecordAuth(state, self.writer.clock.Now())
	})
	evs.SetRecordReceipts(self.receipts)
	return nil
}
