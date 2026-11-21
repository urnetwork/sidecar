package sidecar

import (
	"context"
	"crypto/sha256"

	"github.com/urnetwork/sidecar/protocol/bridge"
	"google.golang.org/protobuf/proto"
)

// ReadMemberView returns one published state and the names and local policy of its
// verified base. The joining client's rows-only pass never supplies any of them.
func (self *ConfigClient) ReadMemberView(ctx context.Context) (*ConfigState, *ConfigHead, *AclLocalPolicy, error) {
	var rowsBytes []byte
	state := func() *ConfigState {
		self.followLock.Lock()
		defer self.followLock.Unlock()
		log := self.Log()
		if log == nil {
			return nil
		}
		state := log.State()
		if state != nil && state.base != nil {
			hash := state.base.header.GetRowsSha256()
			if len(hash) == sha256.Size {
				rowsBytes = log.baseRows[[sha256.Size]byte(hash)]
			}
		}
		return state
	}()
	if state == nil {
		return nil, nil, nil, ErrEvsNoConfig
	}
	header := state.Base()
	if header == nil {
		return state, nil, nil, nil
	}
	if len(rowsBytes) == 0 || self.args.Heads == nil {
		return nil, nil, nil, ErrConfigHeadUnavailable
	}
	head, err := self.args.Heads.ReadConfigHead(ctx, header.GetConfigVersion(), header.GetConfigHeadSha256())
	if err != nil {
		return nil, nil, nil, err
	}
	var rows bridge.ProjectionRows
	if err := proto.Unmarshal(rowsBytes, &rows); err != nil {
		return nil, nil, nil, err
	}
	fold, err := configCompileRowsFromRows(&rows)
	if err != nil {
		return nil, nil, nil, err
	}
	input, err := NewAclCompileInput(head, fold)
	if err != nil {
		return nil, nil, nil, err
	}
	policy, err := CompileAclLocal(input)
	if err != nil {
		return nil, nil, nil, err
	}
	return state, head, policy, nil
}
