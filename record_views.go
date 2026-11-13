//go:build !ios_extension

// What MCP's views read of the root that the files they come from do not export (§16.5; MCP-M3-14): §8.4's action
// and resource text forms, which acl_check takes as a policy document writes them, and a member's registered keys,
// which ur://acl/grants lists by id, never by key.
//
// On every leg but the ios_extension legs, whose forwarding role serves no MCP. Package-level functions are safe for
// concurrent use.

package sidecar

import (
	"bytes"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §8.4's action of a name: dial, listen, route, read, write, admin, deposit, publish or send.
func ParseAclAction(text string) (protocol.AclAction, error) {
	return parseAclAction(text)
}

// §8.4's resource of a text form, as a policy's dst writes it: *, sock:, ip:, evs: and the rest.
func ParseAclResource(text string) (AclResource, error) {
	return parseAclResource(text)
}

// An action's §8.4 name, "" for one it has none.
func AclActionName(action protocol.AclAction) string {
	for name, named := range aclNameActions {
		if named == action {
			return name
		}
	}
	return ""
}

// The keys registered to a member at this state, revoked ones included, by key id. The caller must not change them.
func (self *ConfigState) MemberKeys(memberId Id) []*bridge.KeyRow {
	keys := []*bridge.KeyRow{}
	for _, key := range self.keys {
		if bytes.Equal(key.GetMemberId(), memberId.Bytes()) {
			keys = append(keys, key)
		}
	}
	slices.SortFunc(keys, func(a *bridge.KeyRow, b *bridge.KeyRow) int { return bytes.Compare(a.GetKeyId(), b.GetKeyId()) })
	return keys
}
