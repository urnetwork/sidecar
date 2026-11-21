//go:build !ios_extension && sidecar_http

// An HTTP-only member follows the same anchored projection using the config client's periodic fetch.
package sidecar

import "context"

// The browser opens its replica after enrollment. Its owner closes the follower with the network.
func (self *Sidecar) attachConfigFollower(follower *SidecarConfigFollower) (func(), error) {
	return nil, follower.followIdentity(self.Identity())
}

// The read-only Worker files no private repo markers.
func (self *Sidecar) setMemberEvsHooks(args *EvsClientArgs) {
}

// The Worker has no repo administration surface.
func (self *MemberReplica) setStatementPoster(args *EvsClientArgs) {}

// Browser enrollment is through the owner's signed-in handoff.
func (self *MemberReplica) installRecovery(group *GkmGroupClient) {}

// Browser children read the signed genesis their network serves. Only the native
// standalone owner's follower can publish a candidate when the log is empty.
func (self *SidecarConfigFollower) firstOwnerGenesis(_ context.Context, _ Id, served []byte, readErr error) ([]byte, error) {
	return served, readErr
}
