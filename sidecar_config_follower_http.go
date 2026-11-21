//go:build !ios_extension && sidecar_http

// An HTTP-only member follows the same anchored projection using the config client's periodic fetch.
package sidecar

import "context"

// Opens the top-level key-origin browser's member replica after its account
// sign-in handoff. The browser may verify a first-use genesis for its admitter's
// safety-number comparison. An existing enrollment anchor is always enforced.
func (self *Sidecar) OpenPageMemberReplica(ctx context.Context) (*MemberReplica, error) {
	return self.openMemberReplica(ctx, true)
}

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
