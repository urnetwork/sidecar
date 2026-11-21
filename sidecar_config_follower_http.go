//go:build !ios_extension && sidecar_http

// An HTTP-only member follows the same anchored projection using the config client's periodic fetch.
package sidecar

// The browser opens its replica after enrollment. Its owner closes the follower with the network.
func (self *Sidecar) attachConfigFollower(follower *SidecarConfigFollower) (func(), error) {
	return nil, follower.followIdentity(self.Identity())
}

// The read-only Worker files no private repo markers.
func (self *Sidecar) setMemberEvsHooks(args *EvsClientArgs) {
}

// The Worker has no repo administration surface.
func (self *MemberReplica) setStatementPoster(args *EvsClientArgs) {}
