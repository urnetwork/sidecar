//go:build !sidecar_http && !ios_extension

// ActiveGrant's last test of a publish (acl_grant_file.go; §8.4, §8.10, §13.7, §13.10): a publish binds its audience,
// app mode and a raw link's pin, which the listener's front enforces from the grant, so only a grant that gives
// exactly those covers it. acl_grant_publish_http.go is the page Worker's leg, which judges no publish.

package sidecar

import (
	"bytes"
	"strconv"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// Whether the subject's publish grant for a publish action's tls/<port>/<host> name at nowMs, by §8.4's agreement rule
// (AclState.PublishGrant, in the action's app mode), gives the audience and the raw link's pin the action asks,
// unspecified reading as members and http as the grant's do.
func (self *aclEngineInstall) publishAgrees(subject AclSubject, action *protocol.CanonicalAction, nowMs int64) bool {
	socketName := "tls/" + strconv.FormatUint(uint64(action.GetPort()), 10) + "/" + action.GetHost()
	grant, decision := self.state.PublishGrant(subject, socketName, protocol.AclAppMode(action.GetAppMode()), time.UnixMilli(nowMs))
	if !decision.Allowed || grant == nil {
		return false
	}
	return grant.Audience == aclPublishAudience(protocol.AclAudience(action.GetAudience())) && bytes.Equal(grant.LinkSpkiSha256, action.GetLinkSpkiSha256())
}
