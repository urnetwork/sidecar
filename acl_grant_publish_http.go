//go:build !ios_extension && sidecar_http

// The page Worker's leg of acl_grant_publish.go. It links no publish gate view (acl_gate_view.go), whose agreement rule
// judges every rule that would give a publish, and it runs no tls component, so it publishes nothing; a publish is
// still held to what its grant gives here, by the one rule the evaluation finds for the host (AclState.MayPublish's,
// whose row carries the grant's audience, app mode and pin) rather than by every such rule's agreement.

package sidecar

import (
	"bytes"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// See acl_grant_publish.go's: the grant MayPublish finds for the action's host at nowMs gives the audience, app mode
// and pin the action asks, unspecified reading as members and http on both sides.
func (self *aclEngineInstall) publishAgrees(subject AclSubject, action *protocol.CanonicalAction, nowMs int64) bool {
	decision := self.state.MayPublish(subject, action.GetHost(), time.UnixMilli(nowMs))
	if !decision.Allowed || decision.Rule == nil {
		return false
	}
	audience := func(audience protocol.AclAudience) protocol.AclAudience {
		if audience == protocol.AclAudience_ACL_AUDIENCE_UNSPECIFIED {
			return protocol.AclAudience_ACL_AUDIENCE_MEMBERS
		}
		return audience
	}
	appMode := func(appMode protocol.AclAppMode) protocol.AclAppMode {
		if appMode == protocol.AclAppMode_ACL_APP_MODE_UNSPECIFIED {
			return protocol.AclAppMode_ACL_APP_MODE_HTTP
		}
		return appMode
	}
	rule := decision.Rule
	return audience(rule.GetAudience()) == audience(protocol.AclAudience(action.GetAudience())) &&
		appMode(rule.GetAppMode()) == appMode(protocol.AclAppMode(action.GetAppMode())) &&
		bytes.Equal(rule.GetLinkSpkiSha256(), action.GetLinkSpkiSha256())
}
