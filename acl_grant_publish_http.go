//go:build !ios_extension && sidecar_http

// The page Worker's leg of acl_grant_publish.go: it links no publish gate view (acl_gate_view.go) and runs no tls
// component, so it publishes nothing, and no grant covers a publish there, the closed direction.

package sidecar

import "github.com/urnetwork/sidecar/protocol"

// See acl_grant_publish.go's: false, since this leg judges no publish grant.
func (self *aclEngineInstall) publishAgrees(subject AclSubject, action *protocol.CanonicalAction, nowMs int64) bool {
	return false
}
