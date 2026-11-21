//go:build sidecar_http && !ios_extension

package sidecar

// The browser's member search stays on its local engine.
func (self *MemberReplica) bindSearchRequester() error {
	return nil
}
