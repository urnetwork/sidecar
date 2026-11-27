//go:build !ios_extension && !sidecar_http && (js || ios || android || sdk_mobile_bind)

// The evs tools' reading of the local tier's errors on the legs that have none (evs_local_none.go): head mode answers
// every git-mode write EVS_GIT_REF, so neither error is one a call can meet.

package sidecar

// No local tier: never a moving tip.
func harnessEvsGitTipMoved(err error) bool {
	return false
}

// No local tier: never an unchanged git-mode write.
func harnessEvsGitUnchanged(err error) bool {
	return false
}
