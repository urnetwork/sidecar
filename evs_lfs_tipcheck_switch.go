//go:build !sidecar_testhooks && !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The git-lfs tip check's test switch in every build but sidecar_testhooks (evs_lfs_tipcheck_testhooks.go): no mount's
// check is ever off.

package sidecar

// Never: only the sidecar_testhooks build switches a check off.
func evsLfsTipCheckSwitchedOff(mount *EvsLocalRepo) bool {
	return false
}
