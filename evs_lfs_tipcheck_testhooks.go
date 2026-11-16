//go:build sidecar_testhooks && !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The git-lfs tip check switched off on one mount, for FS-73's twin (§22.8's twins; EVS2-M10-29): a build whose check is
// off publishes a force push to pruned history that the check refuses, and FS-73's schedule must catch that. The switch
// is the sidecar_testhooks build's alone, which no release leg is (§22.4); evs_lfs_tipcheck_switch.go answers off for
// no mount in every other build.
//
// Nothing here holds or derives a key. Safe for concurrent use.

package sidecar

import (
	"sync"
)

// The mounts whose tip check is off.
var evsLfsTipCheckOffMounts sync.Map

// Switches the git-lfs tip check of mount off, or on again: off, every update its receive path publishes skips the check,
// as a build without the check would.
func EvsTestSwitchOffLfsTipCheck(mount *EvsLocalRepo, off bool) {
	if off {
		evsLfsTipCheckOffMounts.Store(mount, true)
		return
	}
	evsLfsTipCheckOffMounts.Delete(mount)
}

// Whether a test switched mount's tip check off.
func evsLfsTipCheckSwitchedOff(mount *EvsLocalRepo) bool {
	_, off := evsLfsTipCheckOffMounts.Load(mount)
	return off
}
