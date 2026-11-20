//go:build !sidecar_http

// The bridge the re-form's external tests read a client's re-form record through (gkm_reform.go): what a sync or a
// ReformGroup call left of it in the keychain. Tests only.

package sidecar

import (
	"time"
)

// The phases of a re-form's record, as TestReformRecord answers them.
const (
	TestGkmReformPhasePosting   = gkmReformPhasePosting
	TestGkmReformPhaseLadder    = gkmReformPhaseLadder
	TestGkmReformPhaseFinishing = gkmReformPhaseFinishing
)

// The keychain's re-form record of the repo: its phase, the group it forms, and when a sync last tried its finishing
// phase, zero for never; found false where none stands.
func (self *GkmGroupClient) TestReformRecord(repoId Id) (phase int, groupId Id, resumedAt time.Time, found bool, err error) {
	record, err := self.manager(repoId).reformRecord()
	if err != nil || record == nil {
		return 0, Id{}, time.Time{}, false, err
	}
	return record.phase, record.groupId, record.resumedAt, true, nil
}
