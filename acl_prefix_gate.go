//go:build !ios_extension

// What evs's gate reads of a repo's prefix rules (DESIGN-DETAILS 16.2.9; QD-803): the position of the repo's newest
// set, which a push that creates or re-creates a shared ref must be pinned at or above (evsservice/check_gate.go).
// evs reads a row's position and never its body (I-18): it cannot tell an opened set from a void, pending or newer
// one, or a set that lifts the rules from one that tightens them, and needs to tell none of them, since a pin held
// above a void set changes no verdict (16.2.3). evs and its tests read "the newest set" here and nowhere else.

package sidecar

import (
	"github.com/urnetwork/sidecar/protocol"
)

// The greatest `at` among the row's prefix_rules, and false where the row holds no set, a nil row included. The fold
// appends rows in position order, and this takes the greatest wherever it stands in the list all the same. It reads
// positions alone and opens no body.
func AclPrefixRulesNewestAt(repo *protocol.AclRepo) (at uint64, ok bool) {
	for _, row := range repo.GetPrefixRules() {
		if !ok || at < row.GetAt() {
			at, ok = row.GetAt(), true
		}
	}
	return at, ok
}
