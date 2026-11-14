//go:build !ios_extension

// DESIGN-DETAILS 16.6's bullet for the helper evs's gate reads (EVS1-M6-07; QD-803): AclPrefixRulesNewestAt over a row
// with no set, with one and with three, the three in the fold's order and out of it.

package sidecar

import (
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// The newest position over a repo's rows, none, one and three, wherever the greatest stands.
func TestAclPrefixRulesNewestAt(t *testing.T) {
	rows := func(ats ...uint64) *protocol.AclRepo {
		repo := &protocol.AclRepo{RepoId: NewId().Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}
		for _, at := range ats {
			repo.PrefixRules = append(repo.PrefixRules, &protocol.AclRepoPrefixRulesRow{Signer: NewId().Bytes(), At: at})
		}
		return repo
	}
	cases := []struct {
		name string
		repo *protocol.AclRepo
		at   uint64
		ok   bool
	}{
		{name: "no row", repo: nil},
		{name: "a row with no set", repo: rows()},
		{name: "one set", repo: rows(12), at: 12, ok: true},
		{name: "three sets in position order", repo: rows(4, 9, 40), at: 40, ok: true},
		{name: "three sets, the newest first", repo: rows(40, 4, 9), at: 40, ok: true},
		{name: "three sets, the newest between", repo: rows(4, 40, 9), at: 40, ok: true},
	}
	for _, c := range cases {
		at, ok := AclPrefixRulesNewestAt(c.repo)
		if at != c.at || ok != c.ok {
			t.Errorf("%s: (%d, %t), want (%d, %t)", c.name, at, ok, c.at, c.ok)
		}
	}
	// it reads the row and leaves it as it was
	repo := rows(9, 4)
	if _, ok := AclPrefixRulesNewestAt(repo); !ok || repo.GetPrefixRules()[0].GetAt() != 9 || repo.GetPrefixRules()[1].GetAt() != 4 {
		t.Errorf("the rows after the read: %v", repo.GetPrefixRules())
	}
}
