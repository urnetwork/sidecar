// The fixture log judges a pin as §10.9's judged row asks of a reader: above its tip it waits, off its chain it is a
// fork, and before what it retains it is not judged. Its config repo answers as ACL's state gives it: the rows' own
// row, else one of kind config with holders_shrunk_at 0.

package sidecartest

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

func TestFakeGkmAuthViewJudgesPinsAsAReader(t *testing.T) {
	log := NewFakeGkmAuthLog()
	repoId := sidecar.NewId()
	reader := sidecar.NewId()
	views := []*FakeGkmAuthView{}
	for shrunkAt := uint64(0); shrunkAt < 3; shrunkAt += 1 {
		views = append(views, log.Append(&FakeGkmAuthFixture{
			Rows:        FakeGkmAuthRows(&protocol.AclRepo{RepoId: repoId.Bytes(), HoldersShrunkAt: shrunkAt}),
			RepoReaders: map[sidecar.Id][]sidecar.Id{repoId: {reader}},
		}))
	}
	tip := views[2]
	if tip.Pin().GetVersion() != 3 || log.Tip() != tip {
		t.Fatalf("tip at %d", tip.Pin().GetVersion())
	}
	if bytes.Equal(views[0].Pin().GetChain(), views[1].Pin().GetChain()) {
		t.Error("two positions share a chain value")
	}

	second, err := tip.At(views[1].Pin())
	if err != nil {
		t.Fatal(err)
	}
	if second.Repo(repoId).GetHoldersShrunkAt() != 1 || !slices.Equal(second.RepoReaders(repoId), []sidecar.Id{reader}) {
		t.Error("At gave another state")
	}
	if !tip.OnChain(views[0].Pin()) || !tip.OnChain(tip.Pin()) {
		t.Error("its own chain is off it")
	}
	if _, err := views[1].At(tip.Pin()); !errors.Is(err, sidecar.ErrGkmAuthAhead) {
		t.Errorf("a pin above the state: %v", err)
	}
	if views[1].OnChain(tip.Pin()) {
		t.Error("a pin above the state is on its chain")
	}
	if _, err := tip.At(FakeGkmForkPin(2)); !errors.Is(err, sidecar.ErrGkmAuthOffChain) {
		t.Errorf("a fork's pin: %v", err)
	}
	if _, err := tip.At(&bridge.AuthPin{}); !errors.Is(err, sidecar.ErrGkmAuthOffChain) {
		t.Errorf("no pin: %v", err)
	}

	log.Retain(2)
	if _, err := tip.At(views[0].Pin()); !errors.Is(err, sidecar.ErrGkmAuthNotRetained) {
		t.Errorf("a pin before retention: %v", err)
	}
	if tip.OnChain(views[0].Pin()) {
		t.Error("a pin before retention is on the chain")
	}
	if tip.Repo(sidecar.NewId()) != nil {
		t.Error("a repo the state does not hold")
	}
}

// A fixture's ConfigRepoId answers kind config with holders_shrunk_at 0 while the rows hold no row of it (QD-719), and
// the rows' own row once they hold one, as from the config's first shrink (QD-762); a fixture naming none adds none.
func TestFakeGkmAuthViewAddsTheConfigRepoAsAclStateDoes(t *testing.T) {
	log := NewFakeGkmAuthLog()
	configRepoId, repoId := sidecar.NewId(), sidecar.NewId()
	rowless := log.Append(&FakeGkmAuthFixture{
		Rows:         FakeGkmAuthRows(&protocol.AclRepo{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}),
		ConfigRepoId: configRepoId,
	})
	row := rowless.Repo(configRepoId)
	if row == nil || !bytes.Equal(row.GetRepoId(), configRepoId.Bytes()) || row.GetKind() != protocol.RepoKind_REPO_KIND_CONFIG ||
		row.GetHoldersShrunkAt() != 0 || len(row.GetAdmins()) != 0 {
		t.Errorf("the config's row while the rows hold none: %v", row)
	}
	held := log.Append(&FakeGkmAuthFixture{
		Rows: FakeGkmAuthRows(
			&protocol.AclRepo{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL},
			&protocol.AclRepo{RepoId: configRepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_CONFIG, HoldersShrunkAt: 2},
		),
		ConfigRepoId: configRepoId,
	})
	if row := held.Repo(configRepoId); row.GetHoldersShrunkAt() != 2 {
		t.Errorf("the rows' own config row: %v", row)
	}
	if row := rowless.Repo(configRepoId); row.GetHoldersShrunkAt() != 0 {
		t.Errorf("an earlier position's config row changed: %v", row)
	}
	unnamed := log.Append(&FakeGkmAuthFixture{Rows: FakeGkmAuthRows()})
	if unnamed.Repo(configRepoId) != nil || unnamed.Repo(sidecar.Id{}) != nil {
		t.Error("a fixture naming no config repo answers one")
	}
}
