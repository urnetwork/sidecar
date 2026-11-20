package gkmservice

// The directory group's hint audience (KEYS-M6-01): the audience as a function, a first KeyPackage upload's part of
// it, and the reconciler's pending hints at a shrink of a directory repo and while its gate stays closed.

import (
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

func TestGkmDirectoryHintAudienceIsTheSignerThenTheConfigWriters(t *testing.T) {
	signer, configA, configB := testId("sc-signer"), testId("sc-config-a"), testId("sc-config-b")
	cases := []struct {
		name          string
		signerIds     []sidecar.Id
		configWriters []sidecar.Id
		want          []sidecar.Id
	}{
		{name: "a signer and the config writers", signerIds: []sidecar.Id{signer}, configWriters: []sidecar.Id{configA, configB}, want: []sidecar.Id{signer, configA, configB}},
		{name: "a signer that writes the config", signerIds: []sidecar.Id{configB}, configWriters: []sidecar.Id{configA, configB}, want: []sidecar.Id{configB, configA}},
		{name: "no signer", configWriters: []sidecar.Id{configA}, want: []sidecar.Id{configA}},
		{name: "nobody", want: []sidecar.Id{}},
	}
	for _, c := range cases {
		if audience := GkmDirectoryHintAudience(c.signerIds, c.configWriters); !slices.Equal(audience, c.want) {
			t.Errorf("%s: %v", c.name, audience)
		}
	}
}

func TestGkmAdmissionSignerIdsNamesOnlySidecars(t *testing.T) {
	signerA, signerB := testId("sc-signer-a"), testId("sc-signer-b")
	row := &bridge.SidecarRow{AdmissionSigners: [][]byte{signerA.Bytes(), make([]byte, 32), signerB.Bytes(), signerA.Bytes()}}
	if signerIds := GkmAdmissionSignerIds(row); !slices.Equal(signerIds, []sidecar.Id{signerA, signerB}) {
		t.Errorf("the admission's signers: %v", signerIds)
	}
	if signerIds := GkmAdmissionSignerIds(nil); len(signerIds) != 0 {
		t.Errorf("no row's signers: %v", signerIds)
	}
}

// A first KeyPackage upload's hint: in the directory group to the standing sidecars that signed the uploader's
// admission and then the config writers, whoever else writes the directory; in any other group to the repo's writers.
func TestGkmFirstUploadAudienceInTheDirectoryGroupIsTheAdmissionsSignerAndTheConfigWriters(t *testing.T) {
	directoryRepoId, generalRepoId, configRepoId, memberId := testId("repo-directory"), testId("repo-general"), testId("repo-config"), testId("member-a")
	signer, revokedSigner, config, writer, uploader := testId("sc-signer"), testId("sc-revoked-signer"), testId("sc-config"), testId("sc-writer"), testId("sc-new")
	everyone := []sidecar.Id{signer, revokedSigner, config, writer, uploader}
	rows := sidecartest.FakeGkmAuthRows(
		&protocol.AclRepo{RepoId: directoryRepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_DIRECTORY},
		&protocol.AclRepo{RepoId: generalRepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL},
	)
	sidecarRows, memberRow := sidecartest.FakeGkmAuthMemberDevices(memberId, everyone...)
	for _, row := range sidecarRows {
		switch sidecar.Id(row.GetSidecarId()) {
		case uploader:
			// a recovery key's hash signs nothing a hint could reach
			row.AdmissionSigners = [][]byte{revokedSigner.Bytes(), make([]byte, 32), signer.Bytes()}
		case revokedSigner:
			row.RevokedAt = 2
		}
	}
	rows.Sidecars = sidecarRows
	rows.Members = []*bridge.MemberRow{memberRow}
	view := sidecartest.NewFakeGkmAuthLog().Append(&sidecartest.FakeGkmAuthFixture{
		Rows:         rows,
		IdentityKeys: map[sidecar.Id][]byte{},
		RepoReaders:  map[sidecar.Id][]sidecar.Id{directoryRepoId: everyone, generalRepoId: everyone, configRepoId: everyone},
		RepoWriters:  map[sidecar.Id][]sidecar.Id{directoryRepoId: everyone, generalRepoId: {writer}, configRepoId: {config}},
		ConfigRepoId: configRepoId,
	})
	now := time.UnixMilli(1790000000000)
	if audience := GkmFirstUploadAudience(view, directoryRepoId, uploader, []sidecar.Id{config}, now); !slices.Equal(audience, []sidecar.Id{signer, config}) {
		t.Errorf("the directory group's audience: %v", audience)
	}
	if audience := GkmFirstUploadAudience(view, generalRepoId, uploader, []sidecar.Id{writer}, now); !slices.Equal(audience, []sidecar.Id{writer}) {
		t.Errorf("a general repo's audience: %v", audience)
	}
	// an uploader whose admission the config writer signed is hinted once
	if audience := GkmFirstUploadAudience(view, directoryRepoId, uploader, []sidecar.Id{signer, config}, now); !slices.Equal(audience, []sidecar.Id{signer, config}) {
		t.Errorf("a signer that writes the config: %v", audience)
	}
}

// §10.9's hints row at the reconciler: a shrink of the directory repo hints pending to the statement's signer and
// the config writers and to no other writer, though every sidecar writes the directory; while the gate stays closed
// the repeats go to the config writers, and no unhinted writer is ever told.
func TestGkmReconcilerHintsOnlyTheSignerAndTheConfigWritersInTheDirectoryGroup(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	configRepoId := testId("repo-config")
	signer, config, unhintedA, unhintedB, revoked := testId("sc-revoker"), testId("sc-config-writer"), testId("sc-unhinted-a"), testId("sc-unhinted-b"), testId("sc-revoked")
	everyone := []sidecar.Id{signer, config, unhintedA, unhintedB, revoked}
	for _, sidecarId := range everyone {
		fixture.clientOf(sidecarId)
	}
	state := func(readers []sidecar.Id, shrunkAt uint64) *sidecartest.FakeGkmAuthView {
		rows := sidecartest.FakeGkmAuthRows(&protocol.AclRepo{RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_DIRECTORY, HoldersShrunkAt: shrunkAt})
		sidecarRows, memberRow := sidecartest.FakeGkmAuthMemberDevices(world.memberId, readers...)
		rows.Sidecars = sidecarRows
		rows.Members = []*bridge.MemberRow{memberRow}
		return world.log.Append(&sidecartest.FakeGkmAuthFixture{
			Rows:         rows,
			IdentityKeys: map[sidecar.Id][]byte{},
			// every sidecar of the team reads the directory and writes it
			RepoReaders:  map[sidecar.Id][]sidecar.Id{world.repoId: readers, configRepoId: readers},
			RepoWriters:  map[sidecar.Id][]sidecar.Id{world.repoId: readers, configRepoId: {config}},
			ConfigRepoId: configRepoId,
		})
	}
	repoIds := []sidecar.Id{configRepoId, world.repoId}
	view1 := state(everyone, 0)
	world.key1 = world.putGeneration(nil, view1.Pin())
	world.awaitState(view1, func() { world.state.set(world.networkId, view1, repoIds, nil) })
	for _, sidecarId := range everyone {
		if count := world.pendingHints(sidecarId); count != 0 {
			t.Fatalf("a first sight with the gate open hinted %s: %d", sidecarId, count)
		}
	}

	// the revocation, which the revoker signed: a shrink at position 2 that gen/1 does not cover
	view2 := state([]sidecar.Id{signer, config, unhintedA, unhintedB}, 2)
	world.awaitState(view2, func() { world.state.set(world.networkId, view2, repoIds, &signer) })
	if count := world.pendingHints(signer); count != 1 {
		t.Errorf("the revocation's signer's pending hints: %d", count)
	}
	if count := world.pendingHints(config); count != 1 {
		t.Errorf("the config writer's pending hints: %d", count)
	}
	for _, sidecarId := range []sidecar.Id{unhintedA, unhintedB, revoked} {
		if count := world.pendingHints(sidecarId); count != 0 {
			t.Errorf("a writer that neither signed nor writes the config was hinted: %s, %d", sidecarId, count)
		}
	}
	// the gate stays closed: the repeats reach the config writers, and still no other writer
	world.advance(world.reconciler.settings.PendingHintInterval)
	if count := world.pendingHints(config); count != 2 {
		t.Errorf("the config writer's pending hints one interval into a closed gate: %d", count)
	}
	for _, sidecarId := range []sidecar.Id{unhintedA, unhintedB} {
		if count := world.pendingHints(sidecarId); count != 0 {
			t.Errorf("an unhinted writer was told while the gate stayed closed: %s, %d", sidecarId, count)
		}
	}
}
