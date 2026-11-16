package sidecartest

// §22.7's suites in their Team forms on T2 (TEAM-M6-12): each Team row its own top-level test on FakeApi over T2's fake
// first cluster, every reader compared with the reference, and FS-101's log-retention fixture run 30 days and 10 folds
// past a pin. server/api/sidecar_team_t3_test.go runs the same rows on server's sequencer.

import (
	"bytes"
	"errors"
	"flag"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var teamSuiteFull = flag.Bool("team-suite-full", false, "run the Team suite's admissions row at 5,000 admissions")

func TestTeamKOfNEndToEnd(t *testing.T) {
	RunTeamRow(t, "k of n end to end", admissionT2Tier(t), nil)
}

func TestTeamTwoAdminsForceKOfOne(t *testing.T) {
	RunTeamRow(t, "n at most 2 forces k = 1", admissionT2Tier(t), nil)
}

func TestTeamSeatsInTheDirectoryGroup(t *testing.T) {
	RunTeamRow(t, "seats in the directory group", admissionT2Tier(t), nil)
}

// The admissions row just past the leaves' first 1,000 in every run, and at §20.4's 5,000 Team config_admissions
// (QUOTA-M6-06's number) behind -team-suite-full, whose run takes minutes.
func TestTeamAdmissionsMeetNoMemberDeviceCap(t *testing.T) {
	tier := admissionT2Tier(t)
	settings := ReducedTeamSuiteSettings()
	if *teamSuiteFull {
		settings = DefaultTeamSuiteSettings()
		tier.Settings = DefaultAdmissionSuiteSettings()
		tier.Settings.RowTimeout = 30 * time.Minute
	}
	RunTeamRow(t, "admissions meet no member-device cap", tier, settings)
}

func TestTeamEphemeralWritesNoConfig(t *testing.T) {
	RunTeamRow(t, "an ephemeral writes no config", admissionT2Tier(t), nil)
}

// FS-101's fixture: repo admin E's repo P created at n0, then the log runs 30 days and 10 folds past n0 with the
// production fold and retention values. api's store no longer holds n0's entry, nor any entry below its retention
// point; the long-running reader holds n0's pin no longer either, its base pins older than 30 days dropped; a fresh
// member device, started from what api still holds, cannot reach the state at n0, yet judges E's right on P at n0
// from the access log's positions, which the config head keeps for the repo's life (D-MCP-35; §16.11's repo file
// row), and agrees with the long-running reader at the tip.
func TestTeamLogRetentionRunsThirtyDaysAndTenFoldsPastAPin(t *testing.T) {
	fixture := NewTeamLogRetention(t, admissionT2Tier(t), nil)
	defer fixture.Close()
	net := fixture.Net()
	memberE, e := net.ConsentedMember("e")
	repoId := net.Id("repo p")
	net.MustLand(net.Sign(e, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		Header: net.Header(), RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
	}))
	n0 := net.Tip().GetVersion()
	pinN0 := proto.Clone(net.Tip()).(*bridge.AuthPin)
	timeN0 := net.State().TimeMs()
	if view := sidecar.NewDirectoryAuthView(net.State()); !teamRepoAdminRight(t, view, repoId, e.SidecarId, n0) {
		t.Fatal("E holds no right on P at n0 before the run")
	}
	baseN0 := teamPinAt(t, net.AdmissionNet, net.State().Base().GetVersion())

	fixture.RunPast(n0)
	tip := net.State()
	if span := net.Clock().Now().Sub(time.UnixMilli(timeN0)); span < fixture.Settings().RunSpan {
		t.Fatalf("the run spanned %s past n0", span)
	}
	if fixture.Folds() < fixture.Settings().RunFolds {
		t.Fatalf("the run published %d bases", fixture.Folds())
	}
	point := fixture.RetentionPoint()
	if point <= n0 || fixture.Held(n0) || fixture.Held(point-1) || !fixture.Held(point) || !fixture.Held(0) {
		t.Fatalf("api's store past its retention point %d: n0 %t, point-1 %t, point %t, genesis %t",
			point, fixture.Held(n0), fixture.Held(point-1), fixture.Held(point), fixture.Held(0))
	}
	// the long-running reader holds neither n0's A_n nor the pin of the base n0 stood on, over 30 days old
	if tip.OnChain(pinN0) || tip.OnChain(baseN0) {
		t.Fatal("the long-running reader still holds n0's pin or its base's a month and ten folds on")
	}

	fresh := fixture.FreshDevice()
	state := fresh.State()
	if !proto.Equal(state.Pin(), tip.Pin()) {
		t.Fatalf("the fresh device stands at %d, the reference at %d", state.Pin().GetVersion(), tip.Pin().GetVersion())
	}
	if err := admissionStatesEqual(state, tip); err != nil {
		t.Fatalf("the fresh device: %v", err)
	}
	if _, err := state.StateAt(pinN0); !errors.Is(err, sidecar.ErrConfigPinNotRetained) {
		t.Fatalf("the fresh device's state at n0: %v", err)
	}
	view := sidecar.NewDirectoryAuthView(state)
	if _, err := view.At(pinN0); !errors.Is(err, sidecar.ErrDirectoryAuthNotRetained) {
		t.Fatalf("the fresh device's view at n0: %v", err)
	}
	if !teamRepoAdminRight(t, view, repoId, e.SidecarId, n0) {
		t.Fatal("the fresh device does not judge E's right on P at n0 from the access log's positions")
	}
	if teamRepoAdminRight(t, view, repoId, net.Device("e never admitted", memberE).SidecarId, n0) {
		t.Fatal("a device the log never admitted holds P's right at the fresh device")
	}
	if repo, ok := view.Repo(repoId); !ok || !repo.Live || repo.CreatedAt != n0 || !bytes.Equal(repo.RepoId.Bytes(), repoId.Bytes()) {
		t.Fatalf("P as the fresh device holds it: %+v, %t", repo, ok)
	}
}

// The pin of the entry at n, as the world read it.
func teamPinAt(t *testing.T, net *AdmissionNet, n uint64) *bridge.AuthPin {
	t.Helper()
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(net.Entry(n), entry); err != nil {
		t.Fatal(err)
	}
	chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
	if err != nil {
		t.Fatal(err)
	}
	return &bridge.AuthPin{Version: n, Chain: chain[:]}
}

// view's D-MCP-35 right of sidecarId on repoId at position, failing t on an error.
func teamRepoAdminRight(t *testing.T, view sidecar.DirectoryAuthView, repoId sidecar.Id, sidecarId sidecar.Id, position uint64) bool {
	t.Helper()
	right, err := view.RepoAdminRight(repoId, sidecarId, position)
	if err != nil {
		t.Fatalf("the right of %s on %s at %d: %v", sidecarId, repoId, position, err)
	}
	return right
}
