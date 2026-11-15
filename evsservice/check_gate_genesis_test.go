// 5d's genesis pin (QD-081 #4; QD-824): the config repo's first push, which base 1 names, carries auth {0, A_0}, and
// evs takes that pin there alone. A general repo's first push pinned at the genesis, and a config repo's push meeting a
// head, are final refusals before the pin is judged against evs's chain; and the push's shape holds the pin to a ref's
// first push, a push on a base refused before it is ever signed.

package evsservice

import (
	"bytes"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A genesis pin anywhere but the config repo's first push is refused, final.
func TestCheckGateTakesTheGenesisPinOnTheConfigReposFirstPushAlone(t *testing.T) {
	fixture := newCheckFixture(t)
	genesisPin := &bridge.AuthPin{Version: 0, Chain: bytes.Repeat([]byte{0x47}, 32)}

	general := fixture.rulesView(genesisPin, nil)
	refusal := CheckGate(general)
	requireCheckRefusal(t, "a general repo's first push", refusal, EvsCheckReasonPinForked)
	if refusal != nil && refusal.Detail != "a genesis pin outside the config repo's first push" {
		t.Errorf("the refusal's detail: %q", refusal.Detail)
	}

	config := fixture.rulesView(genesisPin, nil)
	config.Repo.Kind = protocol.RepoKind_REPO_KIND_CONFIG
	config.Head = checkTestHead(config, 1)
	refusal = CheckGate(config)
	requireCheckRefusal(t, "a config repo's push on a head", refusal, EvsCheckReasonPinForked)
	if refusal != nil && refusal.Detail != "a genesis pin outside the config repo's first push" {
		t.Errorf("the refusal's detail: %q", refusal.Detail)
	}

	// on the config repo's first push the genesis rule passes, and the pin goes on to evs's chain
	first := fixture.rulesView(genesisPin, nil)
	first.Repo.Kind = protocol.RepoKind_REPO_KIND_CONFIG
	if refusal := CheckGate(first); refusal != nil && refusal.Detail == "a genesis pin outside the config repo's first push" {
		t.Errorf("the config repo's first push refused as outside it")
	}

	plan := fixture.plan()
	plan.Auth = genesisPin
	plan.BaseVersion = 1
	plan.Changes = []*sidecar.EvsPlannedChange{fixture.change(plan, checkTestPath("a"), 0, 2)}
	if _, err := sidecar.NewEvsStatementBuilder(checkTestSign(fixture.signingKey, fixture.signerId)).Build(plan); !errors.Is(err, sidecar.ErrEvsPushInvalid) {
		t.Errorf("a push on version 1 pinned at the genesis: %v", err)
	}
}
