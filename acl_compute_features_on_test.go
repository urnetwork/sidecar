//go:build !ios_extension && !sidecar_http

// Turning an authorization feature on (acl_compute_features_on.go; DESIGN-COMPUTE §16.6, CACL-M11-03): the core sync
// states this release's features and reads the services' and the lacking sidecars back; a confirmed turning-on on an
// Owner's or Admin's device files the bit beside the head's and never clears one; every refusal signs nothing,
// naming who can where a Member's device asks; and the prompt names the feature, whether this person may turn it on,
// the Owners and Admins, and the sidecars that would pause, which api lists to an Owner's or Admin's device alone.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The team's Owners and Admins, in id order.
func testAuthFeatureAdmins(team *testConfigTeam) []Id {
	memberIds := []Id{team.ownerMemberId, team.adminB.memberId, team.adminC.memberId}
	slices.SortFunc(memberIds, Id.Cmp)
	return memberIds
}

// A turning-on on state for the device sidecarId, recording what it files.
func testAuthFeatureTurnOn(state *ConfigState, core *SidecarSyncCore, sidecarId Id, implemented AuthFeature) (*authFeatureTurnOn, *[]*ServiceSettingsChange) {
	filed := []*ServiceSettingsChange{}
	return &authFeatureTurnOn{
		state:       state,
		core:        core,
		sidecarId:   sidecarId,
		implemented: implemented,
		save: func(ctx context.Context, change *ServiceSettingsChange) error {
			filed = append(filed, change)
			return nil
		},
	}, &filed
}

// The request states this release's features, which a release implementing none leaves out; the answer's services'
// features and lacking sidecars read back, a name that is no feature's and an id that does not parse dropped; and an
// older api's answer, naming none, offers nothing.
func TestSyncCoreStatesAndReadsAuthFeatures(t *testing.T) {
	// a release implementing none, whatever this build's owners registered
	WithAuthFeaturesImplementedForTest(t, 0, nil)
	listedId := NewId()
	answers := map[bool]string{
		true: `{"version":"8","gates":[],"min_secure_version":0,"revoked":false,"auth_features":["agent_repos","listeners","nothing"],` +
			`"auth_features_lacking":{"sidecars":[{"sidecar_id":"` + listedId.String() + `","auth_features":["agent_repos"]},` +
			`{"sidecar_id":"not an id","auth_features":[]}],"more":true}}`,
		false: `{"version":"8","gates":[],"min_secure_version":0,"revoked":false}`,
	}
	for _, newer := range []bool{true, false} {
		transport := &scriptedApiTransport{answer: func(request *http.Request, _ []byte) (*http.Response, error) {
			return syntheticResponse(request, http.StatusOK, answers[newer], nil), nil
		}}
		api := newTestSidecarApi(t, transport)
		core, err := api.SyncCore(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if request, _ := transport.onlyRequest(t); request.URL.RawQuery != "" {
			t.Fatalf("a release implementing no feature stated %q", request.URL.RawQuery)
		}
		if !newer {
			if core.AuthFeatures != 0 || core.AuthFeaturesLacking != nil {
				t.Fatalf("an older api's answer offers %s, lacking %+v", core.AuthFeatures, core.AuthFeaturesLacking)
			}
			continue
		}
		if core.AuthFeatures != AuthFeatureAgentRepos|AuthFeatureListeners {
			t.Fatalf("the services' features read %s", core.AuthFeatures)
		}
		lacking := core.AuthFeaturesLacking
		if lacking == nil || !lacking.More || !slices.Equal(lacking.Sidecars, []SidecarStatedAuthFeatures{{SidecarId: listedId, AuthFeatures: AuthFeatureAgentRepos}}) {
			t.Fatalf("the lacking sidecars read %+v", lacking)
		}
	}

	WithAuthFeaturesImplementedForTest(t, AuthFeatureAgentRepos|AuthFeatureEnclaves, nil)
	transport := &scriptedApiTransport{answer: func(request *http.Request, _ []byte) (*http.Response, error) {
		return syntheticResponse(request, http.StatusOK, answers[false], nil), nil
	}}
	if _, err := newTestSidecarApi(t, transport).SyncCore(t.Context()); err != nil {
		t.Fatal(err)
	}
	if request, _ := transport.onlyRequest(t); request.URL.Path != "/sidecar/sync/core" || request.URL.Query().Get("auth_features") != "agent_repos,enclaves" {
		t.Fatalf("the release's features were stated as %q", request.URL.RawQuery)
	}
}

// A confirmed turning-on on an Owner's and on an Admin's device files the feature alone through SaveServiceSettings'
// change; the change sets the bit beside the head's, other fields kept, a later change of another field keeping it, so
// no filing clears a bit, and readers take the head; a feature already on files nothing.
func TestAdminSettingsFeatureConfirmed(t *testing.T) {
	ctx := context.Background()
	team := newTestConfigTeam(t)
	state := team.log.State()
	core := &SidecarSyncCore{AuthFeatures: AuthFeatureAgentRepos | AuthFeatureListeners}
	implemented := AuthFeatureAgentRepos | AuthFeatureListeners | AuthFeatureEnclaves
	for _, device := range []testConfigDevice{team.owner, team.adminB} {
		turnOn, filed := testAuthFeatureTurnOn(state, core, device.sidecarId, implemented)
		if err := turnOn.run(ctx, &AuthFeatureTurnOnArgs{Feature: AuthFeatureAgentRepos, Confirmed: true}); err != nil {
			t.Fatalf("%s's device: %v", device.memberId, err)
		}
		if len(*filed) != 1 || *(*filed)[0] != (ServiceSettingsChange{AuthFeatures: AuthFeatureAgentRepos}) {
			t.Fatalf("%s's device filed %+v", device.memberId, *filed)
		}
	}

	// the filing through the head: the bit beside the head's, every other field kept, and never cleared after
	existing := &protocol.ServiceSettings{MailStrict: true, AuthFeatures: uint32(AuthFeatureListeners)}
	head, err := testConfigHead(t, team.testConfigNet).WithFile(ConfigHeadServiceSettingsPath, team.sign(team.owner, bridge.SignedType_SIGNED_SERVICE_SETTINGS, existing))
	if err != nil {
		t.Fatal(err)
	}
	heads := &testServiceSettingsHeads{head: head}
	sign := func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body:      bytes.Clone(body),
			SignerId:  team.owner.sidecarId.Bytes(),
			Signature: ed25519.Sign(team.owner.key, bridge.SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		}, nil
	}
	steps := []struct {
		change *ServiceSettingsChange
		want   *protocol.ServiceSettings
	}{
		{
			change: &ServiceSettingsChange{AuthFeatures: AuthFeatureAgentRepos},
			want:   &protocol.ServiceSettings{MailStrict: true, AuthFeatures: uint32(AuthFeatureListeners | AuthFeatureAgentRepos)},
		},
		{
			change: &ServiceSettingsChange{MailStrict: testServiceSettingsBool(false)},
			want:   &protocol.ServiceSettings{AuthFeatures: uint32(AuthFeatureListeners | AuthFeatureAgentRepos)},
		},
	}
	for i, step := range steps {
		filed, err := configSaveServiceSettings(ctx, heads, sign, step.change)
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		held, signed, err := heads.head.ServiceSettings()
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(filed, step.want) || !proto.Equal(held, step.want) {
			t.Errorf("step %d filed %v and the head holds %v", i, filed, held)
		}
		if err := configHeadRecordSignedByAdmin(state, signed, bridge.SignedType_SIGNED_SERVICE_SETTINGS); err != nil {
			t.Errorf("step %d: a reader refuses the head's settings: %v", i, err)
		}
	}

	// a feature already on files nothing
	team.log.authFeatures = implemented
	base := testFeatureBase(t, team.testConfigNet, AuthFeatureAgentRepos)
	if verdict, err := team.log.Apply(base, team.source); err != nil || !verdict.Accepted() {
		t.Fatalf("the base turning agent_repos on: %v", err)
	}
	turnOn, filed := testAuthFeatureTurnOn(team.log.State(), core, team.owner.sidecarId, implemented)
	if err := turnOn.run(ctx, &AuthFeatureTurnOnArgs{Feature: AuthFeatureAgentRepos, Confirmed: true}); err != nil || len(*filed) != 0 {
		t.Fatalf("a feature already on: %v, filed %+v", err, *filed)
	}
}

// Every refusal signs nothing: an unconfirmed act and one under a harness; a value that is not one feature; no verified
// state; a Member's device, naming the network's Owners and Admins; a bit this release lacks; one the services serving
// the network lack; and any while no core answer is current. On a Sidecar the same refusals reach TurnOnAuthFeature and
// SaveServiceSettings before any writer.
func TestAdminSettingsFeatureRefused(t *testing.T) {
	ctx := context.Background()
	team := newTestConfigTeam(t)
	member := team.admitMemberDevice("plain")
	state := team.log.State()
	core := &SidecarSyncCore{AuthFeatures: AuthFeatureAgentRepos | AuthFeatureListeners}
	implemented := AuthFeatureAgentRepos | AuthFeatureEnclaves
	confirmed := func(feature AuthFeature) *AuthFeatureTurnOnArgs {
		return &AuthFeatureTurnOnArgs{Feature: feature, Confirmed: true}
	}
	for _, c := range []struct {
		name      string
		state     *ConfigState
		core      *SidecarSyncCore
		sidecarId Id
		args      *AuthFeatureTurnOnArgs
		want      error
		names     bool
	}{
		{name: "no args", state: state, core: core, sidecarId: team.owner.sidecarId, args: nil, want: ErrSidecarActMode},
		{name: "unconfirmed", state: state, core: core, sidecarId: team.owner.sidecarId, args: &AuthFeatureTurnOnArgs{Feature: AuthFeatureAgentRepos}, want: ErrAuthFeatureTurnOnUnconfirmed},
		{name: "under a harness", state: state, core: core, sidecarId: team.owner.sidecarId, args: &AuthFeatureTurnOnArgs{Feature: AuthFeatureAgentRepos, Confirmed: true, HarnessAncestor: true}, want: ErrSidecarActMode},
		{name: "two features", state: state, core: core, sidecarId: team.owner.sidecarId, args: confirmed(AuthFeatureAgentRepos | AuthFeatureListeners), want: ErrAuthFeatureUnknown},
		{name: "a bit the format does not name", state: state, core: core, sidecarId: team.owner.sidecarId, args: confirmed(AuthFeature(16)), want: ErrAuthFeatureUnknown},
		{name: "no verified state", state: nil, core: core, sidecarId: team.owner.sidecarId, args: confirmed(AuthFeatureAgentRepos), want: ErrSidecarActNoAuthority},
		{name: "a Member's device", state: state, core: core, sidecarId: member.sidecarId, args: confirmed(AuthFeatureAgentRepos), want: ErrServiceSettingsSigner, names: true},
		{name: "a bit this release lacks", state: state, core: core, sidecarId: team.owner.sidecarId, args: confirmed(AuthFeatureListeners), want: ErrAuthFeatureUnsupported, names: true},
		{name: "a bit the services lack", state: state, core: core, sidecarId: team.owner.sidecarId, args: confirmed(AuthFeatureEnclaves), want: ErrAuthFeatureServicesLack, names: true},
		{name: "no current core answer", state: state, core: nil, sidecarId: team.owner.sidecarId, args: confirmed(AuthFeatureAgentRepos), want: ErrAuthFeatureServicesLack, names: true},
	} {
		turnOn, filed := testAuthFeatureTurnOn(c.state, c.core, c.sidecarId, implemented)
		err := turnOn.run(ctx, c.args)
		if !errors.Is(err, c.want) || len(*filed) != 0 {
			t.Errorf("%s: %v, filed %+v", c.name, err, *filed)
			continue
		}
		required := &AuthFeatureRequiredError{}
		if errors.As(err, &required) != c.names {
			t.Errorf("%s: names who can %v: %v", c.name, !c.names, err)
			continue
		}
		if c.names && (required.MayTurnOn || !slices.Equal(required.AdminMemberIds, testAuthFeatureAdmins(team))) {
			t.Errorf("%s: may turn on %v, names %v", c.name, required.MayTurnOn, required.AdminMemberIds)
		}
	}
	// a Member's device says who can, by member id
	turnOn, _ := testAuthFeatureTurnOn(state, core, member.sidecarId, implemented)
	err := turnOn.run(ctx, confirmed(AuthFeatureAgentRepos))
	for _, memberId := range testAuthFeatureAdmins(team) {
		if err == nil || !strings.Contains(err.Error(), memberId.String()) {
			t.Errorf("a Member's device's refusal does not name %s: %v", memberId, err)
		}
	}

	// on a Sidecar: the release lacking it, a Member's device, and no current core answer each refused before any writer
	world := newTestConfigClientWorld(t)
	memberId, _ := world.net.consentedMember("plain member")
	memberSidecar, _ := testServiceSettingsSidecar(t, world, "plain member laptop", memberId)
	ownerSidecar, _ := testServiceSettingsSidecar(t, world, "owner laptop", world.net.ownerMemberId)
	if _, err := ownerSidecar.TurnOnAuthFeature(ctx, confirmed(AuthFeatureAgentRepos)); !errors.Is(err, ErrAuthFeatureUnsupported) {
		t.Fatalf("a release implementing none: %v", err)
	}
	if _, err := ownerSidecar.SaveServiceSettings(ctx, &ServiceSettingsChange{AuthFeatures: AuthFeatureAgentRepos}, SidecarActConfirmed); !errors.Is(err, ErrAuthFeatureUnsupported) {
		t.Fatalf("SaveServiceSettings with a release implementing none: %v", err)
	}
	WithAuthFeaturesImplementedForTest(t, AuthFeatureAgentRepos, nil)
	required := &AuthFeatureRequiredError{}
	if _, err := memberSidecar.TurnOnAuthFeature(ctx, confirmed(AuthFeatureAgentRepos)); !errors.Is(err, ErrServiceSettingsSigner) || !errors.As(err, &required) ||
		!slices.Equal(required.AdminMemberIds, []Id{world.net.ownerMemberId}) {
		t.Fatalf("a Member's device: %v", err)
	}
	if _, err := ownerSidecar.TurnOnAuthFeature(ctx, confirmed(AuthFeatureAgentRepos)); !errors.Is(err, ErrAuthFeatureServicesLack) {
		t.Fatalf("an Owner's device with no current core answer: %v", err)
	}
	if _, err := ownerSidecar.SaveServiceSettings(ctx, &ServiceSettingsChange{AuthFeatures: AuthFeatureAgentRepos}, SidecarActConfirmed); !errors.Is(err, ErrAuthFeatureServicesLack) {
		t.Fatalf("SaveServiceSettings with no current core answer: %v", err)
	}
	if _, err := ownerSidecar.TurnOnAuthFeature(ctx, &AuthFeatureTurnOnArgs{Feature: AuthFeatureAgentRepos, Confirmed: true, HarnessAncestor: true}); !errors.Is(err, ErrSidecarActMode) {
		t.Fatalf("an Owner's device under a harness: %v", err)
	}
	if _, err := ownerSidecar.SaveServiceSettings(ctx, &ServiceSettingsChange{AuthFeatures: AuthFeatureAgentRepos}, SidecarActMcp); !errors.Is(err, ErrSidecarActMode) {
		t.Fatalf("through MCP: %v", err)
	}
}

// The prompt: a feature off answers AuthFeatureRequiredError, unwrapping to ErrAuthFeatureOff, with the feature, whether
// this person may turn it on, the network's Owners and Admins, and the sidecars that would pause, which api lists to an
// Owner's or Admin's device alone; once the feature is on, nothing. The statuses ur admin settings and the apps read say
// the same.
func TestAuthFeatureRequiredNamesAdmins(t *testing.T) {
	team := newTestConfigTeam(t)
	member := team.admitMemberDevice("plain")
	state := team.log.State()
	implemented := AuthFeatureAgentRepos | AuthFeatureListeners
	ownerCore := &SidecarSyncCore{
		AuthFeatures: AuthFeatureAgentRepos | AuthFeatureListeners,
		AuthFeaturesLacking: &SidecarSyncCoreLacking{Sidecars: []SidecarStatedAuthFeatures{
			{SidecarId: team.adminB.sidecarId, AuthFeatures: AuthFeatureAgentRepos},
			{SidecarId: member.sidecarId, AuthFeatures: 0},
		}},
	}
	memberCore := &SidecarSyncCore{AuthFeatures: ownerCore.AuthFeatures}

	err := authFeatureRequired(state, ownerCore, team.owner.sidecarId, implemented, AuthFeatureAgentRepos)
	ownerRequired := &AuthFeatureRequiredError{}
	if !errors.Is(err, ErrAuthFeatureOff) || !errors.As(err, &ownerRequired) {
		t.Fatalf("the Owner's device: %v", err)
	}
	if ownerRequired.Feature != AuthFeatureAgentRepos || !ownerRequired.MayTurnOn || !slices.Equal(ownerRequired.AdminMemberIds, testAuthFeatureAdmins(team)) ||
		!slices.Equal(ownerRequired.PausingSidecarIds, []Id{member.sidecarId}) || !strings.Contains(err.Error(), "ur admin settings --feature agent_repos") {
		t.Fatalf("the Owner's device's prompt: %+v, %v", ownerRequired, err)
	}
	// listeners: the Admin's device states agent_repos alone, so it pauses too
	if err := authFeatureRequired(state, ownerCore, team.owner.sidecarId, implemented, AuthFeatureListeners); !errors.As(err, &ownerRequired) ||
		!slices.Equal(ownerRequired.PausingSidecarIds, []Id{team.adminB.sidecarId, member.sidecarId}) {
		t.Fatalf("listeners' prompt: %+v", ownerRequired)
	}

	err = authFeatureRequired(state, memberCore, member.sidecarId, implemented, AuthFeatureAgentRepos)
	memberRequired := &AuthFeatureRequiredError{}
	if !errors.Is(err, ErrAuthFeatureOff) || !errors.As(err, &memberRequired) {
		t.Fatalf("the Member's device: %v", err)
	}
	if memberRequired.MayTurnOn || !slices.Equal(memberRequired.AdminMemberIds, testAuthFeatureAdmins(team)) || memberRequired.PausingSidecarIds != nil {
		t.Fatalf("the Member's device's prompt: %+v", memberRequired)
	}
	for _, memberId := range testAuthFeatureAdmins(team) {
		if !strings.Contains(err.Error(), memberId.String()) {
			t.Errorf("the Member's device's prompt does not name %s: %v", memberId, err)
		}
	}

	// the statuses say the same, a feature this release lacks never offered
	status := authFeatureStatusAt(state, ownerCore, team.owner.sidecarId, implemented, AuthFeatureEnclaves)
	if status.On || status.Implemented || status.MayTurnOn || status.Supported || !status.SupportKnown || !status.PausingKnown {
		t.Fatalf("enclaves' status: %+v", status)
	}
	if status := authFeatureStatusAt(state, nil, team.owner.sidecarId, implemented, AuthFeatureAgentRepos); status.MayTurnOn || status.SupportKnown || status.PausingKnown {
		t.Fatalf("with no core answer: %+v", status)
	}

	// once on, no prompt
	team.log.authFeatures = implemented
	base := testFeatureBase(t, team.testConfigNet, AuthFeatureAgentRepos)
	if verdict, err := team.log.Apply(base, team.source); err != nil || !verdict.Accepted() {
		t.Fatalf("the base turning agent_repos on: %v", err)
	}
	if err := authFeatureRequired(team.log.State(), memberCore, member.sidecarId, implemented, AuthFeatureAgentRepos); err != nil {
		t.Fatalf("agent_repos on: %v", err)
	}
	if status := authFeatureStatusAt(team.log.State(), ownerCore, team.owner.sidecarId, implemented, AuthFeatureAgentRepos); !status.On || status.MayTurnOn {
		t.Fatalf("agent_repos on: %+v", status)
	}

	// on a Sidecar: no verified state, then a Member's device's prompt
	if err := (&Sidecar{}).CheckAuthFeature(AuthFeatureAgentRepos); !errors.Is(err, ErrSidecarActNoAuthority) {
		t.Fatalf("no verified state: %v", err)
	}
	if _, err := (&Sidecar{}).AuthFeatureStatuses(); !errors.Is(err, ErrSidecarActNoAuthority) {
		t.Fatalf("no verified state's statuses: %v", err)
	}
	world := newTestConfigClientWorld(t)
	memberId, _ := world.net.consentedMember("plain member")
	memberSidecar, _ := testServiceSettingsSidecar(t, world, "plain member laptop", memberId)
	sidecarRequired := &AuthFeatureRequiredError{}
	if err := memberSidecar.CheckAuthFeature(AuthFeatureAgentRepos); !errors.As(err, &sidecarRequired) || sidecarRequired.MayTurnOn ||
		!slices.Equal(sidecarRequired.AdminMemberIds, []Id{world.net.ownerMemberId}) {
		t.Fatalf("a Member's Sidecar: %v", err)
	}
	statuses, err := memberSidecar.AuthFeatureStatuses()
	if err != nil || len(statuses) != 4 {
		t.Fatalf("the statuses: %v", err)
	}
	for i, name := range []string{"agent_repos", "compute_policy", "listeners", "enclaves"} {
		if statuses[i].Name != name || statuses[i].On || statuses[i].MayTurnOn {
			t.Errorf("status %d: %+v", i, statuses[i])
		}
	}
}
