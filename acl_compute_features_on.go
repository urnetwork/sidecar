//go:build !ios_extension && !sidecar_http

// Turning an authorization feature on (DESIGN-COMPUTE §16.6's turn on, point and prompt rows, D-CACL-8, R2-02;
// CACL-M11-03): how a network turns on one of §16.6's features, whose mechanism in every reader is
// acl_compute_features.go's.
//
//	core     each GET /sidecar/sync/core states the features this release implements, which api keeps per sidecar,
//	         unsigned and for the prompt alone ({scf_<network_id>}); its answer names the features every service serving
//	         the network implements and, to an Owner's or Admin's device, the sidecars whose last stated features lack
//	         one of them (SidecarSyncCore, push_poll.go)
//	point    api refuses a base turning on a feature some service serving the network lacks, feature_unsupported, with
//	         the tip, reading only the base's rows' features (ConfigRowsAuthFeatures) and the services' bits
//	turn on  an Owner's or Admin's device, on the person's confirmation alone, as for every ServiceSettings change:
//	         TurnOnAuthFeature, which ur admin settings --feature and the apps' prompt call, files the bit through
//	         SaveServiceSettings (ServiceSettingsChange.AuthFeatures), which sets it beside the head's and never clears
//	         one. It refuses, signing nothing, an act no person confirmed or one under a harness ancestor; a bit this
//	         release does not implement, which is never offered; a device that is no Owner's or Admin's, naming those
//	         who can; and a bit the services serving the network do not implement as the current core answer says, or
//	         any while no answer is current, since api would refuse the base and leave the head that sets it unpublished
//	prompt   a device that meets a feature off at the first act needing it answers AuthFeatureRequiredError
//	         (CheckAuthFeature): the feature, whether this person may turn it on, who can, and the sidecars that would
//	         pause until they update; ur admin settings and the apps read the same from AuthFeatureStatuses
//
// api's core answer is unsigned, so it only narrows what a device offers and files: every reader judges each base
// itself (acl_compute_features.go), and api judges the base again at the tip. Nothing here creates, derives or unwraps
// a key; the identity key signs through the config writer, as every ServiceSettings change does.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"strings"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// A turning-on no person confirmed, or one asked under a harness: nothing was signed.
	ErrAuthFeatureTurnOnUnconfirmed = fmt.Errorf("%w: turning an authorization feature on", ErrSidecarActMode)
	// The services serving the network do not implement the feature, as api's current core answer says, or no answer
	// is current to say: api would refuse the base (feature_unsupported), so nothing was signed.
	ErrAuthFeatureServicesLack = errors.New("the services serving this network do not implement the authorization feature yet")
)

// One authorization feature as this device sees it, for the turn-on prompt: ur admin settings and the apps'
// GetAuthFeatures. The services' support and the pausing sidecars are api's unsigned word, which only narrows what is
// offered.
type AuthFeatureStatus struct {
	Feature AuthFeature `json:"-"`
	// agent_repos, compute_policy, listeners or enclaves.
	Name string `json:"name"`
	// On from the newest base whose rows set it.
	On bool `json:"on"`
	// This release implements it (AuthFeaturesImplemented): one it does not is never offered.
	Implemented bool `json:"implemented"`
	// Every service serving the network implements it, as the current core answer says.
	Supported bool `json:"supported"`
	// A core answer is current, so Supported says something: false offline.
	SupportKnown bool `json:"support_known"`
	// This person may turn it on from this device now: off, implemented and supported, and this device an Owner's or
	// Admin's standing, untagged one.
	MayTurnOn bool `json:"may_turn_on"`
	// The network's Owners and Admins, who can, by member id.
	AdminMemberIds []Id `json:"admin_member_ids"`
	// The sidecars that would pause until they update: those api lists to this device whose last stated features lack
	// it, held already where it is on. Empty when none, and while api lists none to this device (PausingKnown).
	PausingSidecarIds []Id `json:"pausing_sidecar_ids"`
	// api listed the sidecars to this device, an Owner's or Admin's, in its current core answer.
	PausingKnown bool `json:"pausing_known"`
	// More sidecars lack a feature than api listed, so more may pause.
	PausingMore bool `json:"pausing_more"`
}

// A feature off that an act needs, or a turning-on this device may not make (§16.6's prompt and turn on rows): what the
// prompt shows. Unwraps to its cause: ErrAuthFeatureOff for an act that needs the feature, else the turning-on's
// refusal.
type AuthFeatureRequiredError struct {
	// The feature.
	Feature AuthFeature
	// Whether this person may turn it on from this device now.
	MayTurnOn bool
	// The network's Owners and Admins, who can, by member id.
	AdminMemberIds []Id
	// The sidecars that would pause until they update, as api lists them to an Owner's or Admin's device; nil elsewhere
	// and while unknown.
	PausingSidecarIds []Id
	// Why.
	Err error
}

// The feature and why, then who can turn it on, this person or the network's Owners and Admins by member id, and how
// many sidecars would pause.
func (self *AuthFeatureRequiredError) Error() string {
	parts := []string{fmt.Sprintf("authorization feature %s: %v", self.Feature, self.Err)}
	switch {
	case self.MayTurnOn:
		parts = append(parts, fmt.Sprintf("ur admin settings --feature %s turns it on", self.Feature))
	case 0 < len(self.AdminMemberIds):
		memberIds := make([]string, 0, len(self.AdminMemberIds))
		for _, memberId := range self.AdminMemberIds {
			memberIds = append(memberIds, memberId.String())
		}
		parts = append(parts, "the network's Owners and Admins can turn it on: "+strings.Join(memberIds, ", "))
	}
	if 0 < len(self.PausingSidecarIds) {
		parts = append(parts, fmt.Sprintf("%d of the network's sidecars would pause until they update", len(self.PausingSidecarIds)))
	}
	return strings.Join(parts, "; ")
}

// ErrAuthFeatureOff for an act that needs the feature, else the turning-on's refusal.
func (self *AuthFeatureRequiredError) Unwrap() error {
	return self.Err
}

// The features a base's rows carry (ProjectionSettings.auth_features), read as every reader reads them: what api's
// feature_unsupported check reads of a base, and nothing else, ConfigLog.CheckBase judging the rest.
func ConfigRowsAuthFeatures(rows []byte) (AuthFeature, error) {
	return configRowsAuthFeatures(rows)
}

// Whether sidecarId may sign a ServiceSettings at this state, the rule every reader holds a head's record to: an Owner's
// or Admin's standing, untagged device. Who may turn a feature on, and to whom api lists the sidecars that lack one.
func (self *ConfigState) ServiceSettingsSigner(sidecarId Id) bool {
	return configServiceSettingsSigner(self, sidecarId) == nil
}

// The network's Owners and Admins at this state, in id order: who can turn a feature on.
func (self *ConfigState) AdminMemberIds() []Id {
	memberIds := []Id{}
	for _, memberId := range self.MemberIds() {
		switch self.Member(memberId).GetRole() {
		case bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_ADMIN:
			memberIds = append(memberIds, memberId)
		}
	}
	return memberIds
}

// Nil where features may be filed into a head now: each a feature the format names, implemented by this release and by
// every service serving the network as core says. A refusal signs nothing.
func checkAuthFeaturesFiling(features AuthFeature, implemented AuthFeature, core *SidecarSyncCore) error {
	switch {
	case features&^authFeaturesKnown != 0:
		return fmt.Errorf("%w: %d names no feature", ErrAuthFeatureUnknown, features)
	case features&^implemented != 0:
		return fmt.Errorf("%w: %s", ErrAuthFeatureUnsupported, features&^implemented)
	case core == nil:
		return fmt.Errorf("%w: no current core answer names the services' features", ErrAuthFeatureServicesLack)
	case features&^core.AuthFeatures != 0:
		return fmt.Errorf("%w: %s", ErrAuthFeatureServicesLack, features&^core.AuthFeatures)
	}
	return nil
}

// feature's status at state for the device sidecarId, the core answer core (nil while none is current) and the
// release's implemented features.
func authFeatureStatusAt(state *ConfigState, core *SidecarSyncCore, sidecarId Id, implemented AuthFeature, feature AuthFeature) *AuthFeatureStatus {
	status := &AuthFeatureStatus{
		Feature:           feature,
		Name:              feature.String(),
		On:                state.AuthFeatureOn(feature),
		Implemented:       feature != 0 && implemented&feature == feature,
		AdminMemberIds:    state.AdminMemberIds(),
		PausingSidecarIds: []Id{},
	}
	if core != nil {
		status.SupportKnown = true
		status.Supported = feature != 0 && core.AuthFeatures&feature == feature
		if lacking := core.AuthFeaturesLacking; lacking != nil {
			status.PausingKnown = true
			status.PausingMore = lacking.More
			for _, stated := range lacking.Sidecars {
				if stated.AuthFeatures&feature != feature {
					status.PausingSidecarIds = append(status.PausingSidecarIds, stated.SidecarId)
				}
			}
		}
	}
	status.MayTurnOn = !status.On && status.Implemented && status.Supported && state.ServiceSettingsSigner(sidecarId)
	return status
}

// Nil where feature is on at state; else the prompt's AuthFeatureRequiredError, unwrapping to ErrAuthFeatureOff.
func authFeatureRequired(state *ConfigState, core *SidecarSyncCore, sidecarId Id, implemented AuthFeature, feature AuthFeature) error {
	if state.AuthFeatureOn(feature) {
		return nil
	}
	status := authFeatureStatusAt(state, core, sidecarId, implemented, feature)
	required := &AuthFeatureRequiredError{
		Feature:        feature,
		MayTurnOn:      status.MayTurnOn,
		AdminMemberIds: status.AdminMemberIds,
		Err:            fmt.Errorf("%w: %s is not on for this network", ErrAuthFeatureOff, feature),
	}
	if status.PausingKnown {
		required.PausingSidecarIds = status.PausingSidecarIds
	}
	return required
}

// This Sidecar's current core answer, nil offline and while none is current (sidecarGeneration.currentCore).
func (self *Sidecar) authFeatureCore() *SidecarSyncCore {
	generation := self.runningGeneration()
	if generation == nil {
		return nil
	}
	return generation.currentCore()
}

// This device's sidecar id, zero before it has an identity, which no state counts as a signer.
func (self *Sidecar) authFeatureSidecarId() Id {
	if identity := self.Identity(); identity != nil {
		return identity.SidecarId
	}
	return Id{}
}

// Every feature as this device sees it, in bit order: ErrSidecarActNoAuthority before a verified state.
func (self *Sidecar) AuthFeatureStatuses() ([]*AuthFeatureStatus, error) {
	state, err := self.configState()
	if err != nil {
		return nil, ErrSidecarActNoAuthority
	}
	core, sidecarId, implemented := self.authFeatureCore(), self.authFeatureSidecarId(), AuthFeaturesImplemented()
	statuses := make([]*AuthFeatureStatus, 0, len(authFeatureNames))
	for _, entry := range authFeatureNames {
		statuses = append(statuses, authFeatureStatusAt(state, core, sidecarId, implemented, entry.feature))
	}
	return statuses, nil
}

// Nil where feature is on for this network at the newest verified state; else an *AuthFeatureRequiredError for the
// prompt, or ErrSidecarActNoAuthority before a verified state. Every act that files an entry using a feature checks it
// here first (§16.6's before row: a device files no such entry), and a refusal is what the apps raise their prompt on.
func (self *Sidecar) CheckAuthFeature(feature AuthFeature) error {
	state, err := self.configState()
	if err != nil {
		return ErrSidecarActNoAuthority
	}
	return authFeatureRequired(state, self.authFeatureCore(), self.authFeatureSidecarId(), AuthFeaturesImplemented(), feature)
}

// What turning a feature on asks (§16.6's turn on row).
type AuthFeatureTurnOnArgs struct {
	// One of the four features.
	Feature AuthFeature
	// A person confirmed it on /dev/tty or in an app's UI (D-CORE-13).
	Confirmed bool
	// The caller has a harness process among its ancestors: refused.
	HarnessAncestor bool
}

// A turning-on's checks and its filing, apart from the Sidecar, so a test supplies each.
type authFeatureTurnOn struct {
	// the newest verified state, nil before one
	state *ConfigState
	// the current core answer, nil while none is current
	core *SidecarSyncCore
	// this device, zero before it has an identity
	sidecarId   Id
	implemented AuthFeature
	// files the change as the person's confirmed ServiceSettings change: SaveServiceSettings
	save func(ctx context.Context, change *ServiceSettingsChange) error
}

// Checks the turning-on and files it, a feature already on filing nothing. A refusal signs nothing: see the file header.
func (self *authFeatureTurnOn) run(ctx context.Context, args *AuthFeatureTurnOnArgs) error {
	if args == nil || !args.Confirmed || args.HarnessAncestor {
		return ErrAuthFeatureTurnOnUnconfirmed
	}
	feature := args.Feature
	if bits.OnesCount32(uint32(feature)) != 1 || feature&^authFeaturesKnown != 0 {
		return fmt.Errorf("%w: %d is not one feature", ErrAuthFeatureUnknown, feature)
	}
	if self.state == nil {
		return ErrSidecarActNoAuthority
	}
	status := authFeatureStatusAt(self.state, self.core, self.sidecarId, self.implemented, feature)
	if status.On {
		return nil
	}
	refuse := func(err error) error {
		refusal := &AuthFeatureRequiredError{Feature: feature, AdminMemberIds: status.AdminMemberIds, Err: err}
		if status.PausingKnown {
			refusal.PausingSidecarIds = status.PausingSidecarIds
		}
		return refusal
	}
	if !status.Implemented {
		return refuse(fmt.Errorf("%w: %s, so it is not offered", ErrAuthFeatureUnsupported, feature))
	}
	// a Member's device names who can: an Owner's or Admin's standing, untagged device
	if err := configServiceSettingsSigner(self.state, self.sidecarId); err != nil {
		return refuse(err)
	}
	if err := checkAuthFeaturesFiling(feature, self.implemented, self.core); err != nil {
		return refuse(err)
	}
	return self.save(ctx, &ServiceSettingsChange{AuthFeatures: feature})
}

// Turns feature on for this network, the person's confirmed act on an Owner's or Admin's device, filed into the config
// head's ServiceSettings and on from the base that names the head: see the file header. Answers the feature's status at
// the newest verified state, on once the base lands; one already on files nothing. A refusal is an
// *AuthFeatureRequiredError naming who can, or the act's own refusal, with nothing signed.
func (self *Sidecar) TurnOnAuthFeature(ctx context.Context, args *AuthFeatureTurnOnArgs) (*AuthFeatureStatus, error) {
	turnOn := &authFeatureTurnOn{
		core:        self.authFeatureCore(),
		sidecarId:   self.authFeatureSidecarId(),
		implemented: AuthFeaturesImplemented(),
		save: func(ctx context.Context, change *ServiceSettingsChange) error {
			_, err := self.SaveServiceSettings(ctx, change, SidecarActConfirmed)
			return err
		},
	}
	if state, err := self.configState(); err == nil {
		turnOn.state = state
	}
	if err := turnOn.run(ctx, args); err != nil {
		return nil, err
	}
	state, err := self.configState()
	if err != nil {
		return nil, ErrSidecarActNoAuthority
	}
	return authFeatureStatusAt(state, self.authFeatureCore(), self.authFeatureSidecarId(), AuthFeaturesImplemented(), args.Feature), nil
}
