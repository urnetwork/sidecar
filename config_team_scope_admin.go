//go:build !ios_extension && !sidecar_http

// ur admin scopes' root half (QD-1163; §7.9's ServiceSettings, §8.8, §12.5, §13.8; owner decisions 40, 58, 126): a Team
// scope's first binding, filed into the config head's ServiceSettings.team_scopes by an Owner's or Admin's device, as the
// person confirmed it, through this network's config writer, the head's other settings kept:
//
//	origin   only a person's confirmation, a ur command on /dev/tty or an app's UI, files one: MCP, a hook and an
//	         unconfirmed control call are refused before anything is read or signed (D-CORE-13)
//	signer   this device is an untagged, standing sidecar of an Owner or Admin at the newest verified state, the rule
//	         every reader holds the head's record to (configServiceSettingsSigner)
//	label    one lowercase LDH label, as §12.5 holds a scope label: no -- at 3-4, not reserved, not a word-number label,
//	         none of §12.7's refused owners (b, mx, mail, mta-sts), no brand-confusable token, no client name the head's
//	         names file holds and no host the policy publishes; and bound to no owner yet. Each label's first binding is
//	         immutable, its retirement's included, so a label bound once is never bound again, the same owner's
//	         included, and reassignment waits for a consented-member transition rule (DESIGN-DEFER.md)
//	owner    a member the verified state holds, or a tag the head's tags table holds, by its name; one label an owner,
//	         since a device two scopes take is ambiguous to every reader of its scope (ConfigState.TeamScopeForDevice)
//	head     the head's ServiceSettings with the binding added in label order, signed as a new SIGNED_SERVICE_SETTINGS
//	         and saved through the writer, which re-reads the head on a race; each reader takes the binding only once a
//	         base's verified rows hold it, as compile writes them from the head (configCompileTeamScopes)
//
// Nothing here creates, derives or unwraps a key: the identity key signs through the writer's Sign.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// The label cannot be a Team scope's: §12.5's rules, a client name or a published host. Nothing was signed.
	ErrTeamScopeLabel = errors.New("team scope: the label cannot be a scope's")
	// The label is bound already, to this owner or another, or the owner holds a label already: a first binding never
	// changes and reassignment waits for its consent rule (QD-1163). Nothing was signed.
	ErrTeamScopeBound = errors.New("team scope: bound already")
	// The binding names no member the state holds or no tag the head's tags table holds. Nothing was signed.
	ErrTeamScopeOwner = errors.New("team scope: no such member or tag")
)

// One Team scope's first binding as ur admin scopes add asks it: its label and its owner, a member by id or a tag by
// the name tagOwners gives it, with or without its tag: prefix.
type TeamScopeBinding struct {
	Label    string
	MemberId Id
	Tag      string
}

// The label's own checks, which need no state: §12.5's rules for a scope label (configTeamScopeLabelValid's, which
// every reader holds a binding to), §12.7's refused owners and the brand rules a new name meets.
func teamScopeCheckLabel(label string) error {
	if !configTeamScopeLabelValid(label) || slices.Contains(mailZoneRefusedLabels, label) || IsBrandConfusableDnsName(label) {
		return ErrTeamScopeLabel
	}
	return nil
}

// Files binding into head's ServiceSettings through heads, signed by sign, judged against state, the newest verified
// one, and the head the writer edits, at now: see the file header. Answers the binding as filed.
func configSaveTeamScope(ctx context.Context, heads configServiceSettingsHeads, sign ConfigSignFunction, state *ConfigState, binding *TeamScopeBinding,
	now time.Time) (AclScope, error) {
	if binding == nil || (binding.MemberId == (Id{})) == (binding.Tag == "") {
		return AclScope{}, fmt.Errorf("%w: a binding names a member or a tag", ErrTeamScopeOwner)
	}
	label := binding.Label
	if err := teamScopeCheckLabel(label); err != nil {
		return AclScope{}, err
	}
	if _, bound := state.TeamScope(label); bound {
		return AclScope{}, fmt.Errorf("%w: the label's first binding stands, and reassignment waits for its consent rule", ErrTeamScopeBound)
	}
	if binding.MemberId != (Id{}) {
		if state.Member(binding.MemberId) == nil {
			return AclScope{}, fmt.Errorf("%w: the member", ErrTeamScopeOwner)
		}
	}
	// the hosts the policy publishes, which a label must not be: unknown hosts refuse every label
	acl, err := state.Acl()
	if err != nil {
		return AclScope{}, fmt.Errorf("%w: the policy's published hosts are not known: %w", ErrTeamScopeLabel, err)
	}
	for _, name := range acl.PublishedNames(now) {
		if name.Host == label {
			return AclScope{}, fmt.Errorf("%w: a host the policy publishes", ErrTeamScopeLabel)
		}
	}
	tagName := strings.TrimPrefix(binding.Tag, "tag:")
	var filed AclScope
	_, err = heads.SaveHead(ctx, func(head *ConfigHead) (*ConfigHead, error) {
		current, _, err := head.ServiceSettings()
		if err != nil {
			return nil, err
		}
		settings := &protocol.ServiceSettings{}
		if current != nil {
			settings = proto.Clone(current).(*protocol.ServiceSettings)
		}
		names, err := head.Names()
		if err != nil {
			return nil, err
		}
		for _, name := range names.GetNames() {
			if name.GetName() == label {
				return nil, fmt.Errorf("%w: a client's name (§7.7)", ErrTeamScopeLabel)
			}
		}
		row := &bridge.TeamScopeRow{Label: label}
		scope := AclScope{Label: label}
		if binding.MemberId != (Id{}) {
			row.MemberId, scope.MemberId = binding.MemberId.Bytes(), binding.MemberId
		} else {
			tags := &protocol.ConfigAtomTable{}
			if data := head.File(ConfigHeadTagsPath); data != nil {
				if err := proto.Unmarshal(data, tags); err != nil {
					return nil, fmt.Errorf("%w: the head's tags file", ErrConfigHeadMalformed)
				}
			}
			for _, atom := range tags.GetAtoms() {
				if atom.GetName() == tagName {
					tagId, err := IdFromBytes(atom.GetAtomId())
					if err != nil {
						return nil, fmt.Errorf("%w: the head's tags file", ErrConfigHeadMalformed)
					}
					row.TagAtom, scope.TagId = tagId.Bytes(), tagId
				}
			}
			if len(row.TagAtom) == 0 {
				return nil, fmt.Errorf("%w: a tag the policy declares no owners of", ErrTeamScopeOwner)
			}
		}
		// the head as it stands now, which another admin's binding may have reached first
		for _, held := range settings.GetTeamScopes() {
			if held.GetLabel() == label {
				return nil, fmt.Errorf("%w: the label's first binding stands, and reassignment waits for its consent rule", ErrTeamScopeBound)
			}
			if (len(row.MemberId) != 0 && string(held.GetMemberId()) == string(row.MemberId)) ||
				(len(row.TagAtom) != 0 && string(held.GetTagAtom()) == string(row.TagAtom)) {
				return nil, fmt.Errorf("%w: the owner holds a scope's label already", ErrTeamScopeBound)
			}
		}
		settings.TeamScopes = append(settings.TeamScopes, row)
		slices.SortFunc(settings.TeamScopes, func(a *bridge.TeamScopeRow, b *bridge.TeamScopeRow) int {
			return strings.Compare(a.GetLabel(), b.GetLabel())
		})
		if err := CheckServiceSettings(settings); err != nil {
			return nil, err
		}
		signed, err := configSignRecord(sign, bridge.SignedType_SIGNED_SERVICE_SETTINGS, settings)
		if err != nil {
			return nil, err
		}
		filed = scope
		return head.WithFile(ConfigHeadServiceSettingsPath, signed)
	})
	if err != nil {
		return AclScope{}, err
	}
	return filed, nil
}

// Files a Team scope's first binding into the config head, signed by this device: see the file header. Answers the
// binding as filed, which every reader of a scope takes once a base's verified rows hold it.
func (self *Sidecar) SaveTeamScope(ctx context.Context, binding *TeamScopeBinding, origin SidecarActOrigin) (AclScope, error) {
	if origin != SidecarActConfirmed {
		return AclScope{}, ErrSidecarActMode
	}
	authority, ok := self.authority().(*ConfigAuthority)
	if !ok {
		return AclScope{}, ErrSidecarActNoAuthority
	}
	state := authority.client.State()
	if state == nil {
		return AclScope{}, ErrSidecarActNoAuthority
	}
	identity := self.Identity()
	if identity == nil {
		return AclScope{}, ErrSidecarNoIdentity
	}
	if err := configServiceSettingsSigner(state, identity.SidecarId); err != nil {
		return AclScope{}, err
	}
	writer := authority.client.Writer()
	if writer == nil {
		return AclScope{}, errors.New("no config writer runs for this network on this device")
	}
	return configSaveTeamScope(ctx, writer, writer.args.Sign, state, binding, self.clock.Now())
}

// The Team scopes the newest verified base holds, in label order: what every reader of a scope takes, and nothing a
// head declared that no base holds yet. ErrSidecarActNoAuthority before a verified state.
func (self *Sidecar) TeamScopes() ([]AclScope, error) {
	state, err := self.configState()
	if err != nil {
		return nil, ErrSidecarActNoAuthority
	}
	scopes := []AclScope{}
	for _, label := range state.TeamScopeLabels() {
		if scope, found := state.TeamScope(label); found {
			scopes = append(scopes, scope)
		}
	}
	return scopes, nil
}
