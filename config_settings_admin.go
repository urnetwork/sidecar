//go:build !ios_extension && !sidecar_http

// ur admin settings' root half (§7.9's Settings fields; owner decisions 302, 305; QD-204; question
// service-settings-7-9-admin-settings-command): ServiceSettings' mail_strict, record_cost and record_required filed into
// the config head by an Owner's or Admin's device, as the person confirmed it, through this network's config writer, as
// SaveDirectoryServiceSettings files ServiceSettings.directory (directory_admin.go):
//
//	origin   only a person's confirmation, a ur command on /dev/tty or an app's UI, ever files them: MCP, a hook and an
//	         unconfirmed control call are refused before anything is read or signed (D-CORE-13), so record_required in
//	         particular is never set through MCP (owner decision 305)
//	signer   this device is an untagged, standing sidecar of an Owner or Admin at the newest verified state, the rule
//	         every reader holds the head's record to (configHeadRecordSignedByAdmin), checked before signing so a
//	         non-admin's device signs nothing rather than a head that would fork its base
//	head     the head's ServiceSettings as it stands, every other field kept, the asked fields set, signed as a new
//	         SIGNED_SERVICE_SETTINGS and saved through the writer, which re-reads the head on a race; a device that runs
//	         no config writer refuses
//
// Nothing here creates, derives or unwraps a key: the identity key signs through the writer's Sign.

package sidecar

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// This device may not sign a ServiceSettings: it is no Owner's or Admin's standing, untagged sidecar. Nothing was signed.
var ErrServiceSettingsSigner = errors.New("only an Owner's or Admin's standing device signs ServiceSettings")

// What ur admin settings changes among the Settings fields: a nil field keeps the head's value.
type ServiceSettingsChange struct {
	MailStrict     *bool
	RecordCost     *bool
	RecordRequired *bool
}

// Whether the change sets anything.
func (self *ServiceSettingsChange) empty() bool {
	return self == nil || (self.MailStrict == nil && self.RecordCost == nil && self.RecordRequired == nil)
}

// settings with the change's fields set: record_cost as its explicit value, on or off.
func (self *ServiceSettingsChange) apply(settings *protocol.ServiceSettings) {
	if self.MailStrict != nil {
		settings.MailStrict = *self.MailStrict
	}
	if self.RecordCost != nil {
		settings.RecordCost = protocol.RecordCostMode_RECORD_COST_MODE_OFF
		if *self.RecordCost {
			settings.RecordCost = protocol.RecordCostMode_RECORD_COST_MODE_ON
		}
	}
	if self.RecordRequired != nil {
		settings.RecordRequired = *self.RecordRequired
	}
}

// Whether sidecarId may sign a ServiceSettings at state, as every reader judges the head's record: an untagged
// sidecar standing at the state's time whose member is an Owner or Admin. ErrServiceSettingsSigner, wrapped, otherwise.
func configServiceSettingsSigner(state *ConfigState, sidecarId Id) error {
	if state == nil {
		return ErrSidecarActNoAuthority
	}
	row, standing := state.standingSidecar(sidecarId, state.TimeMs())
	if !standing {
		return fmt.Errorf("%w: this device is not standing at position %d", ErrServiceSettingsSigner, state.Pin().GetVersion())
	}
	memberId, untagged := configRowMember(row)
	if !untagged {
		return fmt.Errorf("%w: this device is a tagged sidecar", ErrServiceSettingsSigner)
	}
	switch state.Member(memberId).GetRole() {
	case bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_ADMIN:
		return nil
	}
	return fmt.Errorf("%w: this device's member is no Owner or Admin", ErrServiceSettingsSigner)
}

// The writer the change saves through: ConfigWriter is one.
type configServiceSettingsHeads interface {
	SaveHead(ctx context.Context, edit func(head *ConfigHead) (*ConfigHead, error)) (*bridge.AuthPin, error)
}

var _ configServiceSettingsHeads = (*ConfigWriter)(nil)

// Saves change into the head's ServiceSettings through heads, every other field kept, signed by sign. Answers the
// ServiceSettings as filed.
func configSaveServiceSettings(ctx context.Context, heads configServiceSettingsHeads, sign ConfigSignFunction, change *ServiceSettingsChange) (*protocol.ServiceSettings, error) {
	var filed *protocol.ServiceSettings
	_, err := heads.SaveHead(ctx, func(head *ConfigHead) (*ConfigHead, error) {
		current, _, err := head.ServiceSettings()
		if err != nil {
			return nil, err
		}
		settings := &protocol.ServiceSettings{}
		if current != nil {
			settings = proto.Clone(current).(*protocol.ServiceSettings)
		}
		change.apply(settings)
		if err := CheckServiceSettings(settings); err != nil {
			return nil, err
		}
		signed, err := configSignRecord(sign, bridge.SignedType_SIGNED_SERVICE_SETTINGS, settings)
		if err != nil {
			return nil, err
		}
		filed = settings
		return head.WithFile(ConfigHeadServiceSettingsPath, signed)
	})
	if err != nil {
		return nil, err
	}
	return filed, nil
}

// Files the change into the config head, signed by this device: see the file header. Answers the Settings fields as
// filed, which every device honors from the base that names the head.
func (self *Sidecar) SaveServiceSettings(ctx context.Context, change *ServiceSettingsChange, origin SidecarActOrigin) (*ConfigTeamSettings, error) {
	if origin != SidecarActConfirmed {
		return nil, ErrSidecarActMode
	}
	if change.empty() {
		return nil, errors.New("a settings change sets mail_strict, record_cost or record_required")
	}
	authority, ok := self.authority().(*ConfigAuthority)
	if !ok {
		return nil, ErrSidecarActNoAuthority
	}
	state := authority.client.State()
	if state == nil {
		return nil, ErrSidecarActNoAuthority
	}
	identity := self.Identity()
	if identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	if err := configServiceSettingsSigner(state, identity.SidecarId); err != nil {
		return nil, err
	}
	writer := authority.client.Writer()
	if writer == nil {
		return nil, errors.New("no config writer runs for this network on this device")
	}
	filed, err := configSaveServiceSettings(ctx, writer, writer.args.Sign, change)
	if err != nil {
		return nil, err
	}
	return &ConfigTeamSettings{
		Team:           state.teamNetwork(),
		Known:          true,
		MailStrict:     filed.GetMailStrict(),
		RecordCost:     filed.GetRecordCost() != protocol.RecordCostMode_RECORD_COST_MODE_OFF,
		RecordRequired: filed.GetRecordRequired(),
	}, nil
}

// The Settings fields as this device honors them now (ConfigState.TeamSettings), for ur admin settings and ur status to
// show and ur install-harness to read: ErrSidecarActNoAuthority before a verified state.
func (self *Sidecar) TeamSettings() (*ConfigTeamSettings, error) {
	state, err := self.configState()
	if err != nil {
		return nil, ErrSidecarActNoAuthority
	}
	return state.TeamSettings(), nil
}
