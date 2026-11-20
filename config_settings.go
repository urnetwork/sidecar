// §7.9's ServiceSettings: a record that rides config heads alone, signed by an Owner's or Admin's device, taking effect
// at the base that names its head. DESIGN-DETAILS 5.2.3 splits it by who judges by it:
//
//	rows       self_admit and scim_signer compile into ProjectionRows.settings, which every verifier, api and the
//	             gates included, judges by, so a rows-only reader reaches a full reader's verdict on a member's own
//	             admission (owner decision 112; question details-5-settings-in-rows, built on its recommendation)
//	head only  team_mail, stale_leaf_days (90), witness_bound_hours (72, refused outside 24-168), directory, and the
//	             Settings fields mail_strict (off), record_cost (on) and record_required (off), which only devices
//	             read: a rows-only reader reports them unknown
//
// directory is reserved at M2 and ignored (D-PHASE-9), and a head holding VersioningRules applies nothing from it at
// format 1 and still applies (owner decision 164): nothing here reads either. A full reader holds a base's rows to its
// head's settings: rows whose settings are not the head's are a fork.
//
// The Settings fields (owner decisions 302, 304, 305; QD-204) are 7 to 9, reserved before M2's freeze as directory was,
// so a reader whose config.proto lacks them skips them as unknown fields and reads every other field as before.
// record_cost is RecordCostMode, whose zero reads as on, since a bool's zero cannot say on (SelfAdmitMode's pattern).
// Where the head cannot be opened, each reads its closed value through ConfigTeamSettings: mail_strict off, so no mail
// claims strict_custom_mx; record_cost off, so cost stays in the vault; record_required off, so nothing requires
// fail-closed hooks on a head this device cannot read, and ur install-harness and ur status say it is not known.
//
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret. On every leg.

package sidecar

import (
	"bytes"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §7.9's ServiceSettings defaults and bounds (QD-702): the format's values, which every reader holds alike, so changing
// one is a format change no deployment makes on one side alone.
type ConfigServiceFormatSettings struct {
	// stale_leaf_days where a head leaves it 0, in days: 90 (§10.9's stale Removes).
	StaleLeafDays uint32
	// witness_bound_hours where a head leaves it 0, in hours: 72 (D-TRUST-10, owner decision 129).
	WitnessBoundHours uint32
	// The hours a head's witness_bound_hours other than 0 lies within, inclusive: 24 to 168. A head outside them forks
	// its base.
	WitnessBoundMinHours uint32
	WitnessBoundMaxHours uint32
}

// The format's values, the only source of their defaults. A fresh value each call, sharing nothing mutable.
func DefaultConfigServiceFormatSettings() *ConfigServiceFormatSettings {
	return &ConfigServiceFormatSettings{
		StaleLeafDays:        90,
		WitnessBoundHours:    72,
		WitnessBoundMinHours: 24,
		WitnessBoundMaxHours: 168,
	}
}

// Checks a ServiceSettings a head holds: known enum values, record_cost's among them, a witness_bound_hours of 0 (the
// default) or within the format's bounds, and a scim_signer of none or a sidecar_id. directory is ignored at M2, so its
// values are not judged, and mail_strict and record_required are bools, either value good.
func CheckServiceSettings(settings *protocol.ServiceSettings) error {
	if settings == nil {
		return nil
	}
	format := DefaultConfigServiceFormatSettings()
	if _, known := protocol.TeamMailMode_name[int32(settings.GetTeamMail())]; !known {
		return fmt.Errorf("%w: team_mail %d", ErrConfigRule, settings.GetTeamMail())
	}
	if _, known := protocol.SelfAdmitMode_name[int32(settings.GetSelfAdmit())]; !known {
		return fmt.Errorf("%w: self_admit %d", ErrConfigRule, settings.GetSelfAdmit())
	}
	if hours := settings.GetWitnessBoundHours(); hours != 0 && (hours < format.WitnessBoundMinHours || format.WitnessBoundMaxHours < hours) {
		return fmt.Errorf("%w: witness_bound_hours %d outside %d-%d", ErrConfigRule, hours, format.WitnessBoundMinHours, format.WitnessBoundMaxHours)
	}
	if scimSigner := settings.GetScimSigner(); len(scimSigner) != 0 && len(scimSigner) != len(Id{}) {
		return fmt.Errorf("%w: a scim_signer of %d bytes", ErrConfigRule, len(scimSigner))
	}
	if _, known := protocol.RecordCostMode_name[int32(settings.GetRecordCost())]; !known {
		return fmt.Errorf("%w: record_cost %d", ErrConfigRule, settings.GetRecordCost())
	}
	return nil
}

// The settings a head's ServiceSettings compiles to in rows: self_admit and scim_signer, the zero value for none.
func ConfigProjectionSettings(settings *protocol.ServiceSettings) *bridge.ProjectionSettings {
	return &bridge.ProjectionSettings{
		SelfAdmit:  uint32(settings.GetSelfAdmit()),
		ScimSigner: bytes.Clone(settings.GetScimSigner()),
	}
}

// Checks the settings rows carry, as every reader takes them: a self_admit value SelfAdmitMode names and a scim_signer
// of none or a sidecar_id.
func configCheckRowsSettings(settings *bridge.ProjectionSettings) error {
	if _, known := protocol.SelfAdmitMode_name[int32(settings.GetSelfAdmit())]; !known {
		return fmt.Errorf("rows: settings.self_admit %d", settings.GetSelfAdmit())
	}
	if scimSigner := settings.GetScimSigner(); len(scimSigner) != 0 && len(scimSigner) != len(Id{}) {
		return fmt.Errorf("rows: settings.scim_signer of %d bytes", len(scimSigner))
	}
	return nil
}

// Whether a full reader's rows carry its head's settings: what compile writes from the head (DESIGN-DETAILS 5.2.3).
func configRowsSettingsMatch(rows *bridge.ProjectionSettings, head *protocol.ServiceSettings) bool {
	return proto.Equal(configRowsSettingsOrDefault(rows), ConfigProjectionSettings(head))
}

// The settings rows carry, the zero value for none.
func configRowsSettingsOrDefault(settings *bridge.ProjectionSettings) *bridge.ProjectionSettings {
	if settings == nil {
		return &bridge.ProjectionSettings{}
	}
	return settings
}

// The ServiceSettings values every verifier judges by, from the newest base's rows; the zero value before base 1 and
// for a head that holds none, so the defaults hold. The caller must not change it.
func (self *ConfigState) Settings() *bridge.ProjectionSettings {
	return configRowsSettingsOrDefault(self.settings)
}

// The newest base's config head's ServiceSettings, nil when it holds none, so the defaults hold; known is false at a
// reader that could not open the head (a rows-only one), which only devices' head-only values need. The caller must
// not change it.
func (self *ConfigState) HeadSettings() (settings *protocol.ServiceSettings, known bool) {
	return self.headSettings, self.headSettingsKnown
}

// Whether the network's self_admit is on (owner decision 112): unset or on. Every verifier knows it from rows.
func (self *ConfigState) SelfAdmit() bool {
	return self.Settings().GetSelfAdmit() != uint32(protocol.SelfAdmitMode_SELF_ADMIT_MODE_OFF)
}

// ServiceSettings.scim_signer: the sidecar_id of the admin's indexer that signs SCIM's MemberRevokes (7.6), false for
// none.
func (self *ConfigState) ScimSigner() (Id, bool) {
	scimSigner, err := IdFromBytes(self.Settings().GetScimSigner())
	return scimSigner, err == nil
}

// stale_leaf_days (§10.9's stale Removes), the format's default unless the head sets it; false at a reader that could
// not open the head.
func (self *ConfigState) StaleLeafDays() (uint32, bool) {
	if !self.headSettingsKnown {
		return 0, false
	}
	if days := self.headSettings.GetStaleLeafDays(); days != 0 {
		return days, true
	}
	return DefaultConfigServiceFormatSettings().StaleLeafDays, true
}

// witness_bound_hours (D-TRUST-10, owner decision 129), the format's default unless the head sets it within the
// format's bounds, which a head outside them cannot, since its base forks; false at a reader that could not open the
// head.
func (self *ConfigState) WitnessBoundHours() (uint32, bool) {
	if !self.headSettingsKnown {
		return 0, false
	}
	if hours := self.headSettings.GetWitnessBoundHours(); hours != 0 {
		return hours, true
	}
	return DefaultConfigServiceFormatSettings().WitnessBoundHours, true
}

// A network's Settings fields as a device honors them (§7.9; owner decisions 302, 305; QD-204), each a closed value
// where the head cannot be opened: see the file header.
type ConfigTeamSettings struct {
	// The config names a team record or a team directory, live or not: a Team's network, in which team-create's first
	// Owner device files both (owner decision 303; D-TEAM-28). A personal network names neither.
	Team bool
	// This device opened the newest base's config head, so the fields below are the head's.
	Known bool
	// §15.4's mail.strict: off unless the head sets it.
	MailStrict bool
	// Per-run cost totals go to the team record as well as the vault (RECORD.md section 6.3's row 28): on unless the
	// head turns it off (owner decision 302).
	RecordCost bool
	// Each member's ur install-harness writes fail-closed hooks, and the daemon's config check reads a fail-open install
	// as changed (§16.7; owner decision 305): off unless the head sets it.
	RecordRequired bool
}

// The newest base's Settings fields as this state holds them, with their defaults where the head leaves them unset and
// their closed values where it could not be opened.
func (self *ConfigState) TeamSettings() *ConfigTeamSettings {
	honored := &ConfigTeamSettings{Team: self.teamNetwork(), Known: self.headSettingsKnown}
	if !self.headSettingsKnown {
		return honored
	}
	honored.MailStrict = self.headSettings.GetMailStrict()
	honored.RecordCost = self.headSettings.GetRecordCost() != protocol.RecordCostMode_RECORD_COST_MODE_OFF
	honored.RecordRequired = self.headSettings.GetRecordRequired()
	return honored
}

// Whether the state names a team record or a team directory, live, deleted or shredded (ConfigTeamSettings.Team).
func (self *ConfigState) teamNetwork() bool {
	acl, err := self.Acl()
	if err != nil {
		return false
	}
	for _, repo := range acl.Rows().GetRepos() {
		switch repo.GetKind() {
		case protocol.RepoKind_REPO_KIND_DIRECTORY, protocol.RepoKind_REPO_KIND_TEAM_RECORD:
			return true
		}
	}
	return false
}
