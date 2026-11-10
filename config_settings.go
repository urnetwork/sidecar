// §7.9's ServiceSettings: a record that rides config heads alone, signed by an Owner's or Admin's device, taking effect
// at the base that names its head. DESIGN-DETAILS 5.2.3 splits it by who judges by it:
//
//	rows       self_admit and scim_signer compile into ProjectionRows.settings, which every verifier, api and the
//	             gates included, judges by, so a rows-only reader reaches a full reader's verdict on a member's own
//	             admission (owner decision 112; question details-5-settings-in-rows, built on its recommendation)
//	head only  team_mail, stale_leaf_days (90), witness_bound_hours (72, refused outside 24-168) and directory,
//	             which only devices read: a rows-only reader reports them unknown
//
// directory is reserved at M2 and ignored (D-PHASE-9), and a head holding VersioningRules applies nothing from it at
// format 1 and still applies (owner decision 164): nothing here reads either. A full reader holds a base's rows to its
// head's settings: rows whose settings are not the head's are a fork.
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

// §7.9's defaults and bounds, which every reader holds alike.
const (
	// stale_leaf_days' default (§10.9's stale Removes).
	configStaleLeafDaysDefault = uint32(90)
	// witness_bound_hours' default and bounds (D-TRUST-10, owner decision 129).
	configWitnessBoundHoursDefault = uint32(72)
	configWitnessBoundHoursMin     = uint32(24)
	configWitnessBoundHoursMax     = uint32(168)
)

// Checks a ServiceSettings a head holds: known enum values, a witness_bound_hours of 0 (the default) or 24 to 168, and a
// scim_signer of none or a sidecar_id. directory is ignored at M2, so its values are not judged.
func CheckServiceSettings(settings *protocol.ServiceSettings) error {
	if settings == nil {
		return nil
	}
	if _, known := protocol.TeamMailMode_name[int32(settings.GetTeamMail())]; !known {
		return fmt.Errorf("%w: team_mail %d", ErrConfigRule, settings.GetTeamMail())
	}
	if _, known := protocol.SelfAdmitMode_name[int32(settings.GetSelfAdmit())]; !known {
		return fmt.Errorf("%w: self_admit %d", ErrConfigRule, settings.GetSelfAdmit())
	}
	if hours := settings.GetWitnessBoundHours(); hours != 0 && (hours < configWitnessBoundHoursMin || configWitnessBoundHoursMax < hours) {
		return fmt.Errorf("%w: witness_bound_hours %d outside %d-%d", ErrConfigRule, hours, configWitnessBoundHoursMin, configWitnessBoundHoursMax)
	}
	if scimSigner := settings.GetScimSigner(); len(scimSigner) != 0 && len(scimSigner) != len(Id{}) {
		return fmt.Errorf("%w: a scim_signer of %d bytes", ErrConfigRule, len(scimSigner))
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

// stale_leaf_days (§10.9's stale Removes), 90 unless the head sets it; false at a reader that could not open the head.
func (self *ConfigState) StaleLeafDays() (uint32, bool) {
	if !self.headSettingsKnown {
		return 0, false
	}
	if days := self.headSettings.GetStaleLeafDays(); days != 0 {
		return days, true
	}
	return configStaleLeafDaysDefault, true
}

// witness_bound_hours (D-TRUST-10, owner decision 129), 72 unless the head sets it within 24-168, which a head outside
// that range cannot, since its base forks; false at a reader that could not open the head.
func (self *ConfigState) WitnessBoundHours() (uint32, bool) {
	if !self.headSettingsKnown {
		return 0, false
	}
	if hours := self.headSettings.GetWitnessBoundHours(); hours != 0 {
		return hours, true
	}
	return configWitnessBoundHoursDefault, true
}
