//go:build !ios_extension

// The config head's records that stand under a signer who no longer stands, listed for admins (§7.9's Writes and
// records rows; D-TEAM-26; owner decision 699; QD-1207). A ServiceSettings or VersioningRules record rides a config head
// alone, and every head carries it forward byte for byte. Readers judge it once, at the base whose head first holds it,
// and keep it unjudged after, so it stands under its first signer whatever befalls that signer, until an Owner or Admin,
// or for VersioningRules a Network admin, files another. No writer signs it again, which would put an admin's signature
// on choices a revoked device made. Instead every admin surface lists each such record whose signer no longer stands,
// naming the signer and why, so an admin can file a fresh one (ConfigCarriedRecordFilers names who may):
//
//	stands    the signer is judged by the rule a new record of its kind meets at the newest verified state
//	          (configHeadRecordSignedByRole): standing, untagged, of a member whose role signs it, its signature
//	          verifying under its identity key. A record that passes is not listed
//	why       revoked or parked at a position, expired, removed (its member no longer the network's), tagged, role (its
//	          member's role no longer signs it), unlisted (no row holds it), or signature: none of these, its signature
//	          failing under the key its row admits. Tagged, unlisted and signature only a record a reader took
//	          unjudged, at its anchor, can meet; expired also a record an ephemeral device of an Owner or Admin signed
//	head      the records are read from the config head the newest base names, each the record the state holds, byte
//	          for byte, by its Signed bytes' SHA-256 (ConfigState); a reader that opens no config head knows none
//	surfaces  ur admin settings and ur admin versioning, with their control methods; ur admin directory and ur admin
//	          scopes, whose settings the ServiceSettings record holds; the apps, through the sdk's
//	          GetCarriedConfigRecords (Sidecar.CarriedConfigRecords, or ur daemon's admin.settings.show in remote
//	          mode); and the team console's config view, which lists a page Worker's own state's records
//
// The listing judges a record's signer and changes nothing: no verdict, no state, no head. Nothing here creates,
// derives or unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// ConfigCarriedRecord.Why's values: why the record's signer no longer stands as one who may sign it.
const (
	// Its row is revoked, at ConfigCarriedRecord.At.
	ConfigCarriedRevoked = "revoked"
	// §7.9's compromise cascade, or a leaked bundle's DelegationRevoke, parked it at At.
	ConfigCarriedParked = "parked"
	// Its admission's not_after passed, at NotAfterMs.
	ConfigCarriedExpired = "expired"
	// Its member is no longer the network's.
	ConfigCarriedRemoved = "removed"
	// It is a tagged sidecar, which signs no such record.
	ConfigCarriedTagged = "tagged"
	// Its member's role, Role, no longer signs the record.
	ConfigCarriedRole = "role"
	// The network's rows no longer hold it.
	ConfigCarriedUnlisted = "unlisted"
	// None of the above: its signature does not verify under the identity key its row admits, or names no identity key.
	ConfigCarriedSignature = "signature"
)

var (
	// The reader opens no config head, so it holds no record whose signer it could name: a rows-only reader's state.
	ErrConfigCarriedUnknown = errors.New("this reader opens no config head, so the records' signers are not known here")
	// The config head given holds another record than the state does, so it is not the head the state's newest base
	// names.
	ErrConfigCarriedHead = errors.New("the config head is not the one the verified state stands on")
)

// A record the config head of the newest verified base holds whose signer no longer stands as one who may sign it (see
// the file header). Its JSON is what ur's admin settings and admin versioning control methods answer.
type ConfigCarriedRecord struct {
	// The record's head path: ConfigHeadServiceSettingsPath or ConfigHeadVersioningRulesPath.
	Record string `json:"record"`
	// The sidecar whose identity key signed it, as its Signed names it; the zero id where it names none.
	SignerId Id `json:"signer_id"`
	// The signer's member, as its row names it; nil for a tagged signer and one no row holds.
	MemberId *Id `json:"member_id,omitempty"`
	// One of the ConfigCarried values.
	Why string `json:"why"`
	// The position the signer was revoked or parked at, for revoked and parked.
	At uint64 `json:"at,omitempty"`
	// When the signer's admission ended, ms since the epoch, for expired.
	NotAfterMs int64 `json:"not_after_ms,omitempty"`
	// The role the signer's member holds now (owner, admin, network_admin, it_admin, billing_admin, auditor or member),
	// while it is a member.
	Role string `json:"role,omitempty"`
	// The signer's member is no longer the network's: a removal revokes each of its devices, so a revoked signer's
	// member may be gone as well.
	MemberRemoved bool `json:"member_removed,omitempty"`
}

// A member role as ConfigCarriedRecord.Role names it: owner, admin, network_admin, it_admin, billing_admin, auditor or
// member.
func configCarriedRoleName(role bridge.MemberRole) string {
	return strings.TrimPrefix(strings.ToLower(role.String()), "member_role_")
}

// The roles whose standing, untagged devices may file another record at path, the head path a ConfigCarriedRecord
// names, in role order and as ConfigCarriedRecord.Role names a role: the roles §7.9's records table has sign it, read
// from the rule a new record meets (configHeadRecordSignedByRole), so owner and admin for ServiceSettings and
// network_admin as well for VersioningRules. Nil for any other path.
func ConfigCarriedRecordFilers(path string) []string {
	var allow func(role bridge.MemberRole) bool
	switch path {
	case ConfigHeadServiceSettingsPath:
		allow = configAdminSignerRole
	case ConfigHeadVersioningRulesPath:
		allow = configVersioningRulesSignerRole
	default:
		return nil
	}
	roles := []string{}
	for _, value := range slices.Sorted(maps.Keys(bridge.MemberRole_name)) {
		if role := bridge.MemberRole(value); role != bridge.MemberRole_MEMBER_ROLE_UNSPECIFIED && allow(role) {
			roles = append(roles, configCarriedRoleName(role))
		}
	}
	return roles
}

// The records the config head of this state's newest base holds whose signer no longer stands at this state as one
// who may sign it, ServiceSettings' before VersioningRules', each with why (see the file header). head is the head that
// base names, which may be nil where the state holds neither record. None before base 1, whose state no head stands
// under. ErrConfigCarriedUnknown at a reader that opens no config head, and ErrConfigCarriedHead where head holds
// another record than this state does, or one it does not hold.
func (self *ConfigState) CarriedRecords(head *ConfigHead) ([]*ConfigCarriedRecord, error) {
	records := []*ConfigCarriedRecord{}
	if self.base == nil {
		return records, nil
	}
	if !self.headSettingsKnown {
		return nil, ErrConfigCarriedUnknown
	}
	// what the listing says of the record at path, signed, whose signer configHeadRecordSignedByRole refuses here for
	// allow's roles: the signer, its member, and the first reason its row gives, in the order the rule meets them
	carriedRecord := func(path string, signed *bridge.Signed, allow func(role bridge.MemberRole) bool) *ConfigCarriedRecord {
		carried := &ConfigCarriedRecord{Record: path, Why: ConfigCarriedSignature}
		signerId, err := configBaseSigner(signed)
		if err != nil {
			return carried
		}
		carried.SignerId = signerId
		row := self.sidecars[signerId]
		if row == nil {
			carried.Why = ConfigCarriedUnlisted
			return carried
		}
		memberId, untagged := configRowMember(row)
		var member *bridge.MemberRow
		if untagged {
			carried.MemberId = &memberId
			member = self.members[memberId]
			carried.MemberRemoved = member == nil
			if member != nil {
				carried.Role = configCarriedRoleName(member.GetRole())
			}
		}
		switch {
		case row.GetRevokedAt() != 0:
			carried.Why, carried.At = ConfigCarriedRevoked, row.GetRevokedAt()
		case row.GetParkedAt() != 0:
			carried.Why, carried.At = ConfigCarriedParked, row.GetParkedAt()
		case row.GetNotAfter() != 0 && row.GetNotAfter() <= self.timeMs:
			carried.Why, carried.NotAfterMs = ConfigCarriedExpired, row.GetNotAfter()
		case !untagged:
			carried.Why = ConfigCarriedTagged
		case member == nil:
			carried.Why = ConfigCarriedRemoved
		case !allow(member.GetRole()):
			carried.Why = ConfigCarriedRole
		}
		return carried
	}
	for _, c := range []struct {
		path       string
		signedType bridge.SignedType
		holds      bool
		held       []byte
		allow      func(role bridge.MemberRole) bool
	}{
		{
			path:       ConfigHeadServiceSettingsPath,
			signedType: bridge.SignedType_SIGNED_SERVICE_SETTINGS,
			holds:      self.headSettings != nil || len(self.headSettingsRecordSha256) != 0,
			held:       self.headSettingsRecordSha256,
			allow:      configAdminSignerRole,
		},
		{
			path:       ConfigHeadVersioningRulesPath,
			signedType: bridge.SignedType_SIGNED_VERSIONING_RULES,
			holds:      self.headVersioningRules != nil || len(self.headVersioningRulesRecordSha256) != 0,
			held:       self.headVersioningRulesRecordSha256,
			allow:      configVersioningRulesSignerRole,
		},
	} {
		var headSha256 []byte
		if head != nil {
			headSha256 = head.recordSha256(c.path)
		}
		if !c.holds {
			if headSha256 != nil {
				return nil, fmt.Errorf("%w: it holds a %s the state does not", ErrConfigCarriedHead, c.path)
			}
			continue
		}
		if len(c.held) != sha256.Size {
			// a record held without the hash of its bytes, which no full reader's state lacks since QD-1207
			return nil, fmt.Errorf("%w: the state keeps no hash of its %s", ErrConfigCarriedUnknown, c.path)
		}
		if !configHeadRecordCarried(c.held, headSha256) {
			return nil, fmt.Errorf("%w: its %s is not the one the state holds", ErrConfigCarriedHead, c.path)
		}
		signed, _, err := head.signedRecord(c.path, c.signedType)
		if err != nil {
			return nil, err
		}
		if configHeadRecordSignedByRole(self, signed, c.signedType, c.allow) == nil {
			continue
		}
		records = append(records, carriedRecord(c.path, signed, c.allow))
	}
	return records, nil
}

// The records of the newest verified state's config head whose signer no longer stands at that state
// (ConfigState.CarriedRecords), the head read through the client's head reader, and only where the state holds a
// record. ErrSidecarActNoAuthority before the first verified state, CarriedRecords' errors, and the reader's own where
// the head cannot be read now.
func (self *ConfigClient) CarriedRecords(ctx context.Context) ([]*ConfigCarriedRecord, error) {
	state := self.State()
	if state == nil {
		return nil, ErrSidecarActNoAuthority
	}
	header := state.Base()
	holds := state.headSettings != nil || state.headVersioningRules != nil ||
		len(state.headSettingsRecordSha256) != 0 || len(state.headVersioningRulesRecordSha256) != 0
	if header == nil || !state.headSettingsKnown || !holds {
		// no head to read: before base 1, at a reader that opens none, or under a head holding neither record
		return state.CarriedRecords(nil)
	}
	if self.args.Heads == nil {
		return nil, fmt.Errorf("%w: no head reader", ErrConfigHeadUnavailable)
	}
	head, err := self.args.Heads.ReadConfigHead(ctx, header.GetConfigVersion(), header.GetConfigHeadSha256())
	if err != nil {
		return nil, err
	}
	return state.CarriedRecords(head)
}

// The records of this network's newest verified config head whose signer no longer stands (ConfigClient.CarriedRecords),
// for ur admin settings, ur admin versioning, ur admin directory, ur admin scopes and the apps (the sdk's
// GetCarriedConfigRecords) to list: ErrSidecarActNoAuthority before a verified state.
func (self *Sidecar) CarriedConfigRecords(ctx context.Context) ([]*ConfigCarriedRecord, error) {
	authority, ok := self.authority().(*ConfigAuthority)
	if !ok {
		return nil, ErrSidecarActNoAuthority
	}
	return authority.client.CarriedRecords(ctx)
}
