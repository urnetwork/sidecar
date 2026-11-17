// DESIGN-DETAILS 4.4's rows fixture (4.2.4's table; BRIDGE-M8-03; QD-620): the rows a base of a team of n devices
// carries, in 4.2.4's mix. n devices in n/3 members, the first member the owner; every device admitted by the owner's
// first device under its member, with an identity key, an admission confirmed and its live_since; two devices in three
// with a forwarding Delegation's row in 4.2.2's form (its key, its host client and its reader key's digest); three repos
// a member, each consented by the member's devices; and a ring of 1,024 statements. Every id and key is derived from a
// label and a number, the same on every run, so a fixture can sign as any of its devices.
//
// The root's TestTheCompileEstimateCoversTheLoadedRows builds the same rows with a copy of this generator, since the
// root's tests import no sidecartest package (§4.4's layering rule binds them), and loads them as a compile's judge
// loads a base's rows, so the 5x factor of the Forwarder's admission rule is re-measured whenever SidecarRow or AclRows
// change. Both tests hold the six-device rows to one digest, so the copies cannot drift apart.

package forwardcell

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The byte length of a sidecar, member, repo or client id.
const idByteCount = 16

// The mix of a fixture's rows: 4.2.4's from DefaultRowsSettings.
type RowsSettings struct {
	// A member to each DevicesPerMember devices, and at least one.
	DevicesPerMember int
	// Of each ForwardingCycle devices in order, every one but the last holds a forwarding Delegation's row.
	ForwardingCycle int
	// The repos each member owns, each consented by the member's devices.
	ReposPerMember int
	// The statements in the ring.
	RingCount int
	// Device 0's admission time; device i's is i ms later.
	AdmittedTimeMs int64
}

// 4.2.4's mix: n/3 members, two devices in three forwarding, three repos a member and a 1,024-entry ring.
func DefaultRowsSettings() *RowsSettings {
	return &RowsSettings{
		DevicesPerMember: 3,
		ForwardingCycle:  3,
		ReposPerMember:   3,
		RingCount:        1024,
		AdmittedTimeMs:   1_800_000_000_000,
	}
}

// A fixture id from a label and a number, the same on every run.
func Id(label string, i int) []byte {
	seed := sha256.Sum256(binary.BigEndian.AppendUint64([]byte("rows fixture "+label), uint64(i)))
	return seed[:idByteCount]
}

// A fixture digest, 32 bytes, from a label and a number.
func Digest(label string, i int) []byte {
	seed := sha256.Sum256(binary.BigEndian.AppendUint64([]byte("rows fixture digest "+label), uint64(i)))
	return seed[:]
}

// Device i's sidecar id.
func SidecarId(i int) []byte {
	return Id("device", i)
}

// Member i's id.
func MemberId(i int) []byte {
	return Id("member", i)
}

// Device i's identity key; device 0's signs the Genesis and the fixture's bases.
func IdentityKey(i int) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(Digest("identity", i))
}

// Device i's forwarding key, which its forwarding Delegation names.
func ForwardKey(i int) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(Digest("forward", i))
}

// Device i's forwarding Delegation's id.
func DelegationId(i int) []byte {
	return Digest("delegation", i)
}

// The client device i's forwarding Delegation names as its host's, and that client's key.
func HostClientId(i int) []byte {
	return Id("host client", i)
}

// The host client's key of device i's forwarding Delegation.
func HostClientKey(i int) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(Digest("host client", i))
}

// Whether device i holds a forwarding Delegation's row.
func (self *RowsSettings) HasForwarding(i int) bool {
	return i%self.ForwardingCycle != self.ForwardingCycle-1
}

// How many members a fixture of deviceCount devices has.
func (self *RowsSettings) MemberCount(deviceCount int) int {
	return max(1, deviceCount/self.DevicesPerMember)
}

// The position of the ring's first statement: after the admissions (at 2 + i) and the forwarding Delegations (at
// deviceCount + 2 + i).
func (self *RowsSettings) RingStart(deviceCount int) uint64 {
	return uint64(3 * deviceCount)
}

// The least folded_through a base over the rows may name: the ring's last statement's position. A base must also fold
// through fewer than 4,096 positions past the ring's first, the window a ring holds.
func (self *RowsSettings) FoldedThrough(deviceCount int) uint64 {
	return self.RingStart(deviceCount) + uint64(self.RingCount) - 1
}

// The latest admission time among deviceCount devices.
func (self *RowsSettings) LastAdmittedTimeMs(deviceCount int) int64 {
	return self.AdmittedTimeMs + int64(max(0, deviceCount-1))
}

// The genesis's owner and network, as rows over it name them: device 0 under member 0. networkId and configRepoId
// are the caller's.
func Genesis(networkId []byte, configRepoId []byte, timeMs int64) *bridge.Genesis {
	return &bridge.Genesis{
		NetworkId:              networkId,
		ConfigRepoId:           configRepoId,
		OwnerMemberId:          MemberId(0),
		OwnerSidecarId:         SidecarId(0),
		OwnerIdentityPublicKey: IdentityKey(0).Public().(ed25519.PublicKey),
		TimeMs:                 timeMs,
	}
}

// The rows of deviceCount devices in settings' mix, as a base's ProjectionRows with empty settings.
func Rows(deviceCount int, settings *RowsSettings) (*bridge.ProjectionRows, error) {
	if deviceCount < 1 {
		return nil, errors.New("a fixture holds at least the genesis's device")
	}
	if settings == nil {
		settings = DefaultRowsSettings()
	}
	if settings.DevicesPerMember < 1 || settings.ForwardingCycle < 1 || settings.ReposPerMember < 0 || settings.RingCount < 0 {
		return nil, errors.New("a fixture's mix needs a member per device count and a forwarding cycle")
	}
	memberCount := settings.MemberCount(deviceCount)
	rows := &bridge.ProjectionRows{Settings: &bridge.ProjectionSettings{}}
	for i := range memberCount {
		role := bridge.MemberRole_MEMBER_ROLE_MEMBER
		if i == 0 {
			role = bridge.MemberRole_MEMBER_ROLE_OWNER
		}
		rows.Members = append(rows.Members, &bridge.MemberRow{MemberId: MemberId(i), Role: role})
	}
	owner := SidecarId(0)
	memberDevices := make([][][]byte, memberCount)
	for i := range deviceCount {
		sidecarId := SidecarId(i)
		memberIndex := i % memberCount
		memberDevices[memberIndex] = append(memberDevices[memberIndex], sidecarId)
		at := uint64(2 + i)
		row := &bridge.SidecarRow{
			SidecarId:         sidecarId,
			AdmissionSha256:   Digest("admission", i),
			AdmissionSigners:  [][]byte{owner},
			AdmittedAt:        at,
			ConfirmSigner:     owner,
			ConfirmedAt:       at,
			LiveSince:         at,
			IdentityPublicKey: IdentityKey(i).Public().(ed25519.PublicKey),
			IdentityAlg:       "ed25519",
			MemberId:          MemberId(memberIndex),
			AdmittedTimeMs:    settings.AdmittedTimeMs + int64(i),
			Confirmations:     []*bridge.ConfirmationRow{{Signer: owner, At: at}},
		}
		if i == 0 {
			// the Genesis's device, which no entry admitted
			row.AdmissionSigners, row.AdmittedAt, row.AdmittedTimeMs = nil, 0, 0
		}
		rows.Sidecars = append(rows.Sidecars, row)
		if !settings.HasForwarding(i) {
			continue
		}
		// a forwarding Delegation's row in 4.2.2's form: the reader key a digest, the key gkm's object
		rows.Delegations = append(rows.Delegations, &bridge.DelegationRow{
			DelegationId:        DelegationId(i),
			Signer:              sidecarId,
			At:                  uint64(deviceCount + 2 + i),
			Pubkey:              ForwardKey(i).Public().(ed25519.PublicKey),
			ForwardSidecarId:    sidecarId,
			HostClientId:        HostClientId(i),
			HostClientPublicKey: HostClientKey(i).Public().(ed25519.PublicKey),
			ReaderKeySha256:     Digest("reader key", i),
		})
	}
	acl := &protocol.AclRows{}
	for memberIndex := range memberCount {
		for repo := range settings.ReposPerMember {
			acl.Repos = append(acl.Repos, &protocol.AclRepo{
				RepoId:              Id("repo", settings.ReposPerMember*memberIndex+repo),
				Kind:                protocol.RepoKind_REPO_KIND_GENERAL,
				OwnerMemberId:       MemberId(memberIndex),
				ConsentedSidecarIds: memberDevices[memberIndex],
			})
		}
	}
	aclBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(acl)
	if err != nil {
		return nil, err
	}
	rows.Acl = aclBytes
	ringStart := settings.RingStart(deviceCount)
	for i := range settings.RingCount {
		rows.Ring = append(rows.Ring, &bridge.RingRow{StatementId: Id("ring", i), N: ringStart + uint64(i)})
	}
	return rows, nil
}
