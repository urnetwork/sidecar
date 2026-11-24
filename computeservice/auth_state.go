// The real ComputeAuthState: the broker's newest verified authorization state is §8.9's one per-process gate cache,
// sidecar.AclGateCache (C-09), which the compute block's host builds over proj/ on the first metadata cluster as
// tlsedge's does, and §7.8's rev/ objects are the root's RevocationChecker, so the broker judges a token by the log
// alone and api stays a carrier:
//
//	CheckRevocation  rev/ for the token's client, sidecar and member, each answer kept at most RevocationSettings' age
//	Caller           the token's ur_sidecar_id an admitted, unrevoked sidecar of the token's network in the newest
//	                 verified state, and in standing as the exchange judges one (not parked or suspended, its
//	                 not_after unpassed), with its member, role, tags and admission flags read from its row through
//	                 the state's view. The token's (ur_sidecar_id, ur_client_id) pair is §5's binding as the exchange
//	                 bound it (QD-717)
//	Features         the newest base's ProjectionSettings.auth_features (field 3, §16.6's reserve row), read by number,
//	                 so a build from before CACL's reservation still sees a bit a newer writer set, as an unknown
//	                 field, and holds the network rather than serve it under rules it does not know
//
// Every doubt answers ComputeAuthUnknown, which the broker answers 503: a network not loaded, no rev/ reader, a
// feature field that does not parse.
//
// Safe for concurrent use. CheckRevocation does I/O under ctx; the rest answer from memory.

package computeservice

import (
	"context"
	"errors"
	"fmt"
	"math"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// ProjectionSettings' field that carries the authorization features (§16.6's reserve row; Appendix D).
const computeProjectionAuthFeaturesField protowire.Number = 3

// SidecarRow.capabilities' bit 3, an enclave incarnation's admission (§11.4; CACL-M11-02 declares its name).
const computeSidecarCapabilityEnclave uint32 = 8

// §8.9's gate cache as the real state reads it: sidecar.AclGateCache's methods, or a test's stand-in.
type ComputeAclGate interface {
	// The network's verified state and what the cache says of it, with no I/O.
	State(networkId sidecar.Id) (*sidecar.AclGateSnapshot, sidecar.AclGateStatus)
	// Tells the cache a gate needs the network, which starts its load.
	Changed(networkId sidecar.Id)
}

// The rev/ reader the real state uses: sidecar.RevocationChecker's Check, or a test's stand-in.
type ComputeRevocationReader interface {
	Check(ctx context.Context, principal *sidecar.Principal) error
}

// The real ComputeAuthState. See the file header.
type AclComputeAuthState struct {
	gate        ComputeAclGate
	revocations ComputeRevocationReader
	clock       sidecar.Clock
}

var _ ComputeAuthState = (*AclComputeAuthState)(nil)

// The state over gate, reading rev/ through revocations and judging not_after on clock (nil: real time). A nil gate
// or revocations answers every check that needs it 503.
func NewComputeAuthState(gate ComputeAclGate, revocations ComputeRevocationReader, clock sidecar.Clock) *AclComputeAuthState {
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	return &AclComputeAuthState{gate: gate, revocations: revocations, clock: clock}
}

// The network's snapshot, asking the cache to load it on a miss.
func (self *AclComputeAuthState) snapshot(networkId sidecar.Id) *sidecar.AclGateSnapshot {
	if self.gate == nil {
		return nil
	}
	snapshot := sidecar.RequestAclGateSnapshot(self.gate, networkId)
	if snapshot == nil || snapshot.Acl == nil {
		return nil
	}
	return snapshot
}

// See ComputeAuthState: ErrComputeTokenRevoked when an object voids a subject, any other error when the broker cannot
// tell.
func (self *AclComputeAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	if self.revocations == nil {
		return errors.New("this broker reads no revocations")
	}
	err := self.revocations.Check(ctx, principal)
	if errors.Is(err, sidecar.ErrRevocationVoidsToken) {
		return fmt.Errorf("%w: %w", ErrComputeTokenRevoked, err)
	}
	return err
}

// See ComputeAuthState and the file header.
func (self *AclComputeAuthState) Caller(principal *sidecar.Principal) (*ComputeCaller, ComputeAuthAnswer) {
	if principal == nil {
		return nil, ComputeAuthUnknown
	}
	snapshot := self.snapshot(sidecar.Id(principal.NetworkId))
	if snapshot == nil {
		return nil, ComputeAuthUnknown
	}
	if principal.SidecarId == nil {
		return nil, ComputeAuthDenied
	}
	sidecarId := sidecar.Id(*principal.SidecarId)
	view := snapshot.Acl.View()
	admitted := view.Sidecar(sidecarId)
	if admitted == nil || admitted.Row == nil || !snapshot.Acl.Admitted(sidecarId) || view.Parked(sidecarId) || snapshot.Acl.Suspended(sidecarId) {
		return nil, ComputeAuthDenied
	}
	row := admitted.Row
	if notAfter := row.GetNotAfter(); notAfter != 0 && notAfter <= self.clock.Now().UnixMilli() {
		return nil, ComputeAuthDenied
	}
	caller := &ComputeCaller{
		Principal:          principal,
		NetworkId:          sidecar.Id(principal.NetworkId),
		ClientId:           sidecar.Id(principal.ClientId),
		SidecarId:          sidecarId,
		TagIds:             append([]sidecar.Id{}, admitted.TagIds...),
		Consented:          snapshot.Acl.Consented(sidecarId),
		ReadOnly:           row.GetCapabilities()&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) != 0,
		Ephemeral:          admitted.Ephemeral,
		DelegationAdmitted: 0 < len(row.GetDelegationId()),
		EnclaveIncarnation: row.GetCapabilities()&computeSidecarCapabilityEnclave != 0,
		Snapshot:           snapshot,
	}
	if len(admitted.TagIds) == 0 {
		if admitted.MemberId == (sidecar.Id{}) {
			// an untagged admission names its member; one that names neither is no admission
			return nil, ComputeAuthDenied
		}
		caller.MemberId = admitted.MemberId
		member := view.Member(admitted.MemberId)
		if member == nil {
			return nil, ComputeAuthDenied
		}
		caller.Role = member.GetRole()
	}
	return caller, ComputeAuthAllowed
}

// See ComputeAuthState and the file header.
func (self *AclComputeAuthState) Features(networkId sidecar.Id) (ComputeAuthFeatures, ComputeAuthAnswer) {
	snapshot := self.snapshot(networkId)
	if snapshot == nil || snapshot.Config == nil {
		// a rows-only snapshot holds no base's settings, so it cannot say what the base turns on
		return 0, ComputeAuthUnknown
	}
	features, ok := computeProjectionFeatures(snapshot.Config.Settings())
	if !ok {
		return 0, ComputeAuthUnknown
	}
	return features, ComputeAuthAllowed
}

// The features a base's ProjectionSettings turns on: field 3 as this build declares it, or, in a build from before
// the reservation, the varint the field's number carries among the unknown fields, the last one standing as proto3
// reads a repeated scalar. false for a value that does not parse or does not fit 32 bits.
func computeProjectionFeatures(settings *bridge.ProjectionSettings) (ComputeAuthFeatures, bool) {
	if settings == nil {
		return 0, true
	}
	message := settings.ProtoReflect()
	if field := message.Descriptor().Fields().ByNumber(computeProjectionAuthFeaturesField); field != nil {
		if field.Kind() != protoreflect.Uint32Kind || field.Cardinality() == protoreflect.Repeated {
			return 0, false
		}
		return ComputeAuthFeatures(message.Get(field).Uint()), true
	}
	features := uint64(0)
	unknown := []byte(message.GetUnknown())
	for 0 < len(unknown) {
		number, wireType, tagLength := protowire.ConsumeTag(unknown)
		if tagLength < 0 {
			return 0, false
		}
		unknown = unknown[tagLength:]
		if number == computeProjectionAuthFeaturesField {
			if wireType != protowire.VarintType {
				return 0, false
			}
			value, valueLength := protowire.ConsumeVarint(unknown)
			if valueLength < 0 {
				return 0, false
			}
			features = value
			unknown = unknown[valueLength:]
			continue
		}
		valueLength := protowire.ConsumeFieldValue(number, wireType, unknown)
		if valueLength < 0 {
			return 0, false
		}
		unknown = unknown[valueLength:]
	}
	if math.MaxUint32 < features {
		return 0, false
	}
	return ComputeAuthFeatures(features), true
}

// The features a network turns on that this release does not implement, 0 for none.
func computeFeaturesLacking(features ComputeAuthFeatures) ComputeAuthFeatures {
	return features &^ ComputeFeaturesImplemented
}
