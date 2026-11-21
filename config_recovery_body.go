// The public recovery key of a holder comes from the binding that took effect at its row's carrying position.
// A reader starting at a folded base can recover the same statement from the head it checked against the log.
package sidecar

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

type configRecoveryBody struct {
	at   uint64
	kind bridge.SignedType
	body []byte
}

// The verified base rows identify the effective position. A cosign or activating tick names its exact proposal.
// Index proposals by the digest computed over their bytes, including for old head records preceding retention.
func configFoldedRecoveryBodies(members []*bridge.MemberRow, records []*protocol.ConfigRecord) map[Id]*configRecoveryBody {
	result := map[Id]*configRecoveryBody{}
	if !slices.ContainsFunc(members, func(member *bridge.MemberRow) bool {
		return len(member.GetRecoveryKeySha256()) == sha256.Size
	}) {
		return result
	}
	proposals := map[[sha256.Size]byte]*protocol.ConfigRecord{}
	for _, record := range records {
		if record.GetKind() != bridge.AuthEntryKindStatement {
			continue
		}
		signed := &bridge.Signed{}
		if proto.Unmarshal(record.GetBody(), signed) == nil && bridge.SignedType(signed.GetType()) == bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL {
			proposal := &protocol.AuthorityProposal{}
			if proto.Unmarshal(signed.GetBody(), proposal) != nil {
				continue
			}
			switch bridge.SignedType(proposal.GetStatementType()) {
			case bridge.SignedType_SIGNED_RECOVERY_BIND, bridge.SignedType_SIGNED_RECOVERY_REBIND:
			default:
				continue
			}
			id := bridge.SignedBytesSha256(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, signed.GetBody())
			proposals[id] = record
		}
	}
	for _, member := range members {
		memberId, err := IdFromBytes(member.GetMemberId())
		if err != nil || len(member.GetRecoveryKeySha256()) != sha256.Size {
			continue
		}
		for _, binding := range member.GetBindings() {
			if !bytes.Equal(binding.GetKeySha256(), member.GetRecoveryKeySha256()) {
				continue
			}
			at := binding.GetAt()
			if at == 0 || uint64(len(records)) < at || records[at-1].GetN() != at {
				break
			}
			record := records[at-1]
			candidates := []*protocol.ConfigRecord{record}
			var proposalIds [][]byte
			if record.GetKind() == bridge.AuthEntryKindTick {
				tick := &bridge.ApiTick{}
				if proto.Unmarshal(record.GetBody(), tick) == nil {
					proposalIds = tick.GetActivatedProposalIds()
				}
			} else if record.GetKind() == bridge.AuthEntryKindStatement {
				signed := &bridge.Signed{}
				cosign := &protocol.AuthorityCosign{}
				if proto.Unmarshal(record.GetBody(), signed) == nil && bridge.SignedType(signed.GetType()) == bridge.SignedType_SIGNED_AUTHORITY_COSIGN && proto.Unmarshal(signed.GetBody(), cosign) == nil {
					proposalIds = [][]byte{cosign.GetProposalId()}
				}
			}
			for _, id := range proposalIds {
				if len(id) == sha256.Size {
					if proposal := proposals[[sha256.Size]byte(id)]; proposal != nil && proposal.GetN() < at {
						candidates = append(candidates, proposal)
					}
				}
			}
			for _, candidate := range candidates {
				if kind, statement, ok := recoveryBindingOfRecord(candidate.GetKind(), candidate.GetBody(), memberId, binding.GetKeySha256()); ok {
					result[memberId] = &configRecoveryBody{at: at, kind: kind, body: statement}
					break
				}
			}
			break
		}
	}
	return result
}

// Opens only the effective binding, under its config generation and this state's trusted genesis.
func (self *ConfigState) recoveryKey(memberId Id, keyAt func(uint64) *EvsRepoKey) (*GkmRecoveryKey, error) {
	binding, statement := self.CurrentBinding(memberId), self.recoveryBodies[memberId]
	if binding == nil || statement == nil || statement.at != binding.GetAt() {
		return nil, fmt.Errorf("%w: no verified statement of the current recovery binding", ErrGkmKeyMissing)
	}
	member, digest, body, err := openRecoveryBindBody(statement.kind, statement.body, &recoveryAnchorKeys{keyAt: keyAt}, self.networkId, self.genesisChain[:])
	if err != nil {
		return nil, err
	}
	if member != memberId || !bytes.Equal(digest, binding.GetKeySha256()) {
		return nil, ErrGkmKeyMissing
	}
	return &GkmRecoveryKey{BindingKeySha256: bytes.Clone(digest), XwingPublicKey: bytes.Clone(body.GetXwingPublicKey())}, nil
}
