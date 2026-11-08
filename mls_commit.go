// A Commit's wire form (RFC 9420 §12.4). Framing reads it because no length header bounds a Commit, so
// only its structure says where the signature after it starts. What a commit may hold, and what it
// does to a group, is the group state's to judge.
//
// §10.4 commits proposals inline, so a reference, which could only name a standalone proposal, is
// refused when parsed, as mlsProposal refuses the types outside the subset.

package sidecar

import (
	"fmt"
)

// ProposalOrRefType (RFC §12.4).
const (
	mlsProposalOrRefTypeProposal  uint8 = 1
	mlsProposalOrRefTypeReference uint8 = 2
)

// Commit (RFC §12.4).
type mlsCommit struct {
	proposals []mlsProposal
	// Nil when the commit carries none.
	path *mlsUpdatePath
}

// Commit, each proposal behind its inline tag.
func (self *mlsCommit) encode(encoder *mlsEncoder) {
	encoder.writeVectorOf(func(elements *mlsEncoder) {
		for index := range self.proposals {
			elements.writeUint8(mlsProposalOrRefTypeProposal)
			self.proposals[index].encode(elements)
		}
	})
	encoder.writeOptional(self.path != nil)
	if self.path != nil {
		self.path.encode(encoder)
	}
}

// Commit, refusing a reference and whatever mlsProposal refuses.
func (self *mlsCommit) decode(decoder *mlsDecoder) {
	decoder.readVectorOf(func(element *mlsDecoder) {
		switch proposalOrRefType := element.readUint8(); {
		case element.err != nil:
		case proposalOrRefType == mlsProposalOrRefTypeProposal:
			var proposal mlsProposal
			proposal.decode(element)
			self.proposals = append(self.proposals, proposal)
		case proposalOrRefType == mlsProposalOrRefTypeReference:
			element.fail(fmt.Errorf("%w: a commit referencing a standalone proposal", errMlsRefused))
		default:
			element.fail(fmt.Errorf("%w: proposal or reference type %d", errMlsMalformed, proposalOrRefType))
		}
	})
	if decoder.readOptional() {
		self.path = &mlsUpdatePath{}
		self.path.decode(decoder)
	}
}
