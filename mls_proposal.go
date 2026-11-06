// Proposal (RFC 9420 §12.1), as far as §10.4's subset takes one: Add, Remove, ExternalInit and
// GroupContextExtensions, always inline in a commit. Update, PreSharedKey and ReInit are refused when
// parsed, and so is any other type, whose body has no known length.

package sidecar

import (
	"fmt"
)

// Proposal types (RFC §17.4), all of them default types, which capabilities never list (RFC §7.2).
const (
	mlsProposalTypeAdd                    uint16 = 0x0001
	mlsProposalTypeUpdate                 uint16 = 0x0002
	mlsProposalTypeRemove                 uint16 = 0x0003
	mlsProposalTypePsk                    uint16 = 0x0004
	mlsProposalTypeReInit                 uint16 = 0x0005
	mlsProposalTypeExternalInit           uint16 = 0x0006
	mlsProposalTypeGroupContextExtensions uint16 = 0x0007
)

// Proposal (RFC §12.1). proposalType says which of the fields below it holds.
type mlsProposal struct {
	proposalType uint16

	// Add.
	keyPackage *mlsKeyPackage
	// Remove.
	removed mlsLeafIndex
	// ExternalInit.
	kemOutput []byte
	// GroupContextExtensions.
	extensions []mlsExtension
}

// Proposal, refusing what decode refuses.
func (self *mlsProposal) encode(encoder *mlsEncoder) {
	encoder.writeUint16(self.proposalType)
	switch self.proposalType {
	case mlsProposalTypeAdd:
		self.keyPackage.encode(encoder)
	case mlsProposalTypeRemove:
		encoder.writeUint32(uint32(self.removed))
	case mlsProposalTypeExternalInit:
		encoder.writeVector(self.kemOutput)
	case mlsProposalTypeGroupContextExtensions:
		encoder.writeExtensions(self.extensions)
	default:
		encoder.fail(fmt.Errorf("%w: proposal type %#x", errMlsRefused, self.proposalType))
	}
}

// Proposal: its type, then that type's body.
func (self *mlsProposal) decode(decoder *mlsDecoder) {
	self.proposalType = decoder.readUint16()
	if decoder.err != nil {
		return
	}
	switch self.proposalType {
	case mlsProposalTypeAdd:
		self.keyPackage = &mlsKeyPackage{}
		self.keyPackage.decode(decoder)
	case mlsProposalTypeRemove:
		self.removed = mlsLeafIndex(decoder.readUint32())
	case mlsProposalTypeExternalInit:
		self.kemOutput = decoder.readVector()
	case mlsProposalTypeGroupContextExtensions:
		self.extensions = decoder.readExtensions()
	default:
		decoder.fail(fmt.Errorf("%w: proposal type %#x", errMlsRefused, self.proposalType))
	}
}
