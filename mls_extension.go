// MLS extensions (RFC 9420 §13.4): typed opaque blobs on KeyPackages, LeafNodes, GroupInfo and the
// GroupContext. A list keeps unknown types as they arrived, since it is hashed and signed as sent.
//
// §10.4 refuses external senders, so an external_senders extension is refused in every list, read or
// written, and no leaf counts as supporting it (mlsCapabilities.supportsExtension).
//
// Three more are this subset's. ur_group (0xF553, QD-469) says what a group is for, in its GroupContext from
// creation on, so its key schedule and every GroupInfo signature bind it (§10.5), and no commit changes it.
// required_capabilities makes every leaf support ur_group and credential 0xF552 (§10.4). last_resort marks
// the one KeyPackage a sidecar keeps (§10.6's KeyPackages), so gkm's upload states it once, in the
// KeyPackage's own extensions; its value is draft-ietf-mls-extensions' (question keys-m2-07-last-resort).

package sidecar

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// Registered extension types (RFC §17.3), the subset's private-use ur_group, and last_resort.
const (
	mlsExtensionTypeApplicationId        uint16 = 0x0001
	mlsExtensionTypeRatchetTree          uint16 = 0x0002
	mlsExtensionTypeRequiredCapabilities uint16 = 0x0003
	mlsExtensionTypeExternalPub          uint16 = 0x0004
	mlsExtensionTypeExternalSenders      uint16 = 0x0005
	mlsExtensionTypeLastResort           uint16 = 0x000a
	mlsExtensionTypeUrGroup              uint16 = 0xf553
)

// One extension, its data left encoded.
type mlsExtension struct {
	extensionType uint16
	extensionData []byte
}

// Extension, in RFC §7.2's field order.
func (self *mlsExtension) encode(encoder *mlsEncoder) {
	encoder.writeUint16(self.extensionType)
	encoder.writeVector(self.extensionData)
}

// Extension, in RFC §7.2's field order.
func (self *mlsExtension) decode(decoder *mlsDecoder) {
	self.extensionType = decoder.readUint16()
	self.extensionData = decoder.readVector()
}

// Extension extensions<V>, refusing what readExtensions refuses for the subset.
func (self *mlsEncoder) writeExtensions(extensions []mlsExtension) {
	self.writeVectorOf(func(elements *mlsEncoder) {
		for index := range extensions {
			if extensions[index].extensionType == mlsExtensionTypeExternalSenders {
				elements.fail(fmt.Errorf("%w: external senders", errMlsRefused))
				return
			}
			extensions[index].encode(elements)
		}
	})
}

// Extension extensions<V>, refusing a list with two of one type (RFC §13.4) and, in every list, the
// external_senders extension (§10.4).
func (self *mlsDecoder) readExtensions() []mlsExtension {
	var extensions []mlsExtension
	seenTypes := map[uint16]bool{}
	self.readVectorOf(func(element *mlsDecoder) {
		var extension mlsExtension
		extension.decode(element)
		if element.err != nil {
			return
		}
		if extension.extensionType == mlsExtensionTypeExternalSenders {
			element.fail(fmt.Errorf("%w: external senders", errMlsRefused))
			return
		}
		if seenTypes[extension.extensionType] {
			element.fail(fmt.Errorf("%w: extension type %#x twice in a list", errMlsMalformed, extension.extensionType))
			return
		}
		seenTypes[extension.extensionType] = true
		extensions = append(extensions, extension)
	})
	return extensions
}

// The extension of this type in a list, or nil.
func mlsFindExtension(extensions []mlsExtension, extensionType uint16) *mlsExtension {
	for index := range extensions {
		if extensions[index].extensionType == extensionType {
			return &extensions[index]
		}
	}
	return nil
}

// ur_group's data (QD-469): struct { opaque network_id<V>; opaque repo_id<V>; uint8 kind; opaque
// owner_member_id<V>; }, the owner empty when the repo is not owner-bound.
func mlsEncodeUrGroup(urGroup *MlsUrGroup) ([]byte, error) {
	if err := mlsCheckUrGroup(urGroup); err != nil {
		return nil, err
	}
	encoder := &mlsEncoder{}
	encoder.writeVector(urGroup.NetworkId.Bytes())
	encoder.writeVector(urGroup.RepoId.Bytes())
	encoder.writeUint8(uint8(urGroup.Kind))
	if urGroup.OwnerMemberId == nil {
		encoder.writeVector(nil)
	} else {
		encoder.writeVector(urGroup.OwnerMemberId.Bytes())
	}
	return encoder.finish()
}

// ur_group from its data, refusing what mlsCheckUrGroup refuses.
func mlsDecodeUrGroup(data []byte) (*MlsUrGroup, error) {
	decoder := &mlsDecoder{remaining: data}
	networkId := decoder.readVector()
	repoId := decoder.readVector()
	kind := decoder.readUint8()
	ownerMemberId := decoder.readVector()
	if err := decoder.finish(); err != nil {
		return nil, err
	}
	if len(networkId) != gkmIdByteCount || len(repoId) != gkmIdByteCount {
		return nil, fmt.Errorf("%w: ur_group ids of %d and %d bytes", errMlsInvalid, len(networkId), len(repoId))
	}
	urGroup := &MlsUrGroup{
		NetworkId: Id(networkId),
		RepoId:    Id(repoId),
		Kind:      protocol.RepoKind(kind),
	}
	switch len(ownerMemberId) {
	case 0:
	case gkmIdByteCount:
		owner := Id(ownerMemberId)
		urGroup.OwnerMemberId = &owner
	default:
		return nil, fmt.Errorf("%w: ur_group owner of %d bytes", errMlsInvalid, len(ownerMemberId))
	}
	if err := mlsCheckUrGroup(urGroup); err != nil {
		return nil, err
	}
	return urGroup, nil
}

// A kind §11.12 names, general 1 to secret 9, directory among them (owner decision 171).
func mlsCheckUrGroup(urGroup *MlsUrGroup) error {
	if urGroup == nil {
		return fmt.Errorf("%w: a group needs its ur_group", errMlsInvalid)
	}
	if _, ok := protocol.RepoKind_name[int32(urGroup.Kind)]; !ok || urGroup.Kind == protocol.RepoKind_REPO_KIND_UNSPECIFIED {
		return fmt.Errorf("%w: ur_group kind %d", errMlsInvalid, urGroup.Kind)
	}
	return nil
}

// What every leaf of a group must support (§10.4): ur_group and credential 0xF552.
func mlsSubsetRequiredCapabilities() *mlsRequiredCapabilities {
	return &mlsRequiredCapabilities{
		extensionTypes:  []uint16{mlsExtensionTypeUrGroup},
		credentialTypes: []uint16{mlsCredentialTypeUrSidecar},
	}
}

// What every leaf this sidecar makes advertises: mls10, the one suite, ur_group and last_resort, and
// credential 0xF552 alone.
func mlsSubsetCapabilities(suite *mlsCipherSuite) mlsCapabilities {
	return mlsCapabilities{
		versions:     []uint16{mlsProtocolVersion10},
		cipherSuites: []uint16{suite.value},
		extensions:   []uint16{mlsExtensionTypeLastResort, mlsExtensionTypeUrGroup},
		credentials:  []uint16{mlsCredentialTypeUrSidecar},
	}
}

// A new group's GroupContext extensions: its ur_group, then required_capabilities.
func mlsSubsetGroupExtensions(urGroup *MlsUrGroup) ([]mlsExtension, error) {
	urGroupData, err := mlsEncodeUrGroup(urGroup)
	if err != nil {
		return nil, err
	}
	required, err := mlsMarshal(mlsSubsetRequiredCapabilities())
	if err != nil {
		return nil, err
	}
	return []mlsExtension{
		{extensionType: mlsExtensionTypeUrGroup, extensionData: urGroupData},
		{extensionType: mlsExtensionTypeRequiredCapabilities, extensionData: required},
	}, nil
}

// A group's ur_group, once its GroupContext extensions carry one and require of every leaf what
// mlsSubsetRequiredCapabilities does. A group without either is no group of this subset, so nothing
// joins it, and a commit that would drop either is refused.
func mlsCheckSubsetGroupExtensions(extensions []mlsExtension) (*MlsUrGroup, error) {
	urGroupExtension := mlsFindExtension(extensions, mlsExtensionTypeUrGroup)
	if urGroupExtension == nil {
		return nil, fmt.Errorf("%w: a group with no ur_group", errMlsInvalid)
	}
	urGroup, err := mlsDecodeUrGroup(urGroupExtension.extensionData)
	if err != nil {
		return nil, err
	}
	requiredExtension := mlsFindExtension(extensions, mlsExtensionTypeRequiredCapabilities)
	if requiredExtension == nil {
		return nil, fmt.Errorf("%w: a group requiring no capabilities", errMlsInvalid)
	}
	required := &mlsRequiredCapabilities{}
	if err := mlsUnmarshal(requiredExtension.extensionData, required); err != nil {
		return nil, err
	}
	if !slices.Contains(required.extensionTypes, mlsExtensionTypeUrGroup) || !slices.Contains(required.credentialTypes, mlsCredentialTypeUrSidecar) {
		return nil, fmt.Errorf("%w: a group not requiring ur_group and credential 0xF552", errMlsInvalid)
	}
	return urGroup, nil
}

// Whether a GroupContextExtensions proposal keeps ur_group as creation fixed it (§10.5; §10.9's
// GroupContextExtensions row: kind and owner never change), and the subset's requirements with it.
func mlsCheckGroupExtensionsChange(previous []mlsExtension, next []mlsExtension) error {
	if _, err := mlsCheckSubsetGroupExtensions(next); err != nil {
		return err
	}
	previousUrGroup := mlsFindExtension(previous, mlsExtensionTypeUrGroup)
	nextUrGroup := mlsFindExtension(next, mlsExtensionTypeUrGroup)
	if previousUrGroup == nil || !bytes.Equal(previousUrGroup.extensionData, nextUrGroup.extensionData) {
		return fmt.Errorf("%w: a commit changing ur_group", errMlsInvalid)
	}
	return nil
}

// Whether a KeyPackage's extensions mark it last resort.
func mlsIsLastResort(extensions []mlsExtension) bool {
	return mlsFindExtension(extensions, mlsExtensionTypeLastResort) != nil
}
