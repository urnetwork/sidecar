// MLS extensions (RFC 9420 §13.4): typed opaque blobs on KeyPackages, LeafNodes, GroupInfo and the
// GroupContext. A list keeps unknown types as they arrived, since it is hashed and signed as sent.

package sidecar

import (
	"fmt"
)

// Registered extension types (§17.3).
const (
	mlsExtensionTypeApplicationId        uint16 = 0x0001
	mlsExtensionTypeRatchetTree          uint16 = 0x0002
	mlsExtensionTypeRequiredCapabilities uint16 = 0x0003
	mlsExtensionTypeExternalPub          uint16 = 0x0004
	mlsExtensionTypeExternalSenders      uint16 = 0x0005
)

// One extension, its data left encoded.
type mlsExtension struct {
	extensionType uint16
	extensionData []byte
}

func (self *mlsExtension) encode(encoder *mlsEncoder) {
	encoder.writeUint16(self.extensionType)
	encoder.writeVector(self.extensionData)
}

func (self *mlsExtension) decode(decoder *mlsDecoder) {
	self.extensionType = decoder.readUint16()
	self.extensionData = decoder.readVector()
}

// Extension extensions<V>.
func (self *mlsEncoder) writeExtensions(extensions []mlsExtension) {
	self.writeVectorOf(func(elements *mlsEncoder) {
		for index := range extensions {
			extensions[index].encode(elements)
		}
	})
}

// Extension extensions<V>, refusing a list with two of one type (§13.4).
func (self *mlsDecoder) readExtensions() []mlsExtension {
	var extensions []mlsExtension
	seenTypes := map[uint16]bool{}
	self.readVectorOf(func(element *mlsDecoder) {
		var extension mlsExtension
		extension.decode(element)
		if element.err != nil {
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
