//go:build !ios_extension

// §17.9's share seal (BRIDGE-M6-03; QD-108; DESIGN-DETAILS 12.2.2, 12.2.7; I-2): how the two networks of a share
// exchange their tables through a server that reads neither.
//
//	K        HKDF-SHA256(code, salt x_network_id, info "urnetwork-sidecar-v1/bridge-share"), 32 B: the invite's
//	         256-bit code derives it, and api, which holds the code's SHA-256, cannot
//	sealed   nonce (24 random B a seal) || XChaCha20-Poly1305(K, nonce, body, ad), with ad =
//	         "urnetwork-sidecar-v1/bridge-share/" || label || 0x00 || x_network_id || y_network_id || u64be(version)
//	labels   targets    BridgeShareTargets, which X seals before any accept, so its y_network_id is 16 zero bytes
//	         aliases    BridgeShareAliases
//	         share-key  BridgeShareKeyBody
//	         shortfall  BridgeShareShortfall
//	body     proto3, deterministic, padded by its pad field to a multiple of PadByteCount
//
// A seal binds its label, both networks and the table's version, so a table of another share's networks, another
// label or another version does not open. A failed open is ErrBridgeShareSeal, which refuses the share: there is no
// fallback. A multi-use code's accepters all hold K, so a seal proves only a code holder: what pins one ShareKey and
// one alias table to one share is X's approving admin (BridgeShareGrant, bridge_share_invite.go).
//
// The accepting side's seals travel together as one BridgeShareAccept, the value network_bridge_share stores as that
// side's table (question bridge-m6-03-accept-seals).
//
// Pure: no clock and no network. Safe for concurrent use.

package sidecar

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// A sealed table did not open: another key, label, network or version, a changed byte, or a body that is not its
	// label's message whole. The share is refused (§17.9's open row).
	ErrBridgeShareSeal = errors.New("bridge share seal did not open")
	// A body, a code or an id the seal does not take.
	ErrBridgeShareSealInvalid = errors.New("bridge share seal refused")
)

// A sealed body's label (§17.9's labels row). Format values.
type BridgeShareLabel string

const (
	BridgeShareLabelTargets   BridgeShareLabel = "targets"
	BridgeShareLabelAliases   BridgeShareLabel = "aliases"
	BridgeShareLabelShareKey  BridgeShareLabel = "share-key"
	BridgeShareLabelShortfall BridgeShareLabel = "shortfall"
)

// The seal's derivation and associated-data strings, and the sizes its primitives fix. Format values.
const (
	bridgeShareSealInfo      = "urnetwork-sidecar-v1/bridge-share"
	bridgeShareSealAdPrefix  = "urnetwork-sidecar-v1/bridge-share/"
	bridgeShareCodeByteCount = 32
	bridgeShareKeyByteCount  = chacha20poly1305.KeySize
	// the pad field every sealed body carries
	bridgeSharePadField = protoreflect.FieldNumber(15)
)

// Tunables of the share seal and the tables it carries. Both networks of a share read the same values, since a
// reader refuses a body that is padded otherwise.
type BridgeShareSettings struct {
	// Every sealed body is padded to a multiple of this many bytes, so a table's size tells its row count only
	// coarsely: 256 (QD-108). Non-positive is the default.
	PadByteCount int
	// The largest sealed value either side stores, as network_bridge_share bounds it: 256 KiB. Non-positive is the
	// default.
	TableMaxByteCount int
}

// QD-108's values and the server's bound.
func DefaultBridgeShareSettings() *BridgeShareSettings {
	return &BridgeShareSettings{
		PadByteCount:      256,
		TableMaxByteCount: 256 * 1024,
	}
}

// The settings as read: nil and non-positive fields take the defaults. The caller's are never changed.
func bridgeShareSettingsOrDefault(settings *BridgeShareSettings) *BridgeShareSettings {
	defaults := DefaultBridgeShareSettings()
	if settings == nil {
		return defaults
	}
	read := *settings
	if read.PadByteCount <= 0 {
		read.PadByteCount = defaults.PadByteCount
	}
	if read.TableMaxByteCount <= 0 {
		read.TableMaxByteCount = defaults.TableMaxByteCount
	}
	return &read
}

// One share's seal: K and the sharing network it was derived for.
type BridgeShareSeal struct {
	key              []byte
	sharingNetworkId Id
	settings         *BridgeShareSettings
}

// The seal an invite's code derives for the sharing network X (the file's K row). The code never reaches a server.
func NewBridgeShareSeal(code []byte, sharingNetworkId Id, settings *BridgeShareSettings) (*BridgeShareSeal, error) {
	if len(code) != bridgeShareCodeByteCount {
		return nil, fmt.Errorf("%w: a code of %d bytes", ErrBridgeShareSealInvalid, len(code))
	}
	if sharingNetworkId == (Id{}) {
		return nil, fmt.Errorf("%w: no sharing network", ErrBridgeShareSealInvalid)
	}
	key, err := hkdf.Key(sha256.New, code, sharingNetworkId.Bytes(), bridgeShareSealInfo, bridgeShareKeyByteCount)
	if err != nil {
		return nil, err
	}
	testHookSecret("bridge-share-table-key", key)
	return &BridgeShareSeal{key: key, sharingNetworkId: sharingNetworkId, settings: bridgeShareSettingsOrDefault(settings)}, nil
}

// The seal over K itself, as X's config holds it in a BridgeShareGrant (table_key), for the sharing network X.
func NewBridgeShareSealOfKey(tableKey []byte, sharingNetworkId Id, settings *BridgeShareSettings) (*BridgeShareSeal, error) {
	if len(tableKey) != bridgeShareKeyByteCount {
		return nil, fmt.Errorf("%w: a table key of %d bytes", ErrBridgeShareSealInvalid, len(tableKey))
	}
	if sharingNetworkId == (Id{}) {
		return nil, fmt.Errorf("%w: no sharing network", ErrBridgeShareSealInvalid)
	}
	key := append([]byte{}, tableKey...)
	testHookSecret("bridge-share-table-key", key)
	return &BridgeShareSeal{key: key, sharingNetworkId: sharingNetworkId, settings: bridgeShareSettingsOrDefault(settings)}, nil
}

// K, a copy: what X's approving admin writes as BridgeShareGrant.table_key.
func (self *BridgeShareSeal) TableKey() []byte {
	return append([]byte{}, self.key...)
}

// The sharing network X the seal was derived for.
func (self *BridgeShareSeal) SharingNetworkId() Id {
	return self.sharingNetworkId
}

// A new, empty body of a label's message, nil for a label the seal does not know.
func bridgeShareBodyOf(label BridgeShareLabel) proto.Message {
	switch label {
	case BridgeShareLabelTargets:
		return &bridge.BridgeShareTargets{}
	case BridgeShareLabelAliases:
		return &bridge.BridgeShareAliases{}
	case BridgeShareLabelShareKey:
		return &bridge.BridgeShareKeyBody{}
	case BridgeShareLabelShortfall:
		return &bridge.BridgeShareShortfall{}
	}
	return nil
}

// The associated data of one seal (the file's sealed row).
func (self *BridgeShareSeal) associatedData(label BridgeShareLabel, acceptingNetworkId Id, version uint64) ([]byte, error) {
	if bridgeShareBodyOf(label) == nil {
		return nil, fmt.Errorf("%w: a label %q", ErrBridgeShareSealInvalid, string(label))
	}
	if (label == BridgeShareLabelTargets) != (acceptingNetworkId == (Id{})) {
		return nil, fmt.Errorf("%w: targets are sealed before any accept, and every other body names the accepting network", ErrBridgeShareSealInvalid)
	}
	if version == 0 {
		return nil, fmt.Errorf("%w: a version of 0", ErrBridgeShareSealInvalid)
	}
	ad := append([]byte(bridgeShareSealAdPrefix), string(label)...)
	ad = append(ad, 0x00)
	ad = append(ad, self.sharingNetworkId.Bytes()...)
	ad = append(ad, acceptingNetworkId.Bytes()...)
	return binary.BigEndian.AppendUint64(ad, version), nil
}

// body's deterministic bytes, padded by its pad field to a multiple of padByteCount. body is not changed.
func bridgeSharePadded(body proto.Message, padByteCount int) ([]byte, error) {
	padded := proto.Clone(body)
	reflected := padded.ProtoReflect()
	field := reflected.Descriptor().Fields().ByNumber(bridgeSharePadField)
	if field == nil || field.Kind() != protoreflect.BytesKind {
		return nil, fmt.Errorf("%w: a body with no pad", ErrBridgeShareSealInvalid)
	}
	reflected.Clear(field)
	marshal := proto.MarshalOptions{Deterministic: true}
	plain, err := marshal.Marshal(padded)
	if err != nil {
		return nil, err
	}
	if len(plain)%padByteCount == 0 && 0 < len(plain) {
		return plain, nil
	}
	// the pad field costs its tag, its length and its bytes, and an empty one is not written: the shortest pad of at
	// least one byte that lands on the multiple
	return bridgeSharePadSearch(padded, field, padByteCount)
}

// Finds the shortest pad that brings padded's size to a multiple of padByteCount, and answers its bytes.
func bridgeSharePadSearch(padded proto.Message, field protoreflect.FieldDescriptor, padByteCount int) ([]byte, error) {
	marshal := proto.MarshalOptions{Deterministic: true}
	reflected := padded.ProtoReflect()
	for padLength := 1; padLength <= 3*padByteCount+16; padLength += 1 {
		reflected.Set(field, protoreflect.ValueOfBytes(make([]byte, padLength)))
		if marshal.Size(padded)%padByteCount == 0 {
			return marshal.Marshal(padded)
		}
	}
	return nil, fmt.Errorf("%w: no pad reaches a multiple of %d", ErrBridgeShareSealInvalid, padByteCount)
}

// Seals body, the label's message, for the accepting network Y at a table version; random is crypto/rand's reader
// when nil. The zero id is Y for targets alone.
func (self *BridgeShareSeal) Seal(label BridgeShareLabel, acceptingNetworkId Id, version uint64, body proto.Message, random io.Reader) ([]byte, error) {
	ad, err := self.associatedData(label, acceptingNetworkId, version)
	if err != nil {
		return nil, err
	}
	if body == nil || body.ProtoReflect().Descriptor().FullName() != bridgeShareBodyOf(label).ProtoReflect().Descriptor().FullName() {
		return nil, fmt.Errorf("%w: a body that is not the label's", ErrBridgeShareSealInvalid)
	}
	plain, err := bridgeSharePadded(body, self.settings.PadByteCount)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(self.key)
	if err != nil {
		return nil, err
	}
	if random == nil {
		random = rand.Reader
	}
	sealed := make([]byte, chacha20poly1305.NonceSizeX, chacha20poly1305.NonceSizeX+len(plain)+chacha20poly1305.Overhead)
	if _, err := io.ReadFull(random, sealed); err != nil {
		return nil, err
	}
	sealed = aead.Seal(sealed, sealed[:chacha20poly1305.NonceSizeX], plain, ad)
	if self.settings.TableMaxByteCount < len(sealed) {
		return nil, fmt.Errorf("%w: a sealed body of %d bytes", ErrBridgeShareSealInvalid, len(sealed))
	}
	return sealed, nil
}

// Opens sealed into body, the label's message, as sealed for the accepting network Y at a table version.
// ErrBridgeShareSeal for anything that does not open whole: a wrong key, label, network or version, a changed byte, a
// body that is not padded to the multiple, or one with a field this build does not know.
func (self *BridgeShareSeal) Open(label BridgeShareLabel, acceptingNetworkId Id, version uint64, sealed []byte, body proto.Message) error {
	ad, err := self.associatedData(label, acceptingNetworkId, version)
	if err != nil {
		return err
	}
	if body == nil || body.ProtoReflect().Descriptor().FullName() != bridgeShareBodyOf(label).ProtoReflect().Descriptor().FullName() {
		return fmt.Errorf("%w: a body that is not the label's", ErrBridgeShareSealInvalid)
	}
	if len(sealed) < chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead || self.settings.TableMaxByteCount < len(sealed) {
		return fmt.Errorf("%w: %d bytes", ErrBridgeShareSeal, len(sealed))
	}
	aead, err := chacha20poly1305.NewX(self.key)
	if err != nil {
		return err
	}
	plain, err := aead.Open(nil, sealed[:chacha20poly1305.NonceSizeX], sealed[chacha20poly1305.NonceSizeX:], ad)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrBridgeShareSeal, string(label))
	}
	if len(plain) == 0 || len(plain)%self.settings.PadByteCount != 0 {
		return fmt.Errorf("%w: %s: a body of %d bytes is not padded", ErrBridgeShareSeal, string(label), len(plain))
	}
	proto.Reset(body)
	if err := proto.Unmarshal(plain, body); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrBridgeShareSeal, string(label), err)
	}
	if bridgeLedgerUnknownFields(body) {
		return fmt.Errorf("%w: %s: a field this build does not know", ErrBridgeShareSeal, string(label))
	}
	// the pad is the seal's, not the table's
	reflected := body.ProtoReflect()
	reflected.Clear(reflected.Descriptor().Fields().ByNumber(bridgeSharePadField))
	return nil
}

// SHA-256 of a sealed table as network_bridge_share stores it: what a BridgeShareGrant pins.
func BridgeShareTableSha256(sealed []byte) []byte {
	sum := sha256.Sum256(sealed)
	return sum[:]
}
