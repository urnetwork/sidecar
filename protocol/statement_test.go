// §22.6's typed Signed case across the two packages: a body that parses as two statements is still only
// the one it was signed as. It sits here because OwnerConfirm is protocol's and protocol/bridge sees none
// of protocol.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

func TestGrantRevokePresentedAsOwnerConfirmIsRefused(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, ed25519.SeedSize))
	publicKey := key.Public().(ed25519.PublicKey)
	header := &bridge.StatementHeader{
		NetworkId:  bytes.Repeat([]byte{0x01}, 16),
		At:         &bridge.AuthPin{Version: 7, Chain: bytes.Repeat([]byte{0x02}, 32)},
		Nonce:      bytes.Repeat([]byte{0x03}, 16),
		NotAfterMs: 1,
	}
	id := bytes.Repeat([]byte{0x04}, 16)

	body, err := proto.Marshal(&bridge.GrantRevoke{Header: header, GrantId: id})
	if err != nil {
		t.Fatal(err)
	}
	confirmBody, err := proto.Marshal(&OwnerConfirm{Header: header, SidecarId: id})
	if err != nil {
		t.Fatal(err)
	}
	// The two encode alike, so nothing in the body tells them apart and the type must.
	if !bytes.Equal(body, confirmBody) {
		t.Fatal("the fixture must give one body for both statements, or this proves nothing")
	}

	purpose := "acl"
	grantRevokeType := bridge.SignedType_SIGNED_GRANT_REVOKE
	ownerConfirmType := bridge.SignedType_SIGNED_OWNER_CONFIRM
	signed := &bridge.Signed{
		Body:      body,
		Signature: ed25519.Sign(key, bridge.SignedBytes(purpose, grantRevokeType, body)),
		Type:      uint32(grantRevokeType),
	}
	err = bridge.VerifySigned(signed, purpose, grantRevokeType, bridge.SignedKeyAlgEd25519, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	err = bridge.VerifySigned(signed, purpose, ownerConfirmType, bridge.SignedKeyAlgEd25519, publicKey)
	if !errors.Is(err, bridge.ErrSignedTypeMismatch) {
		t.Errorf("presented as OwnerConfirm: %v", err)
	}

	signed.Type = uint32(ownerConfirmType)
	err = bridge.VerifySigned(signed, purpose, ownerConfirmType, bridge.SignedKeyAlgEd25519, publicKey)
	if !errors.Is(err, bridge.ErrSignedSignature) {
		t.Errorf("rewritten to OwnerConfirm: %v", err)
	}
}
