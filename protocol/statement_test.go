// Statements as the log carries them, across the two packages, which is why these sit here: protocol/bridge sees none
// of protocol. §22.6's typed Signed case, a body that parses as two statements being still only the one it was signed
// as; a share's alias showing nothing of its target; and a recovery key's statements verifying from rows alone.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Two statements that encode alike, told apart by the signed type alone, whichever way a relay lies about it.
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

// §17.9 seals a share's targets from every server, host included, and §17.8's gates never see an alias. Each canary
// below is in the row, and the filing's bytes hold none of them, however the seal turns out: the stand-in here only has
// to differ from its input, since what is under test is what sits beside the seal.
func TestBridgeAliasShowsNoShareTarget(t *testing.T) {
	shareId := bytes.Repeat([]byte{0xA1}, 16)
	hostId := bytes.Repeat([]byte{0xA2}, 16)
	aliasAddress := uint32(0xC6336400) // 198.51.100.0
	body, err := proto.Marshal(&bridge.BridgeAliasBody{
		ShareId:     shareId,
		TargetIndex: 3,
		AliasPrefix: &bridge.BridgeIpv4Prefix{Address: aliasAddress, Length: 24},
		Host:        hostId,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, hostId) || !bytes.Contains(body, shareId) {
		t.Fatal("the canaries must be in the row, or this proves nothing")
	}
	sealedBody := make([]byte, len(body))
	for i := range body {
		sealedBody[i] = body[i] ^ 0xFF
	}

	filing, err := proto.Marshal(&bridge.BridgeAlias{
		Header: &bridge.StatementHeader{
			NetworkId:  bytes.Repeat([]byte{0x01}, 16),
			At:         &bridge.AuthPin{Version: 7, Chain: bytes.Repeat([]byte{0x02}, 32)},
			Nonce:      bytes.Repeat([]byte{0x03}, 16),
			NotAfterMs: 1,
		},
		SealedBody: sealedBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(filing, hostId) {
		t.Error("the filing shows the target's host")
	}
	if bytes.Contains(filing, shareId) {
		t.Error("the filing shows the share")
	}
}

// §7.9's "before admission" row from end to end: a recovery key signs each statement it can, and a verifier holding only
// what api holds, the RecoveryBind's clear fields compiled into a MemberRow, checks it. The key's one source is the
// statement, as RecoveryBindBody is sealed from api, so this fails if nothing carries it. A later rebind leaves the
// old key refused.
func TestRecoverySignedStatementsVerifyFromTheirRow(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x66}, ed25519.SeedSize))
	publicKey := key.Public().(ed25519.PublicKey)
	publicKeySha256 := sha256.Sum256(publicKey)
	memberId := bytes.Repeat([]byte{0x04}, 16)
	sidecarId := bytes.Repeat([]byte{0x05}, 16)
	header := &bridge.StatementHeader{
		NetworkId:  bytes.Repeat([]byte{0x01}, 16),
		At:         &bridge.AuthPin{Version: 7, Chain: bytes.Repeat([]byte{0x02}, 32)},
		Nonce:      bytes.Repeat([]byte{0x03}, 16),
		NotAfterMs: 1,
	}

	bind := &RecoveryBind{
		Header:                 header,
		MemberId:               memberId,
		Ed25519PublicKeySha256: publicKeySha256[:],
		SealedBody:             []byte("opaque"),
	}
	row := &bridge.MemberRow{MemberId: bind.GetMemberId(), RecoveryKeySha256: bind.GetEd25519PublicKeySha256()}
	bindBytes, err := proto.Marshal(bind)
	if err != nil {
		t.Fatal(err)
	}
	rowBytes, err := proto.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bindBytes, publicKey) || bytes.Contains(rowBytes, publicKey) {
		t.Fatal("the key shows outside the statement, so this would prove nothing")
	}

	admit := &SidecarAdmit{
		Header:            header,
		NetworkId:         header.GetNetworkId(),
		SidecarId:         sidecarId,
		IdentityPublicKey: bytes.Repeat([]byte{0x06}, ed25519.PublicKeySize),
		IdentityAlg:       "ed25519",
		MemberId:          memberId,
	}
	admitBody, err := proto.Marshal(admit)
	if err != nil {
		t.Fatal(err)
	}
	proposal := &AuthorityProposal{
		Header:        header,
		StatementType: uint32(bridge.SignedType_SIGNED_SIDECAR_ADMIT),
		Statement:     admitBody,
	}
	cosign := &AuthorityCosign{Header: header, ProposalId: bytes.Repeat([]byte{0x07}, sha256.Size)}

	purpose := "authority"
	cases := []struct {
		name       string
		signedType bridge.SignedType
		statement  proto.Message
	}{
		{name: "SidecarAdmit", signedType: bridge.SignedType_SIGNED_SIDECAR_ADMIT, statement: admit},
		{name: "AuthorityProposal", signedType: bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, statement: proposal},
		{name: "AuthorityCosign", signedType: bridge.SignedType_SIGNED_AUTHORITY_COSIGN, statement: cosign},
	}
	otherKeySha256 := sha256.Sum256(bytes.Repeat([]byte{0x08}, ed25519.PublicKeySize))
	for _, c := range cases {
		body, err := proto.Marshal(c.statement)
		if err != nil {
			t.Fatal(err)
		}
		entryBody, err := proto.Marshal(&bridge.Signed{
			Body:      body,
			SignerId:  memberId,
			KeyId:     publicKey,
			Signature: ed25519.Sign(key, bridge.SignedBytes(purpose, c.signedType, body)),
			Type:      uint32(c.signedType),
		})
		if err != nil {
			t.Fatal(err)
		}
		entry, err := proto.Marshal(&bridge.AuthEntry{Kind: 2, Body: entryBody})
		if err != nil {
			t.Fatal(err)
		}

		decodedEntry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entry, decodedEntry); err != nil {
			t.Fatal(err)
		}
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(decodedEntry.GetBody(), signed); err != nil {
			t.Fatal(err)
		}
		err = bridge.VerifyRecoverySigned(signed, purpose, c.signedType, row.GetRecoveryKeySha256())
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		err = bridge.VerifyRecoverySigned(signed, purpose, c.signedType, otherKeySha256[:])
		if !errors.Is(err, bridge.ErrSignedKey) {
			t.Errorf("%s under a later binding: %v", c.name, err)
		}
	}
}
