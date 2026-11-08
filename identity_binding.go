// The identity binding (§5.5, X10, D-CORE-5): one client generation of a sidecar, naming its network, sidecar_id,
// client id, generation, both public keys and its time, signed by the ClientKey and by the identity key, so a peer
// resolves a client to its sidecar from signed bytes and a copied token cannot bind a key of its own. POST
// /sidecar/bind appends each to a never-reaped log, §6's Hello checks it before any other byte (D-PROTO-13), and
// §17.9 resolves subjects through it.
//
// The wire is plan-CORE-binding-wire #1's: SignedSidecarIdentityBinding{body, client_signature,
// identity_signature} in protocol/bridge/auth.proto, body being a SidecarIdentityBinding's bytes, each signature
// Ed25519 over §6.9's signed bytes of body with type SIGNED_SIDECAR_BINDING, purpose binding-client by the
// ClientKey and binding-identity by the identity key. A verifier checks the body as received, never a re-marshal,
// and takes only the canonical encoding of either message, so one binding has one byte string, which api stores
// verbatim and compares for a retry (plan-CORE-binding-wire #5).
//
// VerifySidecarIdentityBinding is exported and connect-free, because server, §6's Hello and §17.9 call it. It
// checks the binding's own signatures and nothing about who may hold the keys: a caller compares the identity key
// with its pin or the config's SidecarAdmit, and the client id and public key with the session or token it has.
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §5.5's binding purposes (plan-CORE-binding-wire #1): the ClientKey's signature and the identity key's.
const (
	sidecarBindingClientPurpose   = "binding-client"
	sidecarBindingIdentityPurpose = "binding-identity"
)

// The most bytes a binding may take on the wire. The canonical encoding of a binding is under 250 bytes, so this
// only stops a decoder reading garbage whole.
const sidecarBindingMaxByteCount = 4 * 1024

// A binding that does not decode, is not canonical, has a field out of its format, or whose signatures do not
// verify. The error says which and never repeats the bytes.
var ErrSidecarBindingInvalid = errors.New("sidecar identity binding invalid")

// Signs binding with both keys and answers the marshalled SignedSidecarIdentityBinding, the bytes Hello and POST
// /sidecar/bind carry. identitySeed and clientKeySeed are the two Ed25519 seeds, read and not kept. The binding's
// public keys are those the seeds make: one left empty is filled in, and one that differs is refused. Every id must
// be set, generation must be at least 1 and IssuedAt must be set, as VerifySidecarIdentityBinding requires.
func NewSidecarIdentityBinding(binding *SidecarIdentityBinding, identitySeed []byte, clientKeySeed []byte) ([]byte, error) {
	if binding == nil || len(identitySeed) != ed25519.SeedSize || len(clientKeySeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: a binding needs both 32-byte seeds", ErrSidecarBindingInvalid)
	}
	identityKey := ed25519.NewKeyFromSeed(identitySeed)
	clientKey := ed25519.NewKeyFromSeed(clientKeySeed)
	defer clear(identityKey)
	defer clear(clientKey)
	identityPublicKey := identityKey.Public().(ed25519.PublicKey)
	clientPublicKey := clientKey.Public().(ed25519.PublicKey)
	if 0 < len(binding.IdentityPublicKey) && !bytes.Equal(binding.IdentityPublicKey, identityPublicKey) {
		return nil, fmt.Errorf("%w: the identity public key is not the identity seed's", ErrSidecarBindingInvalid)
	}
	if 0 < len(binding.ClientPublicKey) && !bytes.Equal(binding.ClientPublicKey, clientPublicKey) {
		return nil, fmt.Errorf("%w: the client public key is not the ClientKey seed's", ErrSidecarBindingInvalid)
	}
	body := &bridge.SidecarIdentityBinding{
		NetworkId:         binding.NetworkId.Bytes(),
		SidecarId:         binding.SidecarId.Bytes(),
		ClientId:          binding.ClientId.Bytes(),
		Generation:        binding.Generation,
		ClientPublicKey:   clientPublicKey,
		IdentityPublicKey: identityPublicKey,
		IssuedAtMs:        binding.IssuedAt.UnixMilli(),
	}
	if err := checkSidecarBindingBody(body); err != nil {
		return nil, err
	}
	bodyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("%w: the body does not encode", ErrSidecarBindingInvalid)
	}
	signed := &bridge.SignedSidecarIdentityBinding{
		Body: bodyBytes,
		ClientSignature: ed25519.Sign(clientKey,
			bridge.SignedBytes(sidecarBindingClientPurpose, bridge.SignedType_SIGNED_SIDECAR_BINDING, bodyBytes)),
		IdentitySignature: ed25519.Sign(identityKey,
			bridge.SignedBytes(sidecarBindingIdentityPurpose, bridge.SignedType_SIGNED_SIDECAR_BINDING, bodyBytes)),
	}
	signedBinding, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		return nil, fmt.Errorf("%w: the binding does not encode", ErrSidecarBindingInvalid)
	}
	// what a verifier would refuse is never handed out
	if _, err := VerifySidecarIdentityBinding(signedBinding); err != nil {
		return nil, err
	}
	return signedBinding, nil
}

// Checks signedBinding, the marshalled SignedSidecarIdentityBinding as received, and answers what it binds. nil
// says both signatures verify over the received body under the keys the body names, every field has its format,
// and both messages are in their canonical encoding with nothing unknown. It says nothing about whether those keys
// belong to this sidecar_id: the caller checks the identity key against its pin or the config, and the client id
// and key against the session or token it holds (§6.4, §5.15).
func VerifySidecarIdentityBinding(signedBinding []byte) (*SidecarIdentityBinding, error) {
	if len(signedBinding) == 0 || sidecarBindingMaxByteCount < len(signedBinding) {
		return nil, fmt.Errorf("%w: its size", ErrSidecarBindingInvalid)
	}
	signed := &bridge.SignedSidecarIdentityBinding{}
	if err := proto.Unmarshal(signedBinding, signed); err != nil {
		return nil, fmt.Errorf("%w: it does not decode", ErrSidecarBindingInvalid)
	}
	if !isCanonicalSidecarBindingMessage(signed, signedBinding) {
		return nil, fmt.Errorf("%w: it is not in its canonical encoding", ErrSidecarBindingInvalid)
	}
	body := &bridge.SidecarIdentityBinding{}
	if err := proto.Unmarshal(signed.GetBody(), body); err != nil {
		return nil, fmt.Errorf("%w: its body does not decode", ErrSidecarBindingInvalid)
	}
	if !isCanonicalSidecarBindingMessage(body, signed.GetBody()) {
		return nil, fmt.Errorf("%w: its body is not in its canonical encoding", ErrSidecarBindingInvalid)
	}
	if err := checkSidecarBindingBody(body); err != nil {
		return nil, err
	}
	clientSignedBytes := bridge.SignedBytes(sidecarBindingClientPurpose, bridge.SignedType_SIGNED_SIDECAR_BINDING, signed.GetBody())
	if !ed25519.Verify(body.GetClientPublicKey(), clientSignedBytes, signed.GetClientSignature()) {
		return nil, fmt.Errorf("%w: the ClientKey's signature", ErrSidecarBindingInvalid)
	}
	identitySignedBytes := bridge.SignedBytes(sidecarBindingIdentityPurpose, bridge.SignedType_SIGNED_SIDECAR_BINDING, signed.GetBody())
	if !ed25519.Verify(body.GetIdentityPublicKey(), identitySignedBytes, signed.GetIdentitySignature()) {
		return nil, fmt.Errorf("%w: the identity key's signature", ErrSidecarBindingInvalid)
	}
	// every id was checked to decode
	networkId, _ := IdFromBytes(body.GetNetworkId())
	sidecarId, _ := IdFromBytes(body.GetSidecarId())
	clientId, _ := IdFromBytes(body.GetClientId())
	return &SidecarIdentityBinding{
		NetworkId:         networkId,
		SidecarId:         sidecarId,
		ClientId:          clientId,
		Generation:        body.GetGeneration(),
		ClientPublicKey:   bytes.Clone(body.GetClientPublicKey()),
		IdentityPublicKey: bytes.Clone(body.GetIdentityPublicKey()),
		IssuedAt:          time.UnixMilli(body.GetIssuedAtMs()).UTC(),
	}, nil
}

// Whether every field of body has its format: three set 16-byte ids, a generation of at least 1, two distinct
// 32-byte Ed25519 public keys, since the ClientKey must never stand for the identity key (D-CORE-6), and a time.
func checkSidecarBindingBody(body *bridge.SidecarIdentityBinding) error {
	for _, idBytes := range [][]byte{body.GetNetworkId(), body.GetSidecarId(), body.GetClientId()} {
		id, err := IdFromBytes(idBytes)
		if err != nil || id == (Id{}) {
			return fmt.Errorf("%w: an id is not set", ErrSidecarBindingInvalid)
		}
	}
	if body.GetGeneration() < 1 {
		return fmt.Errorf("%w: the generation is below 1", ErrSidecarBindingInvalid)
	}
	if len(body.GetClientPublicKey()) != ed25519.PublicKeySize || len(body.GetIdentityPublicKey()) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: a public key is not 32 bytes", ErrSidecarBindingInvalid)
	}
	if bytes.Equal(body.GetClientPublicKey(), body.GetIdentityPublicKey()) {
		return fmt.Errorf("%w: the ClientKey is the identity key", ErrSidecarBindingInvalid)
	}
	if body.GetIssuedAtMs() <= 0 {
		return fmt.Errorf("%w: no time", ErrSidecarBindingInvalid)
	}
	return nil
}

// Whether encoded is message's canonical encoding: nothing unknown, and the bytes a deterministic marshal gives,
// which for these messages of scalars and bytes in field order is the one encoding.
func isCanonicalSidecarBindingMessage(message proto.Message, encoded []byte) bool {
	if len(message.ProtoReflect().GetUnknown()) != 0 {
		return false
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	return err == nil && bytes.Equal(canonical, encoded)
}
