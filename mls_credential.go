// §10.4's credential, private-use type 0xF552 (ur_sidecar), whose UrMlsCredential binds a leaf's MLS signature
// key to its sidecar_id and identity key under the identity key's own signature. It needs no MLS code, so member
// checks reach it before the leaf codec carries it (KEYS-M2-07).
//
// identity_signature covers fields 1 to 7 as received (QD-440): the signed bytes are
// "urnetwork-sidecar-v1/mls-credential" || 0x00 || u32be(0x1306) || body, body being the credential's bytes up to
// field 8's tag. So the encoding has one form, which a reader holds it to and verifies over, never a re-marshal
// (§22.6): each of fields 1 to 8 exactly once, in order, as its own wire type, with minimal varints, no unknown
// field, and nothing after field 8.
//
// A credential is checked here against its own signature and format alone. Whether a SidecarAdmit admits its
// identity key for its sidecar is the member checks' (KEYS-M2-19). not_after is evidence only (QD-057): its value
// refuses nothing here, and a reader judges a stale Remove by it.
//
// On every leg, with no connect import. No key is created, derived or unwrapped here, so nothing calls
// testHookSecret. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The credential's formats (§10.4).
const (
	mlsCredentialPurpose = "mls-credential"
	// identity_alg in v0 (owner decision 44).
	mlsCredentialIdentityAlg = "ed25519"
	// UrMlsCredential's field numbers, in the order they are written.
	mlsCredentialFieldSidecarId             protowire.Number = 1
	mlsCredentialFieldIdentityPublicKey     protowire.Number = 2
	mlsCredentialFieldIdentityAlg           protowire.Number = 3
	mlsCredentialFieldMlsSignaturePublicKey protowire.Number = 4
	mlsCredentialFieldCipherSuite           protowire.Number = 5
	mlsCredentialFieldNotAfter              protowire.Number = 6
	mlsCredentialFieldAdmissionSha256       protowire.Number = 7
	mlsCredentialFieldIdentitySignature     protowire.Number = 8
)

// What a credential states, which SignUrMlsCredential signs.
type UrMlsCredentialArgs struct {
	SidecarId         Id
	IdentityPublicKey ed25519.PublicKey
	// The leaf's Ed25519 key, which a self-update rotates.
	MlsSignaturePublicKey []byte
	// The signing time plus 90 days, a KeyPackage's life (QD-057).
	NotAfter time.Time
	// SHA-256 of the sidecar's SidecarAdmit, or of the Genesis for a network's first device.
	AdmissionSha256 []byte
}

// A credential's encoding, signed by the identity key it names through sign, and held to CheckUrMlsCredential
// before it is returned, so a sign function under another key fails here and not at a member.
func SignUrMlsCredential(args *UrMlsCredentialArgs, sign GkmSignFunction) ([]byte, error) {
	if args == nil || args.NotAfter.UnixMilli() <= 0 {
		return nil, fmt.Errorf("%w: a credential needs its not_after", ErrGkmMalformed)
	}
	body := protowire.AppendTag(nil, mlsCredentialFieldSidecarId, protowire.BytesType)
	body = protowire.AppendBytes(body, args.SidecarId.Bytes())
	body = protowire.AppendTag(body, mlsCredentialFieldIdentityPublicKey, protowire.BytesType)
	body = protowire.AppendBytes(body, args.IdentityPublicKey)
	body = protowire.AppendTag(body, mlsCredentialFieldIdentityAlg, protowire.BytesType)
	body = protowire.AppendString(body, mlsCredentialIdentityAlg)
	body = protowire.AppendTag(body, mlsCredentialFieldMlsSignaturePublicKey, protowire.BytesType)
	body = protowire.AppendBytes(body, args.MlsSignaturePublicKey)
	body = protowire.AppendTag(body, mlsCredentialFieldCipherSuite, protowire.VarintType)
	body = protowire.AppendVarint(body, uint64(mlsCipherSuiteXWing))
	body = protowire.AppendTag(body, mlsCredentialFieldNotAfter, protowire.VarintType)
	body = protowire.AppendVarint(body, uint64(args.NotAfter.UnixMilli()))
	body = protowire.AppendTag(body, mlsCredentialFieldAdmissionSha256, protowire.BytesType)
	body = protowire.AppendBytes(body, args.AdmissionSha256)

	signed, err := gkmSign(mlsCredentialPurpose, bridge.SignedType_SIGNED_UR_MLS_CREDENTIAL, body, sign)
	if err != nil {
		return nil, err
	}
	encoded := protowire.AppendTag(bytes.Clone(body), mlsCredentialFieldIdentitySignature, protowire.BytesType)
	encoded = protowire.AppendBytes(encoded, signed.GetSignature())
	if _, err := CheckUrMlsCredential(encoded); err != nil {
		return nil, err
	}
	return encoded, nil
}

// A credential's fields, once its encoding is the one form above, its cipher suite 0x0010, its identity
// algorithm ed25519, every field at its size, and identity_signature verifies over the received bytes before
// field 8 under the identity key it names.
func CheckUrMlsCredential(encoded []byte) (*protocol.UrMlsCredential, error) {
	malformed := func(reason string) error {
		return fmt.Errorf("%w: credential %s", ErrGkmMalformed, reason)
	}
	credential := &protocol.UrMlsCredential{}
	remaining := encoded
	signedByteCount := 0
	for field := mlsCredentialFieldSidecarId; field <= mlsCredentialFieldIdentitySignature; field += 1 {
		if field == mlsCredentialFieldIdentitySignature {
			signedByteCount = len(encoded) - len(remaining)
		}
		number, wireType, tagByteCount := protowire.ConsumeTag(remaining)
		if tagByteCount < 0 || tagByteCount != protowire.SizeTag(number) {
			return nil, malformed("tag")
		}
		if number != field {
			return nil, malformed(fmt.Sprintf("field %d where field %d belongs", number, field))
		}
		remaining = remaining[tagByteCount:]
		switch field {
		case mlsCredentialFieldCipherSuite, mlsCredentialFieldNotAfter:
			if wireType != protowire.VarintType {
				return nil, malformed(fmt.Sprintf("field %d's wire type", field))
			}
			value, valueByteCount := protowire.ConsumeVarint(remaining)
			if valueByteCount < 0 || valueByteCount != protowire.SizeVarint(value) {
				return nil, malformed(fmt.Sprintf("field %d's varint", field))
			}
			remaining = remaining[valueByteCount:]
			if field == mlsCredentialFieldCipherSuite {
				if value != uint64(mlsCipherSuiteXWing) {
					return nil, malformed(fmt.Sprintf("of cipher suite %#x", value))
				}
				credential.CipherSuite = uint32(value)
			} else {
				if int64(value) <= 0 {
					return nil, malformed("not_after")
				}
				credential.NotAfter = int64(value)
			}
		default:
			if wireType != protowire.BytesType {
				return nil, malformed(fmt.Sprintf("field %d's wire type", field))
			}
			value, valueByteCount := protowire.ConsumeBytes(remaining)
			if valueByteCount < 0 || valueByteCount-len(value) != protowire.SizeVarint(uint64(len(value))) {
				return nil, malformed(fmt.Sprintf("field %d's length", field))
			}
			remaining = remaining[valueByteCount:]
			value = bytes.Clone(value)
			switch field {
			case mlsCredentialFieldSidecarId:
				credential.SidecarId = value
			case mlsCredentialFieldIdentityPublicKey:
				credential.IdentityPublicKey = value
			case mlsCredentialFieldIdentityAlg:
				credential.IdentityAlg = string(value)
			case mlsCredentialFieldMlsSignaturePublicKey:
				credential.MlsSignaturePublicKey = value
			case mlsCredentialFieldAdmissionSha256:
				credential.AdmissionSha256 = value
			case mlsCredentialFieldIdentitySignature:
				credential.IdentitySignature = value
			}
		}
	}
	if len(remaining) != 0 {
		return nil, malformed("with bytes after field 8")
	}

	if len(credential.GetSidecarId()) != gkmIdByteCount {
		return nil, malformed("sidecar_id")
	}
	if credential.GetIdentityAlg() != mlsCredentialIdentityAlg {
		return nil, malformed("identity algorithm")
	}
	if len(credential.GetIdentityPublicKey()) != ed25519.PublicKeySize {
		return nil, malformed("identity key")
	}
	if len(credential.GetMlsSignaturePublicKey()) != ed25519.PublicKeySize {
		return nil, malformed("signature key")
	}
	if len(credential.GetAdmissionSha256()) != gkmDigestByteCount {
		return nil, malformed("admission hash")
	}
	if len(credential.GetIdentitySignature()) != ed25519.SignatureSize {
		return nil, malformed("signature")
	}
	signed := &bridge.Signed{
		Body:      encoded[:signedByteCount],
		Signature: credential.GetIdentitySignature(),
		Type:      uint32(bridge.SignedType_SIGNED_UR_MLS_CREDENTIAL),
	}
	err := bridge.VerifySigned(signed, mlsCredentialPurpose, bridge.SignedType_SIGNED_UR_MLS_CREDENTIAL, bridge.SignedKeyAlgEd25519, credential.GetIdentityPublicKey())
	if err != nil {
		return nil, fmt.Errorf("%w: credential: %w", ErrGkmAuthentication, err)
	}
	return credential, nil
}
