// §10.5's deliveries, which carry RK_g to a holder outside the MLS tree: a ReaderWrap to a sidecar's ReaderKey,
// a DelegationWrap to a Delegation's reader key, and a RecoveryWrap to a member's recovery key. Each is
// HPKE-XWing (QD-441): KEM 0x647a, HKDF-SHA256, AES-128-GCM, base mode, through crypto/hpke's Sender, since
// hpke.Seal takes no AAD, and each is enc || ct, 1,168 bytes.
//
//	wrap_aad      u8(1 ReaderWrap | 2 DelegationWrap) || group_id || u64be(g) || C_g || SHA-256(recipient)
//	              || recipient_key_sha256 || u8(delivery_kind), then, LATE only, u64be(auth.version) ||
//	              auth.chain || i64be(time_ms)
//	recovery aad  member_id || group_id || u64be(g) || C_g || b8, b8 being SHA-256(the binding's Ed25519 key)[0:8]
//
// A KeyDelivery names the key it was sealed to, and wrap_aad binds that digest, so a delivery to one ReaderKey
// never opens as one to another (D-KEYS-24, FI-28): moving it to another key's path changes its AAD. Who may
// sign a delivery, and at what state, is §10.9's delivery checks' (KEYS-M2-19); this file holds a delivery to
// its format and its signature, and opens one only for the recipient it names, at a key it holds, when RK_g
// matches gen/<g>'s C_g.
//
// A ReaderKey is valid from its signing until a not_after at most 7 days later (D-KEYS-25), and a delivery
// seals to one only if time_ms < not_after <= time_ms + 7 days + 10 min, the 10 minutes being gkm's clock
// skew (§10.5's readerkey row). Those are protocol bounds, not settings.
//
// On every leg, with no connect import. Every key created, loaded or unwrapped here passes through
// testHookSecret before its first use. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The formats of 10.5's deliveries.
const (
	// A Delegation's id, SHA-256 of its Signed (§10.5).
	gkmDelegationIdByteCount = sha256.Size
	// enc of X-Wing.
	gkmXWingEncapsulationByteCount = 1120
	// HPKE-XWing of a 32-byte key: enc, the key and AES-128-GCM's tag.
	gkmHpkeWrapByteCount = gkmXWingEncapsulationByteCount + gkmRepoKeyByteCount + 16
	// The first bytes of a key digest that k8 and b8 write in hex (§10.6).
	gkmDigestPrefixByteCount = 8

	gkmWrapInfo     = "UR evs 1.0 wrap"
	gkmRecoveryInfo = "UR evs 1.0 recovery"

	gkmReaderKeyPurpose  = "reader-key"
	gkmReaderWrapPurpose = "reader-wrap"

	// The longest a ReaderKey lives after its signing (D-KEYS-25).
	GkmReaderKeyLifetime = 7 * 24 * time.Hour
	// The clock skew gkm allows, which a delivery's check adds to that lifetime (§10.5's readerkey row).
	GkmClockSkew = 10 * time.Minute
)

// Which signed delivery a KeyDelivery rides in: wrap_aad's first byte.
type GkmWrapType uint8

const (
	// To a sidecar's ReaderKey; recipient is its sidecar_id.
	GkmWrapTypeReader GkmWrapType = 1
	// To a Delegation's reader key; recipient is its delegation_id.
	GkmWrapTypeDelegation GkmWrapType = 2
)

// The SignedType a delivery of this type is signed as, or none.
func (self GkmWrapType) signedType() (bridge.SignedType, bool) {
	switch self {
	case GkmWrapTypeReader:
		return bridge.SignedType_SIGNED_READER_WRAP, true
	case GkmWrapTypeDelegation:
		return bridge.SignedType_SIGNED_DELEGATION_WRAP, true
	}
	return bridge.SignedType_SIGNED_TYPE_NONE, false
}

// How long the type's recipient id is, or 0 for no type.
func (self GkmWrapType) recipientByteCount() int {
	switch self {
	case GkmWrapTypeReader:
		return gkmIdByteCount
	case GkmWrapTypeDelegation:
		return gkmDelegationIdByteCount
	}
	return 0
}

// KeyDelivery.delivery_kind (§10.9).
type GkmDeliveryKind uint32

const (
	// By gen/<g>'s rotator before its claim, judged against the claim's holders.
	GkmDeliveryStaged GkmDeliveryKind = 1
	// After the claim, by any holder but a read_only one, carrying its signer's state and time.
	GkmDeliveryLate GkmDeliveryKind = 2
)

// What a delivery seals RK_g to, besides the key.
type GkmDeliveryArgs struct {
	// The group of the delivery's wrap/ path (§10.6), the group gen/<g> names.
	GroupId Id
	Type    GkmWrapType
	// A sidecar_id for a ReaderWrap, a delegation_id for a DelegationWrap.
	Recipient []byte
	// The X-Wing public key sealed to: a checked ReaderKey's, or the Delegation's reader_xwing_public_key.
	RecipientPublicKey []byte
	Kind               GkmDeliveryKind
	// LATE only: the signer's newest verified state when it signs.
	Auth *bridge.AuthPin
	// LATE only: the signer's clock or, if later, gen/<g>'s time_ms.
	Time time.Time
}

// RK_g sealed to one recipient's key as a KeyDelivery, unsigned (§10.5's step 3 and late row).
func SealGkmDelivery(key *EvsRepoKey, args *GkmDeliveryArgs) (*protocol.KeyDelivery, error) {
	if err := key.checkHeld(); err != nil {
		return nil, err
	}
	if args == nil {
		return nil, fmt.Errorf("%w: no delivery", ErrGkmMalformed)
	}
	publicKey, err := hpke.MLKEM768X25519().NewPublicKey(args.RecipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: recipient key: %w", ErrGkmMalformed, err)
	}
	recipientKeySha256 := sha256.Sum256(args.RecipientPublicKey)
	delivery := &protocol.KeyDelivery{
		GroupId:            args.GroupId.Bytes(),
		Generation:         key.generation,
		Commitment:         bytes.Clone(key.commitment),
		Recipient:          bytes.Clone(args.Recipient),
		RecipientKeySha256: recipientKeySha256[:],
		DeliveryKind:       uint32(args.Kind),
	}
	if args.Kind == GkmDeliveryLate {
		if args.Auth == nil || args.Time.IsZero() {
			return nil, fmt.Errorf("%w: a LATE delivery needs its auth pin and time", ErrGkmMalformed)
		}
		delivery.Auth = proto.Clone(args.Auth).(*bridge.AuthPin)
		delivery.TimeMs = args.Time.UnixMilli()
	}
	aad, err := gkmWrapAad(args.Type, delivery)
	if err != nil {
		return nil, err
	}
	ciphertext, err := gkmHpkeSeal(publicKey, gkmWrapInfo, aad, key.repoKey)
	if err != nil {
		return nil, err
	}
	delivery.Ciphertext = ciphertext
	return delivery, nil
}

// wrap_aad for a delivery of this type, and its format: a delivery that cannot be one refuses here.
func gkmWrapAad(wrapType GkmWrapType, delivery *protocol.KeyDelivery) ([]byte, error) {
	malformed := func(reason string) error {
		return fmt.Errorf("%w: KeyDelivery %s", ErrGkmMalformed, reason)
	}
	if wrapType.recipientByteCount() == 0 {
		return nil, malformed("of no wrap type")
	}
	if len(delivery.GetGroupId()) != gkmIdByteCount || delivery.GetGeneration() == 0 ||
		len(delivery.GetCommitment()) != gkmCommitmentByteCount {
		return nil, malformed("generation pin")
	}
	if len(delivery.GetRecipient()) != wrapType.recipientByteCount() {
		return nil, malformed("recipient")
	}
	if len(delivery.GetRecipientKeySha256()) != gkmDigestByteCount {
		return nil, malformed("key digest")
	}
	recipientSha256 := sha256.Sum256(delivery.GetRecipient())

	aad := make([]byte, 0, 1+gkmIdByteCount+8+gkmCommitmentByteCount+2*gkmDigestByteCount+1+8+gkmAuthChainByteCount+8)
	aad = append(aad, byte(wrapType))
	aad = append(aad, delivery.GetGroupId()...)
	aad = binary.BigEndian.AppendUint64(aad, delivery.GetGeneration())
	aad = append(aad, delivery.GetCommitment()...)
	aad = append(aad, recipientSha256[:]...)
	aad = append(aad, delivery.GetRecipientKeySha256()...)
	switch GkmDeliveryKind(delivery.GetDeliveryKind()) {
	case GkmDeliveryStaged:
		if delivery.GetAuth() != nil || delivery.GetTimeMs() != 0 {
			return nil, malformed("STAGED with an auth pin or time")
		}
		aad = append(aad, byte(GkmDeliveryStaged))
	case GkmDeliveryLate:
		auth := delivery.GetAuth()
		if auth == nil || auth.GetVersion() == 0 || len(auth.GetChain()) != gkmAuthChainByteCount || delivery.GetTimeMs() <= 0 {
			return nil, malformed("LATE without its auth pin and time")
		}
		aad = append(aad, byte(GkmDeliveryLate))
		aad = binary.BigEndian.AppendUint64(aad, auth.GetVersion())
		aad = append(aad, auth.GetChain()...)
		aad = binary.BigEndian.AppendUint64(aad, uint64(delivery.GetTimeMs()))
	default:
		return nil, malformed("of no delivery kind")
	}
	return aad, nil
}

// A delivery as signed: ReaderWrap{wrap} or DelegationWrap{wrap}, deterministically encoded, under the signer's
// identity key, purpose reader-wrap for both (§10.5).
func SignGkmDelivery(delivery *protocol.KeyDelivery, wrapType GkmWrapType, sign GkmSignFunction) (*bridge.Signed, error) {
	signedType, ok := wrapType.signedType()
	if !ok {
		return nil, fmt.Errorf("%w: no wrap type %d", ErrGkmMalformed, wrapType)
	}
	if _, err := gkmWrapAad(wrapType, delivery); err != nil {
		return nil, err
	}
	if len(delivery.GetCiphertext()) != gkmHpkeWrapByteCount {
		return nil, fmt.Errorf("%w: KeyDelivery ciphertext of %d bytes", ErrGkmMalformed, len(delivery.GetCiphertext()))
	}
	var wrapper proto.Message
	if wrapType == GkmWrapTypeReader {
		wrapper = &protocol.ReaderWrap{Wrap: delivery}
	} else {
		wrapper = &protocol.DelegationWrap{Wrap: delivery}
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(wrapper)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGkmMalformed, err)
	}
	return gkmSign(gkmReaderWrapPurpose, signedType, body, sign)
}

// A signed delivery as received and verified: the Signed bytes, whose identity key signed them, which wrap it
// came in and the KeyDelivery inside.
type GkmDelivery struct {
	Signed   *bridge.Signed
	SignerId Id
	Type     GkmWrapType
	Body     *protocol.KeyDelivery
}

// A ReaderWrap or DelegationWrap, wrapType saying which the caller expects, verified under its signer's
// identity key, which identityKey resolves, and held to its format. Whether its signer may deliver, at its
// state, is §10.9's delivery checks' (KEYS-M2-19).
func ParseGkmDelivery(signed *bridge.Signed, wrapType GkmWrapType, identityKey GkmIdentityKeyFunction) (*GkmDelivery, error) {
	signedType, ok := wrapType.signedType()
	if !ok {
		return nil, fmt.Errorf("%w: no wrap type %d", ErrGkmMalformed, wrapType)
	}
	if signed == nil {
		return nil, fmt.Errorf("%w: no delivery", ErrGkmMalformed)
	}
	signerId, err := IdFromBytes(signed.GetSignerId())
	if err != nil {
		return nil, fmt.Errorf("%w: delivery names no signer", ErrGkmMalformed)
	}
	publicKey, err := identityKey(signerId)
	if err != nil {
		return nil, err
	}
	err = bridge.VerifySigned(signed, gkmReaderWrapPurpose, signedType, bridge.SignedKeyAlgEd25519, publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGkmAuthentication, err)
	}
	var delivery *protocol.KeyDelivery
	if wrapType == GkmWrapTypeReader {
		wrapper := &protocol.ReaderWrap{}
		if err := proto.Unmarshal(signed.GetBody(), wrapper); err != nil {
			return nil, fmt.Errorf("%w: ReaderWrap: %w", ErrGkmMalformed, err)
		}
		delivery = wrapper.GetWrap()
	} else {
		wrapper := &protocol.DelegationWrap{}
		if err := proto.Unmarshal(signed.GetBody(), wrapper); err != nil {
			return nil, fmt.Errorf("%w: DelegationWrap: %w", ErrGkmMalformed, err)
		}
		delivery = wrapper.GetWrap()
	}
	if delivery == nil {
		return nil, fmt.Errorf("%w: a wrap with no KeyDelivery", ErrGkmMalformed)
	}
	if _, err := gkmWrapAad(wrapType, delivery); err != nil {
		return nil, err
	}
	if len(delivery.GetCiphertext()) != gkmHpkeWrapByteCount {
		return nil, fmt.Errorf("%w: KeyDelivery ciphertext of %d bytes", ErrGkmMalformed, len(delivery.GetCiphertext()))
	}
	return &GkmDelivery{Signed: signed, SignerId: signerId, Type: wrapType, Body: delivery}, nil
}

// RK_g from a delivery to recipient at privateKey, accepted against generation, gen/<g>'s verified statement
// (§10.9's use row). The delivery must name recipient and the digest of privateKey's public key, and its group,
// generation and commitment gen/<g>'s (§10.9's body row), before anything is decapsulated. A re-formed group's
// deliveries of its old generations name the new group (QD-074(7)), which KEYS-M2-25 admits along the form chain;
// until then they refuse here.
func OpenGkmDelivery(delivery *GkmDelivery, generation *GkmGeneration, recipient []byte, privateKey hpke.PrivateKey) (*EvsRepoKey, error) {
	if delivery == nil || delivery.Body == nil {
		return nil, fmt.Errorf("%w: no delivery", ErrGkmKeyMissing)
	}
	if generation == nil || generation.Rotate == nil {
		return nil, fmt.Errorf("%w: no gen/<g> to check a key against", ErrGkmKeyMissing)
	}
	body := delivery.Body
	if !bytes.Equal(body.GetRecipient(), recipient) {
		return nil, fmt.Errorf("%w: a delivery to another recipient", ErrGkmKeyMissing)
	}
	keySha256 := sha256.Sum256(privateKey.PublicKey().Bytes())
	if !bytes.Equal(body.GetRecipientKeySha256(), keySha256[:]) {
		return nil, fmt.Errorf("%w: a delivery to another key", ErrGkmKeyMissing)
	}
	if !bytes.Equal(body.GetGroupId(), generation.Rotate.GetGroupId()) || body.GetGeneration() != generation.Rotate.GetGeneration() ||
		!bytes.Equal(body.GetCommitment(), generation.Rotate.GetCommitment()) {
		return nil, fmt.Errorf("%w: a delivery of another generation", ErrGkmAuthentication)
	}
	aad, err := gkmWrapAad(delivery.Type, body)
	if err != nil {
		return nil, err
	}
	repoKey, err := gkmHpkeOpen(privateKey, gkmWrapInfo, aad, body.GetCiphertext())
	if err != nil {
		return nil, err
	}
	defer clear(repoKey)
	return OpenEvsRepoKey(generation, repoKey)
}

// What a sidecar publishes so that holders can deliver to it (§10.5's readerkey row).
type GkmReaderKey struct {
	Signed *bridge.Signed
	Body   *protocol.ReaderKey
	// xwing_public_key, parsed.
	PublicKey hpke.PublicKey
	// SHA-256 of xwing_public_key: a delivery's recipient_key_sha256, and k8's source.
	KeySha256 []byte
}

// A fresh X-Wing pair for sidecarId and its ReaderKey, signed at signedAt with notAfter at most
// GkmReaderKeyLifetime later (D-KEYS-25). The caller keeps the private key until 30 days past notAfter and
// never re-signs it (§10.5's readerkey row).
func NewGkmReaderKey(sidecarId Id, signedAt time.Time, notAfter time.Time, sign GkmSignFunction) (*bridge.Signed, hpke.PrivateKey, error) {
	if !signedAt.Before(notAfter) || signedAt.Add(GkmReaderKeyLifetime).Before(notAfter) {
		return nil, nil, fmt.Errorf("%w: a ReaderKey lives after its signing, at most %s", ErrGkmMalformed, GkmReaderKeyLifetime)
	}
	privateKey, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("gkm: reader key: %w", err)
	}
	if err := gkmHookPrivateKey("reader_private_key", privateKey); err != nil {
		return nil, nil, err
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ReaderKey{
		SidecarId:      sidecarId.Bytes(),
		XwingPublicKey: privateKey.PublicKey().Bytes(),
		NotAfter:       notAfter.UnixMilli(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrGkmMalformed, err)
	}
	signed, err := gkmSign(gkmReaderKeyPurpose, bridge.SignedType_SIGNED_READER_KEY, body, sign)
	if err != nil {
		return nil, nil, err
	}
	return signed, privateKey, nil
}

// A ReaderKey private key from its stored 32-byte seed, as a keychain load unwraps it.
func LoadGkmReaderKey(seed []byte) (hpke.PrivateKey, error) {
	privateKey, err := hpke.MLKEM768X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, fmt.Errorf("%w: reader key: %w", ErrGkmMalformed, err)
	}
	if err := gkmHookPrivateKey("reader_private_key", privateKey); err != nil {
		return nil, err
	}
	return privateKey, nil
}

// A Delegation's reader key from its 32-byte delegation_reader_seed, X-Wing's own seed (QD-466), which opens
// the DelegationWraps to its reader_xwing_public_key.
func LoadGkmDelegationKey(seed []byte) (hpke.PrivateKey, error) {
	privateKey, err := hpke.MLKEM768X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, fmt.Errorf("%w: delegation key: %w", ErrGkmMalformed, err)
	}
	if err := gkmHookPrivateKey("delegation_reader_key", privateKey); err != nil {
		return nil, err
	}
	return privateKey, nil
}

// A ReaderKey a delivery may seal to at timeMs: signed by identityPublicKey, s's admitted identity key, for
// sidecarId, with timeMs < not_after <= timeMs + 7 days + 10 min (§10.5's readerkey row). A lapse is no
// expiry of the holder (§7.9): it stops deliveries to this key and nothing else.
func CheckGkmReaderKey(signed *bridge.Signed, sidecarId Id, identityPublicKey []byte, timeMs int64) (*GkmReaderKey, error) {
	err := bridge.VerifySigned(signed, gkmReaderKeyPurpose, bridge.SignedType_SIGNED_READER_KEY, bridge.SignedKeyAlgEd25519, identityPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGkmAuthentication, err)
	}
	body := &protocol.ReaderKey{}
	if err := proto.Unmarshal(signed.GetBody(), body); err != nil {
		return nil, fmt.Errorf("%w: ReaderKey: %w", ErrGkmMalformed, err)
	}
	if !bytes.Equal(body.GetSidecarId(), sidecarId.Bytes()) {
		return nil, fmt.Errorf("%w: a ReaderKey of another sidecar", ErrGkmMalformed)
	}
	if len(body.GetXwingPublicKey()) != gkmXWingPublicKeyByteCount {
		return nil, fmt.Errorf("%w: a ReaderKey's key of %d bytes", ErrGkmMalformed, len(body.GetXwingPublicKey()))
	}
	publicKey, err := hpke.MLKEM768X25519().NewPublicKey(body.GetXwingPublicKey())
	if err != nil {
		return nil, fmt.Errorf("%w: ReaderKey: %w", ErrGkmMalformed, err)
	}
	latestNotAfter := timeMs + (GkmReaderKeyLifetime + GkmClockSkew).Milliseconds()
	if notAfter := body.GetNotAfter(); notAfter <= timeMs || latestNotAfter < notAfter {
		return nil, fmt.Errorf("%w: a ReaderKey not valid at %d", ErrGkmKeyMissing, timeMs)
	}
	keySha256 := sha256.Sum256(body.GetXwingPublicKey())
	return &GkmReaderKey{Signed: signed, Body: body, PublicKey: publicKey, KeySha256: keySha256[:]}, nil
}

// What a RecoveryWrap binds RK_g to, besides the key (QD-468).
type GkmRecoveryArgs struct {
	MemberId Id
	// The group of its recovery/ path, the group gen/<g> names.
	GroupId Id
	// The binding's X-Wing recovery public key, from its RecoveryBind (§7.9).
	RecoveryPublicKey []byte
	// SHA-256 of the binding's Ed25519 key, RecoveryBind's ed25519_public_key_sha256: b8 is its first 8 bytes.
	BindingKeySha256 []byte
}

// The recovery aad: member_id || group_id || u64be(g) || C_g || b8.
func gkmRecoveryAad(args *GkmRecoveryArgs, generation uint64, commitment []byte) ([]byte, error) {
	if len(args.BindingKeySha256) != gkmDigestByteCount || len(commitment) != gkmCommitmentByteCount {
		return nil, fmt.Errorf("%w: a RecoveryWrap's binding or commitment", ErrGkmMalformed)
	}
	aad := append(args.MemberId.Bytes(), args.GroupId.Bytes()...)
	aad = binary.BigEndian.AppendUint64(aad, generation)
	aad = append(aad, commitment...)
	return append(aad, args.BindingKeySha256[:gkmDigestPrefixByteCount]...), nil
}

// RecoveryWrap_{m,g}: RK_g to member m's recovery key, unsigned, bare enc || ct (QD-468, §10.8).
func SealGkmRecoveryWrap(key *EvsRepoKey, args *GkmRecoveryArgs) ([]byte, error) {
	if err := key.checkHeld(); err != nil {
		return nil, err
	}
	if args == nil {
		return nil, fmt.Errorf("%w: no recovery wrap", ErrGkmMalformed)
	}
	publicKey, err := hpke.MLKEM768X25519().NewPublicKey(args.RecoveryPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: recovery key: %w", ErrGkmMalformed, err)
	}
	aad, err := gkmRecoveryAad(args, key.generation, key.commitment)
	if err != nil {
		return nil, err
	}
	return gkmHpkeSeal(publicKey, gkmRecoveryInfo, aad, key.repoKey)
}

// RK_g from member m's RecoveryWrap, opened with its recovery key and accepted against generation, gen/<g>'s
// verified statement, whose group args.GroupId must be, as a delivery's is. args.RecoveryPublicKey is not read:
// privateKey is the key.
func OpenGkmRecoveryWrap(ciphertext []byte, generation *GkmGeneration, args *GkmRecoveryArgs, privateKey hpke.PrivateKey) (*EvsRepoKey, error) {
	if generation == nil || generation.Rotate == nil {
		return nil, fmt.Errorf("%w: no gen/<g> to check a key against", ErrGkmKeyMissing)
	}
	if args == nil {
		return nil, fmt.Errorf("%w: no recovery wrap", ErrGkmMalformed)
	}
	if !bytes.Equal(args.GroupId.Bytes(), generation.Rotate.GetGroupId()) {
		return nil, fmt.Errorf("%w: a recovery wrap of another group", ErrGkmAuthentication)
	}
	aad, err := gkmRecoveryAad(args, generation.Rotate.GetGeneration(), generation.Rotate.GetCommitment())
	if err != nil {
		return nil, err
	}
	repoKey, err := gkmHpkeOpen(privateKey, gkmRecoveryInfo, aad, ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(repoKey)
	return OpenEvsRepoKey(generation, repoKey)
}

// HPKE-XWing of a 32-byte key in base mode: enc || ct.
func gkmHpkeSeal(publicKey hpke.PublicKey, info string, aad []byte, plaintext []byte) ([]byte, error) {
	encapsulation, sender, err := hpke.NewSender(publicKey, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(info))
	if err != nil {
		return nil, fmt.Errorf("gkm: hpke setup: %w", err)
	}
	ciphertext, err := sender.Seal(aad, plaintext)
	if err != nil {
		return nil, fmt.Errorf("gkm: hpke seal: %w", err)
	}
	return append(encapsulation, ciphertext...), nil
}

// The key in enc || ct, hooked, or ErrGkmAuthentication.
func gkmHpkeOpen(privateKey hpke.PrivateKey, info string, aad []byte, sealed []byte) ([]byte, error) {
	if len(sealed) != gkmHpkeWrapByteCount {
		return nil, fmt.Errorf("%w: a wrap of %d bytes", ErrGkmMalformed, len(sealed))
	}
	recipient, err := hpke.NewRecipient(sealed[:gkmXWingEncapsulationByteCount], privateKey, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(info))
	if err != nil {
		return nil, fmt.Errorf("%w: hpke setup: %w", ErrGkmAuthentication, err)
	}
	plaintext, err := recipient.Open(aad, sealed[gkmXWingEncapsulationByteCount:])
	if err != nil {
		return nil, fmt.Errorf("%w: wrap does not open", ErrGkmAuthentication)
	}
	testHookSecret("RK_g", plaintext)
	return plaintext, nil
}
