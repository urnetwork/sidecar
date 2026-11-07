// §10.5's deliveries: wrap_aad and wrap paths as fixed vectors (§22.5, §22.10), the HPKE seals under a fixed random
// stream, each AAD field's binding, a delivery to one key never opening under another (FI-28), and a ReaderKey's
// window at its exact bounds.

package sidecar

import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"testing/cryptotest"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

//go:embed testdata/gkm/wrap_aad.json
var gkmWrapAadVectorsJson []byte

//go:embed testdata/gkm/wrap_paths.json
var gkmWrapPathVectorsJson []byte

// A recipient's X-Wing key from a label.
func gkmTestRecipientKey(t *testing.T, label string) hpke.PrivateKey {
	t.Helper()
	privateKey, err := hpke.MLKEM768X25519().NewPrivateKey(gkmTestBytes("recipient "+label, 32))
	if err != nil {
		t.Fatal(err)
	}
	return privateKey
}

// A LATE delivery's state and time.
func gkmTestLateArgs(groupId Id, wrapType GkmWrapType, recipient []byte, publicKey []byte) *GkmDeliveryArgs {
	return &GkmDeliveryArgs{
		GroupId:            groupId,
		Type:               wrapType,
		Recipient:          recipient,
		RecipientPublicKey: publicKey,
		Kind:               GkmDeliveryLate,
		Auth:               gkmTestAuth(57),
		Time:               gkmTestTime.Add(time.Minute),
	}
}

// A delivery signed and parsed back, as its recipient fetches it.
func gkmTestDelivery(t *testing.T, signer *gkmTestSigner, key *EvsRepoKey, args *GkmDeliveryArgs) *GkmDelivery {
	t.Helper()
	body, err := SealGkmDelivery(key, args)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignGkmDelivery(body, args.Type, signer.sign)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := ParseGkmDelivery(signed, args.Type, signer.identityKey)
	if err != nil {
		t.Fatal(err)
	}
	return delivery
}

func TestGkmDeliveriesOpenForTheirRecipient(t *testing.T) {
	signer := newGkmTestSigner("rotator")
	keys, generations := gkmTestLadder(t, signer)
	groupId := keys[2].GroupId()
	readerKey := gkmTestRecipientKey(t, "reader")
	reader := gkmTestId("reader sidecar")
	delegationKey := gkmTestRecipientKey(t, "delegation")
	delegation := gkmTestBytes("delegation id", gkmDelegationIdByteCount)

	staged := gkmTestDelivery(t, signer, keys[2], &GkmDeliveryArgs{
		GroupId:            groupId,
		Type:               GkmWrapTypeReader,
		Recipient:          reader.Bytes(),
		RecipientPublicKey: readerKey.PublicKey().Bytes(),
		Kind:               GkmDeliveryStaged,
	})
	if len(staged.Body.GetCiphertext()) != 1168 {
		t.Errorf("a wrap of %d bytes", len(staged.Body.GetCiphertext()))
	}
	opened, err := OpenGkmDelivery(staged, generations[2], reader.Bytes(), readerKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.repoKey, keys[2].repoKey) || staged.SignerId != signer.sidecarId {
		t.Error("another key or signer")
	}

	late := gkmTestDelivery(t, signer, keys[2], gkmTestLateArgs(groupId, GkmWrapTypeDelegation, delegation, delegationKey.PublicKey().Bytes()))
	opened, err = OpenGkmDelivery(late, generations[2], delegation, delegationKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.repoKey, keys[2].repoKey) {
		t.Error("another key")
	}
	if late.Body.GetAuth().GetVersion() != 57 || late.Body.GetTimeMs() != gkmTestTime.Add(time.Minute).UnixMilli() {
		t.Error("the LATE delivery lost its state or time")
	}

	// A delivery opens only for its recipient, at its key, of its generation.
	if _, err := OpenGkmDelivery(staged, generations[2], gkmTestId("someone else").Bytes(), readerKey); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("another recipient: %v", err)
	}
	if _, err := OpenGkmDelivery(staged, generations[2], reader.Bytes(), delegationKey); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("another key: %v", err)
	}
	if _, err := OpenGkmDelivery(staged, generations[1], reader.Bytes(), readerKey); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("against gen/2: %v", err)
	}
	if _, err := OpenGkmDelivery(staged, nil, reader.Bytes(), readerKey); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("no gen/<g>: %v", err)
	}
	otherGroup := gkmTestDelivery(t, signer, keys[2], &GkmDeliveryArgs{
		GroupId:            gkmTestId("another group"),
		Type:               GkmWrapTypeReader,
		Recipient:          reader.Bytes(),
		RecipientPublicKey: readerKey.PublicKey().Bytes(),
		Kind:               GkmDeliveryStaged,
	})
	if _, err := OpenGkmDelivery(otherGroup, generations[2], reader.Bytes(), readerKey); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("a delivery naming another group: %v", err)
	}
}

// FI-28: a delivery to K0 never opens under K1. Its body names K0's digest, which wrap_aad binds, so relabeling it
// for K1, as moving it to K1's path would need, opens nothing under either key.
func TestGkmDeliveryToOneKeyNeverOpensUnderAnother(t *testing.T) {
	signer := newGkmTestSigner("rotator")
	keys, generations := gkmTestLadder(t, signer)
	reader := gkmTestId("reader sidecar")
	firstKey := gkmTestRecipientKey(t, "K0")
	secondKey := gkmTestRecipientKey(t, "K1")
	delivery := gkmTestDelivery(t, signer, keys[2], &GkmDeliveryArgs{
		GroupId:            keys[2].GroupId(),
		Type:               GkmWrapTypeReader,
		Recipient:          reader.Bytes(),
		RecipientPublicKey: firstKey.PublicKey().Bytes(),
		Kind:               GkmDeliveryStaged,
	})
	if _, err := OpenGkmDelivery(delivery, generations[2], reader.Bytes(), secondKey); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("under K1: %v", err)
	}
	relabeled := &GkmDelivery{Type: delivery.Type, Body: proto.Clone(delivery.Body).(*protocol.KeyDelivery)}
	secondKeySha256 := sha256.Sum256(secondKey.PublicKey().Bytes())
	relabeled.Body.RecipientKeySha256 = secondKeySha256[:]
	if _, err := OpenGkmDelivery(relabeled, generations[2], reader.Bytes(), secondKey); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("relabeled for K1, under K1: %v", err)
	}
	if _, err := OpenGkmDelivery(relabeled, generations[2], reader.Bytes(), firstKey); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("relabeled for K1, under K0: %v", err)
	}
	firstPath, _ := GkmDeliveryPath(keys[2].GroupId(), delivery)
	secondPath, _ := GkmDeliveryPath(keys[2].GroupId(), relabeled)
	if firstPath == secondPath {
		t.Error("two keys share a wrap path")
	}
}

// Each field of wrap_aad, changed alone after sealing, opens nothing (§10.5).
func TestGkmWrapAadFieldsEachBind(t *testing.T) {
	keys, _ := gkmTestLadder(t, newGkmTestSigner("rotator"))
	recipientKey := gkmTestRecipientKey(t, "reader")
	delegation := gkmTestBytes("delegation id", gkmDelegationIdByteCount)
	sealed, err := SealGkmDelivery(keys[2], gkmTestLateArgs(keys[2].GroupId(), GkmWrapTypeDelegation, delegation, recipientKey.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	aad, err := gkmWrapAad(GkmWrapTypeDelegation, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gkmHpkeOpen(recipientKey, gkmWrapInfo, aad, sealed.GetCiphertext()); err != nil {
		t.Fatalf("does not open as sealed: %v", err)
	}
	mutations := map[string]func(delivery *protocol.KeyDelivery){
		"group_id":             func(delivery *protocol.KeyDelivery) { delivery.GroupId[0] ^= 1 },
		"g":                    func(delivery *protocol.KeyDelivery) { delivery.Generation += 1 },
		"C_g":                  func(delivery *protocol.KeyDelivery) { delivery.Commitment[31] ^= 1 },
		"recipient":            func(delivery *protocol.KeyDelivery) { delivery.Recipient[0] ^= 1 },
		"recipient_key_sha256": func(delivery *protocol.KeyDelivery) { delivery.RecipientKeySha256[0] ^= 1 },
		"auth.version":         func(delivery *protocol.KeyDelivery) { delivery.Auth.Version += 1 },
		"auth.chain":           func(delivery *protocol.KeyDelivery) { delivery.Auth.Chain[0] ^= 1 },
		"time_ms":              func(delivery *protocol.KeyDelivery) { delivery.TimeMs += 1 },
	}
	for name, mutate := range mutations {
		changed := proto.Clone(sealed).(*protocol.KeyDelivery)
		mutate(changed)
		changedAad, err := gkmWrapAad(GkmWrapTypeDelegation, changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := gkmHpkeOpen(recipientKey, gkmWrapInfo, changedAad, sealed.GetCiphertext()); !errors.Is(err, ErrGkmAuthentication) {
			t.Errorf("%s changed: %v", name, err)
		}
	}
	// The wrap type and delivery kind, which change the AAD's own bytes rather than a body field.
	for index, change := range []func(aad []byte){
		func(aad []byte) { aad[0] = byte(GkmWrapTypeReader) },
		func(aad []byte) {
			aad[1+gkmIdByteCount+8+gkmCommitmentByteCount+2*gkmDigestByteCount] = byte(GkmDeliveryStaged)
		},
	} {
		changedAad := bytes.Clone(aad)
		change(changedAad)
		if _, err := gkmHpkeOpen(recipientKey, gkmWrapInfo, changedAad, sealed.GetCiphertext()); !errors.Is(err, ErrGkmAuthentication) {
			t.Errorf("AAD change %d: %v", index, err)
		}
	}
	// The LATE tail dropped, as if relabeled STAGED.
	if _, err := gkmHpkeOpen(recipientKey, gkmWrapInfo, aad[:len(aad)-8-32-8], sealed.GetCiphertext()); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("without its LATE tail: %v", err)
	}
}

func TestGkmDeliveryFormat(t *testing.T) {
	signer := newGkmTestSigner("rotator")
	keys, _ := gkmTestLadder(t, signer)
	recipientKey := gkmTestRecipientKey(t, "reader")
	reader := gkmTestId("reader sidecar").Bytes()
	staged := &GkmDeliveryArgs{
		GroupId:            keys[2].GroupId(),
		Type:               GkmWrapTypeReader,
		Recipient:          reader,
		RecipientPublicKey: recipientKey.PublicKey().Bytes(),
		Kind:               GkmDeliveryStaged,
	}
	refusals := map[string]func(args *GkmDeliveryArgs){
		"no wrap type":             func(args *GkmDeliveryArgs) { args.Type = 0 },
		"a long sidecar_id":        func(args *GkmDeliveryArgs) { args.Recipient = append(bytes.Clone(args.Recipient), 0) },
		"a sidecar_id as delegate": func(args *GkmDeliveryArgs) { args.Type = GkmWrapTypeDelegation },
		"no delivery kind":         func(args *GkmDeliveryArgs) { args.Kind = 0 },
		"LATE without a state":     func(args *GkmDeliveryArgs) { args.Kind = GkmDeliveryLate },
		"a malformed key":          func(args *GkmDeliveryArgs) { args.RecipientPublicKey = args.RecipientPublicKey[:1215] },
	}
	for name, mutate := range refusals {
		args := *staged
		mutate(&args)
		if _, err := SealGkmDelivery(keys[2], &args); !errors.Is(err, ErrGkmMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}

	body, err := SealGkmDelivery(keys[2], staged)
	if err != nil {
		t.Fatal(err)
	}
	withAuth := proto.Clone(body).(*protocol.KeyDelivery)
	withAuth.Auth = gkmTestAuth(3)
	withTime := proto.Clone(body).(*protocol.KeyDelivery)
	withTime.TimeMs = 1
	shortCiphertext := proto.Clone(body).(*protocol.KeyDelivery)
	shortCiphertext.Ciphertext = shortCiphertext.Ciphertext[:1167]
	for name, changed := range map[string]*protocol.KeyDelivery{
		"STAGED with an auth pin": withAuth,
		"STAGED with a time":      withTime,
		"a short ciphertext":      shortCiphertext,
	} {
		if _, err := SignGkmDelivery(changed, GkmWrapTypeReader, signer.sign); !errors.Is(err, ErrGkmMalformed) {
			t.Errorf("%s signed: %v", name, err)
		}
		wrapper, _ := proto.Marshal(&protocol.ReaderWrap{Wrap: changed})
		signed, _ := signer.sign(gkmReaderWrapPurpose, bridge.SignedType_SIGNED_READER_WRAP, wrapper, nil)
		if _, err := ParseGkmDelivery(signed, GkmWrapTypeReader, signer.identityKey); !errors.Is(err, ErrGkmMalformed) {
			t.Errorf("%s parsed: %v", name, err)
		}
	}

	// A ReaderWrap is no DelegationWrap: the type is signed, and so is its purpose.
	signed, err := SignGkmDelivery(body, GkmWrapTypeReader, signer.sign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGkmDelivery(signed, GkmWrapTypeDelegation, signer.identityKey); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("a ReaderWrap as a DelegationWrap: %v", err)
	}
	asGenRotate, _ := signer.sign(gkmGenRotatePurpose, bridge.SignedType_SIGNED_READER_WRAP, signed.GetBody(), nil)
	if _, err := ParseGkmDelivery(asGenRotate, GkmWrapTypeReader, signer.identityKey); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("signed under another purpose: %v", err)
	}
	other := newGkmTestSigner("someone else")
	if _, err := ParseGkmDelivery(signed, GkmWrapTypeReader, func(Id) ([]byte, error) { return other.publicKey(), nil }); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("another signer's key: %v", err)
	}
}

// §10.5's readerkey row at its exact bounds: time_ms < not_after <= time_ms + 7 days + 10 min, and a key lives at
// most 7 days after its signing.
func TestGkmReaderKeyWindow(t *testing.T) {
	signer := newGkmTestSigner("reader")
	signedAt := gkmTestTime
	notAfter := signedAt.Add(7 * 24 * time.Hour)
	signed, privateKey, err := NewGkmReaderKey(signer.sidecarId, signedAt, notAfter, signer.sign)
	if err != nil {
		t.Fatal(err)
	}
	notAfterMs := notAfter.UnixMilli()
	cases := []struct {
		timeMs int64
		valid  bool
	}{
		{timeMs: notAfterMs, valid: false},
		{timeMs: notAfterMs - 1, valid: true},
		{timeMs: signedAt.UnixMilli(), valid: true},
		{timeMs: notAfterMs - (7*24*time.Hour + 10*time.Minute).Milliseconds(), valid: true},
		{timeMs: notAfterMs - (7*24*time.Hour + 10*time.Minute).Milliseconds() - 1, valid: false},
	}
	for _, c := range cases {
		readerKey, err := CheckGkmReaderKey(signed, signer.sidecarId, signer.publicKey(), c.timeMs)
		if c.valid && err != nil {
			t.Errorf("at %d: %v", c.timeMs, err)
		}
		if !c.valid && !errors.Is(err, ErrGkmKeyMissing) {
			t.Errorf("at %d: %v", c.timeMs, err)
		}
		if c.valid && err == nil {
			keySha256 := sha256.Sum256(privateKey.PublicKey().Bytes())
			if !bytes.Equal(readerKey.KeySha256, keySha256[:]) || !bytes.Equal(readerKey.PublicKey.Bytes(), privateKey.PublicKey().Bytes()) {
				t.Error("another key")
			}
		}
	}

	if _, _, err := NewGkmReaderKey(signer.sidecarId, signedAt, notAfter.Add(time.Millisecond), signer.sign); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("7 days and 1 ms: %v", err)
	}
	if _, _, err := NewGkmReaderKey(signer.sidecarId, signedAt, signedAt, signer.sign); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("valid for nothing: %v", err)
	}
	other := newGkmTestSigner("someone else")
	if _, err := CheckGkmReaderKey(signed, signer.sidecarId, other.publicKey(), signedAt.UnixMilli()); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("not s's identity key: %v", err)
	}
	if _, err := CheckGkmReaderKey(signed, other.sidecarId, signer.publicKey(), signedAt.UnixMilli()); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("another sidecar's: %v", err)
	}
	loaded, err := LoadGkmReaderKey(mustPrivateKeyBytes(t, privateKey))
	if err != nil || !bytes.Equal(loaded.PublicKey().Bytes(), privateKey.PublicKey().Bytes()) {
		t.Errorf("a reloaded reader key: %v", err)
	}
}

// The seed of an X-Wing private key.
func mustPrivateKeyBytes(t *testing.T, privateKey hpke.PrivateKey) []byte {
	t.Helper()
	seed, err := privateKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return seed
}

func TestGkmRecoveryWrapOpensOnlyForItsBinding(t *testing.T) {
	signer := newGkmTestSigner("rotator")
	keys, generations := gkmTestLadder(t, signer)
	recoveryKey := gkmTestRecipientKey(t, "recovery")
	args := &GkmRecoveryArgs{
		MemberId:          gkmTestId("member"),
		GroupId:           keys[2].GroupId(),
		RecoveryPublicKey: recoveryKey.PublicKey().Bytes(),
		BindingKeySha256:  gkmTestBytes("binding", gkmDigestByteCount),
	}
	ciphertext, err := SealGkmRecoveryWrap(keys[2], args)
	if err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) != 1168 {
		t.Errorf("a RecoveryWrap of %d bytes, QD-468 says 1,168", len(ciphertext))
	}
	opened, err := OpenGkmRecoveryWrap(ciphertext, generations[2], args, recoveryKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.repoKey, keys[2].repoKey) {
		t.Error("another key")
	}
	mutations := map[string]func(args *GkmRecoveryArgs){
		"member_id": func(args *GkmRecoveryArgs) { args.MemberId = gkmTestId("another member") },
		"group_id":  func(args *GkmRecoveryArgs) { args.GroupId = gkmTestId("another group") },
		"b8": func(args *GkmRecoveryArgs) {
			args.BindingKeySha256 = gkmTestBytes("another binding", gkmDigestByteCount)
		},
	}
	// The AAD binds the group too, which a wrap sealed for another group, opened against this one's gen/<g>, shows.
	otherGroupArgs := *args
	otherGroupArgs.GroupId = gkmTestId("another group")
	otherGroupWrap, err := SealGkmRecoveryWrap(keys[2], &otherGroupArgs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenGkmRecoveryWrap(otherGroupWrap, generations[2], args, recoveryKey); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("a wrap sealed for another group: %v", err)
	}
	for name, mutate := range mutations {
		changed := *args
		mutate(&changed)
		if _, err := OpenGkmRecoveryWrap(ciphertext, generations[2], &changed, recoveryKey); !errors.Is(err, ErrGkmAuthentication) {
			t.Errorf("%s changed: %v", name, err)
		}
	}
	// g and C_g come from the statement it is opened against.
	if _, err := OpenGkmRecoveryWrap(ciphertext, generations[1], args, recoveryKey); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("against gen/2: %v", err)
	}
	// Only b8, the hash's first 8 bytes, is bound, as the path names only those.
	sameB8 := *args
	sameB8.BindingKeySha256 = bytes.Clone(args.BindingKeySha256)
	sameB8.BindingKeySha256[31] ^= 1
	if _, err := OpenGkmRecoveryWrap(ciphertext, generations[2], &sameB8, recoveryKey); err != nil {
		t.Errorf("a hash with the same b8: %v", err)
	}
	if _, err := OpenGkmRecoveryWrap(ciphertext, generations[2], args, gkmTestRecipientKey(t, "another code")); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("another recovery key: %v", err)
	}
}

// wrap_aad and the recovery aad as §10.5 and QD-468 spell them, built by hand.
func TestGkmDeliveryAadsAreSection105s(t *testing.T) {
	groupId := gkmTestId("group")
	commitment := gkmTestBytes("commitment", 32)
	recipient := gkmTestBytes("delegation id", 32)
	keySha256 := gkmTestBytes("key digest", 32)
	late := &protocol.KeyDelivery{
		GroupId:            groupId.Bytes(),
		Generation:         3,
		Commitment:         commitment,
		Recipient:          recipient,
		RecipientKeySha256: keySha256,
		DeliveryKind:       2,
		Auth:               gkmTestAuth(57),
		TimeMs:             1767225660000,
	}
	recipientSha256 := sha256.Sum256(recipient)
	want := []byte{2}
	want = append(want, groupId[:]...)
	want = append(want, 0, 0, 0, 0, 0, 0, 0, 3)
	want = append(want, commitment...)
	want = append(want, recipientSha256[:]...)
	want = append(want, keySha256...)
	want = append(want, 2)
	want = binary.BigEndian.AppendUint64(want, 57)
	want = append(want, gkmTestAuth(57).GetChain()...)
	want = binary.BigEndian.AppendUint64(want, 1767225660000)
	aad, err := gkmWrapAad(GkmWrapTypeDelegation, late)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aad, want) {
		t.Errorf("wrap_aad\n%x\n%x", aad, want)
	}

	memberId := gkmTestId("member")
	binding := gkmTestBytes("binding", 32)
	want = append(append(append(memberId.Bytes(), groupId[:]...), 0, 0, 0, 0, 0, 0, 0, 3), commitment...)
	want = append(want, binding[:8]...)
	recoveryAad, err := gkmRecoveryAad(&GkmRecoveryArgs{MemberId: memberId, GroupId: groupId, BindingKeySha256: binding}, 3, commitment)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recoveryAad, want) {
		t.Errorf("recovery aad\n%x\n%x", recoveryAad, want)
	}
}

// What testdata/gkm/wrap_aad.json holds: wrap_aad and the recovery aad for fixed inputs, and HPKE-XWing seals of
// fixed keys under testing/cryptotest's random stream, since crypto/hpke takes no encapsulation seed.
type gkmWrapAadVectors struct {
	Aads     []gkmWrapAadVector   `json:"aads"`
	Recovery gkmRecoveryAadVector `json:"recovery"`
	Seals    []gkmHpkeSealVector  `json:"seals"`
}

// One delivery's wrap_aad.
type gkmWrapAadVector struct {
	Name               string          `json:"name"`
	Type               GkmWrapType     `json:"wrap_type"`
	GroupId            hexBytes        `json:"group_id"`
	Generation         uint64          `json:"generation"`
	Commitment         hexBytes        `json:"commitment"`
	Recipient          hexBytes        `json:"recipient"`
	RecipientKeySha256 hexBytes        `json:"recipient_key_sha256"`
	Kind               GkmDeliveryKind `json:"delivery_kind"`
	AuthVersion        uint64          `json:"auth_version,omitempty"`
	AuthChain          hexBytes        `json:"auth_chain,omitempty"`
	TimeMs             int64           `json:"time_ms,omitempty"`
	Aad                hexBytes        `json:"aad"`
}

// A RecoveryWrap's aad.
type gkmRecoveryAadVector struct {
	MemberId         hexBytes `json:"member_id"`
	GroupId          hexBytes `json:"group_id"`
	Generation       uint64   `json:"generation"`
	Commitment       hexBytes `json:"commitment"`
	BindingKeySha256 hexBytes `json:"binding_key_sha256"`
	Aad              hexBytes `json:"aad"`
}

// One HPKE-XWing seal of a key: a ReaderWrap's under "UR evs 1.0 wrap" or a RecoveryWrap's under "UR evs 1.0
// recovery".
type gkmHpkeSealVector struct {
	Name            string   `json:"name"`
	Info            string   `json:"info"`
	RecipientSeed   hexBytes `json:"recipient_seed"`
	RecipientSha256 hexBytes `json:"recipient_public_key_sha256"`
	RandomSeed      uint64   `json:"random_seed"`
	Aad             hexBytes `json:"aad"`
	Plaintext       hexBytes `json:"plaintext"`
	Sealed          hexBytes `json:"sealed"`
}

// The delivery bodies the vectors' AADs come from.
func gkmVectorDeliveries() []gkmWrapAadVector {
	groupId := gkmTestId("group")
	commitment := gkmTestBytes("commitment", 32)
	return []gkmWrapAadVector{
		{
			Name: "reader staged", Type: GkmWrapTypeReader, GroupId: groupId.Bytes(), Generation: 3, Commitment: commitment,
			Recipient: gkmTestId("reader sidecar").Bytes(), RecipientKeySha256: gkmTestBytes("reader key", 32), Kind: GkmDeliveryStaged,
		},
		{
			Name: "reader late", Type: GkmWrapTypeReader, GroupId: groupId.Bytes(), Generation: 3, Commitment: commitment,
			Recipient: gkmTestId("reader sidecar").Bytes(), RecipientKeySha256: gkmTestBytes("replaced reader key", 32),
			Kind: GkmDeliveryLate, AuthVersion: 57, AuthChain: gkmTestAuth(57).GetChain(), TimeMs: 1767225660000,
		},
		{
			Name: "delegation staged", Type: GkmWrapTypeDelegation, GroupId: groupId.Bytes(), Generation: 3, Commitment: commitment,
			Recipient: gkmTestBytes("delegation id", 32), RecipientKeySha256: gkmTestBytes("delegation key", 32), Kind: GkmDeliveryStaged,
		},
		{
			Name: "delegation late", Type: GkmWrapTypeDelegation, GroupId: groupId.Bytes(), Generation: 4, Commitment: gkmTestBytes("commitment 4", 32),
			Recipient: gkmTestBytes("delegation id", 32), RecipientKeySha256: gkmTestBytes("delegation key", 32),
			Kind: GkmDeliveryLate, AuthVersion: 1 << 40, AuthChain: gkmTestAuth(1).GetChain(), TimeMs: 1767225660001,
		},
	}
}

// A vector's KeyDelivery, ciphertext aside.
func (self *gkmWrapAadVector) delivery() *protocol.KeyDelivery {
	delivery := &protocol.KeyDelivery{
		GroupId:            self.GroupId,
		Generation:         self.Generation,
		Commitment:         self.Commitment,
		Recipient:          self.Recipient,
		RecipientKeySha256: self.RecipientKeySha256,
		DeliveryKind:       uint32(self.Kind),
		TimeMs:             self.TimeMs,
	}
	if self.Kind == GkmDeliveryLate {
		delivery.Auth = &bridge.AuthPin{Version: self.AuthVersion, Chain: self.AuthChain}
	}
	return delivery
}

// The wrap_aad vectors, computed by this build, the seals under each one's random stream.
func computeGkmWrapAadVectors(t *testing.T) *gkmWrapAadVectors {
	t.Helper()
	vectors := &gkmWrapAadVectors{}
	for _, vector := range gkmVectorDeliveries() {
		aad, err := gkmWrapAad(vector.Type, vector.delivery())
		if err != nil {
			t.Fatal(err)
		}
		vector.Aad = aad
		vectors.Aads = append(vectors.Aads, vector)
	}
	recovery := gkmRecoveryAadVector{
		MemberId:         gkmTestId("member").Bytes(),
		GroupId:          gkmTestId("group").Bytes(),
		Generation:       3,
		Commitment:       gkmTestBytes("commitment", 32),
		BindingKeySha256: gkmTestBytes("binding", 32),
	}
	recoveryAad, err := gkmRecoveryAad(&GkmRecoveryArgs{
		MemberId:         Id(recovery.MemberId),
		GroupId:          Id(recovery.GroupId),
		BindingKeySha256: recovery.BindingKeySha256,
	}, recovery.Generation, recovery.Commitment)
	if err != nil {
		t.Fatal(err)
	}
	recovery.Aad = recoveryAad
	vectors.Recovery = recovery

	for index, seal := range []gkmHpkeSealVector{
		{Name: "reader staged", Info: gkmWrapInfo, Aad: vectors.Aads[0].Aad},
		{Name: "delegation late", Info: gkmWrapInfo, Aad: vectors.Aads[3].Aad},
		{Name: "recovery", Info: gkmRecoveryInfo, Aad: recovery.Aad},
	} {
		seal.RecipientSeed = gkmTestBytes("hpke recipient "+seal.Name, 32)
		privateKey, err := hpke.MLKEM768X25519().NewPrivateKey(seal.RecipientSeed)
		if err != nil {
			t.Fatal(err)
		}
		recipientSha256 := sha256.Sum256(privateKey.PublicKey().Bytes())
		seal.RecipientSha256 = recipientSha256[:]
		seal.RandomSeed = uint64(index + 1)
		seal.Plaintext = gkmTestBytes("hpke key "+seal.Name, 32)
		cryptotest.SetGlobalRandom(t, seal.RandomSeed)
		sealed, err := gkmHpkeSeal(privateKey.PublicKey(), seal.Info, seal.Aad, seal.Plaintext)
		if err != nil {
			t.Fatal(err)
		}
		seal.Sealed = sealed
		vectors.Seals = append(vectors.Seals, seal)
	}
	return vectors
}

// wrap_aad, the recovery aad and the HPKE seals, equal on this leg to the file. A seal's opening is the stable
// half: crypto/hpke keeps the right to change how it draws an encapsulation, so a new toolchain failing only on
// the seals' bytes, with every opening passing, means that and not a broken wrap.
func TestGkmWrapAadVectors(t *testing.T) {
	computed := computeGkmWrapAadVectors(t)
	if *updateGkmVectors {
		writeGkmVectors(t, "testdata/gkm/wrap_aad.json", computed)
		return
	}
	stored := &gkmWrapAadVectors{}
	if err := json.Unmarshal(gkmWrapAadVectorsJson, stored); err != nil {
		t.Fatal(err)
	}
	for index, vector := range stored.Aads {
		aad, err := gkmWrapAad(vector.Type, vector.delivery())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(aad, vector.Aad) {
			t.Errorf("%s: wrap_aad %x", vector.Name, aad)
		}
		if index < len(computed.Aads) && !bytes.Equal(computed.Aads[index].Aad, vector.Aad) {
			t.Errorf("%s: this build's wrap_aad differs", vector.Name)
		}
	}
	recoveryAad, err := gkmRecoveryAad(&GkmRecoveryArgs{
		MemberId:         Id(stored.Recovery.MemberId),
		GroupId:          Id(stored.Recovery.GroupId),
		BindingKeySha256: stored.Recovery.BindingKeySha256,
	}, stored.Recovery.Generation, stored.Recovery.Commitment)
	if err != nil || !bytes.Equal(recoveryAad, stored.Recovery.Aad) {
		t.Errorf("recovery aad %x: %v", recoveryAad, err)
	}
	if len(stored.Seals) != len(computed.Seals) {
		t.Fatalf("%d seals stored, %d computed", len(stored.Seals), len(computed.Seals))
	}
	for index, seal := range stored.Seals {
		privateKey, err := hpke.MLKEM768X25519().NewPrivateKey(seal.RecipientSeed)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := gkmHpkeOpen(privateKey, seal.Info, seal.Aad, seal.Sealed)
		if err != nil || !bytes.Equal(opened, seal.Plaintext) {
			t.Errorf("%s does not open: %v", seal.Name, err)
		}
		if !bytes.Equal(computed.Seals[index].Sealed, seal.Sealed) {
			t.Errorf("%s: this build seals other bytes under random seed %d", seal.Name, seal.RandomSeed)
		}
	}
}

// What testdata/gkm/wrap_paths.json holds.
type gkmWrapPathVector struct {
	Name               string      `json:"name"`
	GroupId            hexBytes    `json:"group_id"`
	MemberId           hexBytes    `json:"member_id,omitempty"`
	Generation         uint64      `json:"generation"`
	Commitment         hexBytes    `json:"commitment,omitempty"`
	Type               GkmWrapType `json:"wrap_type,omitempty"`
	Recipient          hexBytes    `json:"recipient,omitempty"`
	RecipientKeySha256 hexBytes    `json:"recipient_key_sha256,omitempty"`
	BindingKeySha256   hexBytes    `json:"binding_key_sha256,omitempty"`
	Path               string      `json:"path"`
}

// The path a vector names, by its kind.
func (self *gkmWrapPathVector) build() (string, error) {
	switch {
	case self.Type != 0:
		return GkmWrapPath(Id(self.GroupId), self.Generation, self.Commitment, self.Type, self.Recipient, self.RecipientKeySha256)
	case self.BindingKeySha256 != nil:
		return GkmRecoveryWrapPath(Id(self.MemberId), Id(self.GroupId), self.Generation, self.Commitment, self.BindingKeySha256)
	}
	return GkmGenerationPath(Id(self.GroupId), self.Generation), nil
}

// The path vectors' inputs.
func gkmVectorPaths() []gkmWrapPathVector {
	groupId := gkmTestId("group").Bytes()
	commitment := gkmTestBytes("commitment", 32)
	return []gkmWrapPathVector{
		{Name: "gen 1", GroupId: groupId, Generation: 1},
		{Name: "gen max", GroupId: groupId, Generation: ^uint64(0)},
		{
			Name: "reader wrap", GroupId: groupId, Generation: 3, Commitment: commitment, Type: GkmWrapTypeReader,
			Recipient: gkmTestId("reader sidecar").Bytes(), RecipientKeySha256: gkmTestBytes("reader key", 32),
		},
		{
			Name: "delegation wrap", GroupId: groupId, Generation: 3, Commitment: commitment, Type: GkmWrapTypeDelegation,
			Recipient: gkmTestBytes("delegation id", 32), RecipientKeySha256: gkmTestBytes("delegation key", 32),
		},
		{
			Name: "recovery wrap", GroupId: groupId, MemberId: gkmTestId("member").Bytes(), Generation: 3, Commitment: commitment,
			BindingKeySha256: gkmTestBytes("binding", 32),
		},
	}
}

func TestGkmWrapPathVectors(t *testing.T) {
	var computed []gkmWrapPathVector
	for _, vector := range gkmVectorPaths() {
		path, err := vector.build()
		if err != nil {
			t.Fatal(err)
		}
		vector.Path = path
		computed = append(computed, vector)
	}
	if *updateGkmVectors {
		writeGkmVectors(t, "testdata/gkm/wrap_paths.json", computed)
		return
	}
	var stored []gkmWrapPathVector
	if err := json.Unmarshal(gkmWrapPathVectorsJson, &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != len(computed) {
		t.Fatalf("%d paths stored, %d computed", len(stored), len(computed))
	}
	for index, vector := range stored {
		path, err := vector.build()
		if err != nil {
			t.Fatal(err)
		}
		if path != vector.Path || path != computed[index].Path {
			t.Errorf("%s: %s", vector.Name, path)
		}
	}
}

// QD-442's encoding, spelled out from the vectors' own inputs.
func TestGkmWrapPathsAreQd442s(t *testing.T) {
	groupId := gkmTestId("group")
	commitment := gkmTestBytes("commitment", 32)
	sidecarId := gkmTestId("reader sidecar")
	keySha256 := gkmTestBytes("reader key", 32)
	path, err := GkmWrapPath(groupId, 3, commitment, GkmWrapTypeReader, sidecarId.Bytes(), keySha256)
	if err != nil {
		t.Fatal(err)
	}
	want := "gkm/" + hex.EncodeToString(groupId[:]) + "/wrap/00000000000000000003/" + hex.EncodeToString(commitment[:8]) +
		"/s:" + hex.EncodeToString(sidecarId[:]) + "/" + hex.EncodeToString(keySha256[:8])
	if path != want {
		t.Errorf("%s\n%s", path, want)
	}
	if path := GkmGenerationPath(groupId, ^uint64(0)); path != "gkm/"+hex.EncodeToString(groupId[:])+"/gen/18446744073709551615" {
		t.Errorf("gen path %s", path)
	}
	delegationPath, _ := GkmWrapPath(groupId, 3, commitment, GkmWrapTypeDelegation, gkmTestBytes("delegation id", 32), keySha256)
	if len(delegationPath) != len(path)+32 {
		t.Errorf("a delegation path of %d characters", len(delegationPath))
	}
	if _, err := GkmWrapPath(groupId, 3, commitment, GkmWrapTypeDelegation, sidecarId.Bytes(), keySha256); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("a sidecar_id as a delegation: %v", err)
	}
	for _, wrapType := range []GkmWrapType{0, 3} {
		if _, err := GkmWrapPath(groupId, 3, commitment, wrapType, nil, keySha256); !errors.Is(err, ErrGkmMalformed) {
			t.Errorf("wrap type %d: %v", wrapType, err)
		}
	}
	if _, err := GkmWrapPath(groupId, 3, commitment[:8], GkmWrapTypeReader, sidecarId.Bytes(), keySha256); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("c8 from a prefix: %v", err)
	}
	if _, err := GkmRecoveryWrapPath(gkmTestId("member"), groupId, 3, commitment, keySha256[:8]); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("b8 from a prefix: %v", err)
	}
}
