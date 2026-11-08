// §22.10's ladder row (D-KEYS-10): GenWrap_e, LeafWrap and GenLink_g from an MLS epoch's exported secret, and
// KeyDelivery's wrap_aad, each written here from §10.5's text in code of this module's own and held byte-equal to
// what mls_* writes. A seal's nonce is random, so each is checked by opening mls_*'s seal under the key and AAD
// written here and sealing the plaintext again under the same nonce: equal bytes mean one key, one AAD, one cipher
// and one layout. mls_* then opens a seal made here, so the agreement runs both ways. An HPKE delivery encapsulates
// afresh, so wrap_aad is checked by opening mls_*'s ciphertext under the AAD written here, which an AEAD refuses for
// any other AAD.
//
//	KEK_e        MLS-Exporter("UR evs 1.0 kek", repo_id, 32)
//	C_g          SHA-256("UR evs 1.0 commit" || repo_id || u64be(g) || RK_g)
//	K_link_g     HKDF-SHA256(RK_g, salt repo_id, info "UR evs 1.0 link" || u64be(g)), 32 bytes
//	seal         nonce[24] || XChaCha20-Poly1305(key, nonce, plaintext, aad)
//	GenLink_g    seal(K_link_g, RK_{g-1}; aad repo_id || u64be(g) || u8(cause_g))
//	GenWrap_e    seal(KEK_e, RK_g; aad group_id || u64be(e) || u64be(g)), and LeafWrap alike at its epoch
//	wrap_aad     u8(1 ReaderWrap | 2 DelegationWrap) || group_id || u64be(g) || C_g || SHA-256(recipient)
//	             || recipient_key_sha256 || u8(delivery_kind), then, LATE only, u64be(auth.version) || auth.chain
//	             || i64be(time_ms); sealed HPKE-XWing, HKDF-SHA256 and AES-128-GCM, info "UR evs 1.0 wrap"
//
// The widths are keys-ladder-aad-widths.md's: u64be for a generation or an epoch, one byte for an enum.

package mlsinterop

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One sidecar's real engine, with a fresh identity key and store, admitting whatever credential its checks pass.
func ladderEngine(t *testing.T) sidecar.MlsEngine {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sidecarId := sidecar.NewId()
	admission := sha256.Sum256(append([]byte("ladder admission "), sidecarId.Bytes()...))
	engine, err := sidecar.NewMlsEngine(&sidecar.MlsEngineArgs{
		SidecarId:         sidecarId,
		IdentityPublicKey: publicKey,
		AdmissionSha256:   admission[:],
		Sign: func(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
			return &bridge.Signed{
				Body:      bytes.Clone(body),
				SignerId:  sidecarId.Bytes(),
				Signature: ed25519.Sign(privateKey, bridge.SignedBytes(purpose, signedType, body)),
				Type:      uint32(signedType),
			}, nil
		},
		Store:           sidecartest.NewFakeStore().Root(),
		CheckCredential: func(credential *protocol.UrMlsCredential) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

// seal, with its nonce given.
func ladderSeal(t *testing.T, key []byte, nonce []byte, plaintext []byte, aad []byte) []byte {
	t.Helper()
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	return aead.Seal(bytes.Clone(nonce), nonce, plaintext, aad)
}

// A seal's plaintext under key and aad, or the test fails.
func ladderOpen(t *testing.T, label string, key []byte, sealed []byte, aad []byte) []byte {
	t.Helper()
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != chacha20poly1305.NonceSizeX+32+chacha20poly1305.Overhead {
		t.Fatalf("%s: a seal of %d bytes, want 72", label, len(sealed))
	}
	nonce := sealed[:chacha20poly1305.NonceSizeX]
	plaintext, err := aead.Open(nil, nonce, sealed[chacha20poly1305.NonceSizeX:], aad)
	if err != nil {
		t.Fatalf("%s: does not open under the AAD written here: %v", label, err)
	}
	return plaintext
}

// Opens mls_*'s seal under key and aad and seals it again under the seal's own nonce: the bytes must not differ.
func ladderReproduce(t *testing.T, label string, key []byte, sealed []byte, aad []byte) []byte {
	t.Helper()
	plaintext := ladderOpen(t, label, key, sealed, aad)
	if again := ladderSeal(t, key, sealed[:chacha20poly1305.NonceSizeX], plaintext, aad); !bytes.Equal(again, sealed) {
		t.Errorf("%s: sealed again here, the bytes differ", label)
	}
	return plaintext
}

func ladderCommitment(repoId sidecar.Id, generation uint64, repoKey []byte) []byte {
	hasher := sha256.New()
	hasher.Write([]byte("UR evs 1.0 commit"))
	hasher.Write(repoId.Bytes())
	hasher.Write(binary.BigEndian.AppendUint64(nil, generation))
	hasher.Write(repoKey)
	return hasher.Sum(nil)
}

func ladderKeyWrapAad(groupId sidecar.Id, epoch uint64, generation uint64) []byte {
	return binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(groupId.Bytes(), epoch), generation)
}

func ladderGenLinkAad(repoId sidecar.Id, generation uint64, cause sidecar.GkmCause) []byte {
	return append(binary.BigEndian.AppendUint64(repoId.Bytes(), generation), byte(cause))
}

// GenWrap_e, LeafWrap and GenLink from a real epoch's KEK, reproduced here byte for byte, and opened by mls_* when
// sealed here.
func TestLadderSealsMatchMls(t *testing.T) {
	repoId, groupId, networkId := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	group, err := ladderEngine(t).CreateGroup(groupId, &sidecar.MlsUrGroup{NetworkId: networkId, RepoId: repoId, Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	if err != nil {
		t.Fatal(err)
	}
	kek, err := group.Exporter("UR evs 1.0 kek", repoId.Bytes(), 32)
	if err != nil {
		t.Fatal(err)
	}
	if rootKek, err := sidecar.MlsKek(group, repoId); err != nil || !bytes.Equal(rootKek, kek) {
		t.Fatalf("MlsKek is not the exporter's output under the kek label: %v", err)
	}

	holders := sha256.Sum256([]byte("ladder holders"))
	chain := sha256.Sum256([]byte("ladder chain"))
	args := func(cause sidecar.GkmCause, version uint64) *sidecar.GkmGenerationArgs {
		return &sidecar.GkmGenerationArgs{
			Cause:         cause,
			Auth:          &bridge.AuthPin{Version: version, Chain: chain[:]},
			Time:          time.UnixMilli(1_800_000_000_000),
			HoldersSha256: holders[:],
			LeafWrapKek:   kek,
			LeafWrapEpoch: group.Epoch(),
		}
	}
	first, firstRotate, err := sidecar.NewGkmFirstGeneration(repoId, groupId, args(sidecar.GkmCauseRequest, 1))
	if err != nil {
		t.Fatal(err)
	}
	second, secondRotate, err := first.NextGeneration(args(sidecar.GkmCauseRemove, 2))
	if err != nil {
		t.Fatal(err)
	}

	// GenWrap_e of generation 2 at the group's epoch
	genWrap, err := sidecar.SealGkmGenWrap(second, groupId, group.Epoch(), kek)
	if err != nil {
		t.Fatal(err)
	}
	secondKey := ladderReproduce(t, "GenWrap", kek, genWrap, ladderKeyWrapAad(groupId, group.Epoch(), 2))
	if !bytes.Equal(ladderCommitment(repoId, 2, secondKey), secondRotate.GetCommitment()) {
		t.Errorf("GenWrap's key is not C_2's")
	}

	// each generation's LeafWrap
	firstKey := []byte(nil)
	for _, rotate := range []*protocol.GenRotate{firstRotate, secondRotate} {
		leafWrap := rotate.GetLeafWrap()
		if leafWrap == nil {
			t.Fatalf("gen/%d carries no LeafWrap", rotate.GetGeneration())
		}
		key := ladderReproduce(t, "LeafWrap", kek, leafWrap.GetCiphertext(), ladderKeyWrapAad(groupId, leafWrap.GetEpoch(), rotate.GetGeneration()))
		if !bytes.Equal(ladderCommitment(repoId, rotate.GetGeneration(), key), rotate.GetCommitment()) {
			t.Errorf("gen/%d's LeafWrap holds a key that is not its C_g's", rotate.GetGeneration())
		}
		if rotate.GetGeneration() == 1 {
			firstKey = key
		}
	}

	// GenLink_2 opens RK_1 under K_link_2, its AAD naming cause REMOVE
	linkKey, err := hkdf.Key(sha256.New, secondKey, repoId.Bytes(), "UR evs 1.0 link"+string(binary.BigEndian.AppendUint64(nil, 2)), 32)
	if err != nil {
		t.Fatal(err)
	}
	linked := ladderReproduce(t, "GenLink", linkKey, secondRotate.GetGenlink(), ladderGenLinkAad(repoId, 2, sidecar.GkmCauseRemove))
	if !bytes.Equal(linked, firstKey) || !bytes.Equal(ladderCommitment(repoId, 1, linked), firstRotate.GetCommitment()) {
		t.Errorf("GenLink_2 does not open RK_1")
	}
	aead, _ := chacha20poly1305.NewX(linkKey)
	link := secondRotate.GetGenlink()
	if _, err := aead.Open(nil, link[:24], link[24:], ladderGenLinkAad(repoId, 2, sidecar.GkmCauseRequest)); err == nil {
		t.Errorf("GenLink opens under another cause")
	}

	// mls_* opens a GenWrap and a GenLink sealed here
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	rand.Read(nonce)
	ownGenWrap := ladderSeal(t, kek, nonce, secondKey, ladderKeyWrapAad(groupId, group.Epoch(), 2))
	opened, err := sidecar.OpenGkmGenWrap(&sidecar.GkmGeneration{Rotate: secondRotate}, groupId, group.Epoch(), kek, ownGenWrap)
	if err != nil || !bytes.Equal(opened.Commitment(), secondRotate.GetCommitment()) {
		t.Fatalf("mls_* does not open a GenWrap sealed here: %v", err)
	}
	ownLinked := proto.Clone(secondRotate).(*protocol.GenRotate)
	ownLinked.Genlink = ladderSeal(t, linkKey, nonce, firstKey, ladderGenLinkAad(repoId, 2, sidecar.GkmCauseRemove))
	parent, err := opened.OpenParent(&sidecar.GkmGeneration{Rotate: firstRotate})
	if err != nil || !bytes.Equal(parent.Commitment(), firstRotate.GetCommitment()) {
		t.Errorf("mls_* does not walk its own link: %v", err)
	}
	ownOpened, err := sidecar.OpenGkmGenWrap(&sidecar.GkmGeneration{Rotate: ownLinked}, groupId, group.Epoch(), kek, ownGenWrap)
	if err != nil {
		t.Fatal(err)
	}
	if parent, err := ownOpened.OpenParent(&sidecar.GkmGeneration{Rotate: firstRotate}); err != nil || !bytes.Equal(parent.Commitment(), firstRotate.GetCommitment()) {
		t.Errorf("mls_* does not open a GenLink sealed here: %v", err)
	}
}

// wrap_aad as §10.5 spells it, from a KeyDelivery's fields.
func ladderWrapAad(wrapType sidecar.GkmWrapType, delivery *protocol.KeyDelivery) []byte {
	recipientSha256 := sha256.Sum256(delivery.GetRecipient())
	aad := []byte{byte(wrapType)}
	aad = append(aad, delivery.GetGroupId()...)
	aad = binary.BigEndian.AppendUint64(aad, delivery.GetGeneration())
	aad = append(aad, delivery.GetCommitment()...)
	aad = append(aad, recipientSha256[:]...)
	aad = append(aad, delivery.GetRecipientKeySha256()...)
	aad = append(aad, byte(delivery.GetDeliveryKind()))
	if delivery.GetDeliveryKind() == uint32(sidecar.GkmDeliveryLate) {
		aad = binary.BigEndian.AppendUint64(aad, delivery.GetAuth().GetVersion())
		aad = append(aad, delivery.GetAuth().GetChain()...)
		aad = binary.BigEndian.AppendUint64(aad, uint64(delivery.GetTimeMs()))
	}
	return aad
}

// Each kind of delivery mls_* seals opens under the wrap_aad written here, and under no other.
func TestLadderWrapAadMatchesMls(t *testing.T) {
	repoId, groupId := sidecar.NewId(), sidecar.NewId()
	holders := sha256.Sum256([]byte("ladder holders"))
	chain := sha256.Sum256([]byte("ladder chain"))
	key, rotate, err := sidecar.NewGkmFirstGeneration(repoId, groupId, &sidecar.GkmGenerationArgs{
		Cause:         sidecar.GkmCauseRequest,
		Auth:          &bridge.AuthPin{Version: 3, Chain: chain[:]},
		Time:          time.UnixMilli(1_800_000_000_000),
		HoldersSha256: holders[:],
	})
	if err != nil {
		t.Fatal(err)
	}
	recipientKey, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	delegationId := sha256.Sum256([]byte("ladder delegation"))
	late := &bridge.AuthPin{Version: 9, Chain: chain[:]}
	cases := []struct {
		name string
		args *sidecar.GkmDeliveryArgs
	}{
		{name: "a STAGED ReaderWrap", args: &sidecar.GkmDeliveryArgs{Type: sidecar.GkmWrapTypeReader, Recipient: sidecar.NewId().Bytes(), Kind: sidecar.GkmDeliveryStaged}},
		{name: "a LATE ReaderWrap", args: &sidecar.GkmDeliveryArgs{Type: sidecar.GkmWrapTypeReader, Recipient: sidecar.NewId().Bytes(), Kind: sidecar.GkmDeliveryLate,
			Auth: late, Time: time.UnixMilli(1_800_000_060_000)}},
		{name: "a STAGED DelegationWrap", args: &sidecar.GkmDeliveryArgs{Type: sidecar.GkmWrapTypeDelegation, Recipient: delegationId[:], Kind: sidecar.GkmDeliveryStaged}},
		{name: "a LATE DelegationWrap", args: &sidecar.GkmDeliveryArgs{Type: sidecar.GkmWrapTypeDelegation, Recipient: delegationId[:], Kind: sidecar.GkmDeliveryLate,
			Auth: late, Time: time.UnixMilli(1_800_000_060_000)}},
	}
	for _, c := range cases {
		c.args.GroupId = groupId
		c.args.RecipientPublicKey = recipientKey.PublicKey().Bytes()
		delivery, err := sidecar.SealGkmDelivery(key, c.args)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		open := func(aad []byte) ([]byte, error) {
			const encapsulationByteCount = 1120
			sealed := delivery.GetCiphertext()
			recipient, err := hpke.NewRecipient(sealed[:encapsulationByteCount], recipientKey, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte("UR evs 1.0 wrap"))
			if err != nil {
				return nil, err
			}
			return recipient.Open(aad, sealed[encapsulationByteCount:])
		}
		aad := ladderWrapAad(c.args.Type, delivery)
		repoKey, err := open(aad)
		if err != nil {
			t.Errorf("%s: does not open under the wrap_aad written here: %v", c.name, err)
			continue
		}
		if !bytes.Equal(ladderCommitment(repoId, 1, repoKey), rotate.GetCommitment()) {
			t.Errorf("%s: holds a key that is not C_1's", c.name)
		}
		for index := range aad {
			changed := bytes.Clone(aad)
			changed[index] ^= 1
			if _, err := open(changed); err == nil {
				t.Errorf("%s: opens with byte %d of wrap_aad changed", c.name, index)
				break
			}
		}
	}
}
