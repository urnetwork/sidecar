//go:build sidecar_testhooks

// Under the tag, every key §10.5's ladder and deliveries create, derive or unwrap reaches the privacy harness's
// hook, by value and under its name, on the paths a rotator and a reader run.

package sidecar

import (
	"testing"
	"time"
)

func TestGkmHookSeesEveryDerivation(t *testing.T) {
	recorder := mlsRecordHooks(t)
	keys, _ := gkmTestLadder(t, newGkmTestSigner("rotator"))
	key := keys[1]
	for _, purpose := range gkmTestPurposes {
		derived, err := key.DeriveKey(purpose, nil)
		if err != nil {
			t.Fatal(err)
		}
		recorder.require(t, gkmDerivedKeyKinds[purpose], derived)
	}
	groupInfoKey, err := key.DeriveKey(EvsKeyPurposeGroupInfo, GkmGroupInfoContext(key.GroupId(), 5))
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "K_groupinfo", groupInfoKey)
	dropKey, err := key.DropKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "drop_private_key", mustPrivateKeyBytes(t, dropKey))
	for _, generated := range keys {
		recorder.require(t, "RK_g", generated.repoKey)
	}
}

func TestGkmHookSeesEveryUnwrap(t *testing.T) {
	signer := newGkmTestSigner("rotator")
	keys, generations := gkmTestLadder(t, signer)
	kek := gkmTestBytes("kek", gkmKekByteCount)
	genWrap, err := SealGkmGenWrap(keys[2], keys[2].GroupId(), 7, kek)
	if err != nil {
		t.Fatal(err)
	}
	readerKey := gkmTestRecipientKey(t, "reader")
	reader := gkmTestId("reader sidecar")
	delivery := gkmTestDelivery(t, signer, keys[2], &GkmDeliveryArgs{
		GroupId:            keys[2].GroupId(),
		Type:               GkmWrapTypeReader,
		Recipient:          reader.Bytes(),
		RecipientPublicKey: readerKey.PublicKey().Bytes(),
		Kind:               GkmDeliveryStaged,
	})
	recoveryKey := gkmTestRecipientKey(t, "recovery")
	recoveryArgs := &GkmRecoveryArgs{
		MemberId:          gkmTestId("member"),
		GroupId:           keys[2].GroupId(),
		RecoveryPublicKey: recoveryKey.PublicKey().Bytes(),
		BindingKeySha256:  gkmTestBytes("binding", gkmDigestByteCount),
	}
	recoveryWrap, err := SealGkmRecoveryWrap(keys[2], recoveryArgs)
	if err != nil {
		t.Fatal(err)
	}

	// Each unwrap runs with nothing hooked before it, so what it hooks is its own.
	unwraps := map[string]func() (*EvsRepoKey, error){
		"GenWrap": func() (*EvsRepoKey, error) {
			return OpenGkmGenWrap(generations[2], keys[2].GroupId(), 7, kek, genWrap)
		},
		"delivery": func() (*EvsRepoKey, error) {
			return OpenGkmDelivery(delivery, generations[2], reader.Bytes(), readerKey)
		},
		"RecoveryWrap": func() (*EvsRepoKey, error) {
			return OpenGkmRecoveryWrap(recoveryWrap, generations[2], recoveryArgs, recoveryKey)
		},
		"GenLink": func() (*EvsRepoKey, error) {
			top, err := OpenEvsRepoKey(generations[2], keys[2].repoKey)
			if err != nil {
				return nil, err
			}
			return top.OpenParent(generations[1])
		},
	}
	for name, unwrap := range unwraps {
		recorder := mlsRecordHooks(t)
		opened, err := unwrap()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		recorder.require(t, "RK_g", opened.repoKey)
		SetTestHooks(nil)
	}
}

func TestGkmHookSeesEveryPrivateKey(t *testing.T) {
	recorder := mlsRecordHooks(t)
	signer := newGkmTestSigner("reader")
	_, readerKey, err := NewGkmReaderKey(signer.sidecarId, gkmTestTime, gkmTestTime.Add(6*24*time.Hour), signer.sign)
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "reader_private_key", mustPrivateKeyBytes(t, readerKey))

	recorder = mlsRecordHooks(t)
	seed := gkmTestBytes("stored reader key", 32)
	if _, err := LoadGkmReaderKey(seed); err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "reader_private_key", seed)

	recorder = mlsRecordHooks(t)
	seed = gkmTestBytes("delegation_reader_seed", 32)
	if _, err := LoadGkmDelegationKey(seed); err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "delegation_reader_key", seed)
}
