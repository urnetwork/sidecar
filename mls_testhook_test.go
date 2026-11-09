//go:build sidecar_testhooks

// Under the tag, every MLS secret reaches the privacy harness's hook, under the name of what it is.
// TestMlsSecretsComeOnlyThroughHookedFunctions proves the same from source in both builds; these prove
// it by value, on the paths a real group runs.

package sidecar

import (
	"bytes"
	"slices"
	"testing"
)

// Keeps everything hooked until the test ends.
type mlsHookRecorder struct {
	kindSecrets map[string][][]byte
}

// Installs a recorder for this test.
func mlsRecordHooks(t *testing.T) *mlsHookRecorder {
	t.Helper()
	recorder := &mlsHookRecorder{kindSecrets: map[string][][]byte{}}
	t.Cleanup(func() { SetTestHooks(nil) })
	SetTestHooks(&TestHooks{
		Secret: func(kind string, secret []byte) {
			recorder.kindSecrets[kind] = append(recorder.kindSecrets[kind], secret)
		},
	})
	return recorder
}

// Whether this exact value reached the hook under this kind.
func (self *mlsHookRecorder) saw(kind string, secret []byte) bool {
	return slices.ContainsFunc(self.kindSecrets[kind], func(hooked []byte) bool {
		return bytes.Equal(hooked, secret)
	})
}

// Fails the test unless this value was hooked under this kind.
func (self *mlsHookRecorder) require(t *testing.T, kind string, secret []byte) {
	t.Helper()
	if len(secret) == 0 {
		t.Errorf("%s: nothing to look for", kind)
	}
	if !self.saw(kind, secret) {
		t.Errorf("%s did not reach the hook", kind)
	}
}

// Fails the test unless something was hooked under each kind.
func (self *mlsHookRecorder) requireKinds(t *testing.T, kinds ...string) {
	t.Helper()
	for _, kind := range kinds {
		if len(self.kindSecrets[kind]) == 0 {
			t.Errorf("no %s reached the hook", kind)
		}
	}
}

func TestMlsHookSeesTheKeySchedule(t *testing.T) {
	recorder := mlsRecordHooks(t)
	suite := mlsSuite
	initSecret := bytes.Repeat([]byte{1}, suite.hashLength)
	commitSecret := bytes.Repeat([]byte{2}, suite.hashLength)
	groupContext := []byte("group context")

	joinerSecret, err := suite.deriveJoinerSecret(initSecret, commitSecret, groupContext)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := suite.deriveEpochSecrets(joinerSecret, nil, groupContext)
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "joiner_secret", secrets.joinerSecret)
	recorder.require(t, "welcome_secret", secrets.welcomeSecret)
	recorder.require(t, "init_secret", secrets.initSecret)
	recorder.require(t, "sender_data_secret", secrets.senderDataSecret)
	recorder.require(t, "encryption_secret", secrets.encryptionSecret)
	recorder.require(t, "exporter_secret", secrets.exporterSecret)
	recorder.require(t, "external_secret", secrets.externalSecret)
	recorder.require(t, "confirmation_key", secrets.confirmationKey)
	recorder.require(t, "membership_key", secrets.membershipKey)
	recorder.require(t, "resumption_psk", secrets.resumptionPsk)
	recorder.require(t, "epoch_authenticator", secrets.epochAuthenticator)
	recorder.requireKinds(t, "joiner_extract", "member_extract", "epoch_secret")

	exported, err := suite.exporter("UR evs 1.0 kek", secrets.exporterSecret, "UR evs 1.0 kek", []byte("context"), 32)
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "UR evs 1.0 kek", exported)
	recorder.requireKinds(t, "exporter_label_secret")

	externalKey, err := suite.deriveExternalKey(secrets.externalSecret)
	if err != nil {
		t.Fatal(err)
	}
	externalPrivate, err := externalKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "external_priv", externalPrivate)

	kemOutput, joinerInit, err := suite.externalInitSeal(externalKey.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "init_secret", joinerInit)
	clear(recorder.kindSecrets["init_secret"])
	memberInit, err := suite.externalInitOpen(externalKey, kemOutput)
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "init_secret", memberInit)
}

func TestMlsHookSeesANewGroupsEpochSecret(t *testing.T) {
	recorder := mlsRecordHooks(t)
	if _, err := mlsSuite.newGroupEpochSecrets(); err != nil {
		t.Fatal(err)
	}
	recorder.requireKinds(t, "epoch_secret", "encryption_secret", "init_secret")
}

func TestMlsHookSeesTheSecretTree(t *testing.T) {
	recorder := mlsRecordHooks(t)
	suite := mlsSuite
	tree := mlsNewTestSecretTree(t, suite)
	ratchets, err := tree.ratchets(5)
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "handshake_ratchet_secret", ratchets.handshake.secret)
	recorder.require(t, "application_ratchet_secret", ratchets.application.secret)
	if count := len(recorder.kindSecrets["tree_node_secret"]); count != 6 {
		t.Errorf("%d tree node secrets on a path of three levels", count)
	}

	step, err := ratchets.handshake.stepTo(3)
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "ratchet_key", step.key)
	recorder.require(t, "ratchet_nonce", step.nonce)
	recorder.require(t, "ratchet_secret", step.nextSecret)
	// three skipped generations and the step's own next secret
	if count := len(recorder.kindSecrets["ratchet_secret"]); count != 4 {
		t.Errorf("%d ratchet secrets", count)
	}

	_, key, nonce, err := ratchets.application.next()
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "ratchet_key", key)
	recorder.require(t, "ratchet_nonce", nonce)

	senderDataKey, senderDataNonce, err := suite.deriveSenderDataKey(make([]byte, suite.hashLength), []byte("ciphertext"))
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "sender_data_key", senderDataKey)
	recorder.require(t, "sender_data_nonce", senderDataNonce)
}

func TestMlsHookSeesTreeKem(t *testing.T) {
	group := mlsNewMergedTestGroup(t, mlsSuite, 4)
	recorder := mlsRecordHooks(t)
	updatePath, prepared, tree := mlsPreparedCommit(t, group, 0)
	for _, pathSecret := range prepared.pathSecrets {
		recorder.require(t, "path_secret", pathSecret)
	}
	recorder.require(t, "commit_secret", prepared.commitSecret)
	for _, pathKey := range prepared.pathKeys {
		encoded, err := pathKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		recorder.require(t, "node_priv", encoded)
	}
	leafKey, err := prepared.leafKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "leaf_priv", leafKey)
	if count := len(recorder.kindSecrets["node_secret"]); count != len(prepared.path) {
		t.Errorf("%d node secrets for a path of %d", count, len(prepared.path))
	}

	// the receiver's unwrap reaches the hook on its own, not only the committer's copy
	clear(recorder.kindSecrets["path_secret"])
	clear(recorder.kindSecrets["commit_secret"])
	if err := tree.mergeUpdatePath(0, updatePath, nil, group.validation); err != nil {
		t.Fatal(err)
	}
	received, err := group.members[3].secrets.receiveUpdatePath(tree, 0, updatePath, group.provisionalContext(tree), nil)
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "commit_secret", received.commitSecret)
	recorder.require(t, "path_secret", prepared.pathSecrets[len(prepared.pathSecrets)-1])
}

func TestMlsHookSeesKeyCreationAndLoading(t *testing.T) {
	recorder := mlsRecordHooks(t)
	suite := mlsSuite

	secret := suite.generateSecret("fresh_secret")
	recorder.require(t, "fresh_secret", secret)

	generated, err := suite.generateKemKey("generated_kem_key")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := generated.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "generated_kem_key", encoded)

	if _, err := suite.loadKemKey("loaded_kem_key", encoded); err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "loaded_kem_key", encoded)

	signatureKey, err := suite.generateSignatureKey("generated_signature_key")
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "generated_signature_key", signatureKey.Seed())

	if _, err := suite.loadSignatureKey("loaded_signature_key", signatureKey.Seed()); err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "loaded_signature_key", signatureKey.Seed())

	kemOutput, ciphertext, err := suite.encryptWithLabel(generated.PublicKey().Bytes(), "Welcome", nil, []byte("unwrapped"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := suite.decryptWithLabel("unwrapped_secret", generated, "Welcome", nil, kemOutput, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "unwrapped_secret", plaintext)
}

// Forward secrecy for the harness too: the hook's copy outlives the caller's erasure, so a scan can
// still find a key whose owner has overwritten it.
func TestMlsHookKeepsItsCopyPastAnErase(t *testing.T) {
	recorder := mlsRecordHooks(t)
	suite := mlsSuite
	secrets, err := suite.newGroupEpochSecrets()
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(secrets.encryptionSecret)
	secrets.erase()
	recorder.require(t, "encryption_secret", want)
}

// The engine's own paths reach the hook by value: a KeyPackage's keys, a Welcome's group secrets and the keys its
// schedule derives, a path's new signature key, the exporter's output, and every key and secret a reload unwraps
// from disk.
func TestMlsHookSeesTheEngine(t *testing.T) {
	recorder := mlsRecordHooks(t)
	world := newMlsTestWorld(t)
	creator, joiner := world.sidecar(nil), world.sidecar(nil)
	groups := mlsTestGroupOf(t, creator, joiner)
	recorder.requireKinds(t, "init_priv", "leaf_priv", "signature_priv", "group_secrets", "joiner_secret", "welcome_secret", "welcome_key", "welcome_nonce")

	staged, err := groups[1].Commit(&MlsCommitArgs{Path: true, AuthenticatedData: []byte("update")})
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := staged.Adopt()
	if err != nil {
		t.Fatal(err)
	}
	kek, err := MlsKek(adopted, gkmTestId("repo"))
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "exported_secret", kek)
	recorder.require(t, "signature_priv", adopted.(*mlsRealGroup).state.signatureKey.Seed())

	recorder.kindSecrets = map[string][][]byte{}
	joiner.restart(t)
	loaded, err := joiner.engine.LoadGroup(adopted.GroupId())
	if err != nil {
		t.Fatal(err)
	}
	state := loaded.(*mlsRealGroup).state
	recorder.require(t, "init_secret", state.initSecret)
	recorder.require(t, "exporter_secret", state.exporterSecret)
	recorder.require(t, "external_secret", state.externalSecret)
	recorder.require(t, "encryption_secret", state.encryptionSecret)
	recorder.require(t, "sender_data_secret", state.senderDataSecret)
	recorder.require(t, "signature_priv", state.signatureKey.Seed())
	recorder.requireKinds(t, "leaf_priv", "node_priv")
}
