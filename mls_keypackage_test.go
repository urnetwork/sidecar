// A sidecar's KeyPackages and leaves (KEYS-M2-07): credential 0xF552 in the leaf, the subset's capabilities and
// ur_group, the last-resort mark, the checks a leaf's credential gets, and the identity pins §6's Hello shares.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A leaf identity for signer's sidecar: a fresh signature key and its credential.
func mlsTestLeafIdentity(t *testing.T, signer *gkmTestSigner) *mlsLeafIdentity {
	t.Helper()
	signatureKey, err := mlsSuite.generateSignatureKey("test")
	if err != nil {
		t.Fatal(err)
	}
	args := mlsTestCredentialArgs(signer)
	args.MlsSignaturePublicKey = signatureKey.Public().(ed25519.PublicKey)
	credential, err := SignUrMlsCredential(args, signer.sign)
	if err != nil {
		t.Fatal(err)
	}
	return &mlsLeafIdentity{
		signatureKey: signatureKey,
		credential:   mlsCredential{credentialType: mlsCredentialTypeUrSidecar, urMlsCredential: credential},
	}
}

// Admits exactly these signers' identity keys, as KEYS-M2-19's check will through the log.
func mlsTestAdmit(signers ...*gkmTestSigner) MlsCredentialCheck {
	return func(credential *protocol.UrMlsCredential) error {
		for _, signer := range signers {
			if Id(credential.GetSidecarId()) == signer.sidecarId && bytes.Equal(credential.GetIdentityPublicKey(), signer.publicKey()) {
				return nil
			}
		}
		return errors.New("not admitted")
	}
}

// A KeyPackage made here reads back as a KeyPackage MLSMessage, checks against the suite with its credential,
// names its sidecar, and differs from the next; the last-resort one says so in its own extensions alone.
func TestMlsKeyPackageCarriesCredential0xF552(t *testing.T) {
	signer := newGkmTestSigner("key package")
	lifetime := newMlsLifetime(mlsTestTime, 10*time.Minute, 90*24*time.Hour)
	validator := mlsUrCredentialValidator(mlsTestAdmit(signer))
	refs := [][]byte{}
	for _, lastResort := range []bool{false, false, true} {
		held, err := newMlsHeldKeyPackage(mlsSuite, mlsTestLeafIdentity(t, signer), lifetime, lastResort)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := mlsDecodeKeyPackage(mlsSuite, defaultMlsTreeSettings(), validator, held.encoded, &mlsTestTime)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.leafNode.credential.credentialType != mlsCredentialTypeUrSidecar {
			t.Errorf("credential type %#x", decoded.leafNode.credential.credentialType)
		}
		credential, err := CheckUrMlsCredential(decoded.leafNode.credential.urMlsCredential)
		if err != nil || Id(credential.GetSidecarId()) != signer.sidecarId {
			t.Errorf("the credential names %x: %v", credential.GetSidecarId(), err)
		}
		if !decoded.leafNode.capabilities.satisfies(mlsSubsetRequiredCapabilities()) {
			t.Error("a leaf that does not meet the subset's requirements")
		}
		if mlsIsLastResort(decoded.extensions) != lastResort || held.lastResort != lastResort {
			t.Errorf("last resort %v read as %v", lastResort, mlsIsLastResort(decoded.extensions))
		}
		ref, err := decoded.ref(mlsSuite)
		if err != nil || !bytes.Equal(ref, held.ref) {
			t.Errorf("ref: %v", err)
		}
		if slices.ContainsFunc(refs, func(other []byte) bool { return bytes.Equal(other, ref) }) {
			t.Error("two KeyPackages with one ref")
		}
		refs = append(refs, ref)
		if _, err := ParseMlsHeader(held.encoded); err == nil {
			t.Error("gkm read a KeyPackage as a commit")
		}
	}
}

// What gkm reads of an upload: the ref the engine named, the last-resort mark, the lifetime and the credential, and
// nothing from bytes that are not a whole, checked KeyPackage.
func TestMlsParseKeyPackageReadsWhatGkmStores(t *testing.T) {
	signer := newGkmTestSigner("parse key package")
	lifetime := newMlsLifetime(mlsTestTime, 10*time.Minute, 90*24*time.Hour)
	for _, lastResort := range []bool{false, true} {
		held, err := newMlsHeldKeyPackage(mlsSuite, mlsTestLeafIdentity(t, signer), lifetime, lastResort)
		if err != nil {
			t.Fatal(err)
		}
		info, err := ParseMlsKeyPackage(held.encoded)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(info.Ref, held.ref) || info.LastResort != lastResort {
			t.Errorf("ref %x last resort %v", info.Ref, info.LastResort)
		}
		if Id(info.Credential.GetSidecarId()) != signer.sidecarId || !bytes.Equal(info.Credential.GetIdentityPublicKey(), signer.publicKey()) {
			t.Error("the credential names another sidecar or key")
		}
		if info.NotBefore.Unix() != int64(lifetime.notBefore) || info.NotAfter.Unix() != int64(lifetime.notAfter) {
			t.Errorf("lifetime %s to %s", info.NotBefore, info.NotAfter)
		}
		for _, broken := range [][]byte{held.encoded[:len(held.encoded)-1], append(bytes.Clone(held.encoded), 0)} {
			if _, err := ParseMlsKeyPackage(broken); err == nil {
				t.Error("a cut or padded KeyPackage parsed")
			}
		}
		tampered := bytes.Clone(held.encoded)
		tampered[len(tampered)-1] ^= 1
		if _, err := ParseMlsKeyPackage(tampered); err == nil {
			t.Error("a KeyPackage with a broken signature parsed")
		}
	}
}

// A leaf's lifetime starts a little before now and spans exactly the tree's bound, so a committer whose clock runs
// behind adds it and the tree takes its span.
func TestMlsKeyPackageLifetimeStartsBeforeNow(t *testing.T) {
	lifetime := newMlsLifetime(mlsTestTime, 10*time.Minute, 90*24*time.Hour)
	if !lifetime.contains(mlsTestTime.Add(-9*time.Minute)) || lifetime.contains(mlsTestTime.Add(-11*time.Minute)) {
		t.Error("the lifetime does not start ten minutes back")
	}
	if !lifetime.validSpan(defaultMlsTreeSettings().MaximumLeafLifetime) {
		t.Error("the tree refuses the lifetime's span")
	}
	if lifetime.contains(mlsTestTime.Add(90 * 24 * time.Hour)) {
		t.Error("the lifetime runs past 90 days from its start")
	}
}

// Credential 0xF552 round-trips in a leaf as opaque<V> and re-encodes byte for byte.
func TestMlsCredential0xF552RoundTripsInALeaf(t *testing.T) {
	identity := mlsTestLeafIdentity(t, newGkmTestSigner("round trip"))
	encoded, err := mlsMarshal(&identity.credential)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &mlsCredential{}
	if err := mlsUnmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.urMlsCredential, identity.credential.urMlsCredential) || !bytes.Equal(decoded.body(), identity.credential.urMlsCredential) {
		t.Error("the credential's body changed")
	}
	reencoded, err := mlsMarshal(decoded)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		t.Errorf("re-encoded differently: %v", err)
	}
	// production reads it too
	mlsTestReadsBasicCredentials = false
	defer func() { mlsTestReadsBasicCredentials = true }()
	if err := mlsUnmarshal(encoded, &mlsCredential{}); err != nil {
		t.Errorf("production refuses 0xF552: %v", err)
	}
}

// The leaf validator takes credential 0xF552 alone, its own signature good, naming the leaf's own key, and then
// only what the check admits; with no check it refuses every credential.
func TestMlsLeafCredentialValidatorRefusals(t *testing.T) {
	signer := newGkmTestSigner("validator")
	identity := mlsTestLeafIdentity(t, signer)
	signatureKey := []byte(identity.signatureKey.Public().(ed25519.PublicKey))
	validator := mlsUrCredentialValidator(mlsTestAdmit(signer))
	if err := validator(&identity.credential, signatureKey); err != nil {
		t.Fatal(err)
	}

	otherKey, err := mlsSuite.generateSignatureKey("test")
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(identity.credential.urMlsCredential)
	tampered[len(tampered)-1] ^= 1
	cases := []struct {
		name         string
		validator    mlsCredentialValidator
		credential   mlsCredential
		signatureKey []byte
	}{
		{name: "basic", validator: validator, credential: mlsCredential{credentialType: mlsCredentialTypeBasic, identity: []byte("anyone")}, signatureKey: signatureKey},
		{name: "another signature key", validator: validator, credential: identity.credential, signatureKey: []byte(otherKey.Public().(ed25519.PublicKey))},
		{name: "a bad identity signature", validator: validator, credential: mlsCredential{credentialType: mlsCredentialTypeUrSidecar, urMlsCredential: tampered}, signatureKey: signatureKey},
		{name: "not admitted", validator: mlsUrCredentialValidator(mlsTestAdmit(newGkmTestSigner("someone else"))), credential: identity.credential, signatureKey: signatureKey},
		{name: "no check", validator: mlsUrCredentialValidator(nil), credential: identity.credential, signatureKey: signatureKey},
	}
	for _, c := range cases {
		if err := c.validator(&c.credential, c.signatureKey); err == nil {
			t.Errorf("%s was taken", c.name)
		}
	}
}

// A KeyPackage refused for a foreign credential type, when parsed in production and by the validator in tests, and
// for a missing required capability when it would enter a group.
func TestMlsKeyPackageRefusals(t *testing.T) {
	signer := newGkmTestSigner("refusals")
	validator := mlsUrCredentialValidator(mlsTestAdmit(signer))

	// a basic credential: production refuses its bytes, and the subset's validator refuses it in tests
	basic := mlsNewTestClient(t, mlsSuite, "basic")
	encodedBasic, err := mlsMarshalMessageOf(mlsWireFormatKeyPackage, basic.keyPackage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mlsDecodeKeyPackage(mlsSuite, defaultMlsTreeSettings(), validator, encodedBasic, &mlsTestTime); err == nil {
		t.Error("a basic credential's KeyPackage was taken")
	}
	mlsTestReadsBasicCredentials = false
	if _, err := mlsDecodeKeyPackage(mlsSuite, defaultMlsTreeSettings(), validator, encodedBasic, &mlsTestTime); !errors.Is(err, errMlsRefused) {
		t.Errorf("production read a basic credential: %v", err)
	}
	mlsTestReadsBasicCredentials = true

	// a leaf that lists no ur_group cannot enter a group that requires it
	identity := mlsTestLeafIdentity(t, signer)
	held, err := newMlsHeldKeyPackage(mlsSuite, identity, newMlsLifetime(mlsTestTime, time.Minute, 90*24*time.Hour), false)
	if err != nil {
		t.Fatal(err)
	}
	lacking := *held.keyPackage
	lacking.leafNode.capabilities.extensions = []uint16{mlsExtensionTypeLastResort}
	if err := lacking.leafNode.sign(mlsSuite, identity.signatureKey, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := lacking.sign(mlsSuite, identity.signatureKey); err != nil {
		t.Fatal(err)
	}
	if err := lacking.validate(mlsSuite, defaultMlsTreeSettings(), validator, &mlsTestTime); err != nil {
		t.Fatalf("the KeyPackage alone: %v", err)
	}
	extensions, err := mlsSubsetGroupExtensions(mlsTestUrGroup())
	if err != nil {
		t.Fatal(err)
	}
	tree := newMlsRatchetTree(mlsSuite, defaultMlsTreeSettings(), &held.keyPackage.leafNode)
	if err := tree.validateGroupCompatibility(&lacking.leafNode, extensions); !errors.Is(err, errMlsInvalid) {
		t.Errorf("a leaf without ur_group joined a group requiring it: %v", err)
	}
	if err := tree.validateGroupCompatibility(&held.keyPackage.leafNode, extensions); err != nil {
		t.Errorf("a subset leaf: %v", err)
	}

	// a KeyPackage of another wire format, or past its lifetime when sent
	encoded := held.encoded
	if _, err := mlsDecodeKeyPackage(mlsSuite, defaultMlsTreeSettings(), validator, append([]byte{0, 1, 0, 4}, encoded[4:]...), nil); err == nil {
		t.Error("a KeyPackage framed as a GroupInfo was read")
	}
	late := mlsTestTime.Add(91 * 24 * time.Hour)
	if _, err := mlsDecodeKeyPackage(mlsSuite, defaultMlsTreeSettings(), validator, encoded, &late); !errors.Is(err, errMlsInvalid) {
		t.Errorf("a lapsed KeyPackage sent: %v", err)
	}
}

// ur_group for the tests' groups.
func mlsTestUrGroup() *MlsUrGroup {
	owner := gkmTestId("owner")
	return &MlsUrGroup{NetworkId: gkmTestId("network"), RepoId: gkmTestId("repo"), Kind: protocol.RepoKind_REPO_KIND_VAULT, OwnerMemberId: &owner}
}

// ur_group round-trips in QD-469's encoding, owner present or not, and refuses what is not one.
func TestMlsUrGroupEncoding(t *testing.T) {
	for _, urGroup := range []*MlsUrGroup{
		mlsTestUrGroup(),
		{NetworkId: gkmTestId("network"), RepoId: gkmTestId("repo"), Kind: protocol.RepoKind_REPO_KIND_DIRECTORY},
	} {
		encoded, err := mlsEncodeUrGroup(urGroup)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := mlsDecodeUrGroup(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.NetworkId != urGroup.NetworkId || decoded.RepoId != urGroup.RepoId || decoded.Kind != urGroup.Kind ||
			(decoded.OwnerMemberId == nil) != (urGroup.OwnerMemberId == nil) || (decoded.OwnerMemberId != nil && *decoded.OwnerMemberId != *urGroup.OwnerMemberId) {
			t.Errorf("decoded %+v", decoded)
		}
	}
	// network, repo, kind and owner, each byte as QD-469 writes them
	urGroup := mlsTestUrGroup()
	encoded, err := mlsEncodeUrGroup(urGroup)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{16}, urGroup.NetworkId.Bytes()...)
	want = append(want, 16)
	want = append(want, urGroup.RepoId.Bytes()...)
	want = append(want, 7, 16)
	want = append(want, urGroup.OwnerMemberId.Bytes()...)
	if !bytes.Equal(encoded, want) {
		t.Errorf("encoded %x", encoded)
	}

	refused := map[string][]byte{
		"kind 0":          bytes.Replace(bytes.Clone(encoded), []byte{7, 16}, []byte{0, 16}, 1),
		"kind 10":         bytes.Replace(bytes.Clone(encoded), []byte{7, 16}, []byte{10, 16}, 1),
		"a short owner":   append(bytes.Clone(encoded[:len(encoded)-17]), 5, 1, 2, 3, 4, 5),
		"a short network": append([]byte{4, 1, 2, 3, 4}, encoded[17:]...),
		"a byte past":     append(bytes.Clone(encoded), 0),
	}
	for name, data := range refused {
		if _, err := mlsDecodeUrGroup(data); err == nil {
			t.Errorf("%s was read", name)
		}
	}
	if _, err := mlsEncodeUrGroup(&MlsUrGroup{Kind: 42}); err == nil {
		t.Error("kind 42 was written")
	}
}

// A group of the subset carries ur_group and requires it and 0xF552 of every leaf; a list missing either, or
// changing ur_group, is refused.
func TestMlsSubsetGroupExtensions(t *testing.T) {
	extensions, err := mlsSubsetGroupExtensions(mlsTestUrGroup())
	if err != nil {
		t.Fatal(err)
	}
	urGroup, err := mlsCheckSubsetGroupExtensions(extensions)
	if err != nil || urGroup.RepoId != mlsTestUrGroup().RepoId {
		t.Fatalf("%v", err)
	}
	if err := mlsCheckGroupExtensionsChange(extensions, extensions); err != nil {
		t.Errorf("an unchanged list: %v", err)
	}
	other := mlsTestUrGroup()
	other.Kind = protocol.RepoKind_REPO_KIND_GENERAL
	otherExtensions, err := mlsSubsetGroupExtensions(other)
	if err != nil {
		t.Fatal(err)
	}
	weaker, err := mlsMarshal(&mlsRequiredCapabilities{extensionTypes: []uint16{mlsExtensionTypeUrGroup}})
	if err != nil {
		t.Fatal(err)
	}
	refused := map[string][]mlsExtension{
		"no ur_group":                {extensions[1]},
		"no required capabilities":   {extensions[0]},
		"0xF552 not required":        {extensions[0], {extensionType: mlsExtensionTypeRequiredCapabilities, extensionData: weaker}},
		"an unreadable ur_group":     {{extensionType: mlsExtensionTypeUrGroup, extensionData: []byte{1}}, extensions[1]},
	}
	for name, list := range refused {
		if _, err := mlsCheckSubsetGroupExtensions(list); err == nil {
			t.Errorf("%s was taken", name)
		}
	}
	if err := mlsCheckGroupExtensionsChange(extensions, otherExtensions); !errors.Is(err, errMlsInvalid) {
		t.Errorf("a change of kind: %v", err)
	}
}

// A credential pins its identity key to its sidecar, and a second key for a pinned sidecar is refused, whichever
// side, a Hello or a leaf, pinned it first.
func TestMlsCredentialPins(t *testing.T) {
	signer := newGkmTestSigner("pins")
	identity := mlsTestLeafIdentity(t, signer)
	pin, err := MlsCredentialPin(identity.credential.urMlsCredential)
	if err != nil {
		t.Fatal(err)
	}
	if pin.SidecarId != signer.sidecarId || !bytes.Equal(pin.IdentityPublicKey, signer.publicKey()) {
		t.Errorf("pin %+v", pin)
	}
	pins := map[Id][]byte{}
	pinned := func(sidecarId Id) []byte { return pins[sidecarId] }
	if err := CheckMlsIdentityPin(pinned, pin); err != nil {
		t.Errorf("a first use: %v", err)
	}
	pins[pin.SidecarId] = pin.IdentityPublicKey
	if err := CheckMlsIdentityPin(pinned, pin); err != nil {
		t.Errorf("the pinned key: %v", err)
	}
	impostor := &gkmTestSigner{sidecarId: signer.sidecarId, privateKey: newGkmTestSigner("impostor").privateKey}
	second, err := MlsCredentialPin(mlsTestLeafIdentity(t, impostor).credential.urMlsCredential)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckMlsIdentityPin(pinned, second); !errors.Is(err, ErrMlsIdentityPin) {
		t.Errorf("a second key: %v", err)
	}
	tampered := bytes.Clone(identity.credential.urMlsCredential)
	tampered[3] ^= 1
	if _, err := MlsCredentialPin(tampered); err == nil {
		t.Error("a tampered credential pinned a key")
	}
	if err := CheckMlsIdentityPin(pinned, &MlsIdentityPin{SidecarId: signer.sidecarId}); !errors.Is(err, ErrMlsIdentityPin) {
		t.Errorf("a pin with no key: %v", err)
	}
}

// messages.json's KeyPackages re-encode byte for byte as MLSMessages.
func TestMlsMessagesKeyPackageVectors(t *testing.T) {
	var vectors []struct {
		KeyPackage mlsHexBytes `json:"mls_key_package"`
	}
	mlsLoadVectors(t, "messages", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	for index, vector := range vectors {
		keyPackage := &mlsKeyPackage{}
		if err := mlsUnmarshalMessageOf(vector.KeyPackage, mlsWireFormatKeyPackage, keyPackage); err != nil {
			t.Errorf("vector %d: %v", index, err)
			continue
		}
		reencoded, err := mlsMarshalMessageOf(mlsWireFormatKeyPackage, keyPackage)
		if err != nil || !bytes.Equal(reencoded, vector.KeyPackage) {
			t.Errorf("vector %d: re-encoded differently: %v", index, err)
		}
	}
}

// A reader key or delegation key keeps its own copy of the seed it loads from, so a caller erasing its buffer, as a
// keychain load does, changes nothing of the key.
func TestGkmLoadedKeysSurviveTheirSeedsErased(t *testing.T) {
	for _, load := range []func(seed []byte) (hpkePrivateKeyBytes, error){
		func(seed []byte) (hpkePrivateKeyBytes, error) { return LoadGkmReaderKey(seed) },
		func(seed []byte) (hpkePrivateKeyBytes, error) { return LoadGkmDelegationKey(seed) },
	} {
		seed := gkmTestBytes("erased seed", 32)
		key, err := load(seed)
		if err != nil {
			t.Fatal(err)
		}
		clear(seed)
		encoded, err := key.Bytes()
		if err != nil || !bytes.Equal(encoded, gkmTestBytes("erased seed", 32)) {
			t.Errorf("the key's seed changed with its caller's buffer: %v", err)
		}
	}
}

// What the loaders' keys answer for their seed.
type hpkePrivateKeyBytes interface {
	Bytes() ([]byte, error)
}
