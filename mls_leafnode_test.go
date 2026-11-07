// LeafNode, credentials, capabilities and KeyPackage: their encodings, signatures and RFC §7.3 and
// RFC §10.1 checks.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

// The test binary reads basic credentials, which the mlswg's vectors and every test group use.
// Production never does: TestMlsProductionRefusesBasicCredentials.
func init() {
	mlsTestReadsBasicCredentials = true
}

// Leaf bytes round-trip for each source, and the source decides which fields travel.
func TestMlsLeafNodeRoundTrip(t *testing.T) {
	suite := mlsSuite
	client := mlsNewTestClient(t, suite, "client")
	leaf := client.keyPackage.leafNode
	leaf.extensions = []mlsExtension{{extensionType: mlsExtensionTypeApplicationId, extensionData: []byte("id")}}

	cases := []struct {
		source     uint8
		lifetime   mlsLifetime
		parentHash []byte
	}{
		{source: mlsLeafNodeSourceKeyPackage, lifetime: mlsLifetime{notBefore: 5, notAfter: 9}},
		{source: mlsLeafNodeSourceUpdate},
		{source: mlsLeafNodeSourceCommit, parentHash: []byte{1, 2, 3}},
	}
	for _, c := range cases {
		value := leaf
		value.leafNodeSource = c.source
		value.lifetime = c.lifetime
		value.parentHash = c.parentHash
		encoded, err := mlsMarshal(&value)
		if err != nil {
			t.Fatal(err)
		}
		decoded := &mlsLeafNode{}
		if err := mlsUnmarshal(encoded, decoded); err != nil {
			t.Fatalf("source %d: %v", c.source, err)
		}
		reencoded, err := mlsMarshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, reencoded) {
			t.Errorf("source %d: re-encoded differently", c.source)
		}
		if decoded.lifetime != c.lifetime || !bytes.Equal(decoded.parentHash, c.parentHash) {
			t.Errorf("source %d: decoded %+v", c.source, decoded)
		}
	}
}

func TestMlsLeafNodeRefusesAnUnknownSource(t *testing.T) {
	client := mlsNewTestClient(t, mlsSuite, "client")
	leaf := client.keyPackage.leafNode
	leaf.leafNodeSource = 4
	if _, err := mlsMarshal(&leaf); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
	// a valid encoding with the source octet rewritten
	valid := client.keyPackage.leafNode
	encoded, err := mlsMarshal(&valid)
	if err != nil {
		t.Fatal(err)
	}
	prefix := &mlsEncoder{}
	prefix.writeVector(valid.encryptionKey)
	prefix.writeVector(valid.signatureKey)
	valid.credential.encode(prefix)
	valid.capabilities.encode(prefix)
	encoded[len(prefix.encoded)] = 4
	if err := mlsUnmarshal(encoded, &mlsLeafNode{}); !errors.Is(err, errMlsMalformed) {
		t.Fatal(err)
	}
}

// Whatever cannot be read must not be skipped: its length is unknown, and it is outside §10.4.
func TestMlsCredentialRefusesEveryOtherType(t *testing.T) {
	for _, credentialType := range []uint16{0, 2, mlsCredentialTypeUrSidecar, 0x0a0a, 0xffff} {
		encoder := &mlsEncoder{}
		encoder.writeUint16(credentialType)
		encoder.writeVector([]byte("body"))
		if err := mlsUnmarshal(encoder.encoded, &mlsCredential{}); !errors.Is(err, errMlsRefused) {
			t.Errorf("type %#x: %v", credentialType, err)
		}
		if _, err := mlsMarshal(&mlsCredential{credentialType: credentialType}); !errors.Is(err, errMlsRefused) {
			t.Errorf("type %#x encoded: %v", credentialType, err)
		}
	}
}

// §10.4 takes 0xF552 alone, so outside the test binary basic is refused like any other type, when
// read and when written, and a KeyPackage carrying it does not decode.
func TestMlsProductionRefusesBasicCredentials(t *testing.T) {
	credential := &mlsCredential{credentialType: mlsCredentialTypeBasic, identity: []byte("anyone")}
	encoded, err := mlsMarshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	encodedKeyPackage, err := mlsMarshal(mlsNewTestClient(t, mlsTestSuiteX25519, "client").keyPackage)
	if err != nil {
		t.Fatal(err)
	}

	mlsTestReadsBasicCredentials = false
	t.Cleanup(func() { mlsTestReadsBasicCredentials = true })
	if err := mlsUnmarshal(encoded, &mlsCredential{}); !errors.Is(err, errMlsRefused) {
		t.Errorf("decoded: %v", err)
	}
	if _, err := mlsMarshal(credential); !errors.Is(err, errMlsRefused) {
		t.Errorf("encoded: %v", err)
	}
	if err := mlsUnmarshal(encodedKeyPackage, &mlsKeyPackage{}); !errors.Is(err, errMlsRefused) {
		t.Errorf("a KeyPackage decoded: %v", err)
	}
}

// Fails closed until §7.9's admission check exists.
func TestMlsProductionValidatorRefusesEverything(t *testing.T) {
	for _, credentialType := range []uint16{mlsCredentialTypeBasic, mlsCredentialTypeUrSidecar} {
		credential := &mlsCredential{credentialType: credentialType, identity: []byte("anyone")}
		if err := mlsRefuseEveryCredential(credential, make([]byte, 32)); !errors.Is(err, errMlsRefused) {
			t.Errorf("type %#x: %v", credentialType, err)
		}
	}
}

func TestMlsCapabilitiesTreatDefaultsAsImplicit(t *testing.T) {
	capabilities := &mlsCapabilities{extensions: []uint16{0xf001}, proposals: []uint16{0xf002}, credentials: []uint16{1}}
	for extensionType := uint16(1); extensionType <= 4; extensionType++ {
		if !capabilities.supportsExtension(extensionType) {
			t.Errorf("default extension %d", extensionType)
		}
	}
	// the fifth default, external_senders, is §10.4's to refuse, even where a leaf lists it
	listing := &mlsCapabilities{extensions: []uint16{mlsExtensionTypeExternalSenders}}
	if capabilities.supportsExtension(mlsExtensionTypeExternalSenders) || listing.supportsExtension(mlsExtensionTypeExternalSenders) {
		t.Error("external senders count as supported")
	}
	for proposalType := uint16(1); proposalType <= 7; proposalType++ {
		if !capabilities.supportsProposal(proposalType) {
			t.Errorf("default proposal %d", proposalType)
		}
	}
	if !capabilities.supportsExtension(0xf001) || capabilities.supportsExtension(0xf003) || capabilities.supportsExtension(0) || capabilities.supportsExtension(6) {
		t.Error("extension support is wrong")
	}
	if !capabilities.supportsProposal(0xf002) || capabilities.supportsProposal(0xf003) || capabilities.supportsProposal(8) {
		t.Error("proposal support is wrong")
	}
	if !capabilities.supportsCredential(1) || capabilities.supportsCredential(2) {
		t.Error("credential support is wrong")
	}
}

func TestMlsCapabilitiesSatisfyRequirements(t *testing.T) {
	capabilities := &mlsCapabilities{extensions: []uint16{0xf001}, proposals: []uint16{0xf002}, credentials: []uint16{1}}
	cases := []struct {
		required mlsRequiredCapabilities
		want     bool
	}{
		{required: mlsRequiredCapabilities{}, want: true},
		{required: mlsRequiredCapabilities{extensionTypes: []uint16{0xf001, 2}}, want: true},
		{required: mlsRequiredCapabilities{proposalTypes: []uint16{0xf002, 1}}, want: true},
		{required: mlsRequiredCapabilities{credentialTypes: []uint16{1}}, want: true},
		{required: mlsRequiredCapabilities{extensionTypes: []uint16{0xf00f}}},
		{required: mlsRequiredCapabilities{proposalTypes: []uint16{0xf00f}}},
		{required: mlsRequiredCapabilities{credentialTypes: []uint16{2}}},
	}
	for index, c := range cases {
		if got := capabilities.satisfies(&c.required); got != c.want {
			t.Errorf("case %d: %v", index, got)
		}
	}
}

func TestMlsRequiredCapabilitiesRoundTrip(t *testing.T) {
	required := &mlsRequiredCapabilities{
		extensionTypes:  []uint16{0xf000},
		proposalTypes:   []uint16{},
		credentialTypes: []uint16{mlsCredentialTypeUrSidecar},
	}
	encoded, err := mlsMarshal(required)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &mlsRequiredCapabilities{}
	if err := mlsUnmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.extensionTypes) != 1 || len(decoded.proposalTypes) != 0 || decoded.credentialTypes[0] != mlsCredentialTypeUrSidecar {
		t.Fatalf("decoded %+v", decoded)
	}
}

func TestMlsLifetimeSpanAndWindow(t *testing.T) {
	day := 24 * time.Hour
	cases := []struct {
		lifetime mlsLifetime
		maximum  time.Duration
		valid    bool
	}{
		{lifetime: mlsLifetime{notBefore: 0, notAfter: 90 * 24 * 60 * 60}, maximum: 90 * day, valid: true},
		{lifetime: mlsLifetime{notBefore: 0, notAfter: 90*24*60*60 + 1}, maximum: 90 * day},
		{lifetime: mlsLifetime{notBefore: 10, notAfter: 9}, maximum: 90 * day},
		{lifetime: mlsLifetime{notBefore: 10, notAfter: 9}},
		{lifetime: mlsLifetime{notBefore: 0, notAfter: ^uint64(0)}, valid: true},
		{lifetime: mlsLifetime{notBefore: 0, notAfter: ^uint64(0)}, maximum: 90 * day},
	}
	for index, c := range cases {
		if got := c.lifetime.validSpan(c.maximum); got != c.valid {
			t.Errorf("case %d: %v", index, got)
		}
	}

	lifetime := mlsLifetime{notBefore: 100, notAfter: 200}
	for seconds, want := range map[int64]bool{99: false, 100: true, 150: true, 200: true, 201: false, -1: false} {
		if got := lifetime.contains(time.Unix(seconds, 0)); got != want {
			t.Errorf("second %d: %v", seconds, got)
		}
	}
}

// Update and commit leaves are bound to their group and position. KeyPackage leaves are bound to
// neither, because they exist before any group does.
func TestMlsLeafSignatureBinding(t *testing.T) {
	suite := mlsSuite
	client := mlsNewTestClient(t, suite, "client")
	for _, source := range []uint8{mlsLeafNodeSourceUpdate, mlsLeafNodeSourceCommit} {
		leaf := client.keyPackage.leafNode
		leaf.leafNodeSource = source
		leaf.parentHash = []byte("hash")
		if err := leaf.sign(suite, client.signatureKey, []byte("group"), 3); err != nil {
			t.Fatal(err)
		}
		if !leaf.verifySignature(suite, []byte("group"), 3) {
			t.Errorf("source %d: does not verify", source)
		}
		if leaf.verifySignature(suite, []byte("other group"), 3) {
			t.Errorf("source %d: verified in another group", source)
		}
		if leaf.verifySignature(suite, []byte("group"), 4) {
			t.Errorf("source %d: verified at another position", source)
		}
	}
	leaf := client.keyPackage.leafNode
	if !leaf.verifySignature(suite, []byte("any group"), 9) {
		t.Error("a KeyPackage leaf depends on its group or position")
	}
}

// The checks on a leaf alone, each with a leaf signed after the change so only the rule can catch it.
func TestMlsValidateAloneRefusals(t *testing.T) {
	suite := mlsTestSuiteX25519
	settings := defaultMlsTreeSettings()
	cases := []struct {
		name   string
		change func(leaf *mlsLeafNode)
		want   error
	}{
		{
			name:   "credential type not in its capabilities",
			change: func(leaf *mlsLeafNode) { leaf.capabilities.credentials = []uint16{0x7777} },
			want:   errMlsInvalid,
		},
		{
			name: "extension not in its capabilities",
			change: func(leaf *mlsLeafNode) {
				leaf.extensions = []mlsExtension{{extensionType: 0xf000}}
			},
			want: errMlsInvalid,
		},
		{
			name:   "lifetime past the bound",
			change: func(leaf *mlsLeafNode) { leaf.lifetime.notAfter += 24 * 60 * 60 },
			want:   errMlsInvalid,
		},
		{
			name:   "inverted lifetime",
			change: func(leaf *mlsLeafNode) { leaf.lifetime.notAfter = leaf.lifetime.notBefore - 1 },
			want:   errMlsInvalid,
		},
		{
			name:   "encryption key the KEM refuses",
			change: func(leaf *mlsLeafNode) { leaf.encryptionKey = []byte("short") },
			want:   errMlsInvalid,
		},
	}
	for _, c := range cases {
		client := mlsNewTestClient(t, suite, "client")
		leaf := client.keyPackage.leafNode
		c.change(&leaf)
		if err := leaf.sign(suite, client.signatureKey, nil, 0); err != nil {
			t.Fatal(err)
		}
		err := leaf.validateAlone(suite, settings, mlsAcceptBasicCredential, nil, 0)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestMlsValidateAloneTakesListedAndDefaultExtensions(t *testing.T) {
	suite := mlsTestSuiteX25519
	settings := defaultMlsTreeSettings()
	client := mlsNewTestClient(t, suite, "client")
	leaf := client.keyPackage.leafNode
	leaf.capabilities.extensions = []uint16{0xf000}
	leaf.extensions = []mlsExtension{
		{extensionType: mlsExtensionTypeApplicationId, extensionData: []byte("id")},
		{extensionType: 0xf000},
	}
	if err := leaf.sign(suite, client.signatureKey, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := leaf.validateAlone(suite, settings, mlsAcceptBasicCredential, nil, 0); err != nil {
		t.Fatal(err)
	}
}

func TestMlsValidateAloneRefusesABadSignature(t *testing.T) {
	suite := mlsTestSuiteX25519
	client := mlsNewTestClient(t, suite, "client")
	leaf := client.keyPackage.leafNode
	leaf.credential.identity = []byte("someone else")
	err := leaf.validateAlone(suite, defaultMlsTreeSettings(), mlsAcceptBasicCredential, nil, 0)
	if !errors.Is(err, errMlsAuthentication) {
		t.Fatal(err)
	}
}

// Nothing in a group works without a credential the validator takes.
func TestMlsValidateAloneAsksTheValidator(t *testing.T) {
	suite := mlsTestSuiteX25519
	client := mlsNewTestClient(t, suite, "client")
	leaf := &client.keyPackage.leafNode
	var seenKey []byte
	var seenIdentity []byte
	validator := func(credential *mlsCredential, signatureKey []byte) error {
		seenKey = signatureKey
		seenIdentity = credential.identity
		return errMlsRefused
	}
	err := leaf.validateAlone(suite, defaultMlsTreeSettings(), validator, nil, 0)
	if !errors.Is(err, errMlsRefused) {
		t.Fatal(err)
	}
	if !bytes.Equal(seenKey, leaf.signatureKey) || !bytes.Equal(seenIdentity, []byte("client")) {
		t.Fatal("the validator saw something else")
	}
}

func TestMlsKeyPackageRoundTrip(t *testing.T) {
	for _, suite := range mlsTestSuites {
		client := mlsNewTestClient(t, suite, "client")
		encoded, err := mlsMarshal(client.keyPackage)
		if err != nil {
			t.Fatal(err)
		}
		decoded := &mlsKeyPackage{}
		if err := mlsUnmarshal(encoded, decoded); err != nil {
			t.Fatal(err)
		}
		reencoded, err := mlsMarshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, reencoded) {
			t.Fatalf("suite %#x: re-encoded differently", suite.value)
		}
		if err := decoded.validate(suite, defaultMlsTreeSettings(), mlsAcceptBasicCredential, nil); err != nil {
			t.Fatalf("suite %#x: %v", suite.value, err)
		}
	}
}

// §10.6's size, to within what a basic credential saves over 0xF552's 207 bytes.
func TestMlsKeyPackageSizeUnderXWing(t *testing.T) {
	client := mlsNewTestClient(t, mlsSuite, "client")
	encoded, err := mlsMarshal(client.keyPackage)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) < 2600 || 2900 < len(encoded) {
		t.Fatalf("key package of %d bytes", len(encoded))
	}
}

func TestMlsKeyPackageRefusesOtherVersions(t *testing.T) {
	client := mlsNewTestClient(t, mlsSuite, "client")
	encoded, err := mlsMarshal(client.keyPackage)
	if err != nil {
		t.Fatal(err)
	}
	encoded[1] = 2
	if err := mlsUnmarshal(encoded, &mlsKeyPackage{}); !errors.Is(err, errMlsRefused) {
		t.Fatal(err)
	}
}

func TestMlsKeyPackageValidateRefusals(t *testing.T) {
	suite := mlsTestSuiteX25519
	settings := defaultMlsTreeSettings()
	resign := func(client *mlsTestClient) {
		if err := client.keyPackage.sign(suite, client.signatureKey); err != nil {
			t.Fatal(err)
		}
	}

	otherSuite := mlsNewTestClient(t, suite, "client")
	otherSuite.keyPackage.cipherSuite = mlsCipherSuiteXWing
	resign(otherSuite)
	if err := otherSuite.keyPackage.validate(suite, settings, mlsAcceptBasicCredential, nil); !errors.Is(err, errMlsInvalid) {
		t.Errorf("other suite: %v", err)
	}

	wrongSource := mlsNewTestClient(t, suite, "client")
	wrongSource.keyPackage.leafNode.leafNodeSource = mlsLeafNodeSourceUpdate
	if err := wrongSource.keyPackage.leafNode.sign(suite, wrongSource.signatureKey, []byte("group"), 0); err != nil {
		t.Fatal(err)
	}
	resign(wrongSource)
	if err := wrongSource.keyPackage.validate(suite, settings, mlsAcceptBasicCredential, nil); !errors.Is(err, errMlsInvalid) {
		t.Errorf("wrong source: %v", err)
	}

	sameKey := mlsNewTestClient(t, suite, "client")
	sameKey.keyPackage.initKey = sameKey.keyPackage.leafNode.encryptionKey
	resign(sameKey)
	if err := sameKey.keyPackage.validate(suite, settings, mlsAcceptBasicCredential, nil); !errors.Is(err, errMlsInvalid) {
		t.Errorf("init key equal to the encryption key: %v", err)
	}

	badInitKey := mlsNewTestClient(t, suite, "client")
	badInitKey.keyPackage.initKey = []byte("short")
	resign(badInitKey)
	if err := badInitKey.keyPackage.validate(suite, settings, mlsAcceptBasicCredential, nil); !errors.Is(err, errMlsInvalid) {
		t.Errorf("bad init key: %v", err)
	}

	tampered := mlsNewTestClient(t, suite, "client")
	tampered.keyPackage.extensions = []mlsExtension{{extensionType: 0x0a0a}}
	if err := tampered.keyPackage.validate(suite, settings, mlsAcceptBasicCredential, nil); !errors.Is(err, errMlsAuthentication) {
		t.Errorf("tampered: %v", err)
	}

	refused := mlsNewTestClient(t, suite, "client")
	if err := refused.keyPackage.validate(suite, settings, mlsRefuseEveryCredential, nil); !errors.Is(err, errMlsRefused) {
		t.Errorf("credential: %v", err)
	}
}

// RFC §7.3: a sender must hold the lifetime against its own clock, and a receiver need not.
func TestMlsKeyPackageLifetimeBindsOnlyTheSender(t *testing.T) {
	suite := mlsTestSuiteX25519
	settings := defaultMlsTreeSettings()
	client := mlsNewTestClient(t, suite, "client")
	inside := mlsTestTime.Add(time.Hour)
	if err := client.keyPackage.validate(suite, settings, mlsAcceptBasicCredential, &inside); err != nil {
		t.Fatal(err)
	}
	expired := mlsTestTime.Add(91 * 24 * time.Hour)
	if err := client.keyPackage.validate(suite, settings, mlsAcceptBasicCredential, &expired); !errors.Is(err, errMlsInvalid) {
		t.Errorf("expired: %v", err)
	}
	early := mlsTestTime.Add(-time.Hour)
	if err := client.keyPackage.validate(suite, settings, mlsAcceptBasicCredential, &early); !errors.Is(err, errMlsInvalid) {
		t.Errorf("not yet valid: %v", err)
	}
	if err := client.keyPackage.validate(suite, settings, mlsAcceptBasicCredential, nil); err != nil {
		t.Errorf("a receiver with no clock check: %v", err)
	}
}

func TestMlsKeyPackageRefIsStableAndContentBound(t *testing.T) {
	suite := mlsSuite
	first := mlsNewTestClient(t, suite, "client")
	second := mlsNewTestClient(t, suite, "client")
	firstRef, err := first.keyPackage.ref(suite)
	if err != nil {
		t.Fatal(err)
	}
	again, err := first.keyPackage.ref(suite)
	if err != nil {
		t.Fatal(err)
	}
	secondRef, err := second.keyPackage.ref(suite)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstRef, again) || bytes.Equal(firstRef, secondRef) {
		t.Fatal("the ref is not a function of the key package")
	}
	encoded, err := mlsMarshal(first.keyPackage)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := suite.makeKeyPackageRef(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstRef, direct) {
		t.Fatal("ref and makeKeyPackageRef differ")
	}
}

func TestMlsProposalRoundTrip(t *testing.T) {
	client := mlsNewTestClient(t, mlsSuite, "client")
	proposals := []*mlsProposal{
		{proposalType: mlsProposalTypeAdd, keyPackage: client.keyPackage},
		{proposalType: mlsProposalTypeRemove, removed: 7},
		{proposalType: mlsProposalTypeExternalInit, kemOutput: []byte("kem output")},
		{proposalType: mlsProposalTypeGroupContextExtensions, extensions: []mlsExtension{{extensionType: 0xf000, extensionData: []byte("x")}}},
	}
	for _, proposal := range proposals {
		encoded, err := mlsMarshal(proposal)
		if err != nil {
			t.Fatal(err)
		}
		decoded := &mlsProposal{}
		if err := mlsUnmarshal(encoded, decoded); err != nil {
			t.Fatalf("type %d: %v", proposal.proposalType, err)
		}
		reencoded, err := mlsMarshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, reencoded) {
			t.Errorf("type %d: re-encoded differently", proposal.proposalType)
		}
	}
}

// §10.4's refused list, and a type with no meaning at all.
func TestMlsProposalRefusesWhatTheSubsetRefuses(t *testing.T) {
	for _, proposalType := range []uint16{mlsProposalTypeUpdate, mlsProposalTypePsk, mlsProposalTypeReInit, 0, 8, 0x0a0a} {
		encoder := &mlsEncoder{}
		encoder.writeUint16(proposalType)
		if err := mlsUnmarshal(encoder.encoded, &mlsProposal{}); !errors.Is(err, errMlsRefused) {
			t.Errorf("type %#x: %v", proposalType, err)
		}
		if _, err := mlsMarshal(&mlsProposal{proposalType: proposalType}); !errors.Is(err, errMlsRefused) {
			t.Errorf("type %#x encoded: %v", proposalType, err)
		}
	}
}

func TestMlsSignatureKeyOfATestClientIsItsLeaf(t *testing.T) {
	client := mlsNewTestClient(t, mlsSuite, "client")
	public := client.signatureKey.Public().(ed25519.PublicKey)
	if !bytes.Equal(public, client.keyPackage.leafNode.signatureKey) {
		t.Fatal("test fixture broken")
	}
}
