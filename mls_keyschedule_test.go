// The key schedule against the mlswg's key-schedule and transcript-hashes vectors under 0x0001, and
// its behavior under both suites.

package sidecar

import (
	"bytes"
	"errors"
	"testing"
)

func TestMlsKeyScheduleVectors(t *testing.T) {
	var vectors []struct {
		CipherSuite       uint16      `json:"cipher_suite"`
		GroupId           mlsHexBytes `json:"group_id"`
		InitialInitSecret mlsHexBytes `json:"initial_init_secret"`
		Epochs            []struct {
			TreeHash                mlsHexBytes `json:"tree_hash"`
			CommitSecret            mlsHexBytes `json:"commit_secret"`
			PskSecret               mlsHexBytes `json:"psk_secret"`
			ConfirmedTranscriptHash mlsHexBytes `json:"confirmed_transcript_hash"`
			GroupContext            mlsHexBytes `json:"group_context"`
			JoinerSecret            mlsHexBytes `json:"joiner_secret"`
			WelcomeSecret           mlsHexBytes `json:"welcome_secret"`
			InitSecret              mlsHexBytes `json:"init_secret"`
			SenderDataSecret        mlsHexBytes `json:"sender_data_secret"`
			EncryptionSecret        mlsHexBytes `json:"encryption_secret"`
			ExporterSecret          mlsHexBytes `json:"exporter_secret"`
			EpochAuthenticator      mlsHexBytes `json:"epoch_authenticator"`
			ExternalSecret          mlsHexBytes `json:"external_secret"`
			ConfirmationKey         mlsHexBytes `json:"confirmation_key"`
			MembershipKey           mlsHexBytes `json:"membership_key"`
			ResumptionPsk           mlsHexBytes `json:"resumption_psk"`
			ExternalPub             mlsHexBytes `json:"external_pub"`
			Exporter                struct {
				// the hex text itself is the label: test-vectors.md gives it as a string
				Label   string      `json:"label"`
				Context mlsHexBytes `json:"context"`
				Length  int         `json:"length"`
				Secret  mlsHexBytes `json:"secret"`
			} `json:"exporter"`
		} `json:"epochs"`
	}
	mlsLoadVectors(t, "key-schedule", &vectors)

	suite := mlsTestSuiteX25519
	ran := 0
	for _, vector := range vectors {
		if vector.CipherSuite != suite.value {
			continue
		}
		ran++
		initSecret := []byte(vector.InitialInitSecret)
		for index, epoch := range vector.Epochs {
			groupContext := &mlsGroupContext{
				cipherSuite:             suite.value,
				groupId:                 vector.GroupId,
				epoch:                   uint64(index),
				treeHash:                epoch.TreeHash,
				confirmedTranscriptHash: epoch.ConfirmedTranscriptHash,
			}
			encodedContext, err := mlsMarshal(groupContext)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encodedContext, epoch.GroupContext) {
				t.Fatalf("epoch %d: group context %x, want %x", index, encodedContext, epoch.GroupContext)
			}

			joinerSecret, err := suite.deriveJoinerSecret(initSecret, epoch.CommitSecret, encodedContext)
			if err != nil {
				t.Fatal(err)
			}
			secrets, err := suite.deriveEpochSecrets(joinerSecret, epoch.PskSecret, encodedContext)
			if err != nil {
				t.Fatal(err)
			}
			checks := []struct {
				name string
				got  []byte
				want []byte
			}{
				{name: "joiner_secret", got: secrets.joinerSecret, want: epoch.JoinerSecret},
				{name: "welcome_secret", got: secrets.welcomeSecret, want: epoch.WelcomeSecret},
				{name: "init_secret", got: secrets.initSecret, want: epoch.InitSecret},
				{name: "sender_data_secret", got: secrets.senderDataSecret, want: epoch.SenderDataSecret},
				{name: "encryption_secret", got: secrets.encryptionSecret, want: epoch.EncryptionSecret},
				{name: "exporter_secret", got: secrets.exporterSecret, want: epoch.ExporterSecret},
				{name: "epoch_authenticator", got: secrets.epochAuthenticator, want: epoch.EpochAuthenticator},
				{name: "external_secret", got: secrets.externalSecret, want: epoch.ExternalSecret},
				{name: "confirmation_key", got: secrets.confirmationKey, want: epoch.ConfirmationKey},
				{name: "membership_key", got: secrets.membershipKey, want: epoch.MembershipKey},
				{name: "resumption_psk", got: secrets.resumptionPsk, want: epoch.ResumptionPsk},
			}
			for _, check := range checks {
				if !bytes.Equal(check.got, check.want) {
					t.Errorf("epoch %d: %s %x, want %x", index, check.name, check.got, check.want)
				}
			}

			externalKey, err := suite.deriveExternalKey(secrets.externalSecret)
			if err != nil {
				t.Fatal(err)
			}
			if externalPub := externalKey.PublicKey().Bytes(); !bytes.Equal(externalPub, epoch.ExternalPub) {
				t.Errorf("epoch %d: external_pub %x, want %x", index, externalPub, epoch.ExternalPub)
			}

			exported, err := suite.exporter(
				"test", secrets.exporterSecret, epoch.Exporter.Label, epoch.Exporter.Context, epoch.Exporter.Length,
			)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(exported, epoch.Exporter.Secret) {
				t.Errorf("epoch %d: exporter %x, want %x", index, exported, epoch.Exporter.Secret)
			}

			initSecret = secrets.initSecret
		}
	}
	if ran == 0 {
		t.Fatal("no vector for suite 0x0001")
	}
}

// AuthenticatedContent, its commit left encoded: the vectors' commits are not ones §10.4 takes.
func mlsTestDecodeAuthenticatedContent(t *testing.T, encoded []byte) *mlsAuthenticatedContent {
	t.Helper()
	decoder := &mlsDecoder{remaining: encoded}
	authenticated := &mlsAuthenticatedContent{wireFormat: decoder.readUint16()}
	authenticated.content.decode(decoder, mlsTestReadContent)
	authenticated.auth.decode(decoder, authenticated.content.contentType)
	if err := decoder.finish(); err != nil {
		t.Fatal(err)
	}
	return authenticated
}

func TestMlsTranscriptHashVectors(t *testing.T) {
	var vectors []struct {
		CipherSuite                  uint16      `json:"cipher_suite"`
		ConfirmationKey              mlsHexBytes `json:"confirmation_key"`
		AuthenticatedContent         mlsHexBytes `json:"authenticated_content"`
		InterimTranscriptHashBefore  mlsHexBytes `json:"interim_transcript_hash_before"`
		ConfirmedTranscriptHashAfter mlsHexBytes `json:"confirmed_transcript_hash_after"`
		InterimTranscriptHashAfter   mlsHexBytes `json:"interim_transcript_hash_after"`
	}
	mlsLoadVectors(t, "transcript-hashes", &vectors)

	suite := mlsTestSuiteX25519
	ran := 0
	for _, vector := range vectors {
		if vector.CipherSuite != suite.value {
			continue
		}
		ran++
		authenticated := mlsTestDecodeAuthenticatedContent(t, vector.AuthenticatedContent)
		confirmationTag := authenticated.auth.confirmationTag
		confirmedInput, err := authenticated.confirmedTranscriptHashInput()
		if err != nil {
			t.Fatal(err)
		}

		confirmed := suite.nextConfirmedTranscriptHash(vector.InterimTranscriptHashBefore, confirmedInput)
		if !bytes.Equal(confirmed, vector.ConfirmedTranscriptHashAfter) {
			t.Errorf("confirmed %x, want %x", confirmed, vector.ConfirmedTranscriptHashAfter)
		}
		if tag := suite.confirmationTag(vector.ConfirmationKey, confirmed); !bytes.Equal(tag, confirmationTag) {
			t.Errorf("confirmation tag %x, want %x", tag, confirmationTag)
		}
		if !suite.verifyConfirmationTag(vector.ConfirmationKey, confirmed, confirmationTag) {
			t.Error("the vector's own confirmation tag does not verify")
		}
		interim, err := suite.nextInterimTranscriptHash(confirmed, confirmationTag)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(interim, vector.InterimTranscriptHashAfter) {
			t.Errorf("interim %x, want %x", interim, vector.InterimTranscriptHashAfter)
		}
	}
	if ran == 0 {
		t.Fatal("no vector for suite 0x0001")
	}
}

func TestMlsGroupContextRoundTrip(t *testing.T) {
	groupContext := &mlsGroupContext{
		cipherSuite:             mlsCipherSuiteXWing,
		groupId:                 []byte("group"),
		epoch:                   7,
		treeHash:                bytes.Repeat([]byte{1}, 32),
		confirmedTranscriptHash: bytes.Repeat([]byte{2}, 32),
		extensions:              []mlsExtension{{extensionType: 0xf000, extensionData: []byte("data")}},
	}
	encoded, err := mlsMarshal(groupContext)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &mlsGroupContext{}
	if err := mlsUnmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	reencoded, err := mlsMarshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatalf("%x became %x", encoded, reencoded)
	}
	if decoded.cipherSuite != mlsCipherSuiteXWing || decoded.epoch != 7 || len(decoded.extensions) != 1 {
		t.Fatalf("decoded %+v", decoded)
	}
}

func TestMlsGroupContextRefusesOtherVersions(t *testing.T) {
	encoded, err := mlsMarshal(&mlsGroupContext{cipherSuite: mlsCipherSuiteXWing})
	if err != nil {
		t.Fatal(err)
	}
	encoded[1] = 2
	if err := mlsUnmarshal(encoded, &mlsGroupContext{}); !errors.Is(err, errMlsRefused) {
		t.Fatal(err)
	}
}

func TestMlsExtensionListRefusesARepeatedType(t *testing.T) {
	encoder := &mlsEncoder{}
	encoder.writeExtensions([]mlsExtension{
		{extensionType: 5, extensionData: []byte("a")},
		{extensionType: 6, extensionData: []byte("b")},
		{extensionType: 5, extensionData: []byte("c")},
	})
	encoded, err := encoder.finish()
	if err != nil {
		t.Fatal(err)
	}
	decoder := &mlsDecoder{remaining: encoded}
	decoder.readExtensions()
	if err := decoder.finish(); !errors.Is(err, errMlsMalformed) {
		t.Fatal(err)
	}
}

func TestMlsFindExtension(t *testing.T) {
	extensions := []mlsExtension{{extensionType: 5}, {extensionType: 6, extensionData: []byte("b")}}
	found := mlsFindExtension(extensions, 6)
	if found == nil || !bytes.Equal(found.extensionData, []byte("b")) {
		t.Fatalf("found %+v", found)
	}
	if mlsFindExtension(extensions, 7) != nil {
		t.Fatal("found a type the list lacks")
	}
}

// A commit with no path and a commit-less PSK slot both enter as the all-zero vector.
func TestMlsNilSecretsAreZeroVectors(t *testing.T) {
	for _, suite := range mlsTestSuites {
		initSecret := bytes.Repeat([]byte{3}, suite.hashLength)
		groupContext := []byte("group context")
		zeros := make([]byte, suite.hashLength)

		withNil, err := suite.deriveJoinerSecret(initSecret, nil, groupContext)
		if err != nil {
			t.Fatal(err)
		}
		withZeros, err := suite.deriveJoinerSecret(initSecret, zeros, groupContext)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(withNil, withZeros) {
			t.Error("a nil commit_secret is not the zero vector")
		}

		first, err := suite.deriveEpochSecrets(withNil, nil, groupContext)
		if err != nil {
			t.Fatal(err)
		}
		second, err := suite.deriveEpochSecrets(withNil, zeros, groupContext)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.epochAuthenticator, second.epochAuthenticator) {
			t.Error("a nil psk_secret is not the zero vector")
		}
	}
}

// Every input moves every output, and the group context binds the whole epoch.
func TestMlsEpochSecretsBindTheirInputs(t *testing.T) {
	for _, suite := range mlsTestSuites {
		initSecret := bytes.Repeat([]byte{3}, suite.hashLength)
		commitSecret := bytes.Repeat([]byte{4}, suite.hashLength)
		derive := func(initSecret []byte, commitSecret []byte, pskSecret []byte, groupContext []byte) *mlsEpochSecrets {
			joinerSecret, err := suite.deriveJoinerSecret(initSecret, commitSecret, groupContext)
			if err != nil {
				t.Fatal(err)
			}
			secrets, err := suite.deriveEpochSecrets(joinerSecret, pskSecret, groupContext)
			if err != nil {
				t.Fatal(err)
			}
			return secrets
		}
		base := derive(initSecret, commitSecret, nil, []byte("one"))
		variations := []*mlsEpochSecrets{
			derive(commitSecret, commitSecret, nil, []byte("one")),
			derive(initSecret, initSecret, nil, []byte("one")),
			derive(initSecret, commitSecret, commitSecret, []byte("one")),
			derive(initSecret, commitSecret, nil, []byte("two")),
		}
		for index, variation := range variations {
			if bytes.Equal(base.encryptionSecret, variation.encryptionSecret) ||
				bytes.Equal(base.initSecret, variation.initSecret) ||
				bytes.Equal(base.epochAuthenticator, variation.epochAuthenticator) {
				t.Errorf("suite %#x: variation %d left a secret unchanged", suite.value, index)
			}
		}
	}
}

// Each of table 4's labels gives its own value.
func TestMlsEpochSecretsAreDistinct(t *testing.T) {
	secrets, err := mlsSuite.newGroupEpochSecrets()
	if err != nil {
		t.Fatal(err)
	}
	values := [][]byte{
		secrets.initSecret, secrets.senderDataSecret, secrets.encryptionSecret, secrets.exporterSecret,
		secrets.externalSecret, secrets.confirmationKey, secrets.membershipKey, secrets.resumptionPsk,
		secrets.epochAuthenticator,
	}
	for first := range values {
		if len(values[first]) != mlsSuite.hashLength {
			t.Errorf("secret %d is %d bytes", first, len(values[first]))
		}
		for second := range first {
			if bytes.Equal(values[first], values[second]) {
				t.Errorf("secrets %d and %d are equal", first, second)
			}
		}
	}
	if secrets.joinerSecret != nil || secrets.welcomeSecret != nil {
		t.Error("a new group has no joiner or welcome secret")
	}
}

func TestMlsNewGroupEpochSecretsAreFresh(t *testing.T) {
	first, err := mlsSuite.newGroupEpochSecrets()
	if err != nil {
		t.Fatal(err)
	}
	second, err := mlsSuite.newGroupEpochSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.initSecret, second.initSecret) {
		t.Fatal("two groups share an init_secret")
	}
}

func TestMlsEraseOverwritesEverySecret(t *testing.T) {
	joinerSecret := bytes.Repeat([]byte{9}, mlsSuite.hashLength)
	secrets, err := mlsSuite.deriveEpochSecrets(joinerSecret, nil, []byte("context"))
	if err != nil {
		t.Fatal(err)
	}
	values := [][]byte{
		secrets.joinerSecret, secrets.welcomeSecret, secrets.initSecret, secrets.senderDataSecret,
		secrets.encryptionSecret, secrets.exporterSecret, secrets.externalSecret, secrets.confirmationKey,
		secrets.membershipKey, secrets.resumptionPsk, secrets.epochAuthenticator,
	}
	secrets.erase()
	zero := make([]byte, mlsSuite.hashLength)
	for index, value := range values {
		if !bytes.Equal(value, zero) {
			t.Errorf("secret %d survived: %x", index, value)
		}
	}
}

func TestMlsExporterBindsLabelContextAndLength(t *testing.T) {
	for _, suite := range mlsTestSuites {
		secret := bytes.Repeat([]byte{5}, suite.hashLength)
		base, err := suite.exporter("test", secret, "UR evs 1.0 kek", []byte("context"), 32)
		if err != nil {
			t.Fatal(err)
		}
		if len(base) != 32 {
			t.Fatalf("exported %d bytes", len(base))
		}
		otherLabel, err := suite.exporter("test", secret, "other", []byte("context"), 32)
		if err != nil {
			t.Fatal(err)
		}
		otherContext, err := suite.exporter("test", secret, "UR evs 1.0 kek", []byte("other"), 32)
		if err != nil {
			t.Fatal(err)
		}
		otherLength, err := suite.exporter("test", secret, "UR evs 1.0 kek", []byte("context"), 16)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(base, otherLabel) || bytes.Equal(base, otherContext) || bytes.Equal(base[:16], otherLength) {
			t.Errorf("suite %#x: an input did not move the output", suite.value)
		}
	}
}

// RFC §8.3 end to end: a joiner holding only external_pub and a member holding external_secret
// reach one init_secret.
func TestMlsExternalInitAgreesOnTheInitSecret(t *testing.T) {
	for _, suite := range mlsTestSuites {
		secrets, err := suite.newGroupEpochSecrets()
		if err != nil {
			t.Fatal(err)
		}
		externalKey, err := suite.deriveExternalKey(secrets.externalSecret)
		if err != nil {
			t.Fatal(err)
		}

		kemOutput, joinerInitSecret, err := suite.externalInitSeal(externalKey.PublicKey().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		memberInitSecret, err := suite.externalInitOpen(externalKey, kemOutput)
		if err != nil {
			t.Fatal(err)
		}
		if len(joinerInitSecret) != suite.hashLength || !bytes.Equal(joinerInitSecret, memberInitSecret) {
			t.Fatalf("suite %#x: joiner %x, member %x", suite.value, joinerInitSecret, memberInitSecret)
		}

		if _, err := suite.externalInitOpen(externalKey, kemOutput[1:]); !errors.Is(err, errMlsAuthentication) {
			t.Errorf("suite %#x: a short kem_output: %v", suite.value, err)
		}
		if _, _, err := suite.externalInitSeal([]byte{1, 2, 3}); err == nil {
			t.Errorf("suite %#x: sealed to three bytes", suite.value)
		}
	}
}

// RFC §11: a new group's interim hash comes from the empty confirmed hash and its first tag.
func TestMlsTranscriptOfANewGroup(t *testing.T) {
	suite := mlsSuite
	secrets, err := suite.newGroupEpochSecrets()
	if err != nil {
		t.Fatal(err)
	}
	tag := suite.confirmationTag(secrets.confirmationKey, nil)
	interim, err := suite.nextInterimTranscriptHash(nil, tag)
	if err != nil {
		t.Fatal(err)
	}
	encoder := &mlsEncoder{}
	encoder.writeVector(tag)
	if want := suite.hash(encoder.encoded); !bytes.Equal(interim, want) {
		t.Fatalf("interim %x, want %x", interim, want)
	}
}

func TestMlsTranscriptHashChains(t *testing.T) {
	suite := mlsSuite
	first := suite.nextConfirmedTranscriptHash(nil, []byte("commit one"))
	second := suite.nextConfirmedTranscriptHash([]byte("x"), []byte("commit one"))
	if bytes.Equal(first, second) {
		t.Fatal("the interim hash did not reach the confirmed hash")
	}
	interim := bytes.Repeat([]byte{1}, 32)
	input := []byte("input")
	if got := suite.nextConfirmedTranscriptHash(interim, input); !bytes.Equal(got, suite.hash(append(bytes.Clone(interim), input...))) {
		t.Fatalf("confirmed %x", got)
	}
	// the caller's interim hash must not grow under it
	if len(interim) != 32 {
		t.Fatal("interim changed")
	}
}
