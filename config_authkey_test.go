package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// testdata/authkey/vectors.json: an auth key string and the parts it splits into, the same bytes on
// every leg.
type authKeyVector struct {
	Name                  string   `json:"name"`
	Text                  string   `json:"text"`
	Bearer                string   `json:"bearer"`
	GenesisSha256         string   `json:"genesis_sha256,omitempty"`
	HeadVersion           uint64   `json:"head_version,omitempty"`
	HeadChain             string   `json:"head_chain,omitempty"`
	DelegationId          string   `json:"delegation_id,omitempty"`
	DelegationSigningSeed string   `json:"delegation_signing_seed,omitempty"`
	DelegationReaderSeed  string   `json:"delegation_reader_seed,omitempty"`
	TagIds                []string `json:"tag_ids,omitempty"`
}

// Bytes counting up from first, a synthetic value no real key holds.
func countingBytes(first byte, byteCount int) []byte {
	value := make([]byte, byteCount)
	for i := range value {
		value[i] = first + byte(i)
	}
	return value
}

// The synthetic bearer every test here uses: id 0x01.., secret 0x20...
func testAuthKeyBearer() string {
	return authKeyPrefix + authKeyEncoding.EncodeToString(countingBytes(0x01, authKeyIdByteCount)) + "-" +
		authKeyEncoding.EncodeToString(countingBytes(0x20, authKeySecretByteCount))
}

// A synthetic bundle with every field set.
func testAuthKeyBundle() *AuthKeyBundle {
	genesis := sha256.Sum256([]byte("synthetic genesis"))
	head := sha256.Sum256([]byte("synthetic head"))
	delegationId, _ := IdFromBytes(countingBytes(0x41, authKeyIdByteCount))
	return &AuthKeyBundle{
		GenesisSha256:         genesis[:],
		HeadVersion:           7,
		HeadChain:             head[:],
		DelegationId:          delegationId,
		DelegationSigningSeed: countingBytes(0x61, authKeySeedByteCount),
		DelegationReaderSeed:  countingBytes(0x81, authKeySeedByteCount),
		TagIds:                [][]byte{countingBytes(0xa1, authKeyTagIdByteCount), countingBytes(0xc1, authKeyTagIdByteCount)},
	}
}

// The bundle text of message, which a test builds to break one field.
func encodeTestBundle(t *testing.T, message *protocol.AuthKeyBundle) string {
	t.Helper()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// The message testAuthKeyBundle encodes to.
func testBundleMessage() *protocol.AuthKeyBundle {
	bundle := testAuthKeyBundle()
	return &protocol.AuthKeyBundle{
		Version:               authKeyBundleVersion,
		GenesisSha256:         bundle.GenesisSha256,
		Head:                  &bridge.AuthPin{Version: bundle.HeadVersion, Chain: bundle.HeadChain},
		DelegationId:          bundle.DelegationId.Bytes(),
		DelegationSigningSeed: bundle.DelegationSigningSeed,
		DelegationReaderSeed:  bundle.DelegationReaderSeed,
		TagIds:                bundle.TagIds,
	}
}

func readAuthKeyVectors(t *testing.T) []authKeyVector {
	t.Helper()
	encoded, err := os.ReadFile("testdata/authkey/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	vectors := []authKeyVector{}
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 2 {
		t.Fatalf("%d vectors", len(vectors))
	}
	return vectors
}

// The vectors split into their parts, and the parts format back to the same string, on every leg.
func TestAuthKeyVectorsRoundTrip(t *testing.T) {
	for _, vector := range readAuthKeyVectors(t) {
		authKey, err := ParseAuthKey(vector.Text)
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		if authKey.Bearer() != vector.Bearer {
			t.Errorf("%s: bearer", vector.Name)
		}
		bundle := authKey.Bundle()
		if vector.DelegationId == "" {
			if bundle != nil {
				t.Errorf("%s: a bundle from a key with none", vector.Name)
			}
		} else {
			if bundle == nil {
				t.Fatalf("%s: no bundle", vector.Name)
			}
			hexOf := func(value []byte) string { return fmt.Sprintf("%x", value) }
			if hexOf(bundle.GenesisSha256) != vector.GenesisSha256 || bundle.HeadVersion != vector.HeadVersion ||
				hexOf(bundle.HeadChain) != vector.HeadChain || bundle.DelegationId.String() != vector.DelegationId ||
				hexOf(bundle.DelegationSigningSeed) != vector.DelegationSigningSeed ||
				hexOf(bundle.DelegationReaderSeed) != vector.DelegationReaderSeed || len(bundle.TagIds) != len(vector.TagIds) {
				t.Errorf("%s: bundle fields differ", vector.Name)
			}
			for i, tagId := range bundle.TagIds {
				if i < len(vector.TagIds) && hexOf(tagId) != vector.TagIds[i] {
					t.Errorf("%s: tag %d", vector.Name, i)
				}
			}
		}
		text, err := formatAuthKey(authKey.Bearer(), bundle)
		if err != nil || text != vector.Text {
			t.Errorf("%s: formats to another string: %v", vector.Name, err)
		}
	}
}

// The synthetic vectors are what this code builds from the synthetic parts, so the file is not stale.
func TestAuthKeyVectorsAreTheSyntheticParts(t *testing.T) {
	vectors := readAuthKeyVectors(t)
	bare, err := formatAuthKey(testAuthKeyBearer(), nil)
	if err != nil {
		t.Fatal(err)
	}
	full, err := formatAuthKey(testAuthKeyBearer(), testAuthKeyBundle())
	if err != nil {
		t.Fatal(err)
	}
	if vectors[0].Text != bare || vectors[1].Text != full {
		t.Fatal("testdata/authkey/vectors.json is not what the synthetic parts format to")
	}
}

// A bearer given without its prefix reads as the same key, and Bearer answers the prefixed form, as
// server reads both.
func TestParseAuthKeyTakesABearerWithoutItsPrefix(t *testing.T) {
	authKey, err := ParseAuthKey(strings.TrimPrefix(testAuthKeyBearer(), authKeyPrefix))
	if err != nil {
		t.Fatal(err)
	}
	if authKey.Bearer() != testAuthKeyBearer() || authKey.Bundle() != nil {
		t.Fatal("the bare bearer read differently")
	}
}

// D-CORE-7: a urn_ API key is no auth key, with or without a bundle after it.
func TestParseAuthKeyRefusesApiKey(t *testing.T) {
	for _, text := range []string{"urn_synthetic", "urn_synthetic#AAAA"} {
		if _, err := ParseAuthKey(text); !errors.Is(err, ErrAuthKeyIsApiKey) {
			t.Errorf("%v", err)
		}
	}
}

// Every way a string can fail to be a key is refused, and the error says nothing of it.
func TestParseAuthKeyRefusesMalformed(t *testing.T) {
	id := authKeyEncoding.EncodeToString(countingBytes(0x01, authKeyIdByteCount))
	secret := authKeyEncoding.EncodeToString(countingBytes(0x20, authKeySecretByteCount))
	bearer := testAuthKeyBearer()
	breakBundle := func(edit func(message *protocol.AuthKeyBundle)) string {
		message := testBundleMessage()
		edit(message)
		return bearer + "#" + encodeTestBundle(t, message)
	}
	unknownField := func() string {
		encoded, err := proto.Marshal(testBundleMessage())
		if err != nil {
			t.Fatal(err)
		}
		// field 15, varint 1: a field this version does not know
		encoded = append(encoded, 0x78, 0x01)
		return bearer + "#" + base64.RawURLEncoding.EncodeToString(encoded)
	}
	cases := []string{
		"",
		"ur-authkey-",
		"ur-authkey-" + id,
		"ur-authkey-" + id + "-",
		"ur-authkey--" + secret,
		"ur-authkey-" + strings.ToUpper(id) + "-" + secret,
		"ur-authkey-" + id + "=-" + secret,
		"ur-authkey-" + id + "-" + secret + "-extra",
		"ur-authkey-" + id[:len(id)-1] + "-" + secret,
		"ur-authkey-" + id + "-" + secret[:len(secret)-2],
		// a last character whose spare bits are set decodes, and does not encode back
		"ur-authkey-" + id[:len(id)-1] + "b-" + secret,
		bearer + "#",
		bearer + "#!!!!",
		bearer + "#" + encodeTestBundle(t, testBundleMessage()) + "=",
		bearer + "#" + encodeTestBundle(t, testBundleMessage()) + "#again",
		breakBundle(func(message *protocol.AuthKeyBundle) { message.Version = 2 }),
		breakBundle(func(message *protocol.AuthKeyBundle) { message.Version = 0 }),
		breakBundle(func(message *protocol.AuthKeyBundle) { message.GenesisSha256 = message.GenesisSha256[:31] }),
		breakBundle(func(message *protocol.AuthKeyBundle) { message.Head = nil }),
		breakBundle(func(message *protocol.AuthKeyBundle) { message.Head.Version = 0 }),
		breakBundle(func(message *protocol.AuthKeyBundle) { message.Head.Chain = nil }),
		breakBundle(func(message *protocol.AuthKeyBundle) { message.DelegationId = make([]byte, 16) }),
		breakBundle(func(message *protocol.AuthKeyBundle) { message.DelegationId = message.DelegationId[:15] }),
		breakBundle(func(message *protocol.AuthKeyBundle) {
			message.DelegationSigningSeed = message.DelegationSigningSeed[:31]
		}),
		breakBundle(func(message *protocol.AuthKeyBundle) { message.DelegationReaderSeed = nil }),
		breakBundle(func(message *protocol.AuthKeyBundle) { message.TagIds = [][]byte{make([]byte, 15)} }),
		breakBundle(func(message *protocol.AuthKeyBundle) {
			message.TagIds = [][]byte{message.TagIds[0], message.TagIds[0]}
		}),
		unknownField(),
		strings.Repeat("a", authKeyMaxByteCount+1),
	}
	for _, text := range cases {
		_, err := ParseAuthKey(text)
		if !errors.Is(err, ErrAuthKeyMalformed) {
			t.Errorf("case %q: %v", RedactAuthKey(text), err)
			continue
		}
		if 4 < len(text) && strings.Contains(err.Error(), text[len(text)-4:]) {
			t.Errorf("the error repeats the text: %v", err)
		}
	}
}

// Neither an AuthKey nor its bundle prints anything it holds, under any verb.
func TestAuthKeyPrintsNothingItHolds(t *testing.T) {
	text, err := formatAuthKey(testAuthKeyBearer(), testAuthKeyBundle())
	if err != nil {
		t.Fatal(err)
	}
	authKey, err := ParseAuthKey(text)
	if err != nil {
		t.Fatal(err)
	}
	bundle := authKey.Bundle()
	secret := strings.TrimPrefix(testAuthKeyBearer(), authKeyPrefix)[27:]
	for _, printed := range []string{
		fmt.Sprintf("%v", authKey), fmt.Sprintf("%+v", authKey), fmt.Sprintf("%#v", authKey), fmt.Sprintf("%s", authKey),
		fmt.Sprintf("%v", bundle), fmt.Sprintf("%+v", bundle), fmt.Sprintf("%#v", bundle),
	} {
		if strings.Contains(printed, secret) || strings.Contains(printed, fmt.Sprintf("%x", bundle.DelegationSigningSeed)) ||
			strings.Contains(printed, "a,b,c") || strings.Contains(printed, "97 98") || strings.Contains(printed, "[97") {
			t.Errorf("printed %q", printed)
		}
	}
}

// Erase zeroes both seeds and drops the bearer, so a daemon keeps nothing of a key once used (§5.6).
func TestAuthKeyEraseZeroesTheSeeds(t *testing.T) {
	text, err := formatAuthKey(testAuthKeyBearer(), testAuthKeyBundle())
	if err != nil {
		t.Fatal(err)
	}
	authKey, err := ParseAuthKey(text)
	if err != nil {
		t.Fatal(err)
	}
	bundle := authKey.Bundle()
	authKey.Erase()
	if authKey.Bearer() != "" || !bytes.Equal(bundle.DelegationSigningSeed, make([]byte, 32)) ||
		!bytes.Equal(bundle.DelegationReaderSeed, make([]byte, 32)) {
		t.Fatal("something survived Erase")
	}
}

// §7.8: redaction covers both parts wherever the string prints, in a line of text or alone.
func TestRedactAuthKeyCoversBothParts(t *testing.T) {
	text, err := formatAuthKey(testAuthKeyBearer(), testAuthKeyBundle())
	if err != nil {
		t.Fatal(err)
	}
	_, bundleText, _ := strings.Cut(text, "#")
	idText := strings.TrimPrefix(testAuthKeyBearer(), authKeyPrefix)[:26]
	secretText := strings.TrimPrefix(testAuthKeyBearer(), authKeyPrefix)[27:]
	cases := []struct {
		text string
		want string
	}{
		{text: text, want: "ur-authkey-[redacted]"},
		{text: "connect --token " + text + " --ephemeral", want: "connect --token ur-authkey-[redacted] --ephemeral"},
		{text: `{"key":"` + text + `"}`, want: `{"key":"ur-authkey-[redacted]"}`},
		{text: testAuthKeyBearer(), want: "ur-authkey-[redacted]"},
		{text: strings.TrimPrefix(testAuthKeyBearer(), authKeyPrefix), want: "[redacted]"},
		{text: "#" + bundleText, want: "[redacted]"},
		{text: idText + "-" + secretText + "#" + bundleText, want: "[redacted]"},
		{text: "nothing secret here", want: "nothing secret here"},
	}
	for _, c := range cases {
		redacted := RedactAuthKey(c.text)
		if redacted != c.want {
			t.Errorf("got %q, want %q", redacted, c.want)
		}
		for _, part := range []string{secretText, bundleText, bundleText[:16]} {
			if strings.Contains(redacted, part) {
				t.Errorf("%q still shows a part", redacted)
			}
		}
	}
}

// §7.8's guard: a body holding a bundle's prefix in any spelling is refused before sending.
func TestCheckAuthKeyBodyRefusesTheBundlePrefix(t *testing.T) {
	for _, body := range []string{
		`{"auth_key":"x#y"}`,
		`{"device_spec":"x\u0023y"}`,
		`{"device_spec":"x\U0023y"}`,
		`auth_key=x%23y`,
		`auth_key=x%23Y`,
	} {
		if err := CheckAuthKeyBody([]byte(body)); !errors.Is(err, ErrAuthKeyBundleInBody) {
			t.Errorf("%s: %v", body, err)
		} else if strings.Contains(err.Error(), "x") {
			t.Errorf("the error repeats the body: %v", err)
		}
	}
	if err := CheckAuthKeyBody([]byte(`{"auth_key":"` + testAuthKeyBearer() + `"}`)); err != nil {
		t.Fatal(err)
	}
}

// SidecarApi.Enroll runs CheckAuthKeyBody, so a bundle written as JSON's escape in another field never
// leaves either.
func TestEnrollRefusesAnEscapedBundlePrefix(t *testing.T) {
	transport := answerWith(200, `{"by_client_jwt":"synthetic-jwt","client_id":"`+NewId().String()+`","admin_refused":true}`)
	api := newTestSidecarApi(t, transport)
	args := testEnrollArgs()
	args.AuthKey = testAuthKeyBearer()
	// encoding/json escapes no #, so the escape reaches the body only as a literal backslash sequence
	args.DeviceSpec = `ur synthetic/0 \u0023bundle`
	if _, err := api.Enroll(context.Background(), args); !errors.Is(err, ErrSidecarApiBundle) {
		t.Fatalf("%v", err)
	}
	if count := transport.requestCount(); count != 0 {
		t.Fatalf("%d requests sent", count)
	}
}

// No input panics, the bearer never holds the bundle or a #, and no error holds the input.
func FuzzAuthKeyString(f *testing.F) {
	bare, _ := formatAuthKey(testAuthKeyBearer(), nil)
	full, _ := formatAuthKey(testAuthKeyBearer(), testAuthKeyBundle())
	for _, seed := range []string{"", bare, full, "urn_synthetic", full + "#", strings.ToUpper(full), "#" + full} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		authKey, err := ParseAuthKey(text)
		if err != nil {
			if authKey != nil {
				t.Fatal("a key beside an error")
			}
			if 8 <= len(text) && strings.Contains(err.Error(), text) {
				t.Fatal("the error holds the input")
			}
			return
		}
		if strings.Contains(authKey.Bearer(), "#") {
			t.Fatal("the bearer holds a #")
		}
		if _, bundleText, found := strings.Cut(text, "#"); found && bundleText != "" &&
			strings.Contains(authKey.Bearer(), bundleText) {
			t.Fatal("the bearer holds the bundle")
		}
		if (authKey.Bundle() != nil) != strings.Contains(text, "#") {
			t.Fatal("a bundle without a #, or a # without a bundle")
		}
		if strings.Contains(RedactAuthKey(text), strings.TrimPrefix(authKey.Bearer(), authKeyPrefix)) {
			t.Fatal("redaction shows the bearer")
		}
		if err := CheckAuthKeyBody([]byte(authKey.Bearer())); err != nil {
			t.Fatal("a bearer CheckAuthKeyBody refuses")
		}
	})
}
