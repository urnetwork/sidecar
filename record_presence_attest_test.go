// §16.6's registration rows and labels (MCP-M3-08; FS-124): each attestation format on fixture roots, labelled attested,
// and the refusals §22.7's presence row names, another key's attestation and a software key as apple among them, none of
// them ever downgraded to asserted; fmt none and a Secure Enclave key asserted; and the canonical CBOR reader refusing
// every non-canonical form. Fixture roots and certificates are made here from fixed seeds, deterministically, and
// testdata/presence/attestation/vectors.json holds the bytes they give, embedded for the Worker leg. A format change
// regenerates it:
//
//	go test -run TestPresenceAttestationVectors . -args -update-presence-attestation-vectors
//
// No production root is read: QD-137 ships none, and these tests chain only to the fixtures.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"math/big"
	"os"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyteasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

//go:embed testdata/presence/attestation/vectors.json
var presenceAttestationVectorsJson []byte

var updatePresenceAttestationVectors = flag.Bool(
	"update-presence-attestation-vectors",
	false,
	"rewrite testdata/presence/attestation/vectors.json",
)

// Every fixture certificate's validity, and the time registrations are judged at, inside it.
var (
	testAttestNotBefore = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	testAttestNotAfter  = time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	testAttestAt        = time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
)

// The fixture authenticator model and the client data a create ceremony hashed.
var (
	testAttestAaguid         = bytes.Repeat([]byte{0xa6}, 16)
	testAttestCredentialId   = []byte("a synthetic credential id")
	testAttestClientDataJson = []byte(`{"type":"webauthn.create","challenge":"c3ludGhldGlj","origin":"https://ur.io","crossOrigin":false}`)
)

// The create ceremony's client data hash every statement signs.
func testAttestClientDataHash() []byte {
	digest := sha256.Sum256(testAttestClientDataJson)
	return digest[:]
}

// A map for the test encoder, in any order: it sorts keys as canonical form does.
type testCborMap []testCborPair

type testCborPair struct {
	key   any
	value any
}

// A CBOR head in its shortest form.
func testCborHead(majorType byte, argument uint64) []byte {
	switch {
	case argument < 24:
		return []byte{majorType<<5 | byte(argument)}
	case argument < 0x100:
		return []byte{majorType<<5 | 24, byte(argument)}
	case argument < 0x10000:
		return binary.BigEndian.AppendUint16([]byte{majorType<<5 | 25}, uint16(argument))
	case argument < 0x100000000:
		return binary.BigEndian.AppendUint32([]byte{majorType<<5 | 26}, uint32(argument))
	}
	return binary.BigEndian.AppendUint64([]byte{majorType<<5 | 27}, argument)
}

// value in CTAP2's canonical form: int64 or int, []byte, string, []any, testCborMap, bool or nil.
func testCborEncode(value any) []byte {
	switch v := value.(type) {
	case int:
		return testCborEncode(int64(v))
	case int64:
		if 0 <= v {
			return testCborHead(0, uint64(v))
		}
		return testCborHead(1, uint64(-1-v))
	case []byte:
		return append(testCborHead(2, uint64(len(v))), v...)
	case string:
		return append(testCborHead(3, uint64(len(v))), v...)
	case []any:
		encoded := testCborHead(4, uint64(len(v)))
		for _, element := range v {
			encoded = append(encoded, testCborEncode(element)...)
		}
		return encoded
	case testCborMap:
		type encodedPair struct{ key, value []byte }
		pairs := []encodedPair{}
		for _, pair := range v {
			pairs = append(pairs, encodedPair{key: testCborEncode(pair.key), value: testCborEncode(pair.value)})
		}
		slices.SortFunc(pairs, func(a encodedPair, b encodedPair) int {
			if presenceCborKeyBefore(a.key, b.key) {
				return -1
			}
			return 1
		})
		encoded := testCborHead(5, uint64(len(pairs)))
		for _, pair := range pairs {
			encoded = append(append(encoded, pair.key...), pair.value...)
		}
		return encoded
	case bool:
		if v {
			return []byte{0xf5}
		}
		return []byte{0xf4}
	case nil:
		return []byte{0xf6}
	}
	panic("no encoding")
}

// The canonical forms the reader takes, each decoding to what was encoded and keeping its bytes.
func TestPresenceCborReadsCanonicalForms(t *testing.T) {
	values := []any{
		0, 23, 24, 255, 256, 65535, 65536, int64(1) << 32, int64(-1), int64(-24), int64(-25), int64(-1) << 40,
		[]byte{}, []byte("bytes"), "", "text", "ü", []any{}, []any{1, "two", []byte{3}},
		testCborMap{{key: "authData", value: []byte{1}}, {key: "fmt", value: "none"}, {key: "attStmt", value: testCborMap{}}},
		testCborMap{{key: -3, value: []byte{3}}, {key: 1, value: 2}, {key: -1, value: 1}, {key: 3, value: -7}, {key: -2, value: []byte{2}}},
		true, false, nil,
	}
	for _, value := range values {
		encoded := testCborEncode(value)
		item, err := presenceCborDecodeAll(encoded)
		if err != nil {
			t.Errorf("%x: %v", encoded, err)
			continue
		}
		if !bytes.Equal(item.encoded, encoded) {
			t.Errorf("%x kept as %x", encoded, item.encoded)
		}
		if number, ok := value.(int); ok {
			if got, ok := item.int64Value(); !ok || got != int64(number) {
				t.Errorf("%x: %d, want %d", encoded, got, number)
			}
		}
	}
	// the attestation object's keys come out in canonical order whatever order they went in
	object, err := presenceCborDecodeAll(testCborEncode(values[19]))
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for _, key := range object.keys {
		keys = append(keys, string(key.content))
	}
	if !slices.Equal(keys, []string{"fmt", "attStmt", "authData"}) {
		t.Errorf("key order %q", keys)
	}
}

// Decoders refuse non-canonical CBOR (MCP-M3-08's tests): every form that is not the one encoding of its value, and
// what bounds work.
func TestPresenceCborRefusesNonCanonicalForms(t *testing.T) {
	nested := bytes.Repeat([]byte{0x81}, presenceCborMaxDepth)
	nested = append(nested, 0x00)
	cases := []struct {
		name    string
		encoded string
	}{
		{name: "5 in a one-byte argument", encoded: "1805"},
		{name: "16 in a two-byte argument", encoded: "190010"},
		{name: "255 in a four-byte argument", encoded: "1a000000ff"},
		{name: "a length in a long form", encoded: "5801ff"},
		{name: "an indefinite byte string", encoded: "5f41ff ff"},
		{name: "an indefinite array", encoded: "9fff"},
		{name: "an indefinite map", encoded: "bfff"},
		{name: "reserved additional information", encoded: "1c"},
		{name: "a tag", encoded: "c000"},
		{name: "a half float", encoded: "f90000"},
		{name: "a double", encoded: "fb0000000000000000"},
		{name: "undefined", encoded: "f7"},
		{name: "a simple value", encoded: "f820"},
		{name: "text that is not UTF-8", encoded: "61ff"},
		{name: "keys out of order", encoded: "a263736967016361 6c6702"},
		{name: "a repeated key", encoded: "a263666d740163666d7402"},
		{name: "a negative key before an unsigned one", encoded: "a2200101 02"},
		{name: "a longer key first", encoded: "a2636162630161 6102"},
		{name: "an array longer than its bytes", encoded: "9bffffffffffffffff"},
		{name: "a map longer than its bytes", encoded: "bb7fffffffffffffff"},
		{name: "a string longer than its bytes", encoded: "5a0000ffff00"},
		{name: "truncated", encoded: "82 01"},
		{name: "empty", encoded: ""},
		{name: "a byte after the item", encoded: "0000"},
		{name: "nested too deep", encoded: hex.EncodeToString(nested)},
	}
	for _, c := range cases {
		encoded, err := hex.DecodeString(stringsWithoutSpaces(c.encoded))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if _, err := presenceCborDecodeAll(encoded); !errors.Is(err, ErrPresenceCbor) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// s with its spaces dropped, so a case can space out its bytes.
func stringsWithoutSpaces(s string) string {
	return string(bytes.ReplaceAll([]byte(s), []byte(" "), nil))
}

// A fixture CA: its key and self-signed certificate.
type testAttestCa struct {
	key         *testPresenceKey
	certificate *x509.Certificate
	der         []byte
}

// A root CA from seed, signing nothing yet.
func newTestAttestCa(t testing.TB, seed string, serial int64) *testAttestCa {
	key := newTestPresenceKey(t, seed, bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: seed, Organization: []string{"Synthetic Attestation Test"}},
		NotBefore:             testAttestNotBefore,
		NotAfter:              testAttestNotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(nil, template, template, &key.privateKey.PublicKey, key.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testAttestCa{key: key, certificate: certificate, der: der}
}

// A certificate of template for publicKeyOf's key, signed by the CA, deterministically.
func (self *testAttestCa) issue(t testing.TB, template *x509.Certificate, subjectKey *testPresenceKey) []byte {
	template.NotBefore = testAttestNotBefore
	template.NotAfter = testAttestNotAfter
	der, err := x509.CreateCertificate(nil, template, self.certificate, &subjectKey.privateKey.PublicKey, self.key.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The fixture roots, one CA per format, and a software CA no pool holds.
type testAttestCas struct {
	packed     *testAttestCa
	tpm        *testAttestCa
	androidKey *testAttestCa
	apple      *testAttestCa
	software   *testAttestCa
}

func newTestAttestCas(t testing.TB) *testAttestCas {
	return &testAttestCas{
		packed:     newTestAttestCa(t, "synthetic packed root", 1),
		tpm:        newTestAttestCa(t, "synthetic tpm root", 2),
		androidKey: newTestAttestCa(t, "synthetic android-key root", 3),
		apple:      newTestAttestCa(t, "synthetic apple root", 4),
		software:   newTestAttestCa(t, "synthetic software key ca", 5),
	}
}

// Pools holding each format's fixture root, as a release's would hold its pinned ones.
func (self *testAttestCas) roots() *presenceAttestationRoots {
	pool := func(ca *testAttestCa) *x509.CertPool {
		certificates := x509.NewCertPool()
		certificates.AddCert(ca.certificate)
		return certificates
	}
	return &presenceAttestationRoots{
		packed:     pool(self.packed),
		tpm:        pool(self.tpm),
		androidKey: pool(self.androidKey),
		apple:      pool(self.apple),
	}
}

// The credential's authenticator data, rp ur.io, with UP, UV and attested credential data unless flags says otherwise.
func testAttestAuthData(credential *testPresenceKey, flags byte) []byte {
	rpIdHash := sha256.Sum256([]byte("ur.io"))
	authData := append(rpIdHash[:], flags)
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, testAttestAaguid...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(testAttestCredentialId)))
	authData = append(authData, testAttestCredentialId...)
	coseKey := testCborMap{
		{key: 1, value: presenceCoseKeyTypeEc2},
		{key: 3, value: presenceCoseAlgEs256},
		{key: -1, value: presenceCoseCurveP256},
		{key: -2, value: credential.publicKey[1:33]},
		{key: -3, value: credential.publicKey[33:65]},
	}
	return append(authData, testCborEncode(coseKey)...)
}

// The flags a registration's authenticator data carries.
const testAttestFlags = presenceAuthFlagUserPresent | presenceAuthFlagUserVerified | presenceAuthFlagAttestedData

// An attestation object of format over authData.
func testAttestObject(format string, statement testCborMap, authData []byte) []byte {
	return testCborEncode(testCborMap{
		{key: "fmt", value: format},
		{key: "attStmt", value: statement},
		{key: "authData", value: authData},
	})
}

// What one format's attestation is made of, with each input a test may spoil.
type testAttestation struct {
	cas        *testAttestCas
	credential *testPresenceKey
	authData   []byte
	// The client data hash the statement signs or embeds.
	signedClientDataHash []byte
	// Which CA issues the chain; nil is the format's own.
	issuer *testAttestCa
	// android-key and apple: the certificate's key, nil the credential's.
	certificateKey *testPresenceKey

	packedOu               string
	packedCa               bool
	packedAaguid           []byte
	tpmMagic               uint32
	tpmVersion             string
	tpmNameSpoiled         bool
	tpmSubject             bool
	tpmNoAlternativeName   bool
	tpmNoAikUsage          bool
	androidLevel           int
	androidAllApplications bool
	androidOrigin          int
	androidPurposes        []int
	alg                    int64
}

// An attestation of the credential that verifies as its format's, for a test to spoil one input of.
func newTestAttestation(cas *testAttestCas, credential *testPresenceKey) *testAttestation {
	return &testAttestation{
		cas:                  cas,
		credential:           credential,
		authData:             testAttestAuthData(credential, testAttestFlags),
		signedClientDataHash: testAttestClientDataHash(),
		packedOu:             "Authenticator Attestation",
		packedAaguid:         testAttestAaguid,
		tpmMagic:             presenceTpmGeneratedValue,
		tpmVersion:           "2.0",
		androidLevel:         1,
		androidOrigin:        0,
		androidPurposes:      []int{2},
		alg:                  presenceCoseAlgEs256,
	}
}

// The data a statement signs: authData || the client data hash it was given.
func (self *testAttestation) signedData() []byte {
	return slices.Concat(self.authData, self.signedClientDataHash)
}

func (self *testAttestation) issuerOr(own *testAttestCa) *testAttestCa {
	if self.issuer != nil {
		return self.issuer
	}
	return own
}

func (self *testAttestation) certificateKeyOrCredential() *testPresenceKey {
	if self.certificateKey != nil {
		return self.certificateKey
	}
	return self.credential
}

// packed with an attestation certificate.
func (self *testAttestation) packed(t testing.TB) []byte {
	ca := self.issuerOr(self.cas.packed)
	attestationKey := newTestPresenceKey(t, "synthetic packed attestation key", bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
	aaguidValue, err := asn1.Marshal(self.packedAaguid)
	if err != nil {
		t.Fatal(err)
	}
	leaf := ca.issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject: pkix.Name{
			Country:            []string{"ZZ"},
			Organization:       []string{"Synthetic Authenticator Vendor"},
			OrganizationalUnit: []string{self.packedOu},
			CommonName:         "Synthetic Packed Attestation",
		},
		BasicConstraintsValid: true,
		IsCA:                  self.packedCa,
		ExtraExtensions:       []pkix.Extension{{Id: presenceOidFidoAaguid, Value: aaguidValue}},
	}, attestationKey)
	digest := sha256.Sum256(self.signedData())
	return testAttestObject("packed", testCborMap{
		{key: "alg", value: self.alg},
		{key: "sig", value: attestationKey.signDigest(t, digest[:])},
		{key: "x5c", value: []any{leaf}},
	}, self.authData)
}

// packed self attestation, by the credential key.
func (self *testAttestation) packedSelf(t testing.TB) []byte {
	digest := sha256.Sum256(self.signedData())
	return testAttestObject("packed", testCborMap{
		{key: "alg", value: self.alg},
		{key: "sig", value: self.certificateKeyOrCredential().signDigest(t, digest[:])},
	}, self.authData)
}

// tpm, by an ECC AIK.
func (self *testAttestation) tpm(t testing.TB) []byte {
	ca := self.issuerOr(self.cas.tpm)
	aikKey := newTestPresenceKey(t, "synthetic tpm aik", bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)

	pubArea := binary.BigEndian.AppendUint16(nil, presenceTpmAlgEcc)
	pubArea = binary.BigEndian.AppendUint16(pubArea, presenceTpmAlgSha256)
	pubArea = binary.BigEndian.AppendUint32(pubArea, 0x00060472)
	pubArea = binary.BigEndian.AppendUint16(pubArea, 0)
	pubArea = binary.BigEndian.AppendUint16(pubArea, presenceTpmAlgNull)
	pubArea = binary.BigEndian.AppendUint16(pubArea, presenceTpmAlgNull)
	pubArea = binary.BigEndian.AppendUint16(pubArea, presenceTpmEccNistP256)
	pubArea = binary.BigEndian.AppendUint16(pubArea, presenceTpmAlgNull)
	pubArea = binary.BigEndian.AppendUint16(pubArea, 32)
	pubArea = append(pubArea, self.certificateKeyOrCredential().publicKey[1:33]...)
	pubArea = binary.BigEndian.AppendUint16(pubArea, 32)
	pubArea = append(pubArea, self.certificateKeyOrCredential().publicKey[33:65]...)

	nameDigest := sha256.Sum256(pubArea)
	name := binary.BigEndian.AppendUint16(nil, presenceTpmAlgSha256)
	name = append(name, nameDigest[:]...)
	if self.tpmNameSpoiled {
		name[len(name)-1] ^= 0x01
	}
	extraData := sha256.Sum256(self.signedData())
	certInfo := binary.BigEndian.AppendUint32(nil, self.tpmMagic)
	certInfo = binary.BigEndian.AppendUint16(certInfo, presenceTpmStAttestCertify)
	certInfo = binary.BigEndian.AppendUint16(certInfo, 34)
	certInfo = append(certInfo, append([]byte{0x00, 0x0b}, bytes.Repeat([]byte{0x5e}, 32)...)...)
	certInfo = binary.BigEndian.AppendUint16(certInfo, 32)
	certInfo = append(certInfo, extraData[:]...)
	certInfo = append(certInfo, make([]byte, 8+4+4+1)...)
	certInfo = append(certInfo, make([]byte, 8)...)
	certInfo = binary.BigEndian.AppendUint16(certInfo, uint16(len(name)))
	certInfo = append(certInfo, name...)
	certInfo = binary.BigEndian.AppendUint16(certInfo, 34)
	certInfo = append(certInfo, append([]byte{0x00, 0x0b}, bytes.Repeat([]byte{0x9a}, 32)...)...)

	// a directoryName naming a synthetic TPM's manufacturer, model and version
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyteasn1.SEQUENCE, func(names *cryptobyte.Builder) {
		names.AddASN1(cryptobyteasn1.Tag(4).Constructed().ContextSpecific(), func(directoryName *cryptobyte.Builder) {
			directoryName.AddASN1(cryptobyteasn1.SEQUENCE, func(rdnSequence *cryptobyte.Builder) {
				for _, attribute := range []struct {
					oid   asn1.ObjectIdentifier
					value string
				}{
					{oid: presenceOidTpmManufacturer, value: "id:53594E54"},
					{oid: presenceOidTpmModel, value: "SYNTHETIC"},
					{oid: presenceOidTpmVersion, value: "id:00010002"},
				} {
					rdnSequence.AddASN1(cryptobyteasn1.SET, func(rdn *cryptobyte.Builder) {
						rdn.AddASN1(cryptobyteasn1.SEQUENCE, func(pair *cryptobyte.Builder) {
							pair.AddASN1ObjectIdentifier(attribute.oid)
							pair.AddASN1(cryptobyteasn1.UTF8String, func(value *cryptobyte.Builder) {
								value.AddBytes([]byte(attribute.value))
							})
						})
					})
				}
			})
		})
	})
	alternativeName, err := builder.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(12),
		BasicConstraintsValid: true,
	}
	if self.tpmSubject {
		template.Subject = pkix.Name{CommonName: "Synthetic AIK"}
	}
	if !self.tpmNoAikUsage {
		template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{presenceOidTpmAikCertificate}
	}
	if !self.tpmNoAlternativeName {
		template.ExtraExtensions = []pkix.Extension{{Id: presenceOidSubjectAltName, Critical: true, Value: alternativeName}}
	}
	aik := ca.issue(t, template, aikKey)
	certInfoDigest := sha256.Sum256(certInfo)
	return testAttestObject("tpm", testCborMap{
		{key: "ver", value: self.tpmVersion},
		{key: "alg", value: self.alg},
		{key: "x5c", value: []any{aik}},
		{key: "sig", value: aikKey.signDigest(t, certInfoDigest[:])},
		{key: "certInfo", value: certInfo},
		{key: "pubArea", value: pubArea},
	}, self.authData)
}

// A DER element with a tag of any number, which cryptobyte cannot write past 30.
func testDerElement(class byte, constructed bool, number int, content []byte) []byte {
	identifier := class << 6
	if constructed {
		identifier |= 0x20
	}
	element := []byte{}
	if number < 0x1f {
		element = append(element, identifier|byte(number))
	} else {
		element = append(element, identifier|0x1f)
		groups := []byte{byte(number & 0x7f)}
		for rest := number >> 7; 0 < rest; rest >>= 7 {
			groups = append([]byte{byte(rest&0x7f) | 0x80}, groups...)
		}
		element = append(element, groups...)
	}
	switch length := len(content); {
	case length < 0x80:
		element = append(element, byte(length))
	case length < 0x100:
		element = append(element, 0x81, byte(length))
	default:
		element = append(element, 0x82, byte(length>>8), byte(length))
	}
	return append(element, content...)
}

// A DER INTEGER of a small non-negative value.
func testDerInteger(value int) []byte {
	encoded, err := asn1.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

// android-key: the credential's certificate with its key description.
func (self *testAttestation) androidKey(t testing.TB) []byte {
	ca := self.issuerOr(self.cas.androidKey)
	purposes := []byte{}
	for _, purpose := range self.androidPurposes {
		purposes = append(purposes, testDerInteger(purpose)...)
	}
	teeEnforced := slices.Concat(
		testDerElement(2, true, presenceAndroidPurpose, testDerElement(0, true, 17, purposes)),
		testDerElement(2, true, 2, testDerInteger(3)),
		testDerElement(2, true, presenceAndroidOrigin, testDerInteger(self.androidOrigin)),
	)
	softwareEnforced := []byte{}
	if self.androidAllApplications {
		softwareEnforced = testDerElement(2, true, presenceAndroidAllApplications, []byte{0x05, 0x00})
	}
	description := testDerElement(0, true, 16, slices.Concat(
		testDerInteger(4),
		testDerElement(0, false, 10, []byte{byte(self.androidLevel)}),
		testDerInteger(4),
		testDerElement(0, false, 10, []byte{byte(self.androidLevel)}),
		testDerElement(0, false, 4, self.signedClientDataHash),
		testDerElement(0, false, 4, nil),
		testDerElement(0, true, 16, softwareEnforced),
		testDerElement(0, true, 16, teeEnforced),
	))
	credentialCertificate := ca.issue(t, &x509.Certificate{
		SerialNumber:          big.NewInt(13),
		Subject:               pkix.Name{CommonName: "Synthetic Android Keystore Key"},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: presenceOidAndroidKeyDesc, Value: description}},
	}, self.certificateKeyOrCredential())
	digest := sha256.Sum256(self.signedData())
	return testAttestObject("android-key", testCborMap{
		{key: "alg", value: self.alg},
		{key: "sig", value: self.certificateKeyOrCredential().signDigest(t, digest[:])},
		{key: "x5c", value: []any{credentialCertificate}},
	}, self.authData)
}

// apple: the credential's certificate with its nonce extension.
func (self *testAttestation) apple(t testing.TB) []byte {
	ca := self.issuerOr(self.cas.apple)
	nonce := sha256.Sum256(self.signedData())
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyteasn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
		sequence.AddASN1(cryptobyteasn1.Tag(1).Constructed().ContextSpecific(), func(tagged *cryptobyte.Builder) {
			tagged.AddASN1OctetString(nonce[:])
		})
	})
	nonceExtension, err := builder.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	credentialCertificate := ca.issue(t, &x509.Certificate{
		SerialNumber:          big.NewInt(14),
		Subject:               pkix.Name{CommonName: "Synthetic Apple Credential"},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: presenceOidAppleNonce, Value: nonceExtension}},
	}, self.certificateKeyOrCredential())
	return testAttestObject("apple", testCborMap{{key: "x5c", value: []any{credentialCertificate}}}, self.authData)
}

// fmt none.
func (self *testAttestation) none() []byte {
	return testAttestObject("none", testCborMap{}, self.authData)
}

// The format's object by name.
func (self *testAttestation) object(t testing.TB, format string) []byte {
	switch format {
	case "packed":
		return self.packed(t)
	case "packed self":
		return self.packedSelf(t)
	case "tpm":
		return self.tpm(t)
	case "android-key":
		return self.androidKey(t)
	case "apple":
		return self.apple(t)
	}
	return self.none()
}

// The four formats that chain to a root.
var testAttestChainedFormats = []string{"packed", "tpm", "android-key", "apple"}

// The credential every attestation here registers, and another.
func testAttestCredentials(t testing.TB) (*testPresenceKey, *testPresenceKey) {
	return newTestPresenceKey(t, "webauthn-es256 key a", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256),
		newTestPresenceKey(t, "another key", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
}

// Each format on its fixture root labels attested; packed self attestation and fmt none label asserted.
func TestPresenceAttestationFormatsLabel(t *testing.T) {
	cas := newTestAttestCas(t)
	credential, _ := testAttestCredentials(t)
	for _, format := range append(slices.Clone(testAttestChainedFormats), "packed self", "none") {
		object := newTestAttestation(cas, credential).object(t, format)
		label, err := verifyPresenceAttestationObject(object, testAttestClientDataHash(), credential.publicKey, cas.roots(), testAttestAt)
		want := PresenceLabelAttested
		if format == "packed self" || format == "none" {
			want = PresenceLabelAsserted
		}
		if err != nil || label != want {
			t.Errorf("%s: %s, %v; want %s", format, label, err, want)
		}
	}
}

// Another key's attestation, valid as its own, is refused for this key, in every format.
func TestPresenceAttestationRefusesAnotherKeysAttestation(t *testing.T) {
	cas := newTestAttestCas(t)
	credential, other := testAttestCredentials(t)
	for _, format := range append(slices.Clone(testAttestChainedFormats), "packed self", "none") {
		object := newTestAttestation(cas, other).object(t, format)
		_, err := verifyPresenceAttestationObject(object, testAttestClientDataHash(), credential.publicKey, cas.roots(), testAttestAt)
		if !errors.Is(err, ErrPresenceAttestation) {
			t.Errorf("%s: %v", format, err)
		}
	}
	// a certificate for another key than the credential its statement names
	for _, format := range []string{"android-key", "apple"} {
		attestation := newTestAttestation(cas, credential)
		attestation.certificateKey = other
		_, err := verifyPresenceAttestationObject(
			attestation.object(t, format), testAttestClientDataHash(), credential.publicKey, cas.roots(), testAttestAt)
		if !errors.Is(err, ErrPresenceAttestation) {
			t.Errorf("%s with another key's certificate: %v", format, err)
		}
	}
	// a packed self attestation the credential did not sign
	attestation := newTestAttestation(cas, credential)
	attestation.certificateKey = other
	_, err := verifyPresenceAttestationObject(
		attestation.object(t, "packed self"), testAttestClientDataHash(), credential.publicKey, cas.roots(), testAttestAt)
	if !errors.Is(err, ErrPresenceAttestation) {
		t.Errorf("packed self by another key: %v", err)
	}
}

// A software key presented as apple: its certificate chains to a CA that is no apple root, and it is refused, never
// labelled asserted. So is every format chained to that CA, and every format against the release's empty pools.
func TestPresenceAttestationRefusesASoftwareKeyAsApple(t *testing.T) {
	cas := newTestAttestCas(t)
	credential, _ := testAttestCredentials(t)
	for _, format := range testAttestChainedFormats {
		attestation := newTestAttestation(cas, credential)
		attestation.issuer = cas.software
		label, err := verifyPresenceAttestationObject(
			attestation.object(t, format), testAttestClientDataHash(), credential.publicKey, cas.roots(), testAttestAt)
		if !errors.Is(err, ErrPresenceAttestation) || label != 0 {
			t.Errorf("%s by a software CA: %s, %v", format, label, err)
		}
		object := newTestAttestation(cas, credential).object(t, format)
		label, err = verifyPresenceAttestationObject(
			object, testAttestClientDataHash(), credential.publicKey, presenceReleaseAttestationRoots(), testAttestAt)
		if !errors.Is(err, ErrPresenceAttestation) || label != 0 {
			t.Errorf("%s against the release's roots: %s, %v", format, label, err)
		}
	}
}

// A statement over another create ceremony's client data, in every format but none.
func TestPresenceAttestationRefusesAnotherClientData(t *testing.T) {
	cas := newTestAttestCas(t)
	credential, _ := testAttestCredentials(t)
	otherHash := sha256.Sum256([]byte("another ceremony's client data"))
	for _, format := range append(slices.Clone(testAttestChainedFormats), "packed self") {
		attestation := newTestAttestation(cas, credential)
		attestation.signedClientDataHash = otherHash[:]
		_, err := verifyPresenceAttestationObject(
			attestation.object(t, format), testAttestClientDataHash(), credential.publicKey, cas.roots(), testAttestAt)
		if !errors.Is(err, ErrPresenceAttestation) {
			t.Errorf("%s: %v", format, err)
		}
	}
}

// Outside every fixture certificate's validity, nothing chains.
func TestPresenceAttestationRefusesAnExpiredChain(t *testing.T) {
	cas := newTestAttestCas(t)
	credential, _ := testAttestCredentials(t)
	for _, format := range testAttestChainedFormats {
		object := newTestAttestation(cas, credential).object(t, format)
		_, err := verifyPresenceAttestationObject(
			object, testAttestClientDataHash(), credential.publicKey, cas.roots(), testAttestNotAfter.Add(time.Hour))
		if !errors.Is(err, ErrPresenceAttestation) {
			t.Errorf("%s: %v", format, err)
		}
	}
}

// The authenticator data every format reads: another rp, UP, UV or attested data unset, a credential key that is no
// ES256 key, and bytes after it.
func TestPresenceAttestationRefusesAuthData(t *testing.T) {
	cas := newTestAttestCas(t)
	credential, _ := testAttestCredentials(t)
	good := testAttestAuthData(credential, testAttestFlags)
	otherRp := slices.Clone(good)
	otherRp[0] ^= 0x01
	rs256Key := slices.Concat(good[:presenceAuthDataFixedSize+presenceAuthAaguidSize+2+len(testAttestCredentialId)], testCborEncode(testCborMap{
		{key: 1, value: presenceCoseKeyTypeEc2},
		{key: 3, value: presenceCoseAlgRs256},
		{key: -1, value: presenceCoseCurveP256},
		{key: -2, value: credential.publicKey[1:33]},
		{key: -3, value: credential.publicKey[33:65]},
	}))
	for _, c := range []struct {
		name     string
		authData []byte
	}{
		{name: "another rp", authData: otherRp},
		{name: "UP unset", authData: testAttestAuthData(credential, testAttestFlags&^presenceAuthFlagUserPresent)},
		{name: "UV unset", authData: testAttestAuthData(credential, testAttestFlags&^presenceAuthFlagUserVerified)},
		{name: "no attested data", authData: testAttestAuthData(credential, testAttestFlags&^presenceAuthFlagAttestedData)},
		{name: "extensions flagged and absent", authData: testAttestAuthData(credential, testAttestFlags|presenceAuthFlagExtensionData)},
		{name: "a byte after", authData: append(slices.Clone(good), 0x00)},
		{name: "an RS256 alg", authData: rs256Key},
		{name: "truncated", authData: good[:40]},
	} {
		attestation := newTestAttestation(cas, credential)
		attestation.authData = c.authData
		_, err := verifyPresenceAttestationObject(attestation.none(), testAttestClientDataHash(), credential.publicKey, cas.roots(), testAttestAt)
		if !errors.Is(err, ErrPresenceAttestation) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// extensions, flagged and present, are read and the key still attested
	attestation := newTestAttestation(cas, credential)
	attestation.authData = append(
		testAttestAuthData(credential, testAttestFlags|presenceAuthFlagExtensionData),
		testCborEncode(testCborMap{{key: "credProtect", value: 2}})...,
	)
	label, err := verifyPresenceAttestationObject(attestation.packed(t), testAttestClientDataHash(), credential.publicKey, cas.roots(), testAttestAt)
	if err != nil || label != PresenceLabelAttested {
		t.Errorf("with extensions: %s, %v", label, err)
	}
}

// Each format's own requirements, spoiled one at a time.
func TestPresenceAttestationRefusesFormatRequirements(t *testing.T) {
	cas := newTestAttestCas(t)
	credential, _ := testAttestCredentials(t)
	cases := []struct {
		name   string
		format string
		spoil  func(attestation *testAttestation)
	}{
		{name: "packed: another unit", format: "packed", spoil: func(a *testAttestation) { a.packedOu = "Synthetic Unit" }},
		{name: "packed: a CA certificate", format: "packed", spoil: func(a *testAttestation) { a.packedCa = true }},
		{name: "packed: another aaguid", format: "packed", spoil: func(a *testAttestation) { a.packedAaguid = bytes.Repeat([]byte{0x01}, 16) }},
		{name: "packed: RS256", format: "packed", spoil: func(a *testAttestation) { a.alg = presenceCoseAlgRs256 }},
		{name: "packed self: RS256", format: "packed self", spoil: func(a *testAttestation) { a.alg = presenceCoseAlgRs256 }},
		{name: "tpm: magic", format: "tpm", spoil: func(a *testAttestation) { a.tpmMagic = 0 }},
		{name: "tpm: version", format: "tpm", spoil: func(a *testAttestation) { a.tpmVersion = "1.2" }},
		{name: "tpm: name", format: "tpm", spoil: func(a *testAttestation) { a.tpmNameSpoiled = true }},
		{name: "tpm: a subject", format: "tpm", spoil: func(a *testAttestation) { a.tpmSubject = true }},
		{name: "tpm: no alternative name", format: "tpm", spoil: func(a *testAttestation) { a.tpmNoAlternativeName = true }},
		{name: "tpm: no AIK usage", format: "tpm", spoil: func(a *testAttestation) { a.tpmNoAikUsage = true }},
		{name: "tpm: another key's pubArea", format: "tpm", spoil: func(a *testAttestation) {
			_, other := testAttestCredentials(t)
			a.certificateKey = other
		}},
		{name: "android-key: software", format: "android-key", spoil: func(a *testAttestation) { a.androidLevel = 0 }},
		{name: "android-key: all applications", format: "android-key", spoil: func(a *testAttestation) { a.androidAllApplications = true }},
		{name: "android-key: imported", format: "android-key", spoil: func(a *testAttestation) { a.androidOrigin = 2 }},
		{name: "android-key: not for signing", format: "android-key", spoil: func(a *testAttestation) { a.androidPurposes = []int{3} }},
		{name: "android-key: RS256", format: "android-key", spoil: func(a *testAttestation) { a.alg = presenceCoseAlgRs256 }},
	}
	for _, c := range cases {
		attestation := newTestAttestation(cas, credential)
		c.spoil(attestation)
		label, err := verifyPresenceAttestationObject(
			attestation.object(t, c.format), testAttestClientDataHash(), credential.publicKey, cas.roots(), testAttestAt)
		if !errors.Is(err, ErrPresenceAttestation) || label != 0 {
			t.Errorf("%s: %s, %v", c.name, label, err)
		}
	}
}

// An object that is not an attestation object, or a statement with another shape: refused.
func TestPresenceAttestationRefusesShapes(t *testing.T) {
	cas := newTestAttestCas(t)
	credential, _ := testAttestCredentials(t)
	authData := testAttestAuthData(credential, testAttestFlags)
	for _, c := range []struct {
		name   string
		object []byte
	}{
		{name: "an unknown fmt", object: testAttestObject("fido-u2f", testCborMap{}, authData)},
		{name: "none with a statement", object: testAttestObject("none", testCborMap{{key: "sig", value: []byte{1}}}, authData)},
		{name: "a fourth key", object: testCborEncode(testCborMap{
			{key: "fmt", value: "none"}, {key: "attStmt", value: testCborMap{}}, {key: "authData", value: authData}, {key: "epAtt", value: true},
		})},
		{name: "authData as text", object: testCborEncode(testCborMap{
			{key: "fmt", value: "none"}, {key: "attStmt", value: testCborMap{}}, {key: "authData", value: "text"},
		})},
		{name: "an array", object: testCborEncode([]any{"none"})},
		{name: "apple with alg", object: testAttestObject("apple", testCborMap{{key: "alg", value: -7}, {key: "x5c", value: []any{}}}, authData)},
		{name: "packed with an empty x5c", object: testAttestObject("packed", testCborMap{
			{key: "alg", value: -7}, {key: "sig", value: []byte{1}}, {key: "x5c", value: []any{}},
		}, authData)},
		{name: "packed with a certificate that is none", object: testAttestObject("packed", testCborMap{
			{key: "alg", value: -7}, {key: "sig", value: []byte{1}}, {key: "x5c", value: []any{[]byte("not a certificate")}},
		}, authData)},
		{name: "too long", object: make([]byte, presenceAttestationMaxByteCount+1)},
	} {
		_, err := verifyPresenceAttestationObject(c.object, testAttestClientDataHash(), credential.publicKey, cas.roots(), testAttestAt)
		if !errors.Is(err, ErrPresenceAttestation) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// Through a KeyRegister: fmt none and an empty attestation label a webauthn-es256 key asserted, an ecdsa-p256-sha256 key
// is asserted and carries none, and every chained format is refused, since its client data is not carried (question
// mcp-m2-01-attestation-client-data), and no production root ships besides.
func TestVerifyPresenceAttestationFromAKeyRegister(t *testing.T) {
	cas := newTestAttestCas(t)
	credential, _ := testAttestCredentials(t)
	register := func(alg bridge.KeyAlg, attestation []byte) *protocol.KeyRegister {
		return &protocol.KeyRegister{
			KeyId:       bytes.Clone(credential.keyId),
			Alg:         alg,
			PublicKey:   bytes.Clone(credential.publicKey),
			Attestation: attestation,
			Purpose:     bridge.KeyPurpose_KEY_PURPOSE_PRESENCE,
		}
	}
	atMillis := testAttestAt.UnixMilli()
	asserted := []*protocol.KeyRegister{
		register(bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256, newTestAttestation(cas, credential).none()),
		register(bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256, nil),
		register(bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256, nil),
	}
	for _, keyRegister := range asserted {
		label, err := VerifyPresenceAttestation(keyRegister, atMillis)
		if err != nil || label != PresenceLabelAsserted {
			t.Errorf("%s with %d bytes: %s, %v", keyRegister.GetAlg(), len(keyRegister.GetAttestation()), label, err)
		}
	}
	refused := []*protocol.KeyRegister{
		nil,
		register(bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256, newTestAttestation(cas, credential).none()),
		register(bridge.KeyAlg_KEY_ALG_SSH_ED25519, nil),
		register(bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256, []byte("not an attestation object")),
	}
	sshsig := register(bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256, nil)
	sshsig.Purpose = bridge.KeyPurpose_KEY_PURPOSE_SSHSIG
	refused = append(refused, sshsig)
	for _, format := range append(slices.Clone(testAttestChainedFormats), "packed self") {
		refused = append(refused, register(bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256, newTestAttestation(cas, credential).object(t, format)))
	}
	for i, keyRegister := range refused {
		label, err := VerifyPresenceAttestation(keyRegister, atMillis)
		if !errors.Is(err, ErrPresenceAttestation) || label != 0 {
			t.Errorf("refusal %d: %s, %v", i, label, err)
		}
	}
	if PresenceLabelAsserted.String() != "presence (asserted)" || PresenceLabelAttested.String() != "presence (attested)" {
		t.Errorf("labels %q and %q", PresenceLabelAsserted, PresenceLabelAttested)
	}
}

// One attestation vector: the object, what it is checked against, and its label or refusal.
type presenceAttestationVector struct {
	Name           string   `json:"name"`
	Object         hexBytes `json:"object"`
	ClientDataHash hexBytes `json:"client_data_hash"`
	PublicKey      hexBytes `json:"public_key"`
	Roots          string   `json:"roots"`
	Label          string   `json:"label,omitempty"`
	Refused        bool     `json:"refused,omitempty"`
}

// The file's shape: the fixture roots by format, as DER, then the vectors.
type presenceAttestationVectorFile struct {
	Comment string                       `json:"comment"`
	AtMs    int64                        `json:"at_ms"`
	Roots   map[string]hexBytes          `json:"roots"`
	Vectors []*presenceAttestationVector `json:"vectors"`
}

// The vectors this leg computes from the fixed seeds.
func testPresenceAttestationVectorFile(t *testing.T) *presenceAttestationVectorFile {
	cas := newTestAttestCas(t)
	credential, other := testAttestCredentials(t)
	file := &presenceAttestationVectorFile{
		Comment: "Fixed vectors for MCP-M3-08's attestation check (§16.6's registration rows and labels; D-MCP-19, FS-124). " +
			"Every root, certificate and key is synthetic, made from fixed seeds by record_presence_attest_test.go, and " +
			"signatures are RFC 6979 deterministic. A vector is checked against roots \"fixture\", each format's fixture root " +
			"below, or \"release\", this build's empty pools (QD-137), with its client data hash, at at_ms. Bytes are " +
			"lowercase hex. go test -run TestPresenceAttestationVectors -update-presence-attestation-vectors rewrites this " +
			"file, which is a format change.",
		AtMs: testAttestAt.UnixMilli(),
		Roots: map[string]hexBytes{
			"packed":      cas.packed.der,
			"tpm":         cas.tpm.der,
			"android-key": cas.androidKey.der,
			"apple":       cas.apple.der,
		},
	}
	add := func(name string, object []byte, roots string, label PresenceLabel) {
		vector := &presenceAttestationVector{
			Name:           name,
			Object:         object,
			ClientDataHash: testAttestClientDataHash(),
			PublicKey:      credential.publicKey,
			Roots:          roots,
		}
		if label == 0 {
			vector.Refused = true
		} else {
			vector.Label = label.String()
		}
		file.Vectors = append(file.Vectors, vector)
	}
	for _, format := range testAttestChainedFormats {
		add(format+" attested", newTestAttestation(cas, credential).object(t, format), "fixture", PresenceLabelAttested)
		add(format+" without a pinned root", newTestAttestation(cas, credential).object(t, format), "release", 0)
		add(format+" for another key", newTestAttestation(cas, other).object(t, format), "fixture", 0)
		bySoftware := newTestAttestation(cas, credential)
		bySoftware.issuer = cas.software
		add(format+" by a software key's CA", bySoftware.object(t, format), "fixture", 0)
	}
	add("packed self asserted", newTestAttestation(cas, credential).packedSelf(t), "fixture", PresenceLabelAsserted)
	add("none asserted", newTestAttestation(cas, credential).none(), "release", PresenceLabelAsserted)
	add("none for another key", newTestAttestation(cas, other).none(), "release", 0)
	return file
}

// The file as checked in, with what this leg computes from the same seeds beside it.
func TestPresenceAttestationVectorsAreByteEqual(t *testing.T) {
	encoded, err := json.MarshalIndent(testPresenceAttestationVectorFile(t), "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if *updatePresenceAttestationVectors {
		if err := os.WriteFile("testdata/presence/attestation/vectors.json", encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if !bytes.Equal(encoded, presenceAttestationVectorsJson) {
		t.Error("a vector moved: this leg computes other bytes than testdata/presence/attestation/vectors.json holds")
	}
}

// The checked-in vectors' roots, as pools.
func testPresenceAttestationVectorRoots(t *testing.T, file *presenceAttestationVectorFile) *presenceAttestationRoots {
	pool := func(format string) *x509.CertPool {
		certificate, err := x509.ParseCertificate(file.Roots[format])
		if err != nil {
			t.Fatalf("%s's root: %v", format, err)
		}
		certificates := x509.NewCertPool()
		certificates.AddCert(certificate)
		return certificates
	}
	return &presenceAttestationRoots{
		packed:     pool("packed"),
		tpm:        pool("tpm"),
		androidKey: pool("android-key"),
		apple:      pool("apple"),
	}
}

// Each checked-in vector gets its label or refusal from its bytes and the file's roots alone.
func TestPresenceAttestationVectorsVerify(t *testing.T) {
	file := &presenceAttestationVectorFile{}
	if err := json.Unmarshal(presenceAttestationVectorsJson, file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	fixtureRoots := testPresenceAttestationVectorRoots(t, file)
	at := time.UnixMilli(file.AtMs)
	formats := map[string]bool{}
	for _, vector := range file.Vectors {
		roots := fixtureRoots
		if vector.Roots == "release" {
			roots = presenceReleaseAttestationRoots()
		}
		label, err := verifyPresenceAttestationObject(vector.Object, vector.ClientDataHash, vector.PublicKey, roots, at)
		if vector.Refused {
			if !errors.Is(err, ErrPresenceAttestation) || label != 0 {
				t.Errorf("%s: %s, %v; want a refusal", vector.Name, label, err)
			}
			continue
		}
		if err != nil || label.String() != vector.Label {
			t.Errorf("%s: %s, %v; want %s", vector.Name, label, err, vector.Label)
		}
		object, err := presenceCborDecodeAll(vector.Object)
		if err != nil {
			t.Fatal(err)
		}
		format, _ := object.textKey("fmt")
		formats[string(format.content)] = true
	}
	for _, format := range append(slices.Clone(testAttestChainedFormats), "none") {
		if !formats[format] {
			t.Errorf("no vector labels a %s attestation", format)
		}
	}
}
