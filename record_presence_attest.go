// §16.6's registration rows and labels (D-MCP-19, I-8; FS-124): what a presence key's KeyRegister.attestation shows of
// where the key lives, which records and approver screens show as presence (attested) or presence (asserted), both
// channel presence, the policy grammar unchanged.
//
// A webauthn-es256 key is attested when its attestation is packed with a certificate chain, tpm, android-key or apple
// and chains to a root the release pins for that format; it is asserted for fmt none, for an empty attestation, and for
// packed self attestation, which proves only that the key signed, as its KeyRegister's own proof already does. An
// ecdsa-p256-sha256 key, a Secure Enclave's, is always asserted, since no remote attestation of a Secure Enclave key's
// access control exists on an unmanaged device, and carries no attestation. A present attestation that fails is
// refused, never downgraded to asserted, so a software key cannot pass as apple and then show as anything.
//
// Two things hold the attested label back in this build, each failing closed. No production roots ship and clients
// request none conveyance (QD-137's interim), so the release's pools are empty and nothing chains. And every format but
// none signs the create ceremony's client data, which KeyRegister.attestation, the raw attestation object (QD-445), does
// not carry: until question mcp-m2-01-attestation-client-data is answered, VerifyPresenceAttestation refuses those
// formats. verifyPresenceAttestationObject is the whole check on an explicit client data hash and fixture roots, which
// the tests run, ready for the container the answer gives.
//
// The attestation object is parsed by record_presence_cbor.go's canonical reader, and certificates by crypto/x509, so
// the root adds no module. Certificate chains are checked at the time the caller judges the registration at, the
// carrying entry's for a log reader, so every reader of one log labels one key alike under one release.
//
// No key is created, derived or unwrapped here, so nothing calls testHookSecret. Package-level functions are safe for
// concurrent use. On every leg: nothing here names a connect type.

package sidecar

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"slices"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyteasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What records and approver screens show beside channel presence (§16.6's labels).
type PresenceLabel int

const (
	// Nothing vouches for where the key lives but the device that registered it: fmt none, no attestation, packed
	// self attestation, or a Secure Enclave key.
	PresenceLabelAsserted PresenceLabel = iota + 1
	// The key's attestation chains to a root the release pins for its format.
	PresenceLabelAttested
)

// As records and approver screens show it.
func (self PresenceLabel) String() string {
	switch self {
	case PresenceLabelAsserted:
		return "presence (asserted)"
	case PresenceLabelAttested:
		return "presence (attested)"
	}
	return fmt.Sprintf("presence label %d", int(self))
}

// The attestation is present and does not verify, its format is not one §16.6 names, or its key, rp or client data is
// not the registration's. Never a reason to label the key asserted instead.
var ErrPresenceAttestation = errors.New("presence attestation refused")

// Format bounds of an attestation object: its size, which the longest certificate chains a platform sends fit many
// times over, and the certificates in one x5c.
const (
	presenceAttestationMaxByteCount = 64 * 1024
	presenceAttestationMaxChainSize = 8
)

// WebAuthn's authenticator data flags (WebAuthn §6.1): user present, user verified, attested credential data, extension
// data.
const (
	presenceAuthFlagUserPresent     byte = 0x01
	presenceAuthFlagUserVerified    byte = 0x04
	presenceAuthFlagAttestedData    byte = 0x40
	presenceAuthFlagExtensionData   byte = 0x80
	presenceAuthDataFixedSize            = 32 + 1 + 4
	presenceAuthAaguidSize               = 16
	presenceAuthCredentialIdMaxSize      = 1023
)

// COSE's values for an ES256 key (RFC 9053): kty EC2, alg ES256, crv P-256, and RS256 for a tpm statement's signature.
const (
	presenceCoseKeyTypeEc2 = 2
	presenceCoseAlgEs256   = -7
	presenceCoseAlgRs256   = -257
	presenceCoseCurveP256  = 1
)

// The extensions and names §16.6's formats read (WebAuthn §8.2.1, §8.3.1, §8.4.1, §8.8.1).
var (
	presenceOidFidoAaguid        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}
	presenceOidAndroidKeyDesc    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}
	presenceOidAppleNonce        = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}
	presenceOidSubjectAltName    = asn1.ObjectIdentifier{2, 5, 29, 17}
	presenceOidTpmManufacturer   = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	presenceOidTpmModel          = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	presenceOidTpmVersion        = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	presenceOidTpmAikCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 3}
)

// TPM 2.0's values a tpm statement carries (TPM 2.0 Part 2): TPM_GENERATED_VALUE, TPM_ST_ATTEST_CERTIFY, the ECC and
// null algorithms, NIST P-256, and the name hashes this reads.
const (
	presenceTpmGeneratedValue  uint32 = 0xff544347
	presenceTpmStAttestCertify uint16 = 0x8017
	presenceTpmAlgEcc          uint16 = 0x0023
	presenceTpmAlgNull         uint16 = 0x0010
	presenceTpmEccNistP256     uint16 = 0x0003
	presenceTpmAlgSha256       uint16 = 0x000b
	presenceTpmAlgSha384       uint16 = 0x000c
	presenceTpmAlgSha512       uint16 = 0x000d
)

// Android Keystore's values a key description carries: the authorization tags read, KM_ORIGIN_GENERATED and
// KM_PURPOSE_SIGN.
const (
	presenceAndroidPurpose         = 1
	presenceAndroidAllApplications = 600
	presenceAndroidOrigin          = 702
	presenceAndroidOriginGenerated = int64(0)
	presenceAndroidPurposeSign     = int64(2)
)

// The roots a release pins, one pool per format §16.6 names, which a release step refreshes from the FIDO metadata
// service's roots, Apple's WebAuthn root and Google's hardware attestation roots (QD-137). A pool is never nil: an empty
// one chains nothing, where a nil one would mean the system's.
type presenceAttestationRoots struct {
	packed     *x509.CertPool
	tpm        *x509.CertPool
	androidKey *x509.CertPool
	apple      *x509.CertPool
}

// This build's: empty, since no production roots ship until QD-137's release step pins them, so no key labels
// attested.
func presenceReleaseAttestationRoots() *presenceAttestationRoots {
	return &presenceAttestationRoots{
		packed:     x509.NewCertPool(),
		tpm:        x509.NewCertPool(),
		androidKey: x509.NewCertPool(),
		apple:      x509.NewCertPool(),
	}
}

// The label of a presence key's KeyRegister, judged at atMillis, the carrying entry's time for a log reader and now for
// the device about to sign one: asserted or attested, or a refusal (above). register's own proof is
// VerifyPresenceRegistration's, which a caller runs too.
//
// KeyRegister.attestation is read as the raw attestation object (QD-445): fmt none or an empty field labels a
// webauthn-es256 key asserted, and every other format is refused until question mcp-m2-01-attestation-client-data says
// where its client data rides. An ecdsa-p256-sha256 key is asserted and carries none.
func VerifyPresenceAttestation(register *protocol.KeyRegister, atMillis int64) (PresenceLabel, error) {
	if register == nil {
		return 0, fmt.Errorf("%w: no KeyRegister", ErrPresenceAttestation)
	}
	if register.GetPurpose() != bridge.KeyPurpose_KEY_PURPOSE_PRESENCE {
		return 0, fmt.Errorf("%w: purpose %s", ErrPresenceAttestation, register.GetPurpose())
	}
	attestation := register.GetAttestation()
	switch register.GetAlg() {
	case bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256:
		if len(attestation) != 0 {
			return 0, fmt.Errorf("%w: an ecdsa-p256-sha256 key with an attestation", ErrPresenceAttestation)
		}
		return PresenceLabelAsserted, nil
	case bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256:
		if len(attestation) == 0 {
			return PresenceLabelAsserted, nil
		}
		return verifyPresenceAttestationObject(
			attestation,
			nil,
			register.GetPublicKey(),
			presenceReleaseAttestationRoots(),
			time.UnixMilli(atMillis),
		)
	}
	return 0, fmt.Errorf("%w: algorithm %s", ErrPresenceAttestation, register.GetAlg())
}

// A WebAuthn attestation object's label for the credential key publicKey, a SEC 1 point: the object parses as canonical
// CBOR with exactly fmt, attStmt and authData; the authenticator data's rp id is ur.io, UP, UV and attested credential
// data are set, and its credential key is an ES256 COSE key equal to publicKey, so another key's attestation is
// refused; then the format's statement over authData || clientDataHash, chained to roots' pool for the format at time
// at. A nil clientDataHash, no client data to check against, passes fmt none alone.
func verifyPresenceAttestationObject(
	attestationObject []byte,
	clientDataHash []byte,
	publicKey []byte,
	roots *presenceAttestationRoots,
	at time.Time,
) (PresenceLabel, error) {
	if presenceAttestationMaxByteCount < len(attestationObject) {
		return 0, fmt.Errorf("%w: %d bytes", ErrPresenceAttestation, len(attestationObject))
	}
	object, err := presenceCborDecodeAll(attestationObject)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrPresenceAttestation, err)
	}
	if !object.hasTextKeysExactly("fmt", "attStmt", "authData") {
		return 0, fmt.Errorf("%w: not an attestation object", ErrPresenceAttestation)
	}
	format, _ := object.textKey("fmt")
	statement, _ := object.textKey("attStmt")
	authDataItem, _ := object.textKey("authData")
	if format.kind != presenceCborText || statement.kind != presenceCborMap || authDataItem.kind != presenceCborBytes {
		return 0, fmt.Errorf("%w: an attestation object's types", ErrPresenceAttestation)
	}

	authData, err := parsePresenceAuthData(authDataItem.content)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(authData.credentialPublicKey, publicKey) {
		return 0, fmt.Errorf("%w: the attestation is another key's", ErrPresenceAttestation)
	}

	formatName := string(format.content)
	if formatName == "none" {
		if len(statement.keys) != 0 {
			return 0, fmt.Errorf("%w: fmt none with a statement", ErrPresenceAttestation)
		}
		return PresenceLabelAsserted, nil
	}
	if clientDataHash == nil {
		return 0, fmt.Errorf(
			"%w: fmt %q signs client data KeyRegister does not carry (question mcp-m2-01-attestation-client-data)",
			ErrPresenceAttestation,
			formatName,
		)
	}
	if len(clientDataHash) != sha256.Size {
		return 0, fmt.Errorf("%w: a client data hash of %d bytes", ErrPresenceAttestation, len(clientDataHash))
	}
	signedData := slices.Concat(authDataItem.content, clientDataHash)

	switch formatName {
	case "packed":
		return verifyPresencePacked(statement, authData, signedData, roots.packed, at)
	case "tpm":
		return verifyPresenceTpm(statement, authData, signedData, roots.tpm, at)
	case "android-key":
		return verifyPresenceAndroidKey(statement, authData, signedData, clientDataHash, roots.androidKey, at)
	case "apple":
		return verifyPresenceApple(statement, authData, signedData, roots.apple, at)
	}
	return 0, fmt.Errorf("%w: fmt %q", ErrPresenceAttestation, formatName)
}

// What an attestation's authenticator data holds (WebAuthn §6.1, §6.5.1).
type presenceAuthData struct {
	aaguid []byte
	// The credential key as a SEC 1 uncompressed point.
	credentialPublicKey []byte
	credentialX         []byte
	credentialY         []byte
}

// Parses authenticator data that must carry an ES256 credential for rp ur.io, with UP and UV, and nothing after its
// extensions.
func parsePresenceAuthData(authData []byte) (*presenceAuthData, error) {
	if len(authData) < presenceAuthDataFixedSize+presenceAuthAaguidSize+2 {
		return nil, fmt.Errorf("%w: authenticator data of %d bytes", ErrPresenceAttestation, len(authData))
	}
	rpIdHash := sha256.Sum256([]byte("ur.io"))
	if !bytes.Equal(authData[:32], rpIdHash[:]) {
		return nil, fmt.Errorf("%w: rp id hash", ErrPresenceAttestation)
	}
	flags := authData[32]
	required := presenceAuthFlagUserPresent | presenceAuthFlagUserVerified | presenceAuthFlagAttestedData
	if flags&required != required {
		return nil, fmt.Errorf("%w: UP, UV or attested credential data unset", ErrPresenceAttestation)
	}
	rest := authData[presenceAuthDataFixedSize:]
	parsed := &presenceAuthData{aaguid: rest[:presenceAuthAaguidSize]}
	rest = rest[presenceAuthAaguidSize:]
	credentialIdSize := int(binary.BigEndian.Uint16(rest[:2]))
	rest = rest[2:]
	if credentialIdSize == 0 || presenceAuthCredentialIdMaxSize < credentialIdSize || len(rest) < credentialIdSize {
		return nil, fmt.Errorf("%w: a credential id of %d bytes", ErrPresenceAttestation, credentialIdSize)
	}
	rest = rest[credentialIdSize:]

	coseKey, rest, err := presenceCborDecode(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: credential key: %w", ErrPresenceAttestation, err)
	}
	if flags&presenceAuthFlagExtensionData != 0 {
		extensions, extensionsRest, err := presenceCborDecode(rest)
		if err != nil {
			return nil, fmt.Errorf("%w: extensions: %w", ErrPresenceAttestation, err)
		}
		if extensions.kind != presenceCborMap {
			return nil, fmt.Errorf("%w: extensions are no map", ErrPresenceAttestation)
		}
		rest = extensionsRest
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d bytes after the authenticator data", ErrPresenceAttestation, len(rest))
	}

	// exactly kty, alg, crv, x and y, as an ES256 credential key has them
	if coseKey.kind != presenceCborMap || len(coseKey.keys) != 5 {
		return nil, fmt.Errorf("%w: a credential key that is no ES256 key", ErrPresenceAttestation)
	}
	intOf := func(key int64) (int64, bool) {
		value, ok := coseKey.intKey(key)
		if !ok {
			return 0, false
		}
		return value.int64Value()
	}
	bytesOf := func(key int64) []byte {
		value, ok := coseKey.intKey(key)
		if !ok || value.kind != presenceCborBytes {
			return nil
		}
		return value.content
	}
	keyType, keyTypeOk := intOf(1)
	alg, algOk := intOf(3)
	curve, curveOk := intOf(-1)
	x, y := bytesOf(-2), bytesOf(-3)
	if !keyTypeOk || keyType != presenceCoseKeyTypeEc2 || !algOk || alg != presenceCoseAlgEs256 || !curveOk ||
		curve != presenceCoseCurveP256 || len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("%w: a credential key that is no ES256 key", ErrPresenceAttestation)
	}
	parsed.credentialX = x
	parsed.credentialY = y
	parsed.credentialPublicKey = slices.Concat([]byte{0x04}, x, y)
	if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), parsed.credentialPublicKey); err != nil {
		return nil, fmt.Errorf("%w: credential key: %w", ErrPresenceAttestation, err)
	}
	return parsed, nil
}

// An x5c array: 1 to presenceAttestationMaxChainSize certificates, the first the leaf, each parsed.
func parsePresenceX5c(statement *presenceCborItem) ([]*x509.Certificate, error) {
	x5c, ok := statement.textKey("x5c")
	if !ok || x5c.kind != presenceCborArray || len(x5c.items) == 0 || presenceAttestationMaxChainSize < len(x5c.items) {
		return nil, fmt.Errorf("%w: x5c", ErrPresenceAttestation)
	}
	certificates := make([]*x509.Certificate, 0, len(x5c.items))
	for _, item := range x5c.items {
		if item.kind != presenceCborBytes {
			return nil, fmt.Errorf("%w: x5c holds no certificate", ErrPresenceAttestation)
		}
		certificate, err := x509.ParseCertificate(item.content)
		if err != nil {
			return nil, fmt.Errorf("%w: x5c: %w", ErrPresenceAttestation, err)
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

// Chains certificates[0] through the rest to a root of pool at time at. An empty pool chains nothing.
func verifyPresenceChain(certificates []*x509.Certificate, pool *x509.CertPool, at time.Time) error {
	if pool == nil {
		return fmt.Errorf("%w: no roots", ErrPresenceAttestation)
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	_, err := certificates[0].Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("%w: chain: %w", ErrPresenceAttestation, err)
	}
	return nil
}

// A statement's alg, which must be one of algs.
func presenceStatementAlg(statement *presenceCborItem, algs ...int64) (int64, error) {
	algItem, ok := statement.textKey("alg")
	if !ok {
		return 0, fmt.Errorf("%w: no alg", ErrPresenceAttestation)
	}
	alg, ok := algItem.int64Value()
	if !ok || !slices.Contains(algs, alg) {
		return 0, fmt.Errorf("%w: alg", ErrPresenceAttestation)
	}
	return alg, nil
}

// A statement's sig.
func presenceStatementSig(statement *presenceCborItem) ([]byte, error) {
	sig, ok := statement.textKey("sig")
	if !ok || sig.kind != presenceCborBytes {
		return nil, fmt.Errorf("%w: no sig", ErrPresenceAttestation)
	}
	return sig.content, nil
}

// An ES256 signature over message by the certificate's key, which must be P-256.
func verifyPresenceEs256(certificatePublicKey any, message []byte, signature []byte) error {
	publicKey, ok := certificatePublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return fmt.Errorf("%w: a key that is no P-256 key", ErrPresenceAttestation)
	}
	digest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		return fmt.Errorf("%w: signature", ErrPresenceAttestation)
	}
	return nil
}

// A certificate's key as a SEC 1 point, for comparing with a credential key.
func presenceCertificateKey(certificate *x509.Certificate) []byte {
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil
	}
	point, err := publicKey.Bytes()
	if err != nil {
		return nil
	}
	return point
}

// The aaguid extension, where a certificate has one, is not critical and names the authenticator data's aaguid.
func checkPresenceAaguidExtension(certificate *x509.Certificate, aaguid []byte) error {
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(presenceOidFidoAaguid) {
			continue
		}
		var value []byte
		rest, err := asn1.Unmarshal(extension.Value, &value)
		if extension.Critical || err != nil || len(rest) != 0 || !bytes.Equal(value, aaguid) {
			return fmt.Errorf("%w: the aaguid extension", ErrPresenceAttestation)
		}
	}
	return nil
}

// WebAuthn §8.2: packed. With x5c, the attestation certificate's ES256 signature over signedData, its §8.2.1
// requirements, and its chain to pool: attested. Without, self attestation by the credential key: asserted.
func verifyPresencePacked(
	statement *presenceCborItem,
	authData *presenceAuthData,
	signedData []byte,
	pool *x509.CertPool,
	at time.Time,
) (PresenceLabel, error) {
	_, hasX5c := statement.textKey("x5c")
	if hasX5c && !statement.hasTextKeysExactly("alg", "sig", "x5c") || !hasX5c && !statement.hasTextKeysExactly("alg", "sig") {
		return 0, fmt.Errorf("%w: a packed statement's keys", ErrPresenceAttestation)
	}
	if _, err := presenceStatementAlg(statement, presenceCoseAlgEs256); err != nil {
		return 0, err
	}
	sig, err := presenceStatementSig(statement)
	if err != nil {
		return 0, err
	}

	if !hasX5c {
		credentialKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), authData.credentialPublicKey)
		if err != nil {
			return 0, fmt.Errorf("%w: %w", ErrPresenceAttestation, err)
		}
		if err := verifyPresenceEs256(credentialKey, signedData, sig); err != nil {
			return 0, err
		}
		return PresenceLabelAsserted, nil
	}

	certificates, err := parsePresenceX5c(statement)
	if err != nil {
		return 0, err
	}
	leaf := certificates[0]
	if err := verifyPresenceEs256(leaf.PublicKey, signedData, sig); err != nil {
		return 0, err
	}
	subject := leaf.Subject
	if leaf.Version != 3 || len(subject.Country) != 1 || len(subject.Organization) != 1 || subject.CommonName == "" ||
		!slices.Equal(subject.OrganizationalUnit, []string{"Authenticator Attestation"}) {
		return 0, fmt.Errorf("%w: the attestation certificate's subject", ErrPresenceAttestation)
	}
	if !leaf.BasicConstraintsValid || leaf.IsCA {
		return 0, fmt.Errorf("%w: the attestation certificate is a CA", ErrPresenceAttestation)
	}
	if err := checkPresenceAaguidExtension(leaf, authData.aaguid); err != nil {
		return 0, err
	}
	if err := verifyPresenceChain(certificates, pool, at); err != nil {
		return 0, err
	}
	return PresenceLabelAttested, nil
}

// WebAuthn §8.3: tpm. pubArea is the credential key's TPMT_PUBLIC, certInfo a TPMS_ATTEST certifying it over a hash of
// signedData, signed by the AIK certificate in x5c, whose §8.3.1 requirements hold and which chains to pool.
func verifyPresenceTpm(
	statement *presenceCborItem,
	authData *presenceAuthData,
	signedData []byte,
	pool *x509.CertPool,
	at time.Time,
) (PresenceLabel, error) {
	if !statement.hasTextKeysExactly("alg", "sig", "ver", "x5c", "pubArea", "certInfo") {
		return 0, fmt.Errorf("%w: a tpm statement's keys", ErrPresenceAttestation)
	}
	version, _ := statement.textKey("ver")
	if version.kind != presenceCborText || string(version.content) != "2.0" {
		return 0, fmt.Errorf("%w: tpm version", ErrPresenceAttestation)
	}
	alg, err := presenceStatementAlg(statement, presenceCoseAlgEs256, presenceCoseAlgRs256)
	if err != nil {
		return 0, err
	}
	sig, err := presenceStatementSig(statement)
	if err != nil {
		return 0, err
	}
	pubAreaItem, _ := statement.textKey("pubArea")
	certInfoItem, _ := statement.textKey("certInfo")
	if pubAreaItem.kind != presenceCborBytes || certInfoItem.kind != presenceCborBytes {
		return 0, fmt.Errorf("%w: pubArea or certInfo", ErrPresenceAttestation)
	}
	pubArea := pubAreaItem.content
	certInfo := certInfoItem.content

	nameAlg, x, y, err := parsePresenceTpmPublic(pubArea)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(x, authData.credentialX) || !bytes.Equal(y, authData.credentialY) {
		return 0, fmt.Errorf("%w: pubArea is another key", ErrPresenceAttestation)
	}

	// both algorithms take SHA-256 for extraData
	extraData := sha256.Sum256(signedData)
	name, err := presenceTpmName(nameAlg, pubArea)
	if err != nil {
		return 0, err
	}
	if err := checkPresenceTpmAttest(certInfo, extraData[:], name); err != nil {
		return 0, err
	}

	certificates, err := parsePresenceX5c(statement)
	if err != nil {
		return 0, err
	}
	aik := certificates[0]
	switch alg {
	case presenceCoseAlgEs256:
		if err := verifyPresenceEs256(aik.PublicKey, certInfo, sig); err != nil {
			return 0, err
		}
	default:
		publicKey, ok := aik.PublicKey.(*rsa.PublicKey)
		if !ok {
			return 0, fmt.Errorf("%w: an RS256 statement by a key that is no RSA key", ErrPresenceAttestation)
		}
		digest := sha256.Sum256(certInfo)
		if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], sig); err != nil {
			return 0, fmt.Errorf("%w: signature", ErrPresenceAttestation)
		}
	}
	if err := checkPresenceAikCertificate(aik, authData.aaguid); err != nil {
		return 0, err
	}
	if err := verifyPresenceChain(certificates, pool, at); err != nil {
		return 0, err
	}
	return PresenceLabelAttested, nil
}

// TPMT_PUBLIC (TPM 2.0 Part 2 §12.2.4) of an ECC P-256 key: its nameAlg and the point. Refuses any other type, curve, a
// symmetric or kdf other than null, and anything after the point.
func parsePresenceTpmPublic(pubArea []byte) (uint16, []byte, []byte, error) {
	input := cryptobyte.String(pubArea)
	var keyType, nameAlg, symmetric, scheme, curveId, kdf uint16
	var objectAttributes uint32
	var authPolicy, x, y cryptobyte.String
	if !input.ReadUint16(&keyType) || !input.ReadUint16(&nameAlg) || !input.ReadUint32(&objectAttributes) ||
		!input.ReadUint16LengthPrefixed(&authPolicy) {
		return 0, nil, nil, fmt.Errorf("%w: pubArea", ErrPresenceAttestation)
	}
	if keyType != presenceTpmAlgEcc {
		return 0, nil, nil, fmt.Errorf("%w: pubArea is no ECC key", ErrPresenceAttestation)
	}
	if !input.ReadUint16(&symmetric) || symmetric != presenceTpmAlgNull || !input.ReadUint16(&scheme) {
		return 0, nil, nil, fmt.Errorf("%w: pubArea's parameters", ErrPresenceAttestation)
	}
	if scheme != presenceTpmAlgNull {
		var schemeHash uint16
		if !input.ReadUint16(&schemeHash) {
			return 0, nil, nil, fmt.Errorf("%w: pubArea's scheme", ErrPresenceAttestation)
		}
	}
	if !input.ReadUint16(&curveId) || curveId != presenceTpmEccNistP256 || !input.ReadUint16(&kdf) ||
		kdf != presenceTpmAlgNull {
		return 0, nil, nil, fmt.Errorf("%w: pubArea's curve or kdf", ErrPresenceAttestation)
	}
	if !input.ReadUint16LengthPrefixed(&x) || !input.ReadUint16LengthPrefixed(&y) || !input.Empty() {
		return 0, nil, nil, fmt.Errorf("%w: pubArea's point", ErrPresenceAttestation)
	}
	return nameAlg, x, y, nil
}

// A TPM object's name: nameAlg, then that hash of its TPMT_PUBLIC (TPM 2.0 Part 1 §16).
func presenceTpmName(nameAlg uint16, pubArea []byte) ([]byte, error) {
	var digest hash.Hash
	switch nameAlg {
	case presenceTpmAlgSha256:
		digest = sha256.New()
	case presenceTpmAlgSha384:
		digest = sha512.New384()
	case presenceTpmAlgSha512:
		digest = sha512.New()
	default:
		return nil, fmt.Errorf("%w: nameAlg 0x%04x", ErrPresenceAttestation, nameAlg)
	}
	digest.Write(pubArea)
	return digest.Sum(binary.BigEndian.AppendUint16(nil, nameAlg)), nil
}

// TPMS_ATTEST (TPM 2.0 Part 2 §10.12.12): TPM_GENERATED_VALUE, a certify, extraData, and the certified object's name.
func checkPresenceTpmAttest(certInfo []byte, extraData []byte, name []byte) error {
	input := cryptobyte.String(certInfo)
	var magic uint32
	var attestType uint16
	var qualifiedSigner, data, attestedName, qualifiedName cryptobyte.String
	var clockInfo, firmwareVersion []byte
	if !input.ReadUint32(&magic) || !input.ReadUint16(&attestType) || !input.ReadUint16LengthPrefixed(&qualifiedSigner) ||
		!input.ReadUint16LengthPrefixed(&data) || !input.ReadBytes(&clockInfo, 8+4+4+1) ||
		!input.ReadBytes(&firmwareVersion, 8) || !input.ReadUint16LengthPrefixed(&attestedName) ||
		!input.ReadUint16LengthPrefixed(&qualifiedName) || !input.Empty() {
		return fmt.Errorf("%w: certInfo", ErrPresenceAttestation)
	}
	switch {
	case magic != presenceTpmGeneratedValue:
		return fmt.Errorf("%w: certInfo's magic", ErrPresenceAttestation)
	case attestType != presenceTpmStAttestCertify:
		return fmt.Errorf("%w: certInfo's type", ErrPresenceAttestation)
	case !bytes.Equal(data, extraData):
		return fmt.Errorf("%w: certInfo's extraData", ErrPresenceAttestation)
	case !bytes.Equal(attestedName, name):
		return fmt.Errorf("%w: certInfo's name", ErrPresenceAttestation)
	}
	return nil
}

// WebAuthn §8.3.1's AIK certificate: version 3, an empty subject, a critical subject alternative name naming the TPM's
// manufacturer, model and version, tcg-kp-AIKCertificate among its extended key usages, no CA, and the aaguid extension
// where present. Go leaves a critical alternative name holding only a directoryName unhandled, so once this has
// checked it the extension is taken off the unhandled list, as the chain check would otherwise refuse it.
func checkPresenceAikCertificate(aik *x509.Certificate, aaguid []byte) error {
	emptySequence := []byte{0x30, 0x00}
	if aik.Version != 3 || !bytes.Equal(aik.RawSubject, emptySequence) {
		return fmt.Errorf("%w: the AIK certificate's version or subject", ErrPresenceAttestation)
	}
	if !aik.BasicConstraintsValid || aik.IsCA {
		return fmt.Errorf("%w: the AIK certificate is a CA", ErrPresenceAttestation)
	}
	if !slices.ContainsFunc(aik.UnknownExtKeyUsage, presenceOidTpmAikCertificate.Equal) {
		return fmt.Errorf("%w: the AIK certificate's extended key usage", ErrPresenceAttestation)
	}
	alternativeName := -1
	for i, extension := range aik.Extensions {
		if extension.Id.Equal(presenceOidSubjectAltName) {
			alternativeName = i
		}
	}
	if alternativeName < 0 || !aik.Extensions[alternativeName].Critical {
		return fmt.Errorf("%w: the AIK certificate's alternative name", ErrPresenceAttestation)
	}
	if err := checkPresenceTpmAlternativeName(aik.Extensions[alternativeName].Value); err != nil {
		return err
	}
	if err := checkPresenceAaguidExtension(aik, aaguid); err != nil {
		return err
	}
	aik.UnhandledCriticalExtensions = slices.DeleteFunc(
		aik.UnhandledCriticalExtensions,
		presenceOidSubjectAltName.Equal,
	)
	return nil
}

// A subject alternative name (RFC 5280 §4.2.1.6) holding a directoryName whose attributes name the TPM's
// manufacturer, model and version.
func checkPresenceTpmAlternativeName(value []byte) error {
	input := cryptobyte.String(value)
	var names cryptobyte.String
	if !input.ReadASN1(&names, cryptobyteasn1.SEQUENCE) || !input.Empty() {
		return fmt.Errorf("%w: the AIK certificate's alternative name", ErrPresenceAttestation)
	}
	found := map[string]bool{}
	for !names.Empty() {
		var name cryptobyte.String
		var tag cryptobyteasn1.Tag
		if !names.ReadAnyASN1(&name, &tag) {
			return fmt.Errorf("%w: the AIK certificate's alternative name", ErrPresenceAttestation)
		}
		// directoryName is [4], explicit, around a Name: a SEQUENCE of SETs of attribute SEQUENCEs
		if tag != cryptobyteasn1.Tag(4).Constructed().ContextSpecific() {
			continue
		}
		var rdnSequence cryptobyte.String
		if !name.ReadASN1(&rdnSequence, cryptobyteasn1.SEQUENCE) {
			return fmt.Errorf("%w: a directoryName", ErrPresenceAttestation)
		}
		for !rdnSequence.Empty() {
			var rdn cryptobyte.String
			if !rdnSequence.ReadASN1(&rdn, cryptobyteasn1.SET) {
				return fmt.Errorf("%w: a directoryName", ErrPresenceAttestation)
			}
			for !rdn.Empty() {
				var attribute cryptobyte.String
				var oid asn1.ObjectIdentifier
				var attributeValue cryptobyte.String
				var valueTag cryptobyteasn1.Tag
				if !rdn.ReadASN1(&attribute, cryptobyteasn1.SEQUENCE) || !attribute.ReadASN1ObjectIdentifier(&oid) ||
					!attribute.ReadAnyASN1(&attributeValue, &valueTag) {
					return fmt.Errorf("%w: a directoryName", ErrPresenceAttestation)
				}
				if len(attributeValue) != 0 {
					found[oid.String()] = true
				}
			}
		}
	}
	for _, oid := range []asn1.ObjectIdentifier{presenceOidTpmManufacturer, presenceOidTpmModel, presenceOidTpmVersion} {
		if !found[oid.String()] {
			return fmt.Errorf("%w: the AIK certificate names no TPM %s", ErrPresenceAttestation, oid)
		}
	}
	return nil
}

// WebAuthn §8.4: android-key. The credential certificate's key is the credential key and signs signedData; its key
// description holds clientDataHash as the challenge, was made in a TEE or StrongBox, not for all applications, by the
// key's own generation and for signing; and it chains to pool.
func verifyPresenceAndroidKey(
	statement *presenceCborItem,
	authData *presenceAuthData,
	signedData []byte,
	clientDataHash []byte,
	pool *x509.CertPool,
	at time.Time,
) (PresenceLabel, error) {
	if !statement.hasTextKeysExactly("alg", "sig", "x5c") {
		return 0, fmt.Errorf("%w: an android-key statement's keys", ErrPresenceAttestation)
	}
	if _, err := presenceStatementAlg(statement, presenceCoseAlgEs256); err != nil {
		return 0, err
	}
	sig, err := presenceStatementSig(statement)
	if err != nil {
		return 0, err
	}
	certificates, err := parsePresenceX5c(statement)
	if err != nil {
		return 0, err
	}
	leaf := certificates[0]
	if !bytes.Equal(presenceCertificateKey(leaf), authData.credentialPublicKey) {
		return 0, fmt.Errorf("%w: the credential certificate is another key's", ErrPresenceAttestation)
	}
	if err := verifyPresenceEs256(leaf.PublicKey, signedData, sig); err != nil {
		return 0, err
	}
	var description []byte
	for _, extension := range leaf.Extensions {
		if extension.Id.Equal(presenceOidAndroidKeyDesc) {
			description = extension.Value
		}
	}
	if description == nil {
		return 0, fmt.Errorf("%w: no key description", ErrPresenceAttestation)
	}
	if err := checkPresenceAndroidKeyDescription(description, clientDataHash); err != nil {
		return 0, err
	}
	if err := verifyPresenceChain(certificates, pool, at); err != nil {
		return 0, err
	}
	return PresenceLabelAttested, nil
}

// Android's KeyDescription: attestationVersion, attestationSecurityLevel, keymasterVersion, keymasterSecurityLevel,
// attestationChallenge, uniqueId, softwareEnforced and teeEnforced, each AuthorizationList a SEQUENCE of explicitly
// tagged entries.
func checkPresenceAndroidKeyDescription(description []byte, clientDataHash []byte) error {
	input := cryptobyte.String(description)
	var sequence, challenge, uniqueId, softwareEnforced, teeEnforced cryptobyte.String
	var attestationVersion, keymasterVersion int64
	var attestationSecurityLevel, keymasterSecurityLevel int
	if !input.ReadASN1(&sequence, cryptobyteasn1.SEQUENCE) || !input.Empty() ||
		!sequence.ReadASN1Integer(&attestationVersion) || !sequence.ReadASN1Enum(&attestationSecurityLevel) ||
		!sequence.ReadASN1Integer(&keymasterVersion) || !sequence.ReadASN1Enum(&keymasterSecurityLevel) ||
		!sequence.ReadASN1(&challenge, cryptobyteasn1.OCTET_STRING) ||
		!sequence.ReadASN1(&uniqueId, cryptobyteasn1.OCTET_STRING) ||
		!sequence.ReadASN1(&softwareEnforced, cryptobyteasn1.SEQUENCE) ||
		!sequence.ReadASN1(&teeEnforced, cryptobyteasn1.SEQUENCE) || !sequence.Empty() {
		return fmt.Errorf("%w: the key description", ErrPresenceAttestation)
	}
	if !bytes.Equal(challenge, clientDataHash) {
		return fmt.Errorf("%w: the key description's challenge", ErrPresenceAttestation)
	}
	// 1 is a TEE and 2 StrongBox: a key attested by software alone is a software key
	if attestationSecurityLevel != 1 && attestationSecurityLevel != 2 {
		return fmt.Errorf("%w: a key attested at security level %d", ErrPresenceAttestation, attestationSecurityLevel)
	}

	software, err := parsePresenceAuthorizationList(softwareEnforced)
	if err != nil {
		return err
	}
	tee, err := parsePresenceAuthorizationList(teeEnforced)
	if err != nil {
		return err
	}
	if software[presenceAndroidAllApplications] != nil || tee[presenceAndroidAllApplications] != nil {
		return fmt.Errorf("%w: a key for all applications", ErrPresenceAttestation)
	}
	origin := tee[presenceAndroidOrigin]
	var originValue int64
	if origin == nil || !origin.ReadASN1Integer(&originValue) || originValue != presenceAndroidOriginGenerated {
		return fmt.Errorf("%w: a key the TEE did not generate", ErrPresenceAttestation)
	}
	purposes := tee[presenceAndroidPurpose]
	var purposeSet cryptobyte.String
	if purposes == nil || !purposes.ReadASN1(&purposeSet, cryptobyteasn1.SET) {
		return fmt.Errorf("%w: a key with no purpose", ErrPresenceAttestation)
	}
	for !purposeSet.Empty() {
		var purpose int64
		if !purposeSet.ReadASN1Integer(&purpose) {
			return fmt.Errorf("%w: a key's purposes", ErrPresenceAttestation)
		}
		if purpose == presenceAndroidPurposeSign {
			return nil
		}
	}
	return fmt.Errorf("%w: a key not for signing", ErrPresenceAttestation)
}

// An AuthorizationList's entries by tag number, each the content inside its explicit context-specific tag. Android's
// tags run past 30, allApplications being [600] and origin [702], which cryptobyte does not read, so this walks the
// list's DER itself. A repeated or misordered tag is refused.
func parsePresenceAuthorizationList(list cryptobyte.String) (map[int]*cryptobyte.String, error) {
	entries := map[int]*cryptobyte.String{}
	rest := []byte(list)
	lastNumber := -1
	for len(rest) != 0 {
		class, constructed, number, content, after, ok := presenceDerElement(rest)
		if !ok || class != 2 || !constructed {
			return nil, fmt.Errorf("%w: an authorization list entry", ErrPresenceAttestation)
		}
		// DER's SEQUENCE keeps its components in their declared order, which is ascending tags here
		if number <= lastNumber {
			return nil, fmt.Errorf("%w: authorizations out of order", ErrPresenceAttestation)
		}
		lastNumber = number
		entry := cryptobyte.String(content)
		entries[number] = &entry
		rest = after
	}
	return entries, nil
}

// One DER element at the start of input: its class (0 universal to 3 private), whether it is constructed, its tag
// number in either identifier form, its content and what follows it. Refuses what DER forbids: a high tag number where
// one octet would do or with a leading zero group, and a length not in its shortest definite form. Tag numbers and
// lengths are capped well past anything a key description holds.
func presenceDerElement(input []byte) (byte, bool, int, []byte, []byte, bool) {
	if len(input) < 2 {
		return 0, false, 0, nil, nil, false
	}
	class := input[0] >> 6
	constructed := input[0]&0x20 != 0
	number := int(input[0] & 0x1f)
	offset := 1
	if number == 0x1f {
		number = 0
		for i := 0; ; i += 1 {
			// three octets give tag numbers up to 2^21, far past Android's highest
			if len(input) <= offset || 3 <= i {
				return 0, false, 0, nil, nil, false
			}
			octet := input[offset]
			offset += 1
			if i == 0 && octet == 0x80 {
				return 0, false, 0, nil, nil, false
			}
			number = number<<7 | int(octet&0x7f)
			if octet&0x80 == 0 {
				break
			}
		}
		if number < 0x1f {
			return 0, false, 0, nil, nil, false
		}
	}
	if len(input) <= offset {
		return 0, false, 0, nil, nil, false
	}
	lengthOctet := input[offset]
	offset += 1
	length := int(lengthOctet)
	if lengthOctet&0x80 != 0 {
		lengthSize := int(lengthOctet & 0x7f)
		if lengthSize == 0 || 3 < lengthSize || len(input) < offset+lengthSize {
			return 0, false, 0, nil, nil, false
		}
		length = 0
		for _, octet := range input[offset : offset+lengthSize] {
			length = length<<8 | int(octet)
		}
		offset += lengthSize
		// the shortest form: under 128 is short, and no leading zero octet
		if length < 0x80 || input[offset-lengthSize] == 0 {
			return 0, false, 0, nil, nil, false
		}
	}
	if len(input)-offset < length {
		return 0, false, 0, nil, nil, false
	}
	return class, constructed, number, input[offset : offset+length], input[offset+length:], true
}

// WebAuthn §8.8: apple. The credential certificate's nonce extension holds SHA-256(signedData), its key is the
// credential key, and it chains to pool, Apple's WebAuthn root in a release.
func verifyPresenceApple(
	statement *presenceCborItem,
	authData *presenceAuthData,
	signedData []byte,
	pool *x509.CertPool,
	at time.Time,
) (PresenceLabel, error) {
	if !statement.hasTextKeysExactly("x5c") {
		return 0, fmt.Errorf("%w: an apple statement's keys", ErrPresenceAttestation)
	}
	certificates, err := parsePresenceX5c(statement)
	if err != nil {
		return 0, err
	}
	leaf := certificates[0]
	nonce := sha256.Sum256(signedData)
	var extensionNonce []byte
	for _, extension := range leaf.Extensions {
		if !extension.Id.Equal(presenceOidAppleNonce) {
			continue
		}
		// SEQUENCE { [1] EXPLICIT OCTET STRING }
		input := cryptobyte.String(extension.Value)
		var sequence, tagged, value cryptobyte.String
		if !input.ReadASN1(&sequence, cryptobyteasn1.SEQUENCE) || !input.Empty() ||
			!sequence.ReadASN1(&tagged, cryptobyteasn1.Tag(1).Constructed().ContextSpecific()) || !sequence.Empty() ||
			!tagged.ReadASN1(&value, cryptobyteasn1.OCTET_STRING) || !tagged.Empty() {
			return 0, fmt.Errorf("%w: the nonce extension", ErrPresenceAttestation)
		}
		extensionNonce = value
	}
	if !bytes.Equal(extensionNonce, nonce[:]) {
		return 0, fmt.Errorf("%w: the nonce", ErrPresenceAttestation)
	}
	if !bytes.Equal(presenceCertificateKey(leaf), authData.credentialPublicKey) {
		return 0, fmt.Errorf("%w: the credential certificate is another key's", ErrPresenceAttestation)
	}
	if err := verifyPresenceChain(certificates, pool, at); err != nil {
		return 0, err
	}
	return PresenceLabelAttested, nil
}
