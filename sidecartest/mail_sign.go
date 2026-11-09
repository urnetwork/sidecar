// DKIM and ARC signing for tests (RFC 6376, RFC 8463, RFC 8617; MAIL-M7-03): what a sending domain or a
// forwarder adds to a message, written here from the RFCs alone, so a bug in a receiver's verifier
// (MAIL-M7-08, MAIL-M7-09) and a bug here are never the same bug. mail_kit_test.go checks the signatures
// with crypto and RFC 8463's own vector, never through code under test. Keys exist only for a run.
//
// A message is its header section, each field ending CRLF, then CRLF, then its body. Signing prepends its
// fields, as a signer does. Everything here is safe for concurrent use.

package sidecartest

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A DKIM or ARC signing algorithm (a=).
type MailDkimAlgorithm string

const (
	MailDkimRsaSha256     MailDkimAlgorithm = "rsa-sha256"
	MailDkimRsaSha1       MailDkimAlgorithm = "rsa-sha1"
	MailDkimEd25519Sha256 MailDkimAlgorithm = "ed25519-sha256"
)

// The header fields a signature covers when its signer names none.
var mailDkimDefaultHeaders = []string{"from", "to", "subject", "date", "message-id"}

// A message that is not one: no empty line ends its header section, or a field has no colon.
var ErrMailMessage = errors.New("not a message")

// RSA keys by size, made once per process.
var mailRsaKeysLock sync.Mutex
var mailRsaKeys = map[int]*rsa.PrivateKey{}

// An RSA key of bitCount bits for a run, made once per process and size. From 4,096 bits up it is made
// of several primes of 1,024 bits, since two primes of that size take seconds each; a verifier sees only
// the public modulus and exponent, which are an ordinary key's. RFC 6376's sizes run 1,024 to 8,192
// (§15.5), and a larger one makes a key a verifier must refuse.
func MailDkimRsaKey(bitCount int) *rsa.PrivateKey {
	mailRsaKeysLock.Lock()
	defer mailRsaKeysLock.Unlock()
	if key, ok := mailRsaKeys[bitCount]; ok {
		return key
	}
	var key *rsa.PrivateKey
	var err error
	if bitCount < 4096 {
		key, err = rsa.GenerateKey(rand.Reader, bitCount)
	} else {
		key, err = rsa.GenerateMultiPrimeKey(rand.Reader, bitCount/1024, bitCount)
	}
	if err != nil {
		panic(fmt.Errorf("an RSA key of %d bits: %w", bitCount, err))
	}
	mailRsaKeys[bitCount] = key
	return key
}

// An Ed25519 key from a 32-byte seed, so a test can name its key.
func MailDkimEd25519Key(seed []byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(seed)
}

// Signs as one d= and s=.
type MailDkimSigner struct {
	Domain    string
	Selector  string
	Algorithm MailDkimAlgorithm
	// An *rsa.PrivateKey for rsa-sha256 and rsa-sha1, an ed25519.PrivateKey for ed25519-sha256.
	Key crypto.Signer
	// h=, lowercase, in order. Empty takes from, to, subject, date and message-id.
	SignedHeaders []string
	// c=, header then body: relaxed or simple. Empty takes relaxed/relaxed.
	Canonicalization string
	// t=. Zero leaves the tag out.
	SignTime time.Time
}

// A signer of algorithm with key, checking the key fits it.
func NewMailDkimSigner(domain string, selector string, algorithm MailDkimAlgorithm, key crypto.Signer) (*MailDkimSigner, error) {
	switch algorithm {
	case MailDkimRsaSha256, MailDkimRsaSha1:
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("%s needs an RSA key", algorithm)
		}
	case MailDkimEd25519Sha256:
		if _, ok := key.(ed25519.PrivateKey); !ok {
			return nil, fmt.Errorf("%s needs an Ed25519 key", algorithm)
		}
	default:
		return nil, fmt.Errorf("unknown algorithm %q", algorithm)
	}
	return &MailDkimSigner{Domain: domain, Selector: selector, Algorithm: algorithm, Key: key}, nil
}

// The TXT record the selector publishes at <s>._domainkey.<d>: an RSA key as its DER
// SubjectPublicKeyInfo, an Ed25519 key as its 32 bytes (RFC 8463 §4).
func MailDkimKeyRecord(key crypto.Signer) string {
	switch publicKey := key.Public().(type) {
	case ed25519.PublicKey:
		return "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(publicKey)
	default:
		spki, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			panic(err)
		}
		return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(spki)
	}
}

// The name a selector's record sits at.
func MailDkimKeyName(selector string, domain string) string {
	return selector + "._domainkey." + domain
}

// This signer's key record.
func (self *MailDkimSigner) KeyRecord() string {
	return MailDkimKeyRecord(self.Key)
}

// Splits a message at the empty line ending its header section: each field as written, folding and
// CRLF included, then the body.
func mailSplitMessage(message []byte) (fields []string, body []byte, err error) {
	rest := message
	for {
		if bytes.HasPrefix(rest, []byte("\r\n")) {
			return fields, rest[2:], nil
		}
		lineEnd := bytes.Index(rest, []byte("\r\n"))
		if lineEnd < 0 {
			return nil, nil, ErrMailMessage
		}
		line := string(rest[:lineEnd+2])
		rest = rest[lineEnd+2:]
		if line[0] == ' ' || line[0] == '\t' {
			if len(fields) == 0 {
				return nil, nil, ErrMailMessage
			}
			fields[len(fields)-1] += line
			continue
		}
		if !strings.Contains(line, ":") {
			return nil, nil, ErrMailMessage
		}
		fields = append(fields, line)
	}
}

// A field's name, lowercase.
func mailFieldName(field string) string {
	name, _, _ := strings.Cut(field, ":")
	return strings.ToLower(strings.TrimRight(name, " \t"))
}

// RFC 6376 §3.4.2: the name lowercased, the value unfolded, each run of WSP one space, none at either end
// of the value or around the colon, then CRLF.
func mailCanonHeaderRelaxed(field string) string {
	name, value, _ := strings.Cut(field, ":")
	value = strings.ReplaceAll(value, "\r\n", "")
	var builder strings.Builder
	space := false
	for _, c := range value {
		if c == ' ' || c == '\t' {
			space = true
			continue
		}
		if space && 0 < builder.Len() {
			builder.WriteByte(' ')
		}
		space = false
		builder.WriteRune(c)
	}
	return strings.ToLower(strings.TrimRight(name, " \t")) + ":" + builder.String() + "\r\n"
}

// RFC 6376 §3.4.4: each line's trailing WSP gone, each run of WSP one space, the empty lines at the end
// gone, and a non-empty body ending in one CRLF.
func mailCanonBodyRelaxed(body []byte) []byte {
	text := string(body)
	lines := strings.Split(text, "\r\n")
	// a body ending in CRLF, or none, leaves an empty piece after its last line; a last line with no
	// CRLF is a line, which gets one below
	if text == "" || strings.HasSuffix(text, "\r\n") {
		lines = lines[:len(lines)-1]
	}
	canonical := make([]string, 0, len(lines))
	for _, line := range lines {
		var builder strings.Builder
		space := false
		for _, c := range line {
			if c == ' ' || c == '\t' {
				space = true
				continue
			}
			if space {
				builder.WriteByte(' ')
			}
			space = false
			builder.WriteRune(c)
		}
		canonical = append(canonical, builder.String())
	}
	for 0 < len(canonical) && canonical[len(canonical)-1] == "" {
		canonical = canonical[:len(canonical)-1]
	}
	if len(canonical) == 0 {
		return nil
	}
	return []byte(strings.Join(canonical, "\r\n") + "\r\n")
}

// RFC 6376 §3.4.3: the empty lines at the end gone, an empty body one CRLF.
func mailCanonBodySimple(body []byte) []byte {
	trimmed := body
	for bytes.HasSuffix(trimmed, []byte("\r\n\r\n")) {
		trimmed = trimmed[:len(trimmed)-2]
	}
	if len(trimmed) == 0 {
		return []byte("\r\n")
	}
	if !bytes.HasSuffix(trimmed, []byte("\r\n")) {
		return append(bytes.Clone(trimmed), '\r', '\n')
	}
	return trimmed
}

// The fields h= names, each name taking that field's last instance not yet taken (RFC 6376 §5.4.2); a
// name with none left takes nothing.
func mailSelectFields(fields []string, names []string) []string {
	taken := make([]bool, len(fields))
	selected := []string{}
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		for index := len(fields) - 1; 0 <= index; index -= 1 {
			if !taken[index] && mailFieldName(fields[index]) == name {
				taken[index] = true
				selected = append(selected, fields[index])
				break
			}
		}
	}
	return selected
}

// The hash a= signs with.
func mailHashOf(algorithm MailDkimAlgorithm) (func() hash.Hash, crypto.Hash) {
	if algorithm == MailDkimRsaSha1 {
		return sha1.New, crypto.SHA1
	}
	return sha256.New, crypto.SHA256
}

// Signs data under algorithm: PKCS #1 v1.5 over its hash for RSA, Ed25519 over its SHA-256 for
// ed25519-sha256 (RFC 8463 §3).
func mailSignData(algorithm MailDkimAlgorithm, key crypto.Signer, data []byte) ([]byte, error) {
	newHash, cryptoHash := mailHashOf(algorithm)
	digest := newHash()
	digest.Write(data)
	sum := digest.Sum(nil)
	if algorithm == MailDkimEd25519Sha256 {
		return ed25519.Sign(key.(ed25519.PrivateKey), sum), nil
	}
	return rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), cryptoHash, sum)
}

// The bytes a DKIM or AMS signature covers: the selected fields, canonicalized, then the signature's own
// field, its b= value empty and with no CRLF of its own (RFC 6376 §3.7).
func mailSignedData(selected []string, unsignedField string, relaxed bool) []byte {
	var data bytes.Buffer
	for _, field := range selected {
		if relaxed {
			data.WriteString(mailCanonHeaderRelaxed(field))
		} else {
			data.WriteString(field)
		}
	}
	own := unsignedField
	if relaxed {
		own = strings.TrimSuffix(mailCanonHeaderRelaxed(unsignedField), "\r\n")
	}
	data.WriteString(own)
	return data.Bytes()
}

// RFC 6376 §3.7 for a field the caller wrote, its b= value removed: the signature over message's fields
// that h= in that field selects, as base64. RFC 8463's vector checks it with the RFC's own text.
func MailDkimSignOver(message []byte, unsignedField string, algorithm MailDkimAlgorithm, key crypto.Signer, headerNames []string, relaxedHeaders bool) (string, error) {
	fields, _, err := mailSplitMessage(message)
	if err != nil {
		return "", err
	}
	signature, err := mailSignData(algorithm, key, mailSignedData(mailSelectFields(fields, headerNames), unsignedField, relaxedHeaders))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// A body's hash under c='s body half and a='s hash, as bh= carries it.
func mailBodyHash(body []byte, relaxedBody bool, algorithm MailDkimAlgorithm) string {
	canonical := mailCanonBodySimple(body)
	if relaxedBody {
		canonical = mailCanonBodyRelaxed(body)
	}
	newHash, _ := mailHashOf(algorithm)
	digest := newHash()
	digest.Write(canonical)
	return base64.StdEncoding.EncodeToString(digest.Sum(nil))
}

// A field of name from tags, each after the first on a folded line, every line kept within RFC 5322's
// 998 bytes: a long b= or bh= is folded inside, since a base64 value takes folding whitespace (RFC 6376
// §2.4); no other value is, since a domain or selector takes none, and the longest, a 253-byte d=, fits.
func mailFoldField(name string, tags []string) string {
	var builder strings.Builder
	builder.WriteString(name + ": ")
	for index, tag := range tags {
		if 0 < index {
			builder.WriteString(";\r\n ")
		}
		if strings.HasPrefix(tag, "b=") || strings.HasPrefix(tag, "bh=") {
			for 76 < len(tag) {
				builder.WriteString(tag[:76] + "\r\n ")
				tag = tag[76:]
			}
		}
		builder.WriteString(tag)
	}
	return builder.String()
}

// c='s halves.
func (self *MailDkimSigner) canonicalization() (string, bool, bool) {
	canonicalization := self.Canonicalization
	if canonicalization == "" {
		canonicalization = "relaxed/relaxed"
	}
	headerCanon, bodyCanon, _ := strings.Cut(canonicalization, "/")
	if bodyCanon == "" {
		bodyCanon = "simple"
	}
	return canonicalization, headerCanon == "relaxed", bodyCanon == "relaxed"
}

// h='s names.
func (self *MailDkimSigner) headerNames() []string {
	if len(self.SignedHeaders) == 0 {
		return mailDkimDefaultHeaders
	}
	return self.SignedHeaders
}

// The DKIM-Signature field for message, CRLF included.
func (self *MailDkimSigner) SignatureField(message []byte) (string, error) {
	fields, body, err := mailSplitMessage(message)
	if err != nil {
		return "", err
	}
	canonicalization, relaxedHeaders, relaxedBody := self.canonicalization()
	names := self.headerNames()
	tags := []string{
		"v=1",
		"a=" + string(self.Algorithm),
		"c=" + canonicalization,
		"d=" + self.Domain,
		"s=" + self.Selector,
	}
	if !self.SignTime.IsZero() {
		tags = append(tags, "t="+strconv.FormatInt(self.SignTime.Unix(), 10))
	}
	tags = append(tags, "h="+strings.Join(names, ":"), "bh="+mailBodyHash(body, relaxedBody, self.Algorithm), "b=")
	unsigned := mailFoldField("DKIM-Signature", tags)
	signature, err := mailSignData(self.Algorithm, self.Key, mailSignedData(mailSelectFields(fields, names), unsigned, relaxedHeaders))
	if err != nil {
		return "", err
	}
	return mailFoldField("DKIM-Signature", append(tags[:len(tags)-1], "b="+base64.StdEncoding.EncodeToString(signature))) + "\r\n", nil
}

// message with this signer's DKIM-Signature on top.
func (self *MailDkimSigner) Sign(message []byte) ([]byte, error) {
	field, err := self.SignatureField(message)
	if err != nil {
		return nil, err
	}
	return append([]byte(field), message...), nil
}

// A forwarder's ARC sets (RFC 8617), each an ARC-Authentication-Results, an ARC-Message-Signature and an
// ARC-Seal at one instance, always rsa-sha256 and relaxed, as §4.1.3 and §5.1.1 fix them.
type MailArcSealer struct {
	Domain   string
	Selector string
	Key      *rsa.PrivateKey
	// The authserv-id each ARC-Authentication-Results names.
	AuthServId string
	// t=. Zero leaves the tag out.
	SignTime time.Time
}

// ARC's three field names, lowercase.
const (
	mailArcSealName             = "arc-seal"
	mailArcMessageSignatureName = "arc-message-signature"
	mailArcResultsName          = "arc-authentication-results"
)

// The instance a field's i= tag names, 0 when it names none.
func mailArcInstance(field string) int {
	_, value, _ := strings.Cut(field, ":")
	for tag := range strings.SplitSeq(strings.ReplaceAll(value, "\r\n", ""), ";") {
		name, tagValue, found := strings.Cut(strings.TrimSpace(tag), "=")
		if found && strings.TrimSpace(name) == "i" {
			instance, err := strconv.Atoi(strings.TrimSpace(tagValue))
			if err == nil {
				return instance
			}
		}
	}
	return 0
}

// Adds the set at instance with chain validation cv (none, pass or fail) on top of message: what a
// forwarder adds, the seal covering every ARC set already there, in instance order, and this one.
func (self *MailArcSealer) Seal(message []byte, instance int, cv string) ([]byte, error) {
	fields, body, err := mailSplitMessage(message)
	if err != nil {
		return nil, err
	}
	timeTag := []string{}
	if !self.SignTime.IsZero() {
		timeTag = []string{"t=" + strconv.FormatInt(self.SignTime.Unix(), 10)}
	}
	instanceTag := "i=" + strconv.Itoa(instance)
	results := mailFoldField("ARC-Authentication-Results", []string{instanceTag, self.AuthServId + "; arc=" + cv}) + "\r\n"

	// the AMS covers the message's fields as a DKIM signature does; no ARC field, whose instances one
	// name cannot tell apart
	names := mailDkimDefaultHeaders
	messageTags := append([]string{instanceTag, "a=rsa-sha256", "c=relaxed/relaxed", "d=" + self.Domain, "s=" + self.Selector}, timeTag...)
	messageTags = append(messageTags, "h="+strings.Join(names, ":"), "bh="+mailBodyHash(body, true, MailDkimRsaSha256), "b=")
	unsignedMessage := mailFoldField("ARC-Message-Signature", messageTags)
	messageSignature, err := mailSignData(MailDkimRsaSha256, self.Key, mailSignedData(mailSelectFields(fields, names), unsignedMessage, true))
	if err != nil {
		return nil, err
	}
	messageField := mailFoldField("ARC-Message-Signature", append(messageTags[:len(messageTags)-1], "b="+base64.StdEncoding.EncodeToString(messageSignature))) + "\r\n"

	// the seal covers each set's results, message signature and seal, instance by instance, its own b=
	// empty and last
	sealTags := append([]string{instanceTag, "a=rsa-sha256"}, timeTag...)
	sealTags = append(sealTags, "cv="+cv, "d="+self.Domain, "s="+self.Selector, "b=")
	unsignedSeal := mailFoldField("ARC-Seal", sealTags)
	sets := map[int]map[string]string{}
	for _, field := range append([]string{results, messageField}, fields...) {
		name := mailFieldName(field)
		if name != mailArcSealName && name != mailArcMessageSignatureName && name != mailArcResultsName {
			continue
		}
		fieldInstance := mailArcInstance(field)
		if sets[fieldInstance] == nil {
			sets[fieldInstance] = map[string]string{}
		}
		sets[fieldInstance][name] = field
	}
	var sealData bytes.Buffer
	for _, setInstance := range slices.Sorted(maps.Keys(sets)) {
		for _, name := range []string{mailArcResultsName, mailArcMessageSignatureName, mailArcSealName} {
			if setInstance == instance && name == mailArcSealName {
				continue
			}
			if field, ok := sets[setInstance][name]; ok {
				sealData.WriteString(mailCanonHeaderRelaxed(field))
			}
		}
	}
	sealData.WriteString(strings.TrimSuffix(mailCanonHeaderRelaxed(unsignedSeal), "\r\n"))
	sealSignature, err := mailSignData(MailDkimRsaSha256, self.Key, sealData.Bytes())
	if err != nil {
		return nil, err
	}
	sealField := mailFoldField("ARC-Seal", append(sealTags[:len(sealTags)-1], "b="+base64.StdEncoding.EncodeToString(sealSignature))) + "\r\n"
	return append([]byte(sealField+messageField+results), message...), nil
}

// How a chain is built.
type MailArcChainOptions struct {
	// Sets in the chain.
	SetCount int
	// An instance left out, 0 for none: the sets then take 1 to SetCount+1 without it.
	GapAt int
	// The newest set says cv=fail.
	FailNewest bool
}

// message with a chain of sets on it, oldest first, each sealed as a forwarder in turn would: the first
// cv=none, the rest pass, the newest fail if asked.
func (self *MailArcSealer) Chain(message []byte, options *MailArcChainOptions) ([]byte, error) {
	instance := 0
	for count := range options.SetCount {
		instance += 1
		if instance == options.GapAt {
			instance += 1
		}
		cv := "pass"
		if count == 0 {
			cv = "none"
		}
		if count == options.SetCount-1 && options.FailNewest {
			cv = "fail"
		}
		var err error
		message, err = self.Seal(message, instance, cv)
		if err != nil {
			return nil, err
		}
	}
	return message, nil
}
