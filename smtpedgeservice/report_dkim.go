// Two DKIM checks over one canonicalizer (§14.8, D-SMTP-8, D-SMTP-12, D-SMTP-23).
//
//   - The reporter's check is RFC 6376's whole verify of the report message itself: its body hash,
//     taken by SmtpDkimBodyHash as the intake's single pass feeds it the raw bytes, then b= under a key
//     from DNS, through SmtpDnsTxtSource. Whether the reporter is an allowlisted operator is the
//     caller's to decide, from the verified d=.
//   - VerifyHeaders checks a signature's b= over reported headers alone, ignoring bh=, since a report
//     carries no body: §14.8's high and medium joins, and why §14.6 adds a second signature over five
//     fields. Its keys come from SmtpReportLookups.FindDkimKey, retired selectors included, never from
//     DNS, so only URnetwork's own sending keys can pass it.
//
// rsa-sha256 (RFC 6376) and ed25519-sha256 (RFC 8463), relaxed and simple. rsa-sha1 and any l= are
// refused (RFC 8301, §14.6's no l=), as are RSA keys under 1024 bits (RFC 8301) or past
// ReportDkimRsaKeyBitCount. At most ReportDkimSignatureCount signatures are read per header block.
// Keys are public, so nothing here passes through testHookSecret.

package smtpedgeservice

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// The verdicts a signature gets, RFC 8601's words for dkim.
const (
	SmtpDkimResultPass = "pass"
	// The body hash or the signature does not match.
	SmtpDkimResultFail = "fail"
	// Refused by policy: rsa-sha1, l=, a key's size, an expired signature.
	SmtpDkimResultPolicy = "policy"
	// DNS did not answer.
	SmtpDkimResultTempError = "temperror"
	// The signature or its key record is malformed, or no key exists.
	SmtpDkimResultPermError = "permerror"
	// VerifyHeaders: no URnetwork key under that selector and domain.
	SmtpDkimResultNone = "none"
)

const (
	smtpDkimAlgorithmRsaSha256     = "rsa-sha256"
	smtpDkimAlgorithmEd25519Sha256 = "ed25519-sha256"
	// RFC 8301 §3.2: verifiers must not accept a smaller key.
	smtpDkimRsaKeyMinBitCount = 1024
)

// TXT records by name: DNS, behind an interface so tests and hosts choose the resolver. Safe for
// concurrent use.
type SmtpDnsTxtSource interface {
	// Every TXT record at name, each record's strings joined. A name that does not exist, or holds no
	// TXT, answers none and no error; an error means DNS did not answer, which RFC 6376 treats as a
	// temporary failure.
	LookupTxt(ctx context.Context, name string) ([]string, error)
}

// A net.Resolver as a SmtpDnsTxtSource.
type SmtpResolverTxtSource struct {
	// nil is net.DefaultResolver.
	Resolver *net.Resolver
}

// See SmtpDnsTxtSource.
func (self *SmtpResolverTxtSource) LookupTxt(ctx context.Context, name string) ([]string, error) {
	resolver := self.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	records, err := resolver.LookupTXT(ctx, name)
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) && dnsError.IsNotFound {
		return nil, nil
	}
	return records, err
}

// One signature's verdict. Every string is from the signature's own tags or the closed set above.
type SmtpDkimResult struct {
	// d=, lowercased. Empty when the signature did not parse far enough to have one.
	Domain string
	// s=, lowercased.
	Selector string
	// a=.
	Algorithm string
	// SmtpDkimResult*.
	Result string
	// VerifyHeaders: the network whose key passed. Zero otherwise.
	NetworkId sidecar.Id
	// t= and x=. Zero when absent. VerifyHeaders leaves x= to the caller, since a report may arrive
	// after it.
	SignTime   time.Time
	ExpireTime time.Time
}

// A parsed DKIM-Signature.
type smtpDkimSignature struct {
	field         *smtpHeaderField
	algorithm     string
	signature     []byte
	bodyHash      []byte
	headerRelaxed bool
	bodyRelaxed   bool
	domain        string
	selector      string
	// h=, lowercased.
	headers []string
	// i=, as written.
	identity   string
	signTime   time.Time
	expireTime time.Time
	// A verdict reached at parse, policy or permerror, which ends the check. Empty when the
	// signature can be checked.
	refusal string
}

// The verdict a signature has so far, its tags filled in.
func (self *smtpDkimSignature) result(verdict string) *SmtpDkimResult {
	return &SmtpDkimResult{Domain: self.domain, Selector: self.selector, Algorithm: self.algorithm, Result: verdict, SignTime: self.signTime, ExpireTime: self.expireTime}
}

// Whether selector is a DNS name a key could sit under.
func smtpDkimSelectorValid(selector string) bool {
	return smtpLdhName(selector)
}

// A base64 tag value, whitespace and folding removed.
func smtpDkimBase64(value string) ([]byte, bool) {
	decoded, err := base64.StdEncoding.DecodeString(smtpStripFws(value))
	return decoded, err == nil
}

// A DKIM-Signature field, with what can be decided from its tags alone.
func parseSmtpDkimSignature(field *smtpHeaderField) *smtpDkimSignature {
	signature := &smtpDkimSignature{field: field, refusal: SmtpDkimResultPermError}
	tags, ok := smtpDkimTagList(smtpUnfold(field.value))
	if !ok {
		return signature
	}
	signature.domain = strings.ToLower(tags["d"])
	signature.selector = strings.ToLower(tags["s"])
	signature.algorithm = strings.ToLower(tags["a"])
	if tags["v"] != "1" || !smtpLdhName(signature.domain) || !smtpDkimSelectorValid(signature.selector) {
		return signature
	}
	switch signature.algorithm {
	case smtpDkimAlgorithmRsaSha256, smtpDkimAlgorithmEd25519Sha256:
	case "rsa-sha1":
		signature.refusal = SmtpDkimResultPolicy
		return signature
	default:
		return signature
	}
	if signature.signature, ok = smtpDkimBase64(tags["b"]); !ok || len(signature.signature) == 0 {
		return signature
	}
	if signature.bodyHash, ok = smtpDkimBase64(tags["bh"]); !ok || len(signature.bodyHash) != sha256.Size {
		return signature
	}
	headerCanon, bodyCanon, _ := strings.Cut(strings.ToLower(tags["c"]), "/")
	for _, canon := range []string{headerCanon, bodyCanon} {
		if canon != "" && canon != "simple" && canon != "relaxed" {
			return signature
		}
	}
	signature.headerRelaxed = headerCanon == "relaxed"
	signature.bodyRelaxed = bodyCanon == "relaxed"
	signedFrom := false
	for _, name := range strings.Split(tags["h"], ":") {
		name = strings.ToLower(smtpStripFws(name))
		if name == "" {
			return signature
		}
		signature.headers = append(signature.headers, name)
		signedFrom = signedFrom || name == "from"
	}
	if !signedFrom {
		return signature
	}
	if identity, ok := tags["i"]; ok {
		at := strings.LastIndexByte(identity, '@')
		identityDomain := strings.ToLower(identity[at+1:])
		if at < 0 || (identityDomain != signature.domain && !strings.HasSuffix(identityDomain, "."+signature.domain)) {
			return signature
		}
		signature.identity = identity
	}
	if query, ok := tags["q"]; ok {
		// RFC 6376 §3.5's one query method, dns with the txt format
		method, format, _ := strings.Cut(strings.ToLower(query), "/")
		if method != "dns" || !strings.HasPrefix(format, "txt") {
			return signature
		}
	}
	for _, timeTag := range []struct {
		name  string
		value *time.Time
	}{{name: "t", value: &signature.signTime}, {name: "x", value: &signature.expireTime}} {
		text, ok := tags[timeTag.name]
		if !ok {
			continue
		}
		seconds, err := strconv.ParseInt(text, 10, 64)
		if err != nil || seconds < 0 {
			return signature
		}
		*timeTag.value = time.Unix(seconds, 0).UTC()
	}
	if !signature.signTime.IsZero() && !signature.expireTime.IsZero() && signature.expireTime.Before(signature.signTime) {
		return signature
	}
	if _, ok := tags["l"]; ok {
		signature.refusal = SmtpDkimResultPolicy
		return signature
	}
	signature.refusal = ""
	return signature
}

// A verifying key.
type smtpDkimKey struct {
	algorithm string
	rsaKey    *rsa.PublicKey
	ed25519   ed25519.PublicKey
	// t=s: an i= must name d= exactly.
	strict bool
}

// A key from DER or raw octets, held to the size bounds. A verdict when it cannot verify.
func smtpDkimKeyFrom(algorithm string, publicKey []byte, settings *SmtpEdgeSettings) (*smtpDkimKey, string) {
	switch algorithm {
	case smtpDkimAlgorithmRsaSha256:
		var rsaKey *rsa.PublicKey
		if parsed, err := x509.ParsePKIXPublicKey(publicKey); err == nil {
			rsaKey, _ = parsed.(*rsa.PublicKey)
		} else if parsed, err := x509.ParsePKCS1PublicKey(publicKey); err == nil {
			rsaKey = parsed
		}
		if rsaKey == nil {
			return nil, SmtpDkimResultPermError
		}
		if bitCount := rsaKey.N.BitLen(); bitCount < smtpDkimRsaKeyMinBitCount || settings.ReportDkimRsaKeyBitCount < bitCount {
			return nil, SmtpDkimResultPolicy
		}
		return &smtpDkimKey{algorithm: algorithm, rsaKey: rsaKey}, ""
	case smtpDkimAlgorithmEd25519Sha256:
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, SmtpDkimResultPermError
		}
		return &smtpDkimKey{algorithm: algorithm, ed25519: ed25519.PublicKey(publicKey)}, ""
	}
	return nil, SmtpDkimResultPermError
}

// A key record (RFC 6376 §3.6.1) for a signature of algorithm. A verdict when it gives none: a revoked
// key (empty p=) and every malformed or mismatched record are permerror.
func parseSmtpDkimKeyRecord(record string, algorithm string, settings *SmtpEdgeSettings) (*smtpDkimKey, string) {
	tags, ok := smtpDkimTagList(record)
	if !ok {
		return nil, SmtpDkimResultPermError
	}
	if version, ok := tags["v"]; ok && version != "DKIM1" {
		return nil, SmtpDkimResultPermError
	}
	keyType := strings.ToLower(tags["k"])
	if keyType == "" {
		keyType = "rsa"
	}
	if (algorithm == smtpDkimAlgorithmRsaSha256) != (keyType == "rsa") || (algorithm == smtpDkimAlgorithmEd25519Sha256) != (keyType == "ed25519") {
		return nil, SmtpDkimResultPermError
	}
	if hashes, ok := tags["h"]; ok && !strings.Contains(":"+strings.ToLower(smtpStripFws(hashes))+":", ":sha256:") {
		return nil, SmtpDkimResultPermError
	}
	if services, ok := tags["s"]; ok && !strings.Contains(":"+strings.ToLower(smtpStripFws(services))+":", ":*:") && !strings.Contains(":"+strings.ToLower(smtpStripFws(services))+":", ":email:") {
		return nil, SmtpDkimResultPermError
	}
	publicKey, ok := smtpDkimBase64(tags["p"])
	if !ok || len(publicKey) == 0 {
		return nil, SmtpDkimResultPermError
	}
	key, verdict := smtpDkimKeyFrom(algorithm, publicKey, settings)
	if key == nil {
		return nil, verdict
	}
	key.strict = strings.Contains(":"+strings.ToLower(smtpStripFws(tags["t"]))+":", ":s:")
	return key, ""
}

// Checks DKIM signatures. Safe for concurrent use.
type SmtpDkimVerifier struct {
	settings *SmtpEdgeSettings
	txt      SmtpDnsTxtSource
	lookups  SmtpReportLookups
	clock    sidecar.Clock
}

// A verifier reading reporters' keys from txt and URnetwork's from lookups. A nil txt passes no
// reporter, and a nil lookups no reported header; nil clock is real time.
func NewSmtpDkimVerifier(settings *SmtpEdgeSettings, txt SmtpDnsTxtSource, lookups SmtpReportLookups, clock sidecar.Clock) *SmtpDkimVerifier {
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	return &SmtpDkimVerifier{settings: settings, txt: txt, lookups: lookups, clock: clock}
}

// The DKIM-Signature fields of a header block, parsed, at most ReportDkimSignatureCount.
func (self *SmtpDkimVerifier) signatures(fields []*smtpHeaderField) []*smtpDkimSignature {
	signatures := []*smtpDkimSignature{}
	for _, field := range fields {
		if !strings.EqualFold(field.name, "DKIM-Signature") {
			continue
		}
		if self.settings.ReportDkimSignatureCount <= len(signatures) {
			break
		}
		signatures = append(signatures, parseSmtpDkimSignature(field))
	}
	return signatures
}

// The SHA-256 of what a signature's b= covers: the h= fields, each the bottom-most instance not yet
// taken, an absent one adding nothing, then the signature's own field (§3.7, §5.4.2).
func smtpDkimSigningHash(fields []*smtpHeaderField, signature *smtpDkimSignature) []byte {
	hash := sha256.New()
	taken := make([]bool, len(fields))
	// a signature never covers itself, though it may cover other signatures (§3.7)
	for i, field := range fields {
		if field == signature.field {
			taken[i] = true
		}
	}
	for _, name := range signature.headers {
		for i := len(fields) - 1; 0 <= i; i -= 1 {
			if taken[i] || !strings.EqualFold(fields[i].name, name) {
				continue
			}
			taken[i] = true
			hash.Write(smtpDkimCanonHeader(fields[i], signature.headerRelaxed))
			break
		}
	}
	hash.Write(smtpDkimCanonSignatureField(signature.field, signature.headerRelaxed))
	return hash.Sum(nil)
}

// Whether key's signature over digest is good.
func smtpDkimVerifyDigest(key *smtpDkimKey, digest []byte, signature []byte) bool {
	switch key.algorithm {
	case smtpDkimAlgorithmRsaSha256:
		return rsa.VerifyPKCS1v15(key.rsaKey, crypto.SHA256, digest, signature) == nil
	case smtpDkimAlgorithmEd25519Sha256:
		// RFC 8463 §3: PureEdDSA over the SHA-256 hash
		return ed25519.Verify(key.ed25519, digest, signature)
	}
	return false
}

// Checks each signature of a reported header block over the headers alone, bh= ignored, under the key
// URnetwork holds for its selector and domain. A signature under no URnetwork key is none, so only
// URnetwork's own sending keys pass. The error is only ctx's.
func (self *SmtpDkimVerifier) VerifyHeaders(ctx context.Context, headerBlock []byte) ([]*SmtpDkimResult, error) {
	fields, err := smtpHeaderFields(headerBlock, false)
	if err != nil {
		return nil, err
	}
	results := []*SmtpDkimResult{}
	for _, signature := range self.signatures(fields) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if signature.refusal != "" {
			results = append(results, signature.result(signature.refusal))
			continue
		}
		if self.lookups == nil {
			results = append(results, signature.result(SmtpDkimResultNone))
			continue
		}
		stored, err := self.lookups.FindDkimKey(ctx, signature.selector, signature.domain)
		if err != nil {
			results = append(results, signature.result(SmtpDkimResultTempError))
			continue
		}
		if stored == nil {
			results = append(results, signature.result(SmtpDkimResultNone))
			continue
		}
		if !strings.EqualFold(stored.Algorithm, signature.algorithm) {
			results = append(results, signature.result(SmtpDkimResultPermError))
			continue
		}
		key, verdict := smtpDkimKeyFrom(signature.algorithm, stored.PublicKey, self.settings)
		if key == nil {
			results = append(results, signature.result(verdict))
			continue
		}
		result := signature.result(SmtpDkimResultFail)
		if smtpDkimVerifyDigest(key, smtpDkimSigningHash(fields, signature), signature.signature) {
			result.Result = SmtpDkimResultPass
			result.NetworkId = stored.NetworkId
		}
		results = append(results, result)
	}
	return results, nil
}

// One message's body hashes, taken as the intake's single pass over the raw report feeds it. Write
// takes the whole message from its first octet and skips the header block itself. Not safe for
// concurrent use.
type SmtpDkimBodyHash struct {
	fields     []*smtpHeaderField
	signatures []*smtpDkimSignature
	// Header octets still to skip.
	skip    int
	simple  *smtpDkimBodyCanon
	relaxed *smtpDkimBodyCanon
	// Set by digests, after which Write is refused.
	simpleDigest  []byte
	relaxedDigest []byte
	finished      bool
}

// The body hashes for the message whose header block, through its blank line, is headerBlock: one per
// body canonicalization its signatures use.
func (self *SmtpDkimVerifier) NewBodyHash(headerBlock []byte) (*SmtpDkimBodyHash, error) {
	fields, err := smtpHeaderFields(headerBlock, false)
	if err != nil {
		return nil, err
	}
	bodyHash := &SmtpDkimBodyHash{fields: fields, signatures: self.signatures(fields), skip: len(headerBlock)}
	for _, signature := range bodyHash.signatures {
		if signature.refusal != "" {
			continue
		}
		if signature.bodyRelaxed && bodyHash.relaxed == nil {
			bodyHash.relaxed = newSmtpDkimBodyCanon(true, sha256.New())
		}
		if !signature.bodyRelaxed && bodyHash.simple == nil {
			bodyHash.simple = newSmtpDkimBodyCanon(false, sha256.New())
		}
	}
	return bodyHash, nil
}

// Whether any signature can still pass, so a caller may skip a message no check can count.
func (self *SmtpDkimBodyHash) Checkable() bool {
	return self.simple != nil || self.relaxed != nil
}

// Takes the message's next octets. Never fails, as an io.Writer beside the seal.
func (self *SmtpDkimBodyHash) Write(data []byte) (int, error) {
	count := len(data)
	if self.finished {
		return count, nil
	}
	if 0 < self.skip {
		skipped := min(self.skip, len(data))
		data = data[skipped:]
		self.skip -= skipped
	}
	if self.simple != nil {
		self.simple.write(data)
	}
	if self.relaxed != nil {
		self.relaxed.write(data)
	}
	return count, nil
}

// Ends the body, once.
func (self *SmtpDkimBodyHash) finish() {
	if self.finished {
		return
	}
	self.finished = true
	if self.simple != nil {
		self.simpleDigest = self.simple.finish()
	}
	if self.relaxed != nil {
		self.relaxedDigest = self.relaxed.finish()
	}
}

// RFC 6376's whole verify of the message bodyHash was fed, each signature's key from DNS, bounded by
// ReportDnsTimeout in all. The error is only ctx's; a DNS failure is a signature's temperror.
func (self *SmtpDkimVerifier) Verify(ctx context.Context, bodyHash *SmtpDkimBodyHash) ([]*SmtpDkimResult, error) {
	bodyHash.finish()
	dnsCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := self.clock.AfterFunc(self.settings.ReportDnsTimeout, cancel)
	defer stop()
	now := self.clock.Now()
	results := []*SmtpDkimResult{}
	for _, signature := range bodyHash.signatures {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if signature.refusal != "" {
			results = append(results, signature.result(signature.refusal))
			continue
		}
		if !signature.expireTime.IsZero() && signature.expireTime.Before(now) {
			results = append(results, signature.result(SmtpDkimResultPolicy))
			continue
		}
		digest := bodyHash.simpleDigest
		if signature.bodyRelaxed {
			digest = bodyHash.relaxedDigest
		}
		if string(digest) != string(signature.bodyHash) {
			results = append(results, signature.result(SmtpDkimResultFail))
			continue
		}
		key, verdict := self.dnsKey(dnsCtx, signature)
		if key == nil {
			results = append(results, signature.result(verdict))
			continue
		}
		if key.strict && signature.identity != "" && !strings.HasSuffix(strings.ToLower(signature.identity), "@"+signature.domain) {
			results = append(results, signature.result(SmtpDkimResultPermError))
			continue
		}
		result := signature.result(SmtpDkimResultFail)
		if smtpDkimVerifyDigest(key, smtpDkimSigningHash(bodyHash.fields, signature), signature.signature) {
			result.Result = SmtpDkimResultPass
		}
		results = append(results, result)
	}
	return results, nil
}

// A signature's key from <s>._domainkey.<d>, the first of at most ReportDkimKeyRecordCount records
// that gives one. A verdict when none does.
func (self *SmtpDkimVerifier) dnsKey(ctx context.Context, signature *smtpDkimSignature) (*smtpDkimKey, string) {
	if self.txt == nil {
		return nil, SmtpDkimResultTempError
	}
	records, err := self.txt.LookupTxt(ctx, signature.selector+"._domainkey."+signature.domain)
	if err != nil {
		return nil, SmtpDkimResultTempError
	}
	verdict := SmtpDkimResultPermError
	for i, record := range records {
		if self.settings.ReportDkimKeyRecordCount <= i {
			break
		}
		key, recordVerdict := parseSmtpDkimKeyRecord(record, signature.algorithm, self.settings)
		if key != nil {
			return key, ""
		}
		verdict = recordVerdict
	}
	return nil, verdict
}

// The first passing result's domain, or empty: who a verified report is from.
func smtpDkimPassingDomain(results []*SmtpDkimResult) string {
	for _, result := range results {
		if result.Result == SmtpDkimResultPass {
			return result.Domain
		}
	}
	return ""
}

// Whether any result is temperror, so a report that passed nothing may yet pass on a retry.
func smtpDkimTemporary(results []*SmtpDkimResult) bool {
	for _, result := range results {
		if result.Result == SmtpDkimResultTempError {
			return true
		}
	}
	return false
}
