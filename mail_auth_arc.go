//go:build !sidecar_http && !js

// §15.5's arc row (RFC 8617; R-MAIL-16, D-MAIL-14, FS-121; MAIL-M7-09): MailArcVerifier, written here since mox has
// no ARC (plan-MAIL-mox-subset#1), on mail_auth_canon.go's canonicalization.
//
// RFC 8617 §5.2's structure checks come first, with no lookup, on the header the checks read (MailHeaderView):
//
//	none        no ARC field at all, in a header section seen whole
//	fail        an ARC field whose instance does not read; an instance past 50, so over 50 sets; a field repeated
//	            at one instance; a seal whose cv= is not none at instance 1 and pass after it, so any seal marked
//	            cv=fail, the newest included; a set or a field of one missing, with the whole header in view
//	incomplete  a header section cut at 256 KiB, which may hide a set, a newer one or the one missing, unless
//	            the above already failed it; 9 to 50 sets, a count bound
//
// Up to 8 sets, the newest ARC-Message-Signature is verified, then every ARC-Seal from the newest down, and the first
// that does not hold fails the chain: so at most 9 signature checks and 1 body hash, the body hashed only once its
// signature over the header holds. Their keys are fetched at once into the message's memo at ARC's priority, the last
// in §15.5's dns row, as mox's dkim.Lookup reads a key record. A key a bound cut, the 64 queries or the 30 s, leaves
// the chain incomplete; any other failure to verify, a key that is missing, revoked, unparsable or failed to look up
// among them, is cv=fail, since ARC has no temperror and RFC 8617 §5.2 fails a chain on any validation failure.
//
// An AMS is a DKIM-Signature but for its name, its i= instance and no v= (RFC 8617 §4.1.2), so DKIM's verifier rules
// hold: h= must name From, an l= is refused as plan-MAIL-small-readings#11 refuses it for DKIM, x= expires on the
// receiver's clock, and q= must allow dns/txt. A seal is always relaxed and takes no h= (§4.1.3). rsa-sha1 is refused
// (RFC 8301), and a key is held to 1,024 to 8,192 bits as §15.5's dkim row holds DKIM's. A verified set's entry
// names its seal's d=, s= and key, the newest first, the order sets are verified in.
//
// Off sidecar_http and js, with the checks. Safe for concurrent use; a chain is one message's.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rsa"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/mjl-/mox/dkim"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/sidecar/protocol"
)

// RFC 8617's limits and names: at most 50 sets (§4.2.1), and its three fields.
const (
	mailArcSetMaxCount          = 50
	mailArcResultsName          = "arc-authentication-results"
	mailArcMessageSignatureName = "arc-message-signature"
	mailArcSealName             = "arc-seal"
)

// The digits an instance takes at most, which keeps one past any bound from overflowing.
const mailArcInstanceMaxDigitCount = 9

// Why an ARC signature can never verify. Never logged.
var errMailArcUnverifiable = errors.New("mail arc: the signature cannot verify")

// One ARC-Message-Signature or ARC-Seal, as its tags give it.
type mailArcSignature struct {
	field mailHeaderField
	// Its i=, or 0 where it does not read.
	instance int
	// rsa or ed25519.
	keyType   string
	signature []byte
	// d= and s=, lowercase.
	domain   string
	selector string
	// An AMS's bh=, h= and c=.
	bodyHash      []byte
	signedHeaders []string
	relaxedHeader bool
	relaxedBody   bool
	// A seal's cv=, lowercase: none, pass or fail, or empty where it does not read.
	cv string
	// Why it can never verify, or nil.
	broken error
}

// Where its key record is published.
func (self *mailArcSignature) keyName() string {
	return self.selector + "._domainkey." + self.domain + "."
}

// One instance's three fields.
type mailArcSet struct {
	results mailHeaderField
	message *mailArcSignature
	seal    *mailArcSignature
}

// A message's ARC fields, read with no lookup.
type MailArcChain struct {
	// The header the checks read, whose fields an AMS's h= selects from.
	view   *MailHeaderView
	fields []mailHeaderField
	// The highest instance an ARC field named, which AuthLimits.arc_sets carries; 0 with none.
	highestInstance uint32
	// What the structure decided alone, or unspecified where the sets are to be verified.
	verdict protocol.ArcVerdict
	// 9 to 50 sets made it incomplete, a count bound.
	countCut bool
	// Instance 1 first, where the sets are to be verified.
	sets []*mailArcSet
}

// The highest instance an ARC field named.
func (self *MailArcChain) HighestInstance() uint32 {
	return self.highestInstance
}

// What the structure decided with no lookup: none, fail or incomplete, or unspecified where only verifying decides.
func (self *MailArcChain) Verdict() protocol.ArcVerdict {
	return self.verdict
}

// Whether a count bound made the chain incomplete: 9 to 50 sets.
func (self *MailArcChain) CountCut() bool {
	return self.countCut
}

// The keys verifying would fetch, each once, in the order they are verified: the newest AMS's, then each seal's
// from the newest down. None where the structure decided, or where a signature can never verify.
func (self *MailArcChain) KeyNames() []string {
	if self.verdict != protocol.ArcVerdict_ARC_VERDICT_UNSPECIFIED || !self.verifiable() {
		return nil
	}
	names := []string{self.sets[len(self.sets)-1].message.keyName()}
	for index := len(self.sets) - 1; 0 <= index; index -= 1 {
		if name := self.sets[index].seal.keyName(); !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names
}

// Whether every signature verifying would check can verify at all.
func (self *MailArcChain) verifiable() bool {
	if self.sets[len(self.sets)-1].message.broken != nil {
		return false
	}
	for _, set := range self.sets {
		if set.seal.broken != nil {
			return false
		}
	}
	return true
}

// What verifying a chain found.
type MailArcOutcome struct {
	// cv= and each verified set, the newest first.
	Result *protocol.ArcResult
	// The highest instance an ARC field named.
	HighestInstance uint32
	// The body hashes and signature checks made: at most 1 and 9.
	BodyHashCount       int
	SignatureCheckCount int
}

// A receiver's ARC verifier. Safe for concurrent use.
type MailArcVerifier struct {
	clock    Clock
	settings *MailAuthSettings
	// mox's DKIM key record parser, which ARC's keys share (RFC 8617 §4.1.2).
	parseRecord func(text string) (*dkim.Record, bool, error)
}

// A verifier whose x= and expiry read clock, real time when nil.
func NewMailArcVerifier(clock Clock, settings *MailAuthSettings) *MailArcVerifier {
	return &MailArcVerifier{clock: clockOrReal(clock), settings: settings, parseRecord: dkim.ParseRecord}
}

// The instance i= gives: 1 to 9 digits, or 0.
func mailArcInstanceValue(value string) int {
	if value == "" || mailArcInstanceMaxDigitCount < len(value) {
		return 0
	}
	instance := 0
	for index := range len(value) {
		if value[index] < '0' || '9' < value[index] {
			return 0
		}
		instance = instance*10 + int(value[index]-'0')
	}
	return instance
}

// text with its leading CFWS gone: white space, folds and RFC 5322 comments, nested and with quoted pairs. false for
// a comment that never closes.
func mailSkipCfws(text []byte) ([]byte, bool) {
	for {
		text = bytes.TrimLeft(text, " \t\r\n")
		if len(text) == 0 || text[0] != '(' {
			return text, true
		}
		depth := 0
		end := -1
	comment:
		for index := 0; index < len(text); index += 1 {
			switch text[index] {
			case '\\':
				index += 1
			case '(':
				depth += 1
			case ')':
				depth -= 1
				if depth == 0 {
					end = index
					break comment
				}
			}
		}
		if end < 0 {
			return nil, false
		}
		text = text[end+1:]
	}
}

// The instance an ARC-Authentication-Results field names (RFC 8617 §4.1.1: [CFWS] i [CFWS] = [CFWS] digits [CFWS]
// ;, before the results), or 0.
func mailArcResultsInstance(field mailHeaderField) int {
	_, value, _ := bytes.Cut(field.raw, []byte(":"))
	value, ok := mailSkipCfws(value)
	if !ok || len(value) == 0 || value[0] != 'i' {
		return 0
	}
	if value, ok = mailSkipCfws(value[1:]); !ok || len(value) == 0 || value[0] != '=' {
		return 0
	}
	if value, ok = mailSkipCfws(value[1:]); !ok {
		return 0
	}
	digitCount := 0
	for digitCount < len(value) && '0' <= value[digitCount] && value[digitCount] <= '9' {
		digitCount += 1
	}
	instance := mailArcInstanceValue(string(value[:digitCount]))
	if rest, ok := mailSkipCfws(value[digitCount:]); !ok || len(rest) == 0 || rest[0] != ';' {
		return 0
	}
	return instance
}

// A d= or s= value as a lookup names it: lowercase labels of letters, digits, dashes and underscores, each 1 to 63
// bytes, at most 253 in all. false for anything else, a U-label among them.
func mailArcDomainName(value string) (string, bool) {
	if value == "" || dnsDomainMaxByteCount < len(value) {
		return "", false
	}
	value = dnsAsciiLower(value)
	for label := range strings.SplitSeq(value, ".") {
		if label == "" || dnsNameLabelMaxByteCount < len(label) {
			return "", false
		}
		for index := range len(label) {
			c := label[index]
			if !('a' <= c && c <= 'z') && !('0' <= c && c <= '9') && c != '-' && c != '_' {
				return "", false
			}
		}
	}
	return value, true
}

// An AMS's or a seal's tags as a signature: its instance whatever else holds, so the structure can place it, and
// broken set where a tag a verification needs is missing or refused.
func (self *MailArcVerifier) parseSignature(field mailHeaderField) *mailArcSignature {
	seal := field.name == mailArcSealName
	signature := &mailArcSignature{field: field}
	_, value, _ := bytes.Cut(field.raw, []byte(":"))
	tags, ok := mailParseTagList(value)
	if !ok {
		signature.broken = errMailArcUnverifiable
		return signature
	}
	signature.instance = mailArcInstanceValue(tags["i"])
	if seal {
		switch cv := strings.ToLower(tags["cv"]); cv {
		case "none", "pass", "fail":
			signature.cv = cv
		}
	}
	broken := func() *mailArcSignature {
		signature.broken = errMailArcUnverifiable
		return signature
	}
	required := []string{"i", "a", "b", "d", "s"}
	if seal {
		required = append(required, "cv")
	} else {
		required = append(required, "bh", "h")
	}
	for _, name := range required {
		if _, ok := tags[name]; !ok {
			return broken()
		}
	}
	switch strings.ToLower(tags["a"]) {
	case "rsa-sha256":
		signature.keyType = "rsa"
	case "ed25519-sha256":
		signature.keyType = "ed25519"
	default:
		// rsa-sha1 among them (RFC 8301)
		return broken()
	}
	if signature.signature, ok = mailTagBase64(tags["b"]); !ok || len(signature.signature) == 0 {
		return broken()
	}
	if signature.domain, ok = mailArcDomainName(tags["d"]); !ok {
		return broken()
	}
	if signature.selector, ok = mailArcDomainName(tags["s"]); !ok {
		return broken()
	}
	if seal {
		// a seal covers the ARC fields alone, so it names none (RFC 8617 §4.1.3)
		if _, ok := tags["h"]; ok {
			return broken()
		}
		return signature
	}
	if signature.bodyHash, ok = mailTagBase64(tags["bh"]); !ok || len(signature.bodyHash) != 32 {
		return broken()
	}
	from := false
	for name := range strings.SplitSeq(tags["h"], ":") {
		name = strings.Trim(name, " \t")
		if name == "" {
			return broken()
		}
		from = from || strings.EqualFold(name, "from")
		signature.signedHeaders = append(signature.signedHeaders, name)
	}
	if !from {
		return broken()
	}
	if canonicalization, ok := tags["c"]; ok {
		headerCanon, bodyCanon, found := strings.Cut(strings.ToLower(canonicalization), "/")
		if !found {
			bodyCanon = "simple"
		}
		if (headerCanon != "simple" && headerCanon != "relaxed") || (bodyCanon != "simple" && bodyCanon != "relaxed") {
			return broken()
		}
		signature.relaxedHeader, signature.relaxedBody = headerCanon == "relaxed", bodyCanon == "relaxed"
	}
	if _, ok := tags["l"]; ok {
		return broken()
	}
	if methods, ok := tags["q"]; ok {
		dnsTxt := false
		for method := range strings.SplitSeq(methods, ":") {
			dnsTxt = dnsTxt || strings.EqualFold(strings.Trim(method, " \t"), "dns/txt")
		}
		if !dnsTxt {
			return broken()
		}
	}
	if expire, ok := tags["x"]; ok {
		// RFC 6376 §3.5's x=: digits, seconds since the epoch, past which the signature no longer verifies
		seconds, err := strconv.ParseInt(expire, 10, 64)
		if err != nil || strings.TrimLeft(expire, "0123456789") != "" || seconds < self.clock.Now().Unix() {
			return broken()
		}
	}
	return signature
}

// The chain the view's ARC fields make, read with no lookup. See the file header.
func (self *MailArcVerifier) Parse(view *MailHeaderView) (*MailArcChain, error) {
	fields, err := mailHeaderFields(view)
	if err != nil {
		return nil, err
	}
	chain := &MailArcChain{view: view, fields: fields, verdict: protocol.ArcVerdict_ARC_NONE}
	type instanceFields struct {
		results  []mailHeaderField
		messages []*mailArcSignature
		seals    []*mailArcSignature
	}
	byInstance := map[int]*instanceFields{}
	unplaced := false
	seen := false
	for _, field := range fields {
		instance := 0
		var signature *mailArcSignature
		switch field.name {
		case mailArcResultsName:
			instance = mailArcResultsInstance(field)
		case mailArcMessageSignatureName, mailArcSealName:
			signature = self.parseSignature(field)
			instance = signature.instance
		default:
			continue
		}
		seen = true
		if instance <= 0 {
			unplaced = true
			continue
		}
		chain.highestInstance = max(chain.highestInstance, uint32(instance))
		set := byInstance[instance]
		if set == nil {
			set = &instanceFields{}
			byInstance[instance] = set
		}
		switch field.name {
		case mailArcResultsName:
			set.results = append(set.results, field)
		case mailArcMessageSignatureName:
			set.messages = append(set.messages, signature)
		default:
			set.seals = append(set.seals, signature)
		}
	}
	if !seen {
		// a header cut at its bound may hold ARC fields past the cut, so seeing none there shows none only uncut
		if view.Cut {
			chain.verdict = protocol.ArcVerdict_ARC_INCOMPLETE
		}
		return chain, nil
	}
	failed := func() (*MailArcChain, error) {
		chain.verdict = protocol.ArcVerdict_ARC_FAIL
		return chain, nil
	}
	if unplaced || mailArcSetMaxCount < chain.highestInstance {
		return failed()
	}
	for instance, set := range byInstance {
		if 1 < len(set.results) || 1 < len(set.messages) || 1 < len(set.seals) {
			return failed()
		}
		want := "pass"
		if instance == 1 {
			want = "none"
		}
		for _, seal := range set.seals {
			if seal.cv != want {
				return failed()
			}
		}
	}
	complete := true
	for instance := 1; instance <= int(chain.highestInstance); instance += 1 {
		set := byInstance[instance]
		if set == nil || len(set.results) != 1 || len(set.messages) != 1 || len(set.seals) != 1 {
			complete = false
			break
		}
	}
	switch {
	case view.Cut:
		// a field past the cut may be a newer set or the one missing, so nothing seen can pass or fail the rest
		chain.verdict = protocol.ArcVerdict_ARC_INCOMPLETE
	case !complete:
		return failed()
	case uint32(max(0, self.settings.ArcVerifySetMaxCount)) < chain.highestInstance:
		chain.verdict = protocol.ArcVerdict_ARC_INCOMPLETE
		chain.countCut = true
	default:
		chain.verdict = protocol.ArcVerdict_ARC_VERDICT_UNSPECIFIED
		for instance := 1; instance <= int(chain.highestInstance); instance += 1 {
			set := byInstance[instance]
			chain.sets = append(chain.sets, &mailArcSet{results: set.results[0], message: set.messages[0], seal: set.seals[0]})
		}
	}
	return chain, nil
}

// How one signature's key came out.
type mailArcKeyCheck int

const (
	mailArcKeyFound mailArcKeyCheck = iota
	// A bound cut its lookup.
	mailArcKeyCut
	// Missing, refused, revoked, unparsable, or failed to look up.
	mailArcKeyFailed
)

// The key record a signature names, read as mox's dkim.Lookup reads one, exactly one valid DKIM record among the
// TXT records, and held to the signature: its key type, any h= of hashes allowing sha256, not revoked, an RSA key of
// 1,024 to 8,192 bits, a service allowing email.
func (self *MailArcVerifier) key(ctx context.Context, keys *MailAuthResolver, signature *mailArcSignature) (*dkim.Record, mailArcKeyCheck) {
	name := signature.keyName()
	texts, _, err := keys.LookupTXT(ctx, name)
	if err != nil {
		if ctx.Err() != nil || keys.Cut(name, dnsmessage.TypeTXT) {
			return nil, mailArcKeyCut
		}
		return nil, mailArcKeyFailed
	}
	var found *dkim.Record
	for _, text := range texts {
		record, isDkim, err := self.parseRecord(text)
		if err != nil {
			if isDkim {
				return nil, mailArcKeyFailed
			}
			continue
		}
		if found != nil {
			return nil, mailArcKeyFailed
		}
		found = record
	}
	switch {
	case found == nil, !strings.EqualFold(found.Key, signature.keyType), found.PublicKey == nil, !found.ServiceAllowed("email"):
		return nil, mailArcKeyFailed
	case 0 < len(found.Hashes) && !slices.ContainsFunc(found.Hashes, func(hash string) bool { return strings.EqualFold(hash, "sha256") }):
		return nil, mailArcKeyFailed
	}
	if key, ok := found.PublicKey.(*rsa.PublicKey); ok && (key.N.BitLen() < 1024 || self.settings.DkimRsaMaxBitCount < key.N.BitLen()) {
		return nil, mailArcKeyFailed
	}
	return found, mailArcKeyFound
}

// What the newest AMS signs of the header: the fields its h= selects, canonicalized under its c=, then itself without
// its b= value.
func mailArcMessageSignatureData(fields []mailHeaderField, signature *mailArcSignature) []byte {
	var data bytes.Buffer
	for _, field := range mailSelectHeaderFields(fields, signature.signedHeaders) {
		data.Write(mailCanonHeader(field, signature.relaxedHeader))
	}
	own, _ := mailFieldWithoutSignature(signature.field.raw)
	if signature.relaxedHeader {
		own = mailCanonHeaderRelaxed(own)
	}
	data.Write(own)
	return data.Bytes()
}

// What the newest of sets' seal signs (RFC 8617 §5.1.1): each set's AAR, AMS and seal, instance 1 first, relaxed,
// that seal last without its b= value.
func mailArcSealData(sets []*mailArcSet) []byte {
	var data bytes.Buffer
	for index, set := range sets {
		data.Write(mailCanonHeader(set.results, true))
		data.Write(mailCanonHeader(set.message.field, true))
		if index < len(sets)-1 {
			data.Write(mailCanonHeader(set.seal.field, true))
			continue
		}
		own, _ := mailFieldWithoutSignature(set.seal.field.raw)
		data.Write(mailCanonHeaderRelaxed(own))
	}
	return data.Bytes()
}

// The chain's verdict, verifying what the structure left to verify, every key through keys at ARC's priority. See the
// file header.
func (self *MailArcVerifier) Verify(ctx context.Context, resolver *MailAuthResolver, chain *MailArcChain) *MailArcOutcome {
	outcome := &MailArcOutcome{Result: &protocol.ArcResult{Cv: chain.verdict}, HighestInstance: chain.highestInstance}
	if chain.verdict != protocol.ArcVerdict_ARC_VERDICT_UNSPECIFIED {
		return outcome
	}
	failed := func() *MailArcOutcome {
		outcome.Result.Cv = protocol.ArcVerdict_ARC_FAIL
		return outcome
	}
	cut := func() *MailArcOutcome {
		outcome.Result.Cv = protocol.ArcVerdict_ARC_INCOMPLETE
		return outcome
	}
	if !chain.verifiable() {
		return failed()
	}
	keys := resolver.WithPriority(MailAuthPriorityArc)
	keyed := func(signature *mailArcSignature) (*dkim.Record, mailArcKeyCheck) {
		record, check := self.key(ctx, keys, signature)
		if check == mailArcKeyFound {
			outcome.SignatureCheckCount += 1
		}
		return record, check
	}

	newest := chain.sets[len(chain.sets)-1].message
	record, check := keyed(newest)
	switch {
	case check == mailArcKeyCut:
		return cut()
	case check == mailArcKeyFailed:
		return failed()
	case !mailVerifySignatureData(record.PublicKey, mailArcMessageSignatureData(chain.fields, newest), newest.signature):
		return failed()
	}
	outcome.BodyHashCount += 1
	body := io.NewSectionReader(chain.view, chain.view.bodyOffset, chain.view.Size()-chain.view.bodyOffset)
	bodyHash, err := mailCanonBodyHash(ctx, body, newest.relaxedBody)
	switch {
	case err != nil && ctx.Err() != nil:
		return cut()
	case err != nil, !bytes.Equal(bodyHash, newest.bodyHash):
		return failed()
	}

	for index := len(chain.sets) - 1; 0 <= index; index -= 1 {
		seal := chain.sets[index].seal
		record, check := keyed(seal)
		switch {
		case check == mailArcKeyCut:
			return cut()
		case check == mailArcKeyFailed:
			return failed()
		case !mailVerifySignatureData(record.PublicKey, mailArcSealData(chain.sets[:index+1]), seal.signature):
			return failed()
		}
		outcome.Result.Sets = append(outcome.Result.Sets, &protocol.ArcSet{
			Domain:    seal.domain,
			Selector:  seal.selector,
			PublicKey: bytes.Clone(record.Pubkey),
		})
	}
	outcome.Result.Cv = protocol.ArcVerdict_ARC_PASS
	return outcome
}
