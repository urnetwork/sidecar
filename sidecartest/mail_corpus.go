// FS-121's messages (MAIL-M7-03): 64 DKIM signatures with distinct maximal d= and s=, ARC chains of 8, 12
// and 51 sets and one missing an instance, a valid aligned signature behind 3 invalid ones, and a spoofed
// From with 9 aligned bogus signatures. Each is signed by mail_sign.go and its keys and DMARC records are
// published in a FakeMailZone, so a receiver's checks meet them as they would arrive. Names are synthetic,
// under .example (CODESTYLE's test data rule).
//
// One key signs a message's many signatures, published under each selector, since what FS-121 bounds is
// the lookups and checks, not the keys' variety; a bogus signature is made by a key that differs from the
// one published. Keys are the run's own (MailDkimRsaKey).

package sidecartest

import (
	"bytes"
	"crypto"
	"fmt"
	"strings"
	"time"
)

// RFC 1035's longest name and label.
const (
	mailCorpusNameMaxByteCount  = 253
	mailCorpusLabelMaxByteCount = 63
)

// What a message carries, so a test knows what a receiver should find.
type MailCorpusMessage struct {
	Name  string
	Bytes []byte
	// From's domain.
	FromDomain string
	// Each DKIM signature, top of the header section first.
	Signatures []*MailCorpusSignature
	// The ARC sets on it, the instance left out (0 for none), and whether the newest says cv=fail.
	ArcSetCount   int
	ArcGapAt      int
	ArcFailNewest bool
}

// One DKIM signature on a corpus message.
type MailCorpusSignature struct {
	Domain   string
	Selector string
	// Its key is published, and its b= verifies under it.
	Valid bool
	// d= aligns with From under DMARC's relaxed rule.
	Aligned bool
}

// Builds messages into zone, signing as of signTime.
type MailCorpus struct {
	zone     *FakeMailZone
	signTime time.Time
	// The key every corpus signature and seal is made by, and one never published, for bogus ones.
	key      crypto.Signer
	otherKey crypto.Signer
}

func NewMailCorpus(zone *FakeMailZone, signTime time.Time) *MailCorpus {
	return &MailCorpus{
		zone:     zone,
		signTime: signTime,
		key:      MailDkimRsaKey(1024),
		otherKey: MailDkimRsaKey(1536),
	}
}

// A name of exactly byteCount bytes: labels of at most 63 bytes, the first starting with tag so names
// differ, then a dot and suffix when there is one.
func MailCorpusName(tag string, byteCount int, suffix string) string {
	tail := ""
	if suffix != "" {
		tail = "." + suffix
	}
	// the labels' bytes and the dots between them
	remaining := byteCount - len(tail)
	labels := []string{}
	for 0 < remaining {
		labelByteCount := min(mailCorpusLabelMaxByteCount, remaining)
		// never leave a single byte, which a dot alone would take
		if remaining-labelByteCount == 1 {
			labelByteCount -= 1
		}
		label := strings.Repeat("x", labelByteCount)
		if len(labels) == 0 {
			label = (tag + label)[:labelByteCount]
		}
		labels = append(labels, label)
		remaining -= labelByteCount
		if 0 < remaining {
			remaining -= 1
		}
	}
	return strings.Join(labels, ".") + tail
}

// A plain message from fromDomain.
func mailCorpusBase(fromDomain string, subject string) []byte {
	return []byte(strings.Join([]string{
		"From: Sender <sender@" + fromDomain + ">",
		"To: Receiver <receiver@mx.network.root.example>",
		"Subject: " + subject,
		"Date: Sun, 08 Nov 2026 12:00:00 +0000",
		"Message-ID: <" + subject + "@" + fromDomain + ">",
		"",
		"A synthetic body for " + subject + ".",
		"",
	}, "\r\n"))
}

// Signs message as domain and selector by signingKey, publishing publishedKey under the selector.
func (self *MailCorpus) sign(message []byte, domain string, selector string, signingKey crypto.Signer, publishedKey crypto.Signer) ([]byte, error) {
	signer, err := NewMailDkimSigner(domain, selector, MailDkimRsaSha256, signingKey)
	if err != nil {
		return nil, err
	}
	signer.SignTime = self.signTime
	self.zone.AddTxt(MailDkimKeyName(selector, domain), MailDkimKeyRecord(publishedKey))
	return signer.Sign(message)
}

// count signatures with distinct maximal d= and s=: s= one 63-byte label, d= as long as the key's name
// then lets it be, 253 bytes in all, none aligned with From. Every key is published and every signature
// verifies, so only a bound stops a check.
func (self *MailCorpus) MaximalSignatures(count int) (*MailCorpusMessage, error) {
	fromDomain := "sender.example"
	message := mailCorpusBase(fromDomain, "maximal-signatures")
	corpus := &MailCorpusMessage{Name: "maximal-signatures", FromDomain: fromDomain}
	for index := range count {
		tag := fmt.Sprintf("s%02d", index)
		selector := MailCorpusName(tag, mailCorpusLabelMaxByteCount, "")
		domainByteCount := mailCorpusNameMaxByteCount - len(selector) - len("._domainkey.")
		domain := MailCorpusName(fmt.Sprintf("d%02d", index), domainByteCount, "example")
		var err error
		message, err = self.sign(message, domain, selector, self.key, self.key)
		if err != nil {
			return nil, err
		}
		corpus.Signatures = append([]*MailCorpusSignature{{Domain: domain, Selector: selector, Valid: true}}, corpus.Signatures...)
	}
	corpus.Bytes = message
	return corpus, nil
}

// A chain of setCount ARC sets, each by its own forwarder domain, its keys published; gapAt leaves that
// instance out, and failNewest marks the newest set cv=fail.
func (self *MailCorpus) ArcChain(setCount int, gapAt int, failNewest bool) (*MailCorpusMessage, error) {
	name := fmt.Sprintf("arc-%d", setCount)
	if gapAt != 0 {
		name += fmt.Sprintf("-gap-%d", gapAt)
	}
	if failNewest {
		name += "-fail"
	}
	fromDomain := "origin.example"
	message, err := self.sign(mailCorpusBase(fromDomain, name), fromDomain, "origin", self.key, self.key)
	if err != nil {
		return nil, err
	}
	sealer := &MailArcSealer{
		Domain:     "forwarder.example",
		Selector:   "arc",
		Key:        MailDkimRsaKey(1024),
		AuthServId: "mx.forwarder.example",
		SignTime:   self.signTime,
	}
	self.zone.AddTxt(MailDkimKeyName(sealer.Selector, sealer.Domain), MailDkimKeyRecord(sealer.Key))
	message, err = sealer.Chain(message, &MailArcChainOptions{SetCount: setCount, GapAt: gapAt, FailNewest: failNewest})
	if err != nil {
		return nil, err
	}
	return &MailCorpusMessage{
		Name:          name,
		Bytes:         message,
		FromDomain:    fromDomain,
		Signatures:    []*MailCorpusSignature{{Domain: fromDomain, Selector: "origin", Valid: true, Aligned: true}},
		ArcSetCount:   setCount,
		ArcGapAt:      gapAt,
		ArcFailNewest: failNewest,
	}, nil
}

// invalidCount aligned signatures that do not verify, below one aligned that does, which is checked
// after them going up the header section: DKIM and DMARC pass.
func (self *MailCorpus) AlignedAfterInvalid(invalidCount int) (*MailCorpusMessage, error) {
	fromDomain := "aligned.example"
	self.zone.AddTxt("_dmarc."+fromDomain, "v=DMARC1; p=reject")
	message := mailCorpusBase(fromDomain, "aligned-after-invalid")
	corpus := &MailCorpusMessage{Name: "aligned-after-invalid", FromDomain: fromDomain}
	var err error
	for index := range invalidCount {
		selector := fmt.Sprintf("bad%d", index)
		message, err = self.sign(message, fromDomain, selector, self.otherKey, self.key)
		if err != nil {
			return nil, err
		}
		corpus.Signatures = append([]*MailCorpusSignature{{Domain: fromDomain, Selector: selector, Aligned: true}}, corpus.Signatures...)
	}
	message, err = self.sign(message, fromDomain, "good", self.key, self.key)
	if err != nil {
		return nil, err
	}
	corpus.Signatures = append([]*MailCorpusSignature{{Domain: fromDomain, Selector: "good", Valid: true, Aligned: true}}, corpus.Signatures...)
	corpus.Bytes = message
	return corpus, nil
}

// A From of a domain publishing p=reject with bogusCount aligned signatures, none of which verifies:
// DMARC fails, never passes.
func (self *MailCorpus) SpoofedFrom(bogusCount int) (*MailCorpusMessage, error) {
	fromDomain := "bank.example"
	self.zone.AddTxt("_dmarc."+fromDomain, "v=DMARC1; p=reject")
	message := mailCorpusBase(fromDomain, "spoofed-from")
	corpus := &MailCorpusMessage{Name: "spoofed-from", FromDomain: fromDomain}
	var err error
	for index := range bogusCount {
		selector := fmt.Sprintf("s%d", index)
		message, err = self.sign(message, fromDomain, selector, self.otherKey, self.key)
		if err != nil {
			return nil, err
		}
		corpus.Signatures = append([]*MailCorpusSignature{{Domain: fromDomain, Selector: selector, Aligned: true}}, corpus.Signatures...)
	}
	corpus.Bytes = message
	return corpus, nil
}

// The DKIM-Signature fields of a message, top first, unfolded.
func MailDkimSignatureFields(message []byte) ([]string, error) {
	fields, _, err := mailSplitMessage(message)
	if err != nil {
		return nil, err
	}
	signatures := []string{}
	for _, field := range fields {
		if mailFieldName(field) == "dkim-signature" {
			signatures = append(signatures, string(bytes.ReplaceAll([]byte(field), []byte("\r\n"), nil)))
		}
	}
	return signatures, nil
}
