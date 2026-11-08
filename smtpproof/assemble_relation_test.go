package smtpproof

import (
	"bytes"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// What the sender's SMTP-M9-04 assembly makes, held to this module's relation: the root builds the
// octets and relation.go judges them, so the two cannot drift apart unseen.

const (
	testAssembleRelationDomain   = "n1.root.example"
	testAssembleRelationSelector = "abcdefghijklmnopqrstuvwxya"
	testAssembleRelationId       = "aaaaaaaaaaaaaaaaaaaaaaaaaa@n1.root.example"
	testAssembleRelationXUrRef   = "1.ljnfuws2ljnfuws2ljnfuws2ljnfuws2li"
	testAssembleRelationFeedback = "n:p:gmztgmztgmztgmztgmztgmztgm:urnetwork"
)

var testAssembleRelationKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(cryptorand.Reader, sidecar.SmtpDkimRsaKeyBitCount)
	if err != nil {
		panic(err)
	}
	return key
})

type testAssembleRelationSigner struct{}

func (self testAssembleRelationSigner) DkimSelector() string { return testAssembleRelationSelector }
func (self testAssembleRelationSigner) DkimDomain() string   { return testAssembleRelationDomain }
func (self testAssembleRelationSigner) SignDkim(digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(nil, testAssembleRelationKey(), crypto.SHA256, digest)
}

// Every message the sender assembles passes Z5 over its header block and Z6's DATA scan over its
// stuffed body, its preamble passes section 6's checks, and its declared counts are the prover's.
func TestAssembledMessagesSatisfyTheRelation(t *testing.T) {
	signTime := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	for i, c := range []struct {
		message string
		flags   uint32
	}{
		{message: "From: Joe SixPack <joe@n1.root.example>\nTo: Suzie Q <suzie@shopping.example>\nBcc: b@c.example\nSubject: Is dinner ready?\nMessage-ID: <" + testAssembleRelationId + ">\n\nHi.\n\nJoe.\n"},
		{message: "From: \"J. Smith, Esq\" <j@n1.root.example>\nMessage-ID: <" + testAssembleRelationId + ">\nSubject: caf\xc3\xa9\n\n.leading dot\n.\n..\ncaf\xc3\xa9\n" + strings.Repeat("q", 1200) + "\n"},
		{message: "From: a@n1.root.example\nMessage-ID: <" + testAssembleRelationId + ">\nList-Unsubscribe: <https://u.example/x>\n\nbulk\n", flags: sidecar.SmtpFlagBulk | sidecar.SmtpFlagRequireTls},
		{message: "From: a@n1.root.example\nMessage-ID: <" + testAssembleRelationId + ">\n"},
	} {
		wire, err := sidecar.AssembleSmtpMessage(&sidecar.SmtpAssembleArgs{
			Message:          []byte(strings.ReplaceAll(c.message, "\n", "\r\n")),
			HeaderFromDomain: testAssembleRelationDomain,
			MessageIdDomain:  testAssembleRelationDomain,
			Flags:            c.flags,
			Now:              signTime,
		})
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		signed, err := sidecar.SmtpDkimSign(wire, &sidecar.SmtpDkimSignArgs{
			Signer:        testAssembleRelationSigner{},
			Issued:        &sidecar.SmtpIssuedHeaders{XUrRef: testAssembleRelationXUrRef, FeedbackId: testAssembleRelationFeedback},
			SignTime:      signTime,
			ExpireTimeout: 7 * 24 * time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		preamble := &sessionPreamble{
			recipientDomain:  "shopping.example",
			recipientCount:   1,
			messageId:        wire.MessageId(),
			headerFromDomain: wire.HeaderFromDomain(),
			dkimSelector:     testAssembleRelationSelector,
			messageByteCount: uint64(len(signed)),
			flags:            c.flags,
			heloName:         "o1.out.bringyour.example",
			xUrRef:           testAssembleRelationXUrRef,
			feedbackId:       testAssembleRelationFeedback,
			envelopeDomain:   "b.n1.root.example",
		}
		if err := checkSessionPreamble(preamble); err != nil {
			t.Errorf("message %d preamble: %v", i, err)
		}
		headerEnd := bytes.Index(signed, []byte("\r\n\r\n")) + 4
		if err := checkHeaderBlock(signed[:headerEnd], preamble); err != nil {
			t.Errorf("message %d Z5: %v", i, err)
		}
		if body := dotStuffed(signed[headerEnd:]); 0 < len(body) {
			if err := checkDataLines(body); err != nil {
				t.Errorf("message %d Z6: %v", i, err)
			}
		}
		bdat, err := wire.ByteCount(sidecar.SmtpModeBdat)
		if err != nil {
			t.Fatal(err)
		}
		data, err := wire.ByteCount(sidecar.SmtpModeData)
		if err != nil {
			t.Fatal(err)
		}
		if bdat != uint64(len(signed)) || data != uint64(len(dotStuffed(signed))) {
			t.Errorf("message %d: declared %d and %d, prover counts %d and %d", i, bdat, data, len(signed), len(dotStuffed(signed)))
		}
		if DefaultProverSettings().MaxRecordContentBytes < headerEnd {
			t.Errorf("message %d: a %d-octet header block", i, headerEnd)
		}
	}
}
