package smtpproof

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// §14.6's Team custom domains held to this module's relation (SMTP-M9-34, D-SMTP-15): the envelope's MAIL is proven
// at the envelope domain the edge derives, b.<domain> in strict mode and b.<net>.<root> otherwise, and at no other
// (Z4); and a custom-domain message satisfies Z5 under its own header_from_domain, with d= that domain, and fails it
// under the network's. Every name is synthetic.

const (
	testCustomDomainRelationDomain   = "brand.example"
	testCustomDomainRelationNetwork  = "n1.root.example"
	testCustomDomainRelationSelector = "abcdefghijklmnopqrstuvwxye"
	testCustomDomainRelationId       = "aaaaaaaaaaaaaaaaaaaaaaaaaa@" + testCustomDomainRelationDomain
)

// A selector of the custom domain over the run's key.
type testCustomDomainRelationSigner struct{}

func (self testCustomDomainRelationSigner) DkimSelector() string {
	return testCustomDomainRelationSelector
}
func (self testCustomDomainRelationSigner) DkimDomain() string { return testCustomDomainRelationDomain }
func (self testCustomDomainRelationSigner) SignDkim(digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(nil, testAssembleRelationKey(), crypto.SHA256, digest)
}

// A preamble From the custom domain whose envelope the edge derived as envelopeDomain.
func testCustomDomainRelationPreamble(envelopeDomain string, messageByteCount uint64) *sessionPreamble {
	return &sessionPreamble{
		proof:            DefaultProofSettings(),
		recipientDomain:  "shopping.example",
		recipientCount:   1,
		messageId:        testCustomDomainRelationId,
		headerFromDomain: testCustomDomainRelationDomain,
		dkimSelector:     testCustomDomainRelationSelector,
		messageByteCount: messageByteCount,
		heloName:         "o1.out.bringyour.example",
		xUrRef:           testAssembleRelationXUrRef,
		feedbackId:       testAssembleRelationFeedback,
		envelopeDomain:   envelopeDomain,
	}
}

// Whether the MAIL command's content satisfies Z4's template under preamble.
func testCustomDomainRelationMail(preamble *sessionPreamble, command string) error {
	template, err := commandTemplate(recordRoleMail, preamble, len(command))
	if err != nil {
		return err
	}
	return templateMatches(template, []byte(command))
}

// Z4 proves MAIL FROM at the edge's envelope domain alone: strict mode's b.<domain> passes where the edge derived it
// and fails where it derived the network's, and the network's fails where it derived b.<domain>.
func TestCustomDomainEnvelopeIsProvenAtTheEdgesEnvelopeDomain(t *testing.T) {
	strictEnvelope := "b." + testCustomDomainRelationDomain
	networkEnvelope := "b." + testCustomDomainRelationNetwork
	strictMail := "MAIL FROM:<bounce-1@" + strictEnvelope + ">\r\n"
	networkMail := "MAIL FROM:<bounce-1@" + networkEnvelope + ">\r\n"
	strict := testCustomDomainRelationPreamble(strictEnvelope, 1)
	network := testCustomDomainRelationPreamble(networkEnvelope, 1)
	for _, preamble := range []*sessionPreamble{strict, network} {
		if err := checkSessionPreamble(preamble); err != nil {
			t.Fatalf("envelope %s: %v", preamble.envelopeDomain, err)
		}
	}
	if err := testCustomDomainRelationMail(strict, strictMail); err != nil {
		t.Errorf("strict mode's MAIL under its own envelope: %v", err)
	}
	if err := testCustomDomainRelationMail(network, networkMail); err != nil {
		t.Errorf("the network's MAIL under its envelope: %v", err)
	}
	if err := testCustomDomainRelationMail(network, strictMail); err == nil {
		t.Error("b.<domain> passed where the edge derived b.<net>.<root>")
	}
	if err := testCustomDomainRelationMail(strict, networkMail); err == nil {
		t.Error("b.<net>.<root> passed where the edge derived b.<domain>")
	}
	// a name that only ends in the envelope domain is another domain
	if err := testCustomDomainRelationMail(strict, "MAIL FROM:<bounce-1@x"+strictEnvelope+">\r\n"); err == nil {
		t.Error("a longer domain ending in the envelope domain passed")
	}
}

// Z5's literal d= is header_from_domain: the sender's custom-domain message passes Z5 under its own From domain, and
// the same octets fail it under the network's, since its From and d= are not the network's.
func TestCustomDomainHeaderBlockSatisfiesZ5UnderItsOwnDomain(t *testing.T) {
	signTime := time.Date(2026, time.November, 20, 12, 0, 0, 0, time.UTC)
	message := "From: Brand <news@" + testCustomDomainRelationDomain + ">\nTo: someone@shopping.example\nSubject: The catalog\n" +
		"Message-ID: <" + testCustomDomainRelationId + ">\n\nIt is out.\n"
	wire, err := sidecar.AssembleSmtpMessage(&sidecar.SmtpAssembleArgs{
		Message:          []byte(strings.ReplaceAll(message, "\n", "\r\n")),
		HeaderFromDomain: testCustomDomainRelationDomain,
		MessageIdDomain:  testCustomDomainRelationDomain,
		Now:              signTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := sidecar.SmtpDkimSign(wire, &sidecar.SmtpDkimSignArgs{
		Signer:        testCustomDomainRelationSigner{},
		Issued:        &sidecar.SmtpIssuedHeaders{XUrRef: testAssembleRelationXUrRef, FeedbackId: testAssembleRelationFeedback},
		SignTime:      signTime,
		ExpireTimeout: 7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	headerEnd := bytes.Index(signed, []byte("\r\n\r\n")) + 4
	preamble := testCustomDomainRelationPreamble("b."+testCustomDomainRelationNetwork, uint64(len(signed)))
	if err := checkHeaderBlock(signed[:headerEnd], preamble); err != nil {
		t.Fatalf("Z5 under the custom domain: %v", err)
	}
	preamble.headerFromDomain = testCustomDomainRelationNetwork
	if err := checkHeaderBlock(signed[:headerEnd], preamble); err == nil {
		t.Fatal("Z5 passed a custom-domain message under the network's domain")
	}
}
