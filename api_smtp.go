//go:build !sidecar_http && !ios_extension

// §14.14's sender route on SidecarApi: POST /smtp/dkim-keys, the only way a DKIM selector reaches DNS
// (§12.7, §14.6, owner decision 36). The body holds selectors, signing domains and public keys and
// nothing else, so URnetwork never holds a DKIM private key (R-SMTP-10); §2.8's smtp-6 is the row that
// lets the server keep them.
//
// One call both publishes and retires, so a rotation is one write on the server: the new selector goes
// into DNS and the old one is marked retired in the same transaction, and the server keeps a retired
// selector in DNS 7 days before SMTP-M9-17 deletes it. The server's half is SMTP-M9-19's, which this
// body binds:
//
//   - a Client route with mail_send, bearer only, on §7.4's strict_exp allowlist;
//   - each published key is DER SubjectPublicKeyInfo of an RSA-2048 key, its selector 26 lowercase
//     base32 characters (plan-SMTP-small-readings#5), and its domain the network's <net>.<root>, a
//     burner label under it, or a verified Team domain (§7.6);
//   - publishing a selector the caller already published with the same key is no error, and neither
//     is retiring one already retired or one the server does not hold, so a sidecar that lost an
//     answer sends the same body again;
//   - past dns_dkim_selectors, 64 device selectors with burners' excluded, the call is refused whole
//     with a 4xx and a code, and nothing in it applies;
//   - the answer echoes every selector it published and every one it retired.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"slices"
)

// One selector to publish.
type SmtpDkimKeyPublish struct {
	// SmtpDkimSelectorLength lowercase base32 characters: one DNS label, opaque and random.
	Selector string `json:"selector"`
	// d=, lowercase: <net>.<root>, <blabel>.<net>.<root>, or a verified Team domain.
	Domain string `json:"domain"`
	// DER SubjectPublicKeyInfo of the RSA-2048 key, as the TXT record's p= carries it.
	PublicKey []byte `json:"public_key"`
}

// One selector to retire. The server keeps it in DNS 7 days more.
type SmtpDkimKeyRetire struct {
	Selector string `json:"selector"`
	Domain   string `json:"domain"`
}

// POST /smtp/dkim-keys's body.
type SmtpDkimKeysArgs struct {
	Publish []*SmtpDkimKeyPublish `json:"publish,omitempty"`
	Retire  []*SmtpDkimKeyRetire  `json:"retire,omitempty"`
}

// POST /smtp/dkim-keys's answer: the selectors the call published and retired.
type SmtpDkimKeysResult struct {
	Published []string `json:"published"`
	Retired   []string `json:"retired"`
}

// Whether a public key is DER SubjectPublicKeyInfo of an RSA key of SmtpDkimRsaKeyBitCount bits.
func smtpDkimPublicKeyValid(publicKey []byte) bool {
	parsed, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return false
	}
	rsaKey, ok := parsed.(*rsa.PublicKey)
	return ok && rsaKey.N.BitLen() == SmtpDkimRsaKeyBitCount
}

// POST /smtp/dkim-keys (§14.14): publishes args.Publish and retires args.Retire in one call, with the
// jwt as bearer. Refuses before sending a body that publishes and retires nothing, or holds anything
// but a selector, a domain and an RSA-2048 public key, so no other bytes can ride it. A refusal is a
// *SidecarApiError carrying the server's code, such as the selector cap's, and an answer that does not
// echo every selector the call named is ErrSidecarApiReply.
func (self *SidecarApi) SmtpDkimKeys(ctx context.Context, args *SmtpDkimKeysArgs) (*SmtpDkimKeysResult, error) {
	route := "POST /smtp/dkim-keys"
	if args == nil || len(args.Publish)+len(args.Retire) == 0 {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
	}
	for _, publish := range args.Publish {
		if publish == nil || !smtpDkimSelectorForm(publish.Selector) || !smtpDkimDomainForm(publish.Domain) || !smtpDkimPublicKeyValid(publish.PublicKey) {
			return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
		}
	}
	for _, retire := range args.Retire {
		if retire == nil || !smtpDkimSelectorForm(retire.Selector) || !smtpDkimDomainForm(retire.Domain) {
			return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
		}
	}
	result := &SmtpDkimKeysResult{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     route,
		operation: "smtp_dkim_keys",
		method:    "POST",
		url:       self.settings.ApiUrl + "/smtp/dkim-keys",
		bearer:    true,
	}, args, result)
	if err != nil {
		return nil, err
	}
	for _, publish := range args.Publish {
		if !slices.Contains(result.Published, publish.Selector) {
			return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiReply)
		}
	}
	for _, retire := range args.Retire {
		if !slices.Contains(result.Retired, retire.Selector) {
			return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiReply)
		}
	}
	return result, nil
}
