// The ordering desktop's CA and resolver (TLS-M6-05; DESIGN-DETAILS 17.7, QD-288): sidecar.TlsAcmeClient on acmez's
// acme package, so acmez sits in cli/ and on no sdk leg, and sidecar.TlsCustomResolver on the system's resolver.
//
// Each method is one ACME request, acmez retrying a badNonce itself; FinalizeOrder's own polling is cut to one read,
// since 17.2.7's loop polls the order on its own clock. A CA's problem document becomes a *sidecar.TlsAcmeProblem
// with its type stripped of RFC 8555's urn prefix, and a 404 for an order or authorization is sidecar.ErrTlsAcmeGone;
// anything else is an outcome unknown. The directory is CertsSettings' Let's Encrypt value, which every test points
// at Pebble or a scripted CA: no test and no agent run reaches a real CA.

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mholt/acmez/v3/acme"

	"github.com/urnetwork/sidecar"
)

// RFC 8555's problem type prefix.
const tlsAcmeProblemPrefix = "urn:ietf:params:acme:error:"

var _ sidecar.TlsAcmeClient = (*urTlsAcmeClient)(nil)

// See the file header.
type urTlsAcmeClient struct {
	client *acme.Client
}

// A client of the CA at directoryUrl over httpClient, nil taking http.DefaultClient's transport.
func newUrTlsAcmeClient(directoryUrl string, httpClient *http.Client, settings *sidecar.TlsCustomSettings) (*urTlsAcmeClient, error) {
	if directoryUrl == "" {
		return nil, errors.New("no ACME directory")
	}
	return &urTlsAcmeClient{client: &acme.Client{
		Directory:    directoryUrl,
		HTTPClient:   httpClient,
		UserAgent:    "ur",
		PollInterval: settings.OrderPollInterval,
		PollTimeout:  settings.OrderPollInterval,
	}}, nil
}

// err as 17.7's types: a problem, gone, or unknown.
func urTlsAcmeError(err error) error {
	if err == nil {
		return nil
	}
	var problem acme.Problem
	if errors.As(err, &problem) {
		if problem.Status == http.StatusNotFound {
			return sidecar.ErrTlsAcmeGone
		}
		return &sidecar.TlsAcmeProblem{Type: strings.TrimPrefix(problem.Type, tlsAcmeProblemPrefix), Status: problem.Status}
	}
	return err
}

func (self *urTlsAcmeClient) account(key crypto.Signer, accountUri string) acme.Account {
	return acme.Account{Location: accountUri, PrivateKey: key}
}

func (self *urTlsAcmeClient) NewAccount(ctx context.Context, key crypto.Signer, onlyReturnExisting bool) (string, error) {
	if onlyReturnExisting {
		// newAccount with onlyReturnExisting: the key's own account, never a new one (RFC 8555 §7.3.1)
		account, err := self.client.GetAccount(ctx, acme.Account{PrivateKey: key})
		if err != nil {
			return "", urTlsAcmeError(err)
		}
		return account.Location, nil
	}
	account, err := self.client.NewAccount(ctx, acme.Account{PrivateKey: key, TermsOfServiceAgreed: true})
	if err != nil {
		return "", urTlsAcmeError(err)
	}
	return account.Location, nil
}

// Whether key is accountUri's key now: the key's own account is that one.
func (self *urTlsAcmeClient) Account(ctx context.Context, key crypto.Signer, accountUri string) error {
	account, err := self.client.GetAccount(ctx, acme.Account{PrivateKey: key})
	if err != nil {
		return urTlsAcmeError(err)
	}
	if account.Location != accountUri {
		return &sidecar.TlsAcmeProblem{Type: sidecar.TlsAcmeProblemUnauthorized, Status: http.StatusForbidden}
	}
	return nil
}

func (self *urTlsAcmeClient) KeyChange(ctx context.Context, accountUri string, oldKey crypto.Signer, newKey crypto.Signer) error {
	_, err := self.client.AccountKeyRollover(ctx, self.account(oldKey, accountUri), newKey)
	return urTlsAcmeError(err)
}

func (self *urTlsAcmeClient) Deactivate(ctx context.Context, key crypto.Signer, accountUri string) error {
	account := self.account(key, accountUri)
	account.Status = acme.StatusDeactivated
	_, err := self.client.UpdateAccount(ctx, account)
	return urTlsAcmeError(err)
}

func urTlsAcmeOrder(order acme.Order) *sidecar.TlsAcmeOrder {
	return &sidecar.TlsAcmeOrder{
		Url:            order.Location,
		Status:         order.Status,
		Authorizations: order.Authorizations,
		Finalize:       order.Finalize,
		Certificate:    order.Certificate,
	}
}

func (self *urTlsAcmeClient) NewOrder(ctx context.Context, key crypto.Signer, accountUri string, name string, profile string, replacesLeaf []byte) (*sidecar.TlsAcmeOrder, error) {
	order := acme.Order{
		Identifiers: []acme.Identifier{{Type: "dns", Value: name}},
		Profile:     profile,
	}
	if 0 < len(replacesLeaf) {
		leaf, err := x509.ParseCertificate(replacesLeaf)
		if err != nil {
			return nil, err
		}
		certificateId, err := acme.ARIUniqueIdentifier(leaf)
		if err != nil {
			return nil, err
		}
		order.Replaces = certificateId
	}
	created, err := self.client.NewOrder(ctx, self.account(key, accountUri), order)
	if err != nil {
		return nil, urTlsAcmeError(err)
	}
	return urTlsAcmeOrder(created), nil
}

func (self *urTlsAcmeClient) Order(ctx context.Context, key crypto.Signer, accountUri string, orderUrl string) (*sidecar.TlsAcmeOrder, error) {
	order, err := self.client.GetOrder(ctx, self.account(key, accountUri), acme.Order{Location: orderUrl})
	if err != nil {
		return nil, urTlsAcmeError(err)
	}
	return urTlsAcmeOrder(order), nil
}

func (self *urTlsAcmeClient) Authorization(ctx context.Context, key crypto.Signer, accountUri string, url string) (*sidecar.TlsAcmeAuthorization, error) {
	authorization, err := self.client.GetAuthorization(ctx, self.account(key, accountUri), url)
	if err != nil {
		return nil, urTlsAcmeError(err)
	}
	result := &sidecar.TlsAcmeAuthorization{Url: url, Status: authorization.Status}
	for _, challenge := range authorization.Challenges {
		result.Challenges = append(result.Challenges, &sidecar.TlsAcmeChallenge{Type: challenge.Type, Url: challenge.URL, Token: challenge.Token, Status: challenge.Status})
		if challenge.Error != nil {
			result.ProblemType = strings.TrimPrefix(challenge.Error.Type, tlsAcmeProblemPrefix)
		}
	}
	return result, nil
}

func (self *urTlsAcmeClient) Challenge(ctx context.Context, key crypto.Signer, accountUri string, url string) error {
	_, err := self.client.InitiateChallenge(ctx, self.account(key, accountUri), acme.Challenge{URL: url})
	return urTlsAcmeError(err)
}

func (self *urTlsAcmeClient) Finalize(ctx context.Context, key crypto.Signer, accountUri string, order *sidecar.TlsAcmeOrder, csr []byte) (*sidecar.TlsAcmeOrder, error) {
	finalized, err := self.client.FinalizeOrder(ctx, self.account(key, accountUri), acme.Order{Location: order.Url, Finalize: order.Finalize}, csr)
	if err != nil {
		// a poll that ran out reads the order again on the loop's own clock
		if finalized.Status != "" && tlsAcmeTimedOut(err) {
			return urTlsAcmeOrder(finalized), nil
		}
		return nil, urTlsAcmeError(err)
	}
	return urTlsAcmeOrder(finalized), nil
}

// Whether err is acmez giving up its own poll, which says nothing of the order.
func tlsAcmeTimedOut(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timed out")
}

func (self *urTlsAcmeClient) Certificate(ctx context.Context, key crypto.Signer, accountUri string, url string) ([][]byte, error) {
	chains, err := self.client.GetCertificateChain(ctx, self.account(key, accountUri), url)
	if err != nil {
		return nil, urTlsAcmeError(err)
	}
	if len(chains) == 0 {
		return nil, errors.New("the CA answered no chain")
	}
	// the CA's default chain, leaf first
	der := [][]byte{}
	rest := chains[0].ChainPEM
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		der = append(der, block.Bytes)
		rest = remaining
	}
	if len(der) == 0 {
		return nil, errors.New("the CA's chain holds no certificate")
	}
	return der, nil
}

func (self *urTlsAcmeClient) RenewalInfo(ctx context.Context, leaf []byte) (time.Time, time.Time, error) {
	certificate, err := x509.ParseCertificate(leaf)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	info, err := self.client.GetRenewalInfo(ctx, certificate)
	if err != nil {
		return time.Time{}, time.Time{}, urTlsAcmeError(err)
	}
	return info.SuggestedWindow.Start, info.SuggestedWindow.End, nil
}

func (self *urTlsAcmeClient) Revoke(ctx context.Context, key crypto.Signer, accountUri string, leaf []byte, reason int) error {
	certificate, err := x509.ParseCertificate(leaf)
	if err != nil {
		return err
	}
	return urTlsAcmeError(self.client.RevokeCertificate(ctx, self.account(key, accountUri), certificate, key, reason))
}

func (self *urTlsAcmeClient) DeactivateAuthorization(ctx context.Context, key crypto.Signer, accountUri string, url string) error {
	_, err := self.client.DeactivateAuthorization(ctx, self.account(key, accountUri), url)
	return urTlsAcmeError(err)
}

// RFC 8555 §8.1's key authorization: the token and the account key's RFC 7638 thumbprint.
func (self *urTlsAcmeClient) KeyAuthorization(key crypto.Signer, token string) (string, error) {
	publicKey, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("an account key that is not P-256")
	}
	return token + "." + base64.RawURLEncoding.EncodeToString(sidecar.TlsCustomKeyThumbprint(publicKey)), nil
}

// The system's resolver as 17.2.9's paths ask it.
type urTlsCustomResolver struct {
	resolver *net.Resolver
}

var _ sidecar.TlsCustomResolver = (*urTlsCustomResolver)(nil)

func (self *urTlsCustomResolver) LookupCname(ctx context.Context, name string) (string, error) {
	return self.resolver.LookupCNAME(ctx, name)
}

func (self *urTlsCustomResolver) LookupTxt(ctx context.Context, name string) ([]string, error) {
	return self.resolver.LookupTXT(ctx, name)
}
