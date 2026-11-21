// The ordering desktop's CA and resolver (TLS-M6-05; DESIGN-DETAILS 17.7, QD-288): sidecar.TlsAcmeClient on acmez's
// acme package, so acmez sits in cli/ and on no sdk leg, and sidecar.TlsCustomResolver on the system's resolver; and
// ur tls account, whose daemon methods compose the orderer from them, the network's evs and its Sidecar (below).
//
// Each method is one ACME request, acmez retrying a badNonce itself; FinalizeOrder's own polling is cut to one read,
// since 17.2.7's loop polls the order on its own clock. A CA's problem document becomes a *sidecar.TlsAcmeProblem
// with its type stripped of RFC 8555's urn prefix, and a 404 for an order or authorization is sidecar.ErrTlsAcmeGone;
// anything else is an outcome unknown. The directory is CertsSettings' Let's Encrypt value, which every test points
// at Pebble or a scripted CA: no test and no agent run reaches a real CA.

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/docopt/docopt-go"
	"github.com/mholt/acmez/v3/acme"
	standardAcme "golang.org/x/crypto/acme"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
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

// The CA's terms of service, from its directory, "" when it names none.
func (self *urTlsAcmeClient) TermsOfService(ctx context.Context) (string, error) {
	directory, err := self.client.GetDirectory(ctx)
	if err != nil {
		return "", urTlsAcmeError(err)
	}
	if directory.Meta == nil {
		return "", nil
	}
	return directory.Meta.TermsOfService, nil
}

// ur tls account (DESIGN-DETAILS 17.2.13): a Team custom domain's ACME account, made, its key changed and shown from a
// network admin's ordering desktop. Each runs in the daemon, on the network's own Sidecar, its evs and its keychain,
// through the control methods below; create and roll are a person's, confirmed on /dev/tty, and never MCP's.
//
//	ur tls account status [<domain>]   the domain's account, or each of the network's, as the work list gives it
//	ur tls account create <domain>     17.2.13's creation, with --agree-tos for the CA's terms it prints
//	ur tls account roll <domain>       17.2.13's key change R1 to R7 when it is due, or its resume when one is owed

// The control methods ur tls account calls.
const (
	urMethodTlsAccountStatus = "tls.account.status"
	urMethodTlsAccountCreate = "tls.account.create"
	urMethodTlsAccountRoll   = "tls.account.roll"
)

// The desktop uses the Let's Encrypt directory from its ACME dependency for both account commands and renewals.
func urDesktopTlsSettings() *sidecar.TlsCustomSettings {
	settings := sidecar.DefaultTlsCustomSettings()
	settings.DirectoryUrl = standardAcme.LetsEncryptURL
	return settings
}

// A command line ur tls cannot take.
var errUrTlsUsage = errors.New("ur tls: see ur tls --help")

func init() {
	registerUrCommand(&urCommand{
		name: "tls",
		usage: strings.Join([]string{
			"  ur tls account status [<domain>] [--network=<name>]",
			"  ur tls account create <domain> [--agree-tos] [--network=<name>]",
			"  ur tls account roll <domain> [--network=<name>]",
		}, "\n"),
		summary: "a Team custom domain's ACME account: show it, make it, change its key",
		run:     runUrTls,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urTlsAccountMethods)
}

// The account methods' params.
type urTlsAccountParams struct {
	Network  string `json:"network,omitempty"`
	Domain   string `json:"domain,omitempty"`
	AgreeTos bool   `json:"agree_tos,omitempty"`
}

// One account as the methods answer it: public values only, never a key (17.2.5).
type urTlsAccountView struct {
	Domain     string `json:"domain"`
	Ca         string `json:"ca"`
	AccountUri string `json:"account_uri"`
	KeySeq     uint64 `json:"key_seq"`
	KeyRepoId  string `json:"key_repo_id"`
	// A key change is in flight: the row records its next key.
	NextInFlight bool `json:"next_in_flight,omitempty"`
	// The key sequence this desktop's key file gives for the row, 0 for none.
	HeldKeySeq  uint64 `json:"held_key_seq,omitempty"`
	RolloverDue bool   `json:"rollover_due,omitempty"`
	MayRoll     bool   `json:"may_roll,omitempty"`
	// The lock is held, and the CA's holds' remainders.
	Locked    bool   `json:"locked,omitempty"`
	HoldNewMs uint32 `json:"hold_new_ms,omitempty"`
	HoldAllMs uint32 `json:"hold_all_ms,omitempty"`
	WorkCount int    `json:"work_count"`
	AcmeName  string `json:"acme_name,omitempty"`
}

// The view of a status.
func newUrTlsAccountView(status *sidecar.TlsCustomAccountStatus) *urTlsAccountView {
	account := status.Account
	return &urTlsAccountView{
		Domain:       account.Domain,
		Ca:           account.Ca,
		AccountUri:   account.AccountUri,
		KeySeq:       account.KeySeq,
		KeyRepoId:    account.KeyRepoId.String(),
		NextInFlight: 0 < len(account.NextKeyThumbprint),
		HeldKeySeq:   status.KeySeq,
		RolloverDue:  status.RolloverDue,
		MayRoll:      status.MayRoll,
		Locked:       account.LockSidecarId != (sidecar.Id{}),
		HoldNewMs:    account.HoldNewMs,
		HoldAllMs:    account.HoldAllMs,
		WorkCount:    status.WorkCount,
		AcmeName:     account.AcmeName,
	}
}

// tls.account.status's reply.
type urTlsAccountStatusReply struct {
	Accounts []*urTlsAccountView `json:"accounts"`
	// The CA's terms of service, from its directory, which create needs agreed.
	TermsOfService string `json:"terms_of_service,omitempty"`
}

// tls.account.create's reply.
type urTlsAccountCreateReply struct {
	Account *urTlsAccountView `json:"account"`
	// The secret repo the key file went to, and whether this call made it.
	RepoId      string `json:"repo_id"`
	RepoCreated bool   `json:"repo_created,omitempty"`
}

// tls.account.roll's reply.
type urTlsAccountRollReply struct {
	Due     bool              `json:"due,omitempty"`
	MayRoll bool              `json:"may_roll,omitempty"`
	Rolled  bool              `json:"rolled,omitempty"`
	Account *urTlsAccountView `json:"account,omitempty"`
}

// The ordering desktop's parts on one network (DESIGN-DETAILS 17.7): the orderer on this ur's CA client, the system
// resolver and the network's evs, with the key repos its key change reads.
type urTlsCustomHost struct {
	orderer *sidecar.TlsCustomDomainOrderer
	repos   sidecar.TlsCustomKeyRepos
	acme    *urTlsAcmeClient
	evs     *sidecar.EvsClient
}

// running's parts, or why there are none: no CA directory configured, no evs client, no certs audience.
func newUrTlsCustomHost(ctx context.Context, running *sidecar.Sidecar, settings *sidecar.TlsCustomSettings) (*urTlsCustomHost, error) {
	if settings == nil || settings.DirectoryUrl == "" {
		return nil, errUrTlsNoDirectory
	}
	acme, err := newUrTlsAcmeClient(settings.DirectoryUrl, nil, settings)
	if err != nil {
		return nil, err
	}
	if urDaemonEvsClient == nil {
		return nil, errUrNoEvsClient
	}
	evs, err := urDaemonEvsClient(running)
	if err != nil {
		return nil, err
	}
	deps, repos, err := running.TlsCustomOrdererDeps(ctx, acme, &urTlsCustomResolver{resolver: net.DefaultResolver}, &urTlsCustomRepoFiles{client: evs, settings: settings})
	if err != nil {
		return nil, err
	}
	orderer, err := sidecar.NewTlsCustomDomainOrderer(deps, settings)
	if err != nil {
		return nil, err
	}
	return &urTlsCustomHost{orderer: orderer, repos: repos, acme: acme, evs: evs}, nil
}

// No CA directory is configured for custom-domain accounts, so nothing reaches a CA.
var errUrTlsNoDirectory = errors.New("no ACME directory is configured for custom-domain accounts")

// The account methods, on a target that hosts Sidecars.
func urTlsAccountMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	network, ok := target.(*urDaemonNetwork)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name:    urMethodTlsAccountStatus,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urTlsAccountParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				host, err := newUrTlsCustomHost(ctx, call.Sidecar, network.tlsSettings)
				if err != nil {
					return nil, err
				}
				statuses, err := host.orderer.AccountStatus(ctx, params.Domain, host.repos)
				if err != nil {
					return nil, err
				}
				reply := &urTlsAccountStatusReply{Accounts: []*urTlsAccountView{}}
				for _, status := range statuses {
					reply.Accounts = append(reply.Accounts, newUrTlsAccountView(status))
				}
				// the terms are shown, never agreed, here
				if terms, err := host.acme.TermsOfService(ctx); err == nil {
					reply.TermsOfService = terms
				}
				return reply, nil
			},
		},
		{
			Name:    urMethodTlsAccountCreate,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urTlsAccountParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				if !params.AgreeTos {
					return nil, errUrTlsTermsNotAgreed
				}
				host, err := newUrTlsCustomHost(ctx, call.Sidecar, network.tlsSettings)
				if err != nil {
					return nil, err
				}
				if existing, err := host.orderer.Account(ctx, params.Domain); err != nil {
					return nil, err
				} else if existing != nil {
					return nil, sidecar.ErrTlsCustomAccountExists
				}
				// 17.2.13 step 1: the admin's own secret repo, made when the member has none
				secret := call.Sidecar.TlsCustomSecretRepo()
				if secret == nil || secret.MemberId == (sidecar.Id{}) {
					return nil, errors.New("this sidecar's admission names no member, whose secret repo would hold the key")
				}
				reply := &urTlsAccountCreateReply{}
				repoId := secret.RepoId
				if repoId == (sidecar.Id{}) {
					memberId := secret.MemberId
					repo, err := host.evs.CreateRepo(ctx, &sidecar.EvsCreateRepoArgs{
						Kind:          protocol.RepoKind_REPO_KIND_SECRET,
						OwnerMemberId: &memberId,
						Confirmed:     call.Confirmed,
					})
					if err != nil {
						return nil, err
					}
					repoId = repo.RepoId()
					reply.RepoCreated = true
				}
				account, err := host.orderer.CreateAccount(ctx, params.Domain, repoId, secret.ShrunkAt)
				if err != nil {
					return nil, err
				}
				reply.RepoId = repoId.String()
				reply.Account = newUrTlsAccountView(&sidecar.TlsCustomAccountStatus{Account: account, KeySeq: account.KeySeq})
				return reply, nil
			},
		},
		{
			Name:    urMethodTlsAccountRoll,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urTlsAccountParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				host, err := newUrTlsCustomHost(ctx, call.Sidecar, network.tlsSettings)
				if err != nil {
					return nil, err
				}
				statuses, err := host.orderer.AccountStatus(ctx, params.Domain, host.repos)
				if err != nil {
					return nil, err
				}
				if len(statuses) != 1 {
					return nil, errUrTlsNoAccount
				}
				status := statuses[0]
				if status.KeySeq == 0 {
					return nil, sidecar.ErrTlsCustomKeyUnavailable
				}
				// a change in flight is resumed whether or not a new one is due
				inFlight := 0 < len(status.Account.NextKeyThumbprint)
				reply := &urTlsAccountRollReply{Due: status.RolloverDue || inFlight, MayRoll: status.MayRoll}
				if !reply.Due || !reply.MayRoll {
					return reply, nil
				}
				if err := host.orderer.RollAccount(ctx, status.Account, host.repos); err != nil {
					return nil, err
				}
				reply.Rolled = true
				if account, err := host.orderer.Account(ctx, params.Domain); err == nil && account != nil {
					reply.Account = newUrTlsAccountView(&sidecar.TlsCustomAccountStatus{Account: account})
				}
				return reply, nil
			},
		},
	}
}

// create without --agree-tos.
var errUrTlsTermsNotAgreed = errors.New("the CA's terms are not agreed: pass --agree-tos")

// The domain has no account on the work list.
var errUrTlsNoAccount = errors.New("the domain has no account")

func runUrTls(ctx context.Context, cli *urCli, options docopt.Opts) error {
	if !urOptionBool(options, "account") {
		return errUrTlsUsage
	}
	network := urOptionString(options, "--network")
	domain := strings.ToLower(strings.TrimSuffix(urOptionString(options, "<domain>"), "."))
	switch {
	case urOptionBool(options, "status"):
		return runUrTlsAccountStatus(ctx, cli, network, domain)
	case urOptionBool(options, "create"):
		return runUrTlsAccountCreate(ctx, cli, network, domain, urOptionBool(options, "--agree-tos"))
	case urOptionBool(options, "roll"):
		return runUrTlsAccountRoll(ctx, cli, network, domain)
	}
	return errUrTlsUsage
}

// A duration in whole minutes, rounded up, for a hold's remainder.
func urTlsMinutes(ms uint32) string {
	return strconv.FormatUint((uint64(ms)+59999)/60000, 10) + " min"
}

// One account's lines.
func printUrTlsAccount(cli *urCli, account *urTlsAccountView) {
	cli.printf("%s\n", account.Domain)
	cli.printf("  account   %s at %s, key %d", account.AccountUri, account.Ca, account.KeySeq)
	if account.NextInFlight {
		cli.printf(", a key change in flight")
	}
	cli.printf("\n  key file  tls/acme/%s.json in secret repo %s\n", account.Domain, account.KeyRepoId)
	switch {
	case account.HeldKeySeq == 0:
		cli.printf("  this desktop holds no key file for it\n")
	case account.RolloverDue && account.MayRoll:
		cli.printf("  a key change is due: ur tls account roll %s\n", account.Domain)
	case account.RolloverDue:
		cli.printf("  a key change is due, which this desktop may not make\n")
	default:
		cli.printf("  this desktop holds key %d\n", account.HeldKeySeq)
	}
	if 0 < account.HoldAllMs {
		cli.printf("  held by the CA: no order for %s\n", urTlsMinutes(account.HoldAllMs))
	} else if 0 < account.HoldNewMs {
		cli.printf("  held by the CA: renewals only for %s\n", urTlsMinutes(account.HoldNewMs))
	}
	cli.printf("  work      %d rows", account.WorkCount)
	if account.Locked {
		cli.printf(", one desktop holds the lock")
	}
	cli.printf("\n")
	if account.AcmeName != "" {
		cli.printf("  dns-01    _acme-challenge.<host> CNAME %s\n", account.AcmeName)
	}
}

// The CAA records 17.2.13's creation prints: the account pinned, and no wildcard, since no custom certificate is one.
func printUrTlsCaa(cli *urCli, account *urTlsAccountView) {
	cli.printf("publish at %s:\n", account.Domain)
	cli.printf("  %s. CAA 0 issue \"letsencrypt.org; accounturi=%s\"\n", account.Domain, account.AccountUri)
	cli.printf("  %s. CAA 0 issuewild \";\"\n", account.Domain)
}

func runUrTlsAccountStatus(ctx context.Context, cli *urCli, network string, domain string) error {
	reply := &urTlsAccountStatusReply{}
	if err := cli.callDaemon(ctx, urMethodTlsAccountStatus, &urTlsAccountParams{Network: network, Domain: domain}, false, reply); err != nil {
		return err
	}
	if len(reply.Accounts) == 0 {
		if domain != "" {
			cli.printf("%s has no account: ur tls account create %s\n", domain, domain)
		} else {
			cli.printf("no custom-domain account\n")
		}
		return nil
	}
	for _, account := range reply.Accounts {
		printUrTlsAccount(cli, account)
	}
	return nil
}

func runUrTlsAccountCreate(ctx context.Context, cli *urCli, network string, domain string, agreeTos bool) error {
	if domain == "" {
		return errUrTlsUsage
	}
	status := &urTlsAccountStatusReply{}
	if err := cli.callDaemon(ctx, urMethodTlsAccountStatus, &urTlsAccountParams{Network: network, Domain: domain}, false, status); err != nil {
		return err
	}
	if 0 < len(status.Accounts) {
		printUrTlsAccount(cli, status.Accounts[0])
		return sidecar.ErrTlsCustomAccountExists
	}
	if status.TermsOfService != "" {
		cli.printf("the CA's terms of service: %s\n", status.TermsOfService)
	}
	if !agreeTos {
		return errUrTlsTermsNotAgreed
	}
	confirmed, err := confirmOnTty(cli, fmt.Sprintf("make the ACME account for %s, agreeing to the CA's terms, its key in your secret repo?", domain))
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	reply := &urTlsAccountCreateReply{}
	if err := cli.callDaemon(ctx, urMethodTlsAccountCreate, &urTlsAccountParams{Network: network, Domain: domain, AgreeTos: true}, true, reply); err != nil {
		return err
	}
	if reply.RepoCreated {
		cli.printf("made your secret repo %s for the key file\n", reply.RepoId)
	}
	printUrTlsAccount(cli, reply.Account)
	printUrTlsCaa(cli, reply.Account)
	// 17.2.13's step 5 waits on EvsShare filing from here
	cli.printf("share secret repo %s with the ordering desktops' users, so they read the key file\n", reply.RepoId)
	return nil
}

func runUrTlsAccountRoll(ctx context.Context, cli *urCli, network string, domain string) error {
	if domain == "" {
		return errUrTlsUsage
	}
	confirmed, err := confirmOnTty(cli, fmt.Sprintf("change the ACME account key of %s, if a change is due?", domain))
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	reply := &urTlsAccountRollReply{}
	if err := cli.callDaemon(ctx, urMethodTlsAccountRoll, &urTlsAccountParams{Network: network, Domain: domain}, true, reply); err != nil {
		return err
	}
	switch {
	case !reply.Due:
		cli.printf("no key change is due for %s\n", domain)
	case !reply.MayRoll:
		cli.printf("a key change is due for %s, which this desktop may not make\n", domain)
		return errUrTlsMayNotRoll
	default:
		if reply.Account != nil {
			cli.printf("the account key of %s changed: key %d\n", domain, reply.Account.KeySeq)
		} else {
			cli.printf("the account key of %s changed\n", domain)
		}
	}
	return nil
}

// A key change due that this desktop may not make.
var errUrTlsMayNotRoll = errors.New("this desktop may not make the key change")

// The key files of the network's secret repos through its evs client (17.2.3): a read of the main ref's newest
// version, at most KeyFileMaxByteCount, and a write that returns once its push committed.
type urTlsCustomRepoFiles struct {
	client   *sidecar.EvsClient
	settings *sidecar.TlsCustomSettings
}

var _ sidecar.TlsCustomRepoFiles = (*urTlsCustomRepoFiles)(nil)

// A buffer that refuses past limit bytes.
type urTlsCustomBoundedBuffer struct {
	bytes.Buffer
	limit int
}

func (self *urTlsCustomBoundedBuffer) Write(data []byte) (int, error) {
	if self.limit < self.Len()+len(data) {
		return 0, errUrTlsKeyFileSize
	}
	return self.Buffer.Write(data)
}

// A key file past its bound.
var errUrTlsKeyFileSize = errors.New("a key file past its bound")

// See sidecar.TlsCustomRepoFiles: any failure to read, an absent file and one past its bound alike, is a key file this
// desktop cannot read.
func (self *urTlsCustomRepoFiles) ReadKeyFile(ctx context.Context, repoId sidecar.Id, domain string) ([]byte, error) {
	buffer := &urTlsCustomBoundedBuffer{limit: self.settings.KeyFileMaxByteCount}
	if _, err := self.client.Repo(repoId).ReadHead(ctx, &sidecar.EvsReadArgs{Path: sidecar.TlsCustomKeyFilePath(domain), Fresh: true}, buffer); err != nil {
		// nothing of the read's error, which may name the path, goes on (I-13)
		return nil, sidecar.ErrTlsCustomKeyUnavailable
	}
	return buffer.Bytes(), nil
}

func (self *urTlsCustomRepoFiles) WriteKeyFile(ctx context.Context, repoId sidecar.Id, domain string, data []byte) error {
	_, err := self.client.Repo(repoId).Write(ctx, &sidecar.EvsWriteArgs{
		Path:    sidecar.TlsCustomKeyFilePath(domain),
		Content: bytes.NewReader(data),
		Size:    int64(len(data)),
	})
	return err
}
