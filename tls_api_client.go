//go:build !ios_extension

// §13.15's certificate routes as a device calls them (TLS-M5-18; R-TLS-3, D-TLS-7): POST /tls/cert-order and
// GET /tls/cert-order/<id> under a service token for aud certs, GET /tls/certs and POST /tls/cert-revoke under the
// client's own token. All four are api's routes, so they go to ApiUrl; only the order routes' bearer differs, and a
// caller hands that token in, from Sidecar.ServiceToken, since the exchange is its own to run and cache. The
// custom-domain routes an ordering desktop calls (TLS-M6-05; DESIGN-DETAILS 17.2.5) go the same way, each under its
// certs service token.
//
// A refusal is a *SidecarApiError with the route's status and code, and a custom route's is a *TlsCustomError with
// its body's reason, wait, row and key sequence. Nothing here logs or wraps a body, a name or a token (I-7, I-13), and
// an order's url carries only the row's id.

package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
)

// The routes as errors name them.
const (
	tlsCertOrderRoute       = "POST /tls/cert-order"
	tlsCertOrderStatusRoute = "GET /tls/cert-order/<id>"
	tlsCertsRoute           = "GET /tls/certs"
	tlsCertRevokeRoute      = "POST /tls/cert-revoke"

	tlsCustomWorkRoute            = "GET /tls/certs?work=1"
	tlsCustomClaimRoute           = "POST /tls/custom-claim"
	tlsCustomProgressRoute        = "POST /tls/custom-progress"
	tlsCertRegisterRoute          = "POST /tls/cert-register"
	tlsCustomAccountRoute         = "POST /tls/custom-account"
	tlsCustomChallengeRoute       = "POST /tls/custom-challenge"
	tlsCustomChallengeStatusRoute = "GET /tls/custom-challenge/<id>"
)

// POST /tls/cert-order (§13.8): queues the caller's CSR with its attestation, under serviceToken, a service token for
// aud certs. The answer is the row, written before any order. An answer with no row, or a body with no CSR or
// attestation, is refused here.
func (self *SidecarApi) TlsCertOrder(ctx context.Context, serviceToken string, args *TlsCertOrderArgs) (*TlsCertOrderResult, error) {
	if serviceToken == "" || args == nil || len(args.Csr) == 0 || len(args.Attestation) == 0 {
		return nil, fmt.Errorf("sidecar api %s: %w", tlsCertOrderRoute, ErrSidecarApiArgs)
	}
	result := &TlsCertOrderResult{}
	err := self.withByJwt(serviceToken).sendJson(ctx, &sidecarApiRequest{
		route:     tlsCertOrderRoute,
		operation: "tls_cert_order",
		method:    "POST",
		url:       self.settings.ApiUrl + "/tls/cert-order",
		bearer:    true,
	}, args, result)
	if err != nil {
		return nil, err
	}
	if result.CertId == (Id{}) || result.State == "" {
		return nil, fmt.Errorf("sidecar api %s: %w", tlsCertOrderRoute, ErrSidecarApiReply)
	}
	return result, nil
}

// GET /tls/cert-order/<id> (§13.8): the caller's own order, under serviceToken as TlsCertOrder takes it. An answer
// with no state is not the route's.
func (self *SidecarApi) TlsCertOrderStatus(ctx context.Context, serviceToken string, certId Id) (*TlsCertOrderStatus, error) {
	if serviceToken == "" || certId == (Id{}) {
		return nil, fmt.Errorf("sidecar api %s: %w", tlsCertOrderStatusRoute, ErrSidecarApiArgs)
	}
	result := &TlsCertOrderStatus{}
	err := self.withByJwt(serviceToken).sendJson(ctx, &sidecarApiRequest{
		route:     tlsCertOrderStatusRoute,
		operation: "tls_cert_order_status",
		method:    "GET",
		url:       self.settings.ApiUrl + "/tls/cert-order/" + certId.String(),
		bearer:    true,
	}, nil, result)
	if err != nil {
		return nil, err
	}
	if result.State == "" {
		return nil, fmt.Errorf("sidecar api %s: %w", tlsCertOrderStatusRoute, ErrSidecarApiReply)
	}
	return result, nil
}

// GET /tls/certs (§13.15): the caller's network's certificates and their attestations, under its client token. A
// server's answer: a reader verifies each attestation it acts on (VerifyTlsKeyAttestation). A row with no id is not
// the route's.
func (self *SidecarApi) TlsCerts(ctx context.Context) (*TlsCertsResult, error) {
	result := &TlsCertsResult{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     tlsCertsRoute,
		operation: "tls_certs",
		method:    "GET",
		url:       self.settings.ApiUrl + "/tls/certs",
		bearer:    true,
	}, nil, result)
	if err != nil {
		return nil, err
	}
	for _, records := range [][]*TlsCertRecord{result.Certs, result.QueuedCsrs} {
		for _, record := range records {
			if record == nil || record.CertId == (Id{}) {
				return nil, fmt.Errorf("sidecar api %s: %w", tlsCertsRoute, ErrSidecarApiReply)
			}
		}
	}
	return result, nil
}

// POST /tls/cert-revoke (§13.8): marks the caller's own certificate for revocation, with keyCompromise when the body
// says so. The CA hears of it after the request returns.
func (self *SidecarApi) TlsCertRevoke(ctx context.Context, args *TlsCertRevokeArgs) error {
	if args == nil || args.CertId == (Id{}) {
		return fmt.Errorf("sidecar api %s: %w", tlsCertRevokeRoute, ErrSidecarApiArgs)
	}
	return self.sendJson(ctx, &sidecarApiRequest{
		route:     tlsCertRevokeRoute,
		operation: "tls_cert_revoke",
		method:    "POST",
		url:       self.settings.ApiUrl + "/tls/cert-revoke",
		bearer:    true,
	}, args, nil)
}

// One custom route under serviceToken, a service token for aud certs (DESIGN-DETAILS 17.2.5): args as its JSON body,
// when not nil, and its 2xx answer into result, when not nil. A refusal whose body is a custom route's is a
// *TlsCustomError (tlsCustomRefusalOf); any other is a *SidecarApiError.
func (self *SidecarApi) tlsCustomSend(ctx context.Context, serviceToken string, route string, operation string, method string, path string, args any, result any) error {
	if serviceToken == "" {
		return fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
	}
	return self.withByJwt(serviceToken).sendJson(ctx, &sidecarApiRequest{
		route:     route,
		operation: operation,
		method:    method,
		url:       self.settings.ApiUrl + path,
		bearer:    true,
		refusal:   tlsCustomRefusalOf,
	}, args, result)
}

// A custom route's refusal from its status and body (DESIGN-DETAILS 17.2.5): a *TlsCustomError when the body is
// {"reason": <a code>} with retry_after_ms, cert_id and key_seq each of its type when present, else nil, leaving the
// refusal a *SidecarApiError. Nothing of the body but those fields is read.
func tlsCustomRefusalOf(status int, body []byte) error {
	fields := struct {
		Reason       *string `json:"reason"`
		RetryAfterMs *uint32 `json:"retry_after_ms"`
		CertId       *Id     `json:"cert_id"`
		KeySeq       *uint64 `json:"key_seq"`
	}{}
	if json.Unmarshal(body, &fields) != nil || fields.Reason == nil || !isSidecarApiCode(*fields.Reason) {
		return nil
	}
	refusal := &TlsCustomError{Status: status, Refusal: TlsCustomRefusal{Reason: *fields.Reason}}
	if fields.RetryAfterMs != nil {
		refusal.Refusal.RetryAfterMs = *fields.RetryAfterMs
	}
	if fields.CertId != nil {
		refusal.Refusal.CertId = *fields.CertId
	}
	if fields.KeySeq != nil {
		refusal.Refusal.KeySeq = *fields.KeySeq
	}
	return refusal
}

// GET /tls/certs?work=1 (DESIGN-DETAILS 17.2.5): an ordering desktop's accounts and its work list in 17.2.8's plan
// order, under serviceToken. An account with no domain, or a row with no id, is not the route's.
func (self *SidecarApi) TlsCustomWork(ctx context.Context, serviceToken string) (*TlsCertsResult, error) {
	result := &TlsCertsResult{}
	if err := self.tlsCustomSend(ctx, serviceToken, tlsCustomWorkRoute, "tls_custom_work", "GET", "/tls/certs?work=1", nil, result); err != nil {
		return nil, err
	}
	for _, account := range result.Accounts {
		if account == nil || account.Domain == "" {
			return nil, fmt.Errorf("sidecar api %s: %w", tlsCustomWorkRoute, ErrSidecarApiReply)
		}
	}
	for _, record := range result.QueuedCsrs {
		if record == nil || record.CertId == (Id{}) {
			return nil, fmt.Errorf("sidecar api %s: %w", tlsCustomWorkRoute, ErrSidecarApiReply)
		}
	}
	return result, nil
}

// POST /tls/custom-claim (DESIGN-DETAILS 17.2.6): takes or renews an account's lock, under serviceToken. An answer
// with no claim sequence is not the route's.
func (self *SidecarApi) TlsCustomClaim(ctx context.Context, serviceToken string, args *TlsCustomClaimArgs) (*TlsCustomClaimResult, error) {
	if args == nil || args.Domain == "" || args.Purpose == "" {
		return nil, fmt.Errorf("sidecar api %s: %w", tlsCustomClaimRoute, ErrSidecarApiArgs)
	}
	result := &TlsCustomClaimResult{}
	if err := self.tlsCustomSend(ctx, serviceToken, tlsCustomClaimRoute, "tls_custom_claim", "POST", "/tls/custom-claim", args, result); err != nil {
		return nil, err
	}
	if result.ClaimSeq == 0 {
		return nil, fmt.Errorf("sidecar api %s: %w", tlsCustomClaimRoute, ErrSidecarApiReply)
	}
	return result, nil
}

// POST /tls/custom-progress (DESIGN-DETAILS 17.2.5): what the holder learned at the CA, under serviceToken. The answer
// is the claim as the event left it.
func (self *SidecarApi) TlsCustomProgress(ctx context.Context, serviceToken string, args *TlsCustomProgressArgs) (*TlsCustomClaimResult, error) {
	if args == nil || args.Domain == "" || args.Event == "" {
		return nil, fmt.Errorf("sidecar api %s: %w", tlsCustomProgressRoute, ErrSidecarApiArgs)
	}
	result := &TlsCustomClaimResult{}
	if err := self.tlsCustomSend(ctx, serviceToken, tlsCustomProgressRoute, "tls_custom_progress", "POST", "/tls/custom-progress", args, result); err != nil {
		return nil, err
	}
	return result, nil
}

// POST /tls/cert-register (DESIGN-DETAILS 17.2.5): the chain of the row the caller holds its account's lock for, under
// serviceToken.
func (self *SidecarApi) TlsCertRegister(ctx context.Context, serviceToken string, args *TlsCertRegisterArgs) error {
	if args == nil || args.CertId == (Id{}) || args.ClaimSeq == 0 || len(args.Chain) == 0 {
		return fmt.Errorf("sidecar api %s: %w", tlsCertRegisterRoute, ErrSidecarApiArgs)
	}
	return self.tlsCustomSend(ctx, serviceToken, tlsCertRegisterRoute, "tls_cert_register", "POST", "/tls/cert-register", args, nil)
}

// POST /tls/custom-account (DESIGN-DETAILS 17.2.5, 17.2.13): an account's creation or key change, network admins'
// desktops only, under serviceToken. An answer with no domain is not the route's.
func (self *SidecarApi) TlsCustomAccount(ctx context.Context, serviceToken string, args *TlsCustomAccountArgs) (*TlsCustomAccount, error) {
	if args == nil || args.Domain == "" || args.Op == "" {
		return nil, fmt.Errorf("sidecar api %s: %w", tlsCustomAccountRoute, ErrSidecarApiArgs)
	}
	result := &TlsCustomAccount{}
	if err := self.tlsCustomSend(ctx, serviceToken, tlsCustomAccountRoute, "tls_custom_account", "POST", "/tls/custom-account", args, result); err != nil {
		return nil, err
	}
	if result.Domain == "" {
		return nil, fmt.Errorf("sidecar api %s: %w", tlsCustomAccountRoute, ErrSidecarApiReply)
	}
	return result, nil
}

// POST /tls/custom-challenge (QD-175): a DNS-01 value at the account's acme name, under serviceToken. An answer with
// no challenge id is not the route's.
func (self *SidecarApi) TlsCustomChallenge(ctx context.Context, serviceToken string, args *TlsCustomChallengeArgs) (*TlsCustomChallengeResult, error) {
	if args == nil || args.Domain == "" || args.Value == "" {
		return nil, fmt.Errorf("sidecar api %s: %w", tlsCustomChallengeRoute, ErrSidecarApiArgs)
	}
	result := &TlsCustomChallengeResult{}
	if err := self.tlsCustomSend(ctx, serviceToken, tlsCustomChallengeRoute, "tls_custom_challenge", "POST", "/tls/custom-challenge", args, result); err != nil {
		return nil, err
	}
	if result.ChallengeId == 0 {
		return nil, fmt.Errorf("sidecar api %s: %w", tlsCustomChallengeRoute, ErrSidecarApiReply)
	}
	return result, nil
}

// GET /tls/custom-challenge/<id> (QD-175): whether the dns edges serve the value, under serviceToken.
func (self *SidecarApi) TlsCustomChallengeStatus(ctx context.Context, serviceToken string, challengeId uint64) (*TlsCustomChallengeResult, error) {
	if challengeId == 0 {
		return nil, fmt.Errorf("sidecar api %s: %w", tlsCustomChallengeStatusRoute, ErrSidecarApiArgs)
	}
	result := &TlsCustomChallengeResult{}
	if err := self.tlsCustomSend(ctx, serviceToken, tlsCustomChallengeStatusRoute, "tls_custom_challenge_status", "GET", "/tls/custom-challenge/"+strconv.FormatUint(challengeId, 10), nil, result); err != nil {
		return nil, err
	}
	return result, nil
}
