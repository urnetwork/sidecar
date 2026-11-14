//go:build !ios_extension

// §13.15's certificate routes as a device calls them (TLS-M5-18; R-TLS-3, D-TLS-7): POST /tls/cert-order and
// GET /tls/cert-order/<id> under a service token for aud certs, GET /tls/certs and POST /tls/cert-revoke under the
// client's own token. All four are api's routes, so they go to ApiUrl; only the order routes' bearer differs, and a
// caller hands that token in, from Sidecar.ServiceToken, since the exchange is its own to run and cache.
//
// A refusal is a *SidecarApiError with the route's status and code. Nothing here logs or wraps a body, a name or a
// token (I-7, I-13), and an order's url carries only the row's id.

package sidecar

import (
	"context"
	"fmt"
)

// The routes as errors name them.
const (
	tlsCertOrderRoute       = "POST /tls/cert-order"
	tlsCertOrderStatusRoute = "GET /tls/cert-order/<id>"
	tlsCertsRoute           = "GET /tls/certs"
	tlsCertRevokeRoute      = "POST /tls/cert-revoke"
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
