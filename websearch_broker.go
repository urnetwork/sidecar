//go:build !ios_extension && !sidecar_http

// What the device asks of the broker for a search (DESIGN-COMPUTE §21.5, §21.8, §14.3; SRCH-M13-02): the
// authorization's admission, POST compute/v1/search/authorize, and the day's outcomes, POST compute/v1/search/outcomes,
// over the device's broker transport (INFER's ComputeServiceClient: the compute audience's service token with the
// ClientKey's DPoP proof, deterministic protobuf bodies, the broker's JSON refusals, QD-1246).
//
// WebSearchBroker is the seam: webSearchComputeBroker on a Sidecar, and a test's own over the fakes. Its refusals are
// the broker's codes, which webSearchBrokerRefusal turns into the search's: search_off, insufficient_quota,
// rate_limited (with its retry time), payee_refused, capacity and catalog_stale; any other code reads as capacity, and a
// request that never reached the broker, or whose answer was lost, as an error with no code, which the client asks
// again with the same bytes. The broker sees what the request carries and nothing else: never a payee, a nonce, a query
// or a result.

package sidecar

import (
	"context"
	"errors"

	"github.com/urnetwork/sidecar/protocol"
)

// The routes, from the broker's base url.
const (
	webSearchAuthorizePath = "/v1/search/authorize"
	webSearchOutcomesPath  = "/v1/search/outcomes"
)

// The broker's admission of search authorizations, and its intake of outcomes. Safe for concurrent use.
type WebSearchBroker interface {
	// POST compute/v1/search/authorize: the sealed authorization, or the broker's refusal, a *ComputeServiceError.
	Authorize(ctx context.Context, request *protocol.ComputeSearchAuthorizeRequest) (*protocol.ComputeSearchAuthorizeResponse, error)
	// POST compute/v1/search/outcomes: nil once the broker took them.
	ReportOutcomes(ctx context.Context, request *protocol.ComputeSearchOutcomesRequest) error
}

// A Sidecar's broker, through its compute service client, read at use.
type webSearchComputeBroker struct {
	sidecar *Sidecar
}

// See WebSearchBroker.
func (self *webSearchComputeBroker) Authorize(ctx context.Context, request *protocol.ComputeSearchAuthorizeRequest) (*protocol.ComputeSearchAuthorizeResponse, error) {
	client, err := self.sidecar.ComputeServiceClient()
	if err != nil {
		return nil, err
	}
	response := &protocol.ComputeSearchAuthorizeResponse{}
	if err := client.Post(ctx, webSearchAuthorizePath, request, response, 0); err != nil {
		return nil, err
	}
	return response, nil
}

// See WebSearchBroker.
func (self *webSearchComputeBroker) ReportOutcomes(ctx context.Context, request *protocol.ComputeSearchOutcomesRequest) error {
	client, err := self.sidecar.ComputeServiceClient()
	if err != nil {
		return err
	}
	return client.Post(ctx, webSearchOutcomesPath, request, nil, 0)
}

// The broker's codes a search answers as its own; the rest read as capacity.
var webSearchBrokerCodes = []string{
	WebSearchCodeSearchOff, WebSearchCodeInsufficientQuota, WebSearchCodeRateLimited, WebSearchCodePayeeRefused,
	WebSearchCodeCapacity, WebSearchCodeCatalogStale,
}

// The broker's refusal as the search's, and true; false for an error that is no refusal, a request that never reached
// the broker or an answer lost, which the client may ask again with the same bytes.
func webSearchBrokerRefusal(err error) (*WebSearchError, bool) {
	var refusal *ComputeServiceError
	if !errors.As(err, &refusal) {
		return nil, false
	}
	code := WebSearchCodeCapacity
	for _, known := range webSearchBrokerCodes {
		if refusal.Code == known {
			code = known
		}
	}
	return &WebSearchError{Code: code, Message: "the broker refused the authorization", RetryAfter: refusal.RetryAfter, cause: err}, true
}
