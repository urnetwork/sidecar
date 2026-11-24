//go:build !ios_extension

// A call's own ride over a service token it could not have, for the clients that ask the token exchange once a call
// and send nothing without its token: dns's (dns_client.go) and certs' (the certificate manager and the ordering
// desktop's routes, tls_component.go). They read why a token could not be had as evs's and gkm's retry owners do
// (sidecarServiceTokenRefusalOf): a refusal for good ends the call at once, and what may change goes again within the
// call's own bound, which its component's settings give.
//
// The exchange's invalid_scope is final here, with no window: these clients ask no scope, and the exchange answers
// invalid_scope only to a request one of whose scopes it was asked and grants none of (§7.8), so §8.9's lag on a new
// grant never reaches them as one. QD-1226's window stays with evs's and gkm's clients, which ask repo scopes.

package sidecar

import (
	"context"
	"time"
)

// A call's bound on asking for its service token again: its component's settings' values.
type sidecarServiceTokenRetry struct {
	// How many more times after the first a failure that may change is asked again. Non-positive asks once.
	count int
	// The wait before each, where the exchange named none.
	wait time.Duration
	// The longest retry_after waited out; an answer asking a longer one ends the call.
	maxWait time.Duration
}

// A service token from token, read by why one could not be had (sidecarServiceTokenRefusalOf). A refusal for good,
// the exchange's invalid_grant or no enrolled client say, ends the call at once with it. One that may change, no answer
// from api, its 429 or 5xx, a keychain still locked or no api yet, is asked again at most retry.count times, each after
// the exchange's retry_after, else retry.wait, on clock, and one asking past retry.maxWait ends the call, since a try
// before that wait is over would meet the same answer at api's cost. A ctx that ends, before a try or during a wait,
// ends the call with the last failure, so the caller tells its own end by its own context.
func sidecarRetryServiceToken(ctx context.Context, clock Clock, retry sidecarServiceTokenRetry, token func(ctx context.Context) (string, error)) (string, error) {
	for retryCount := 0; ; retryCount += 1 {
		serviceToken, err := token(ctx)
		if err == nil {
			return serviceToken, nil
		}
		refusal := sidecarServiceTokenRefusalOf(err)
		if ctx.Err() != nil || refusal.final || retry.count <= retryCount {
			return "", err
		}
		wait := retry.wait
		if 0 < refusal.retryAfter {
			if retry.maxWait < refusal.retryAfter {
				return "", err
			}
			wait = refusal.retryAfter
		}
		select {
		case <-ctx.Done():
		case <-clock.After(wait):
		}
		// select takes either of two ready cases at random: a wait that ended as ctx did asks nothing more
		if ctx.Err() != nil {
			return "", err
		}
	}
}
