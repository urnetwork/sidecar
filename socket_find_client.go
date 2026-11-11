//go:build !sidecar_http && !ios_extension

// socketFindClient: POST /socket/find (§9.6, §9.15) as both dialers send it, a sidecar's (SOCK-M5-12) and an edge's
// (SOCK-M5-13). It holds the route's shape on both sides of the call: a Find names exactly one of an edge name and a
// token path, in one network, and carries only failed tickets this dialer held; an answer that refuses nothing carries
// a primary ticket, each ticket and claim passing through as the bytes received. A refusal is §9.9's error in §9.6's
// step order (socketFindError), and a call that did not answer, or answered with anything but the route's shape, is
// unavailable, with whatever wait the service gave.
//
// The send is the caller's: SidecarApi.SocketFind on a sidecar's own token, or newSocketFindHttp on an edge host's
// platform client token. Nothing here verifies a ticket or a claim, which are each dialer's own checks, and nothing
// logs or wraps a name (I-13). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// A Find the route would refuse as malformed, which is a dialer's bug and never sent.
var errSocketFindInvalid = errors.New("invalid socket find")

// One POST /socket/find. A refusal of the whole call travels as the result's Error; an error here means the call
// was not answered with the route's body, and a *SidecarApiError carries any wait the service asked for.
type socketFindSend func(ctx context.Context, args *SocketFindArgs) (*SocketFindResult, error)

// The Find call both dialers share. newSocketFindClient makes one.
type socketFindClient struct {
	send socketFindSend
}

// A client over send.
func newSocketFindClient(send socketFindSend) *socketFindClient {
	return &socketFindClient{send: send}
}

// What one Find's answer holds once it refused nothing: the primary ticket, then the backup when the group had one.
type socketFindAnswer struct {
	tickets []*SocketFindTicket
}

// Whether args is a Find the route takes: one network, exactly one of an edge name and a token path, and each failed
// ticket whole.
func checkSocketFindArgs(args *SocketFindArgs) error {
	if args == nil || args.NetworkId == nil {
		return fmt.Errorf("%w: a find names no network", errSocketFindInvalid)
	}
	if (args.Name == "") == (len(args.NameToken) == 0) {
		return fmt.Errorf("%w: a find names exactly one of a name and a token path", errSocketFindInvalid)
	}
	for _, failed := range args.FailedTickets {
		if failed == nil || len(failed.Ticket) == 0 || (failed.Reason != SocketFailedReasonTimeout && failed.Reason != SocketFailedReasonRefused) {
			return fmt.Errorf("%w: a failed ticket of no ticket or reason", errSocketFindInvalid)
		}
	}
	return nil
}

// One Find: its tickets, or §9.9's error as a *SocketCodeError. A Find the route would refuse as malformed is the
// caller's error and never sent.
func (self *socketFindClient) find(ctx context.Context, args *SocketFindArgs) (*socketFindAnswer, error) {
	if err := checkSocketFindArgs(args); err != nil {
		return nil, err
	}
	result, err := self.send(ctx, args)
	if err != nil {
		retryAfter := time.Duration(0)
		var apiErr *SidecarApiError
		if errors.As(err, &apiErr) {
			retryAfter = time.Duration(apiErr.RetryAfterMs) * time.Millisecond
		}
		return nil, &SocketCodeError{Err: ErrSocketUnavailable, RetryAfter: retryAfter}
	}
	if result == nil {
		return nil, &SocketCodeError{Err: ErrSocketUnavailable}
	}
	if result.Error != nil {
		return nil, socketFindError(result.Error)
	}
	if result.Primary == nil || len(result.Primary.Ticket) == 0 {
		return nil, &SocketCodeError{Err: ErrSocketUnavailable}
	}
	answer := &socketFindAnswer{tickets: []*SocketFindTicket{result.Primary}}
	if result.Backup != nil && 0 < len(result.Backup.Ticket) {
		answer.tickets = append(answer.tickets, result.Backup)
	}
	return answer, nil
}

// What newSocketFindHttp takes: where POST /socket/find goes and how a caller with no SidecarApi authenticates, as an
// edge host's platform client does (§9.15's Client class).
type SocketFindHttpArgs struct {
	// The sockets service's origin, with no trailing slash: §19.4's sockets url.
	SocketsUrl string
	// Carries every request. Nil is http.DefaultTransport.
	Transport http.RoundTripper
	// The caller's client token for this call.
	Bearer func(ctx context.Context) (string, error)
	// The most of an answer's body read: past it the answer is no Find's. Zero takes socketFindMaxAnswerByteCount.
	MaxAnswerByteCount int64
}

// The largest Find answer read: two tickets of at most 512 B and their claims, in base64 and JSON, fit many times over.
const socketFindMaxAnswerByteCount = 64 * 1024

// A send for a caller with no SidecarApi: one JSON POST with the caller's bearer, whose 200 body is the route's
// answer. Any other status is a *SidecarApiError carrying Retry-After's wait, which a dialer reads as unavailable.
func newSocketFindHttp(args *SocketFindHttpArgs) (socketFindSend, error) {
	if args == nil || args.SocketsUrl == "" || args.Bearer == nil {
		return nil, fmt.Errorf("%w: a find client needs the sockets url and a bearer", errInvalidSettings)
	}
	if err := checkServiceUrl("SocketsUrl", args.SocketsUrl, "http", "https"); err != nil {
		return nil, err
	}
	transport := args.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	maxAnswerByteCount := args.MaxAnswerByteCount
	if maxAnswerByteCount <= 0 {
		maxAnswerByteCount = socketFindMaxAnswerByteCount
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(redirect *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	url := args.SocketsUrl + "/socket/find"
	return func(ctx context.Context, findArgs *SocketFindArgs) (*SocketFindResult, error) {
		bearer, err := args.Bearer(ctx)
		if err != nil || bearer == "" {
			return nil, fmt.Errorf("sidecar api %s: %w", socketFindRoute, ErrSidecarApiNoToken)
		}
		body, err := json.Marshal(findArgs)
		if err != nil {
			return nil, fmt.Errorf("sidecar api %s: %w", socketFindRoute, ErrSidecarApiArgs)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			// its text would repeat the url
			return nil, fmt.Errorf("sidecar api %s: %w", socketFindRoute, ErrSidecarApiArgs)
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+bearer)
		response, err := client.Do(request)
		if err != nil {
			// the transport's error may repeat the url
			return nil, fmt.Errorf("sidecar api %s: the call failed", socketFindRoute)
		}
		defer response.Body.Close()
		answer, err := io.ReadAll(io.LimitReader(response.Body, maxAnswerByteCount+1))
		if err != nil || maxAnswerByteCount < int64(len(answer)) {
			return nil, fmt.Errorf("sidecar api %s: %w", socketFindRoute, ErrSidecarApiReply)
		}
		if response.StatusCode != http.StatusOK {
			apiErr := &SidecarApiError{Route: socketFindRoute, Status: response.StatusCode}
			if seconds, err := strconv.ParseUint(response.Header.Get("Retry-After"), 10, 32); err == nil {
				apiErr.RetryAfterMs = clampRetryAfterMs(float64(seconds) * 1000)
			}
			return nil, apiErr
		}
		result := &SocketFindResult{}
		if err := json.Unmarshal(answer, result); err != nil {
			return nil, fmt.Errorf("sidecar api %s: %w", socketFindRoute, ErrSidecarApiReply)
		}
		return result, nil
	}, nil
}
