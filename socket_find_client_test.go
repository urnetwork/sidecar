//go:build !sidecar_http && !js

// POST /socket/find's shared client (SOCK-M5-12): a malformed Find is never sent, a refusal is §9.9's error in step
// order, an answer with no primary or a call that did not answer is unavailable with the service's wait, and the
// edge's HTTP send carries its bearer and the route's body.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

func TestSocketFindClientRefusesMalformedFinds(t *testing.T) {
	sent := 0
	client := newSocketFindClient(func(ctx context.Context, args *SocketFindArgs) (*SocketFindResult, error) {
		sent += 1
		return &SocketFindResult{Primary: &SocketFindTicket{Ticket: []byte{1}}}, nil
	})
	networkId := connect.Id(testRegistrarNetworkId)
	for _, args := range []*SocketFindArgs{
		nil,
		{Name: "tls/443/blog"},
		{NetworkId: &networkId},
		{NetworkId: &networkId, Name: "tls/443/blog", NameToken: []byte{1}},
		{NetworkId: &networkId, NameToken: []byte{1}, FailedTickets: []*SocketFailedTicket{{Ticket: []byte{1}, Reason: "lost"}}},
		{NetworkId: &networkId, NameToken: []byte{1}, FailedTickets: []*SocketFailedTicket{{Reason: SocketFailedReasonTimeout}}},
	} {
		if _, err := client.find(context.Background(), args); err == nil {
			t.Errorf("a malformed find passed: %+v", args)
		}
	}
	if sent != 0 {
		t.Fatalf("%d malformed finds sent", sent)
	}
	answer, err := client.find(context.Background(), &SocketFindArgs{NetworkId: &networkId, NameToken: []byte{1}})
	if err != nil || len(answer.tickets) != 1 {
		t.Fatalf("a find: %+v %v", answer, err)
	}
}

func TestSocketFindClientAnswers(t *testing.T) {
	networkId := connect.Id(testRegistrarNetworkId)
	args := &SocketFindArgs{NetworkId: &networkId, NameToken: []byte{1}}
	for _, check := range []struct {
		name    string
		result  *SocketFindResult
		err     error
		want    error
		retry   time.Duration
		tickets int
	}{
		{name: "a primary and a backup", result: &SocketFindResult{Primary: &SocketFindTicket{Ticket: []byte{1}}, Backup: &SocketFindTicket{Ticket: []byte{2}}}, tickets: 2},
		{name: "a primary alone", result: &SocketFindResult{Primary: &SocketFindTicket{Ticket: []byte{1}}}, tickets: 1},
		{name: "no primary", result: &SocketFindResult{Backup: &SocketFindTicket{Ticket: []byte{2}}}, want: ErrSocketUnavailable},
		{name: "busy with its wait", result: &SocketFindResult{Error: &SocketError{Code: SocketErrorCodeBusy, RetryAfterMs: 300}}, want: ErrSocketBusy, retry: 300 * time.Millisecond},
		{name: "denied", result: &SocketFindResult{Error: &SocketError{Code: SocketErrorCodeDenied}}, want: ErrSocketDenied},
		{name: "a page's stale code", result: &SocketFindResult{Error: &SocketError{Code: SocketErrorCodeStale}}, want: ErrSocketDenied},
		{name: "no answer, with the service's wait", err: &SidecarApiError{Route: socketFindRoute, Status: 503, RetryAfterMs: 700}, want: ErrSocketUnavailable, retry: 700 * time.Millisecond},
		{name: "no answer at all", err: errors.New("transport"), want: ErrSocketUnavailable},
	} {
		client := newSocketFindClient(func(ctx context.Context, args *SocketFindArgs) (*SocketFindResult, error) {
			return check.result, check.err
		})
		answer, err := client.find(context.Background(), args)
		if check.want == nil {
			if err != nil || len(answer.tickets) != check.tickets {
				t.Errorf("%s: %+v %v", check.name, answer, err)
			}
			continue
		}
		var codeErr *SocketCodeError
		if !errors.Is(err, check.want) || !errors.As(err, &codeErr) || codeErr.RetryAfter != check.retry {
			t.Errorf("%s: %v", check.name, err)
		}
	}
}

func TestSocketFindHttpSendsTheRoute(t *testing.T) {
	var seen *SocketFindArgs
	var bearer string
	transport := &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			bearer = request.Header.Get("Authorization")
			seen = &SocketFindArgs{}
			if err := json.Unmarshal(body, seen); err != nil || request.URL.Path != "/socket/find" || request.Method != http.MethodPost {
				return syntheticResponse(request, 400, "{}", nil), nil
			}
			return syntheticResponse(request, 200, `{"primary":{"ticket":"AQI=","claim":"Aw=="}}`, nil), nil
		},
	}
	send, err := newSocketFindHttp(&SocketFindHttpArgs{
		SocketsUrl: "https://sockets.example",
		Transport:  transport,
		Bearer: func(ctx context.Context) (string, error) {
			return "edge-token", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	networkId := connect.Id(testRegistrarNetworkId)
	clientId := connect.Id(testSocketId("edge client"))
	answer, err := newSocketFindClient(send).find(context.Background(), &SocketFindArgs{
		NetworkId: &networkId,
		Name:      "tls/443/blog",
		ClientIds: []*connect.Id{&clientId},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.tickets) != 1 || string(answer.tickets[0].Ticket) != "\x01\x02" || string(answer.tickets[0].Claim) != "\x03" {
		t.Errorf("tickets %+v", answer.tickets)
	}
	if bearer != "Bearer edge-token" || seen.Name != "tls/443/blog" || len(seen.ClientIds) != 1 || *seen.ClientIds[0] != clientId {
		t.Errorf("sent %q %+v", bearer, seen)
	}

	// a refusal status is unavailable with Retry-After's wait
	transport.answer = func(request *http.Request, body []byte) (*http.Response, error) {
		return syntheticResponse(request, 503, "{}", http.Header{"Retry-After": []string{"2"}}), nil
	}
	_, err = newSocketFindClient(send).find(context.Background(), &SocketFindArgs{NetworkId: &networkId, Name: "tls/443/blog"})
	var codeErr *SocketCodeError
	if !errors.Is(err, ErrSocketUnavailable) || !errors.As(err, &codeErr) || codeErr.RetryAfter != 2*time.Second {
		t.Errorf("a 503: %v", err)
	}
	if _, err := newSocketFindHttp(&SocketFindHttpArgs{SocketsUrl: "https://sockets.example/", Transport: transport, Bearer: func(ctx context.Context) (string, error) { return "", nil }}); err == nil {
		t.Error("a url with a trailing slash")
	}
	if _, err := newSocketFindHttp(&SocketFindHttpArgs{SocketsUrl: "https://sockets.example", Transport: transport}); err == nil {
		t.Error("no bearer")
	}
	if _, err := newSocketFindHttp(&SocketFindHttpArgs{SocketsUrl: "https://sockets.example", Bearer: func(ctx context.Context) (string, error) { return "t", nil }}); err == nil {
		t.Error("no transport")
	}
}
