//go:build !sidecar_http && !ios_extension

// §9's routes at the sockets service that this sidecar calls (§9.15): POST /socket/registrations, which the registrar
// alone calls (socket_registrar.go), POST /socket/find, which the dialer's find client sends (socket_find_client.go),
// and GET /socket/list, which `ur socket ls` pages through and unseals here (daemon_socket.go). They carry §9's route
// bodies, which name connect.Id, so they stay off the sidecar_http leg, which registers and dials nothing (§18.10).
//
// Each presents a 15-minute service token of audience sockets (QD-1029), never the client token: sockets is a §7.8
// service audience, as evs, gkm and dns are, and reads the caller's sidecar from the token's ur_sidecar_id, which the
// exchange names from this client's binding. The token comes from the exchange (ExchangeToken, resource SocketsUrl,
// no scope) and is kept for the client whose token the exchange presented, under
// SidecarTokenRefreshSettings.ServiceTokenCacheTimeout and its own expires_in, so it renews on the exchange's schedule
// as Sidecar.ServiceToken's do; a new client's exchange names a new subject, so a kept token of another client is
// never presented. A 401 from sockets drops it at once, so the next call exchanges again. A token goes only into a
// request's Authorization header, never a reply, a log or an error (I-7).
//
// A page's refusal is a 200 whose body holds error, which this hands back as it came for the registrar to act on; an
// answer of another status is a *SidecarApiError, with any retry_after_ms or Retry-After the service gave. Nothing
// here logs or wraps a name: a body is the route's own business (I-13).

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// The routes as errors name them.
const (
	socketRegistrationsRoute = "POST /socket/registrations"
	socketFindRoute          = "POST /socket/find"
	socketListRoute          = "GET /socket/list"
)

// Who a token the exchange presents speaks for: its client, which a refresh keeps, or the whole token when it names
// no client readable.
func sidecarApiTokenSubject(byJwt string) string {
	if clientId := parseSidecarJwt(byJwt).stringClaim("client_id"); clientId != "" {
		return "client:" + clientId
	}
	return "token:" + byJwt
}

// The sockets service token the routes present: the one kept for this api's client while under ServiceTokenCacheTimeout
// and its expires_in, or a new exchange's. Refuses with no client token, as the exchange has none to present.
func (self *SidecarApi) socketsServiceToken(ctx context.Context) (string, error) {
	byJwt := self.currentByJwt()
	if byJwt == "" {
		return "", ErrSidecarApiNoToken
	}
	subject := sidecarApiTokenSubject(byJwt)
	kept := func() string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.socketsToken != nil && self.socketsToken.subject == subject && self.now().Before(self.socketsToken.keepUntil) {
			return self.socketsToken.accessToken
		}
		return ""
	}()
	if kept != "" {
		return kept, nil
	}
	issueTime := self.now()
	token, err := self.ExchangeToken(ctx, self.settings.SocketsUrl, nil)
	if err != nil {
		return "", err
	}
	keepFor := self.settings.TokenRefreshSettings.ServiceTokenCacheTimeout
	if 0 < token.ExpiresIn && token.ExpiresIn < keepFor {
		keepFor = token.ExpiresIn
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.socketsToken = &sidecarApiServiceToken{
			accessToken: token.AccessToken,
			subject:     subject,
			keepUntil:   issueTime.Add(keepFor),
		}
	}()
	return token.AccessToken, nil
}

// Drops the kept sockets token if it is still accessToken: sockets refused it, so the next call exchanges again.
func (self *SidecarApi) forgetSocketsServiceToken(accessToken string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.socketsToken != nil && self.socketsToken.accessToken == accessToken {
		self.socketsToken = nil
	}
}

// Sends request to sockets on a sockets service token, args as its JSON body when not nil and its 2xx answer decoded
// into result. A 401 drops the token it presented.
func (self *SidecarApi) sendSocketsJson(ctx context.Context, request *sidecarApiRequest, args any, result any) error {
	token, err := self.socketsServiceToken(ctx)
	if err != nil {
		return fmt.Errorf("sidecar api %s: no sockets token: %w", request.route, err)
	}
	request.bearerOverride = token
	err = self.sendJson(ctx, request, args, result)
	var apiErr *SidecarApiError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
		self.forgetSocketsServiceToken(token)
	}
	return err
}

// POST /socket/registrations (§9.5): one page of the client's set. An answer that refuses nothing must carry one
// status per entry of the page, in its order; anything else is not the route's answer.
func (self *SidecarApi) SocketRegistrations(ctx context.Context, args *SocketRegistrationsArgs) (*SocketRegistrationsResult, error) {
	if args == nil {
		return nil, fmt.Errorf("sidecar api %s: %w", socketRegistrationsRoute, ErrSidecarApiArgs)
	}
	result := &SocketRegistrationsResult{}
	err := self.sendSocketsJson(ctx, &sidecarApiRequest{
		route:     socketRegistrationsRoute,
		operation: "socket_registrations",
		method:    "POST",
		url:       self.settings.SocketsUrl + "/socket/registrations",
	}, args, result)
	if err != nil {
		return nil, err
	}
	if result.Error == nil && len(result.Statuses) != len(args.Registrations) {
		return nil, fmt.Errorf("sidecar api %s: %w: %d statuses for %d entries", socketRegistrationsRoute, ErrSidecarApiReply,
			len(result.Statuses), len(args.Registrations))
	}
	return result, nil
}

// POST /socket/find (§9.6): one Find. An answer that refuses nothing must carry a primary ticket; anything else is not
// the route's answer.
func (self *SidecarApi) SocketFind(ctx context.Context, args *SocketFindArgs) (*SocketFindResult, error) {
	if args == nil {
		return nil, fmt.Errorf("sidecar api %s: %w", socketFindRoute, ErrSidecarApiArgs)
	}
	result := &SocketFindResult{}
	err := self.sendSocketsJson(ctx, &sidecarApiRequest{
		route:     socketFindRoute,
		operation: "socket_find",
		method:    "POST",
		url:       self.settings.SocketsUrl + "/socket/find",
	}, args, result)
	if err != nil {
		return nil, err
	}
	if result.Error == nil && (result.Primary == nil || len(result.Primary.Ticket) == 0) {
		return nil, fmt.Errorf("sidecar api %s: %w: no primary ticket", socketFindRoute, ErrSidecarApiReply)
	}
	return result, nil
}

// GET /socket/list (§9.15): one page of this sidecar's own network's names, from cursor, "" for the first. A page's
// refusal is a 200 whose body holds error, handed back as it came; an answer that refuses nothing must carry a list.
func (self *SidecarApi) SocketList(ctx context.Context, cursor string) (*SocketListResult, error) {
	listUrl := self.settings.SocketsUrl + "/socket/list"
	if cursor != "" {
		listUrl += "?" + url.Values{"cursor": []string{cursor}}.Encode()
	}
	result := &SocketListResult{}
	err := self.sendSocketsJson(ctx, &sidecarApiRequest{
		route:     socketListRoute,
		operation: "socket_list",
		method:    "GET",
		url:       listUrl,
	}, nil, result)
	if err != nil {
		return nil, err
	}
	if result.Error == nil && result.Names == nil {
		return nil, fmt.Errorf("sidecar api %s: %w: no names", socketListRoute, ErrSidecarApiReply)
	}
	return result, nil
}
