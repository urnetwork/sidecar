//go:build !sidecar_http && !ios_extension

// §9's routes at the sockets service that this sidecar calls with its own client token (§9.15; Client class, on §7.4's
// strict_exp allowlist, plan-SOCK-client-auth): POST /socket/registrations, which the registrar alone calls
// (socket_registrar.go), POST /socket/find, which the dialer's find client sends (socket_find_client.go), and
// GET /socket/list, which `ur socket ls` pages through and unseals here (daemon_socket.go). They carry
// §9's route bodies, which name connect.Id, so they stay off the sidecar_http leg, which registers and dials nothing
// (§18.10).
//
// A page's refusal is a 200 whose body holds error, which this hands back as it came for the registrar to act on; an
// answer of another status is a *SidecarApiError, with any retry_after_ms or Retry-After the service gave. Nothing
// here logs or wraps a name: a body is the route's own business (I-13).

package sidecar

import (
	"context"
	"fmt"
	"net/url"
)

// The routes as errors name them.
const (
	socketRegistrationsRoute = "POST /socket/registrations"
	socketFindRoute          = "POST /socket/find"
	socketListRoute          = "GET /socket/list"
)

// POST /socket/registrations (§9.5): one page of the client's set. An answer that refuses nothing must carry one
// status per entry of the page, in its order; anything else is not the route's answer.
func (self *SidecarApi) SocketRegistrations(ctx context.Context, args *SocketRegistrationsArgs) (*SocketRegistrationsResult, error) {
	if args == nil {
		return nil, fmt.Errorf("sidecar api %s: %w", socketRegistrationsRoute, ErrSidecarApiArgs)
	}
	result := &SocketRegistrationsResult{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     socketRegistrationsRoute,
		operation: "socket_registrations",
		method:    "POST",
		url:       self.settings.SocketsUrl + "/socket/registrations",
		bearer:    true,
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
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     socketFindRoute,
		operation: "socket_find",
		method:    "POST",
		url:       self.settings.SocketsUrl + "/socket/find",
		bearer:    true,
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
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     socketListRoute,
		operation: "socket_list",
		method:    "GET",
		url:       listUrl,
		bearer:    true,
	}, nil, result)
	if err != nil {
		return nil, err
	}
	if result.Error == nil && result.Names == nil {
		return nil, fmt.Errorf("sidecar api %s: %w: no names", socketListRoute, ErrSidecarApiReply)
	}
	return result, nil
}
