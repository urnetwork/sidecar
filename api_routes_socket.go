//go:build !sidecar_http

// §9's routes at the sockets service that this sidecar calls with its own client token (§9.15; Client class, on §7.4's
// strict_exp allowlist, plan-SOCK-client-auth): POST /socket/registrations, which the registrar alone calls
// (socket_registrar.go). They carry §9's route bodies, which name connect.Id, so they stay off the sidecar_http leg,
// which registers nothing (§18.10). Find has its own client, SOCK-M5-12's.
//
// A page's refusal is a 200 whose body holds error, which this hands back as it came for the registrar to act on; an
// answer of another status is a *SidecarApiError, with any retry_after_ms or Retry-After the service gave. Nothing
// here logs or wraps a name: a body is the route's own business (I-13).

package sidecar

import (
	"context"
	"fmt"
)

// The route as errors name it.
const socketRegistrationsRoute = "POST /socket/registrations"

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
