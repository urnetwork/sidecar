//go:build !sidecar_http && !ios_extension

// A listen's grant-backed action for a caller beside the socket component (§16.6's grant row, §9.10; QD-772, QD-740):
// MCP's socket_listen, which names an application name's socket by its token path under the network's current K_sock.
// It is Sidecar.Listen's tls/ and smtp/ action (socket_listen.go) for a grant_dst its caller gives, under
// acl_grant_keep.go's rows:
//
//	rule      AclGrantFiler.Action fills the grant's fields from the requests rule that takes the listen: this
//	          sidecar as subject, the socket as the grant_dst given, listen allowed, and the rule's id and expiry; its
//	          effect is the grant component's, which a spendable decision runs into the GrantActivate the approval
//	          fixes, done with its grant_id, which the listen kind's Lookup finds again after a restart
//	kept      the caller's GrantActionKeeper keeps each such action as its request was filed until its expiry, and
//	          gives it up once the grant its decision activated has ended, so the listen asked again after a person
//	          approves presents the bytes the decision names
//	landed    that use is done only once this device's engine holds the grant, waited on in the caller's config
//	          within the sidecar's Sockets.ListenGrantLandTimeout, so the caller registers on a grant the log holds
//	          where the sockets service's gate reads it, rather than being refused by the service; a grant the engine
//	          does not hold by then leaves the use uncertain, which the listen asked again completes
//	named     the listen asked again once the engine holds that grant passes the gate as standing under it, and its
//	          effect answers that grant there, so the caller names it as it names one a use activated
//	standing  a listen no requests rule takes names no rule and no expiry: a standing grant alone passes it, under
//	          the standing effect, and with none it is refused before the gate, filing nothing
//
// The listen kind's Lookup is the stock socket component's, which its host registers while it lives (socket_listen.go's
// listenLookup): it answers for a use of this action as for one of Sidecar.Listen's. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// What a listen beside the socket component asks its grant with (SocketListenGrantAction).
type SocketListenGrantArgs struct {
	// The filer over the engine the gate reads its standing grants from.
	Grants *AclGrantFiler
	// This sidecar, the grant's subject.
	Subject Id
	// The socket as SocketListenGrantDst names it: sock:<name> for a tls/ or smtp/ name, an application name's token
	// path under the network's current K_sock.
	GrantDst string
	// What the request binds beside the action, and the run and agent a decision binds, by which a kept action's
	// spent decision is found (AclGrantFiler.priorGrant).
	Detail  *SidecarActionDetail
	RunId   *Id
	AgentId *Id
	// The network's verified config, which a grant the listen's approval activates is waited on in before the listen
	// registers (the file header's landed row): the ConfigClient whose follower installs each state in Grants' engine.
	// nil waits on nothing, so a grant the engine does not hold as its post answers leaves the use uncertain.
	Config AclGrantConfig
}

// The §5.4 action a listen of args' goes through Authorize as, and its effect (the file header): kind listen with the
// grant's fields, filled from the requests rule that takes it and kept by keeper under key, under the grant
// component's effect, which waits for its grant in args' Config and names it under a standing pass; or, where no
// requests rule takes it, naming no rule and no expiry, under the standing effect, while a standing grant covers it.
// ErrAclGrantFile where neither does, filing nothing, and with no filer or no installed state to judge it on. keeper
// nil keeps none. The caller binds the action to its run and sets the request's detail beside it.
func SocketListenGrantAction[K comparable](ctx context.Context, args *SocketListenGrantArgs, keeper *GrantActionKeeper[K], key K, now time.Time) (*StoredCanonicalAction, SidecarEffect, error) {
	if args == nil || args.Grants == nil || args.Grants.engine == nil || args.Grants.engine.State() == nil {
		return nil, nil, fmt.Errorf("%w: no state installed", ErrAclGrantFile)
	}
	grants := args.Grants
	base := &protocol.CanonicalAction{Kind: uint32(SidecarActionListen)}
	request := &AclGrantRequest{Subject: args.Subject, GrantDst: []string{args.GrantDst}, GrantAllow: []string{socketListenGrantAllow}}
	stored, err := grants.Action(ctx, base, request, now)
	switch {
	case err == nil:
		if keeper != nil {
			stored = keeper.Keep(key, stored, now, func(kept *StoredCanonicalAction) bool {
				return grants.grantEnded(kept, args.Detail, args.RunId, args.AgentId, now)
			})
		}
		// the filer's sidecar's wait, else the defaults' where it has none
		landTimeout := func() time.Duration {
			if grants.sidecar != nil && grants.sidecar.settings != nil && grants.sidecar.settings.Sockets != nil {
				return grants.sidecar.settings.Sockets.ListenGrantLandTimeout
			}
			return DefaultSidecarSocketSettings().ListenGrantLandTimeout
		}()
		return stored, grants.keptEffect(stored, args.Detail, args.RunId, args.AgentId, args.Config, landTimeout), nil
	case !errors.Is(err, ErrAclRequestNoMatch):
		return nil, nil, err
	}
	// no requests rule takes it, so no decision could activate its grant: a standing grant alone passes it, and with
	// none nothing is filed
	standing, buildErr := aclStandingGrantAction(base, request)
	if buildErr != nil {
		return nil, nil, buildErr
	}
	if !grants.engine.ActiveGrant(standing, args.Subject, now) {
		return nil, nil, err
	}
	return standing, aclStandingGrantEffect{}, nil
}
