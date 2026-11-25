//go:build !sidecar_http && !ios_extension

// A listen's grant-backed action for a caller beside the socket component (§16.6's grant row, §9.10; QD-772, QD-740):
// MCP's socket_listen, which names an application name's socket by its token path under the network's current K_sock.
// It is Sidecar.Listen's tls/ and smtp/ action (socket_listen.go) for a grant_dst its caller gives, under
// acl_grant_keep.go's rows:
//
//	rule      AclGrantFiler.Action fills the grant's fields from the requests rule that takes the listen: this
//	          sidecar as subject, the socket as the grant_dst given, listen allowed, and the rule's id and expiry,
//	          the end the caller asks (ExpiresAt) or else the rule's expiresDefault from now; its effect is the grant
//	          component's, which a spendable decision runs into the GrantActivate the approval fixes, done with its
//	          grant_id, which the listen kind's Lookup finds again after a restart
//	expires   MatchAclRequest holds the end asked to the rule's maxExpiry (owner decision 687), so a listen asking past
//	          it, which no standing grant passes, is refused before the gate, filing nothing, its error naming the
//	          maximum (AclGrantMaxExpiryError), as Sidecar.Listen's Expires is refused; a standing grant asks nothing
//	          and passes it whatever it asks
//	kept      the caller's GrantActionKeeper keeps each such action as its request was filed until its expiry, and
//	          gives it up once the grant its decision activated has ended, so the listen asked again after a person
//	          approves presents the bytes the decision names; the caller keys it by the end asked as well, so a listen
//	          asking another end files its own request rather than presenting one filed for another
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
	"slices"
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
	// When the grant the listen asks ends, held to the requests rule's maxExpiry (the file header's expires row; owner
	// decision 687). An end rather than a time from now, as MCP's tools name one, so the call made again asks the same
	// end. Zero takes the rule's expiresDefault; one not after now is refused.
	ExpiresAt time.Time
}

// A grant asked past the requests rule's maxExpiry (MatchAclRequest's bound; owner decision 687): the rule that takes
// it, asked for no expiry, lets a grant run MaxExpiry at most, which a refusal names so its caller can ask a shorter
// one, as tls_publish's --expires and Sidecar.Listen's Expires are refused. A refusal carries it beside its own error,
// ErrAclGrantFile's or ErrSocketDenied's.
type AclGrantMaxExpiryError struct {
	MaxExpiry time.Duration
}

// See error.
func (self *AclGrantMaxExpiryError) Error() string {
	return fmt.Sprintf("the expiry asked is past the requests rule's maxExpiry, %v", self.MaxExpiry)
}

// The longest the requests rule that takes request, asked for no expiry, lets its grant run, where request's expiry is
// past it (MatchAclRequest's bound), so the refusal can name it; false where request asks no expiry, no requests rule
// takes it at all, or its expiry is within that rule's longest, it being refused for another reason. base and request
// as AclGrantFiler.Action takes them.
func aclGrantPastMaxExpiry(ctx context.Context, grants *AclGrantFiler, base *protocol.CanonicalAction, request *AclGrantRequest, now time.Time) (*AclGrantMaxExpiryError, bool) {
	if grants == nil || grants.engine == nil || request == nil || request.ExpiresMs == 0 {
		return nil, false
	}
	atDefault := *request
	atDefault.ExpiresMs = 0
	stored, err := grants.Action(ctx, base, &atDefault, now)
	state := grants.engine.State()
	if err != nil || state == nil {
		return nil, false
	}
	requests := state.Rows().GetRequests()
	index := slices.IndexFunc(requests, func(rule *protocol.AclRequestRule) bool {
		return slices.Equal(rule.GetRuleId(), stored.Action.GetRuleId())
	})
	if index < 0 {
		return nil, false
	}
	nowMs := now.UnixMilli()
	_, maxMs := aclRequestGrantEnd(requests[index], 0, nowMs)
	if request.ExpiresMs <= nowMs+maxMs {
		return nil, false
	}
	return &AclGrantMaxExpiryError{MaxExpiry: time.Duration(maxMs) * time.Millisecond}, true
}

// The §5.4 action a listen of args' goes through Authorize as, and its effect (the file header): kind listen with the
// grant's fields, filled from the requests rule that takes it and kept by keeper under key, under the grant
// component's effect, which waits for its grant in args' Config and names it under a standing pass; or, where no
// requests rule takes it, naming no rule and no expiry, under the standing effect, while a standing grant covers it.
// ErrAclGrantFile where neither does, filing nothing, and with no filer or no installed state to judge it on; beside it
// an *AclGrantMaxExpiryError where a requests rule takes the listen for no longer than args' ExpiresAt asks. keeper
// nil keeps none, and key is the caller's, which names the end asked where args ask one. The caller binds the action
// to its run and sets the request's detail beside it.
func SocketListenGrantAction[K comparable](ctx context.Context, args *SocketListenGrantArgs, keeper *GrantActionKeeper[K], key K, now time.Time) (*StoredCanonicalAction, SidecarEffect, error) {
	if args == nil || args.Grants == nil || args.Grants.engine == nil || args.Grants.engine.State() == nil {
		return nil, nil, fmt.Errorf("%w: no state installed", ErrAclGrantFile)
	}
	if !args.ExpiresAt.IsZero() && !args.ExpiresAt.After(now) {
		return nil, nil, fmt.Errorf("%w: an expiry that is not ahead", ErrAclGrantFile)
	}
	grants := args.Grants
	base := &protocol.CanonicalAction{Kind: uint32(SidecarActionListen)}
	request := &AclGrantRequest{Subject: args.Subject, GrantDst: []string{args.GrantDst}, GrantAllow: []string{socketListenGrantAllow}}
	if !args.ExpiresAt.IsZero() {
		// an absolute expiry, which the match holds to the rule's maxExpiry
		request.ExpiresMs = args.ExpiresAt.UnixMilli()
	}
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
		if maxExpiry, past := aclGrantPastMaxExpiry(ctx, grants, base, request, now); past {
			// a requests rule takes the listen, for no longer than its maximum: the caller can ask a nearer end
			return nil, nil, fmt.Errorf("%w: %w", err, maxExpiry)
		}
		return nil, nil, err
	}
	return standing, aclStandingGrantEffect{}, nil
}
