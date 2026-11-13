// The ur/ namespace on the engine (§9.4, D-SOCK-11, D-SOCK-12, C9; SOCK-M9-01): platform services listen as
// ur/<service> in urnetwork-edge, so a sidecar reaches smtpedge through the same Find and Service path as any socket,
// and the service, not §8, decides what may come through (§14.5).
//
// Registration. Only an urnetwork-edge client registers a ur/ name, in the clear and with no claim, since a platform
// client holds no identity key or Hello binding (SOCK.md reading 7), and only for a service PlatformServices names.
// A sidecar's ur/ entry, or an edge's for a service not named, is refused (denied, or revoked once it held a lease).
// No §8 check runs: urnetwork-edge holds no authorization log, and its view allows nothing (gate_projection.go).
//
// Find. Any enrolled sidecar may Find a ur/ name with no §8 check: the name resolves to urnetwork-edge across
// networks, the paying network is the caller's (§20.6), and §19.11's sockets gate and the fair queue take the
// caller's network too, since urnetwork-edge's rollout is not the caller's. An edge's Find of ur/ is denied: a pair
// has one edge end. A ticket's grant_expire_time_millis is its issue plus the service's GrantLifetime, 60 min unless
// the service names more (smtpedge's 125 min, QD-190), its policy_version 0 and its grant id empty, since nothing of
// §8 allowed it; the listener runs admission without step 6 (SocketPlatformListener).
//
// The pair (§6.10.1, QD-728). A ur/ Find writes field <edge listener client_id> of {svc_<sidecar dialer client_id>},
// keyed by its non-edge end like every pair, so CreateContract's one Redis read is field <edge> of {svc_<sidecar>}
// whichever end listens; the ticket is unchanged. It lives the grant's lifetime and is written again at each Find, never
// from the pair memo, at the position of the dialer's own network's state, whose log the key's other pairs and its
// floor are positions of: a floor that a removal of the sidecar's own edge pairs left refuses only a process behind it.
// The sidecar's removal ({X}c_removed) or revocation takes it with the sidecar's key; an edge's unlisten does not reach
// it, so it ends at its ttl. A registration's pair touch never shortens it (TouchServicePairs).
//
// Safe for concurrent use.

package socketsservice

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// The ur/ prefix a platform name starts with (§9.4): an identifier.
const socketPlatformPrefix = "ur/"

// One platform service's terms.
type SocketPlatformServiceSettings struct {
	// How long a ticket's grant runs past its issue, so how long a stream on it lives, and its {svc_} pair's ttl
	// (§9.6). Positive.
	GrantLifetime time.Duration
}

// The ur/ namespace's tunables (§9.4, §9.6, QD-190).
type SocketPlatformSettings struct {
	// The services a platform client may register, by the name after ur/: smtpedge's (§14). Any other is refused.
	Services map[string]*SocketPlatformServiceSettings
}

// §9.6's 60 minutes, and QD-190's 125 for smtpedge: two hours of DATA, plus 5 min for the ticket's 30 s, the pre-TLS
// exchange and SmtpOutcome.
func DefaultSocketPlatformSettings() *SocketPlatformSettings {
	return &SocketPlatformSettings{
		Services: map[string]*SocketPlatformServiceSettings{
			"smtpedge": {GrantLifetime: 125 * time.Minute},
		},
	}
}

// Whether the platform settings can serve. A refusal names the field.
func (self *SocketPlatformSettings) Validate() error {
	if self == nil {
		return fmt.Errorf("%w: no platform settings", ErrSocketsSettingsRefused)
	}
	for service, serviceSettings := range self.Services {
		if serviceSettings == nil || serviceSettings.GrantLifetime <= 0 {
			return fmt.Errorf("%w: platform.services.%s.grant_lifetime", ErrSocketsSettingsRefused, service)
		}
		if name, namespace, err := sidecar.ParseSocketName(socketPlatformPrefix + service); err != nil ||
			namespace != sidecar.SocketNamespacePlatform || name != socketPlatformPrefix+service {
			return fmt.Errorf("%w: platform.services: a service that is no ur/ name", ErrSocketsSettingsRefused)
		}
	}
	return nil
}

// The terms of the service a ur/ name names, false for none.
func (self *SocketPlatformSettings) service(name string) (*SocketPlatformServiceSettings, bool) {
	service, found := strings.CutPrefix(name, socketPlatformPrefix)
	if !found {
		return nil, false
	}
	serviceSettings := self.Services[service]
	return serviceSettings, serviceSettings != nil
}

// ur/'s hooks: the platform's own rules, since no other owner judges a platform name.
type socketPlatformNamespace struct {
	settings *SocketPlatformSettings
}

var _ SocketNamespaceHooks = (*socketPlatformNamespace)(nil)

// Opens ur/ on the engine with SocketsSettings.Platform's services, registered once. The sockets host calls this
// before serving.
func (self *SocketsService) RegisterPlatformNamespace() error {
	return self.RegisterNamespace(sidecar.SocketNamespacePlatform, &socketPlatformNamespace{settings: self.settings.Platform})
}

// See SocketNamespaceHooks: an urnetwork-edge client's entry for a named service, with no claim. The registration
// path lets only an edge's ur/ entry reach this, and passes no listen verdict.
func (self *socketPlatformNamespace) ValidateListen(ctx context.Context, check *SocketListenCheck) error {
	if check.Namespace != sidecar.SocketNamespacePlatform || check.Registration == nil || check.SidecarId != nil {
		return fmt.Errorf("%w: not a platform client's ur/ entry", ErrSocketListenRefused)
	}
	if _, found := self.settings.service(check.Name); !found {
		return fmt.Errorf("%w: no such platform service", ErrSocketListenRefused)
	}
	if 0 < len(check.Registration.Claim) {
		return fmt.Errorf("%w: a platform client signs no claim", ErrSocketListenRefused)
	}
	return nil
}

// See SocketNamespaceHooks: nothing follows a platform name's first listener.
func (self *socketPlatformNamespace) FirstListen(networkId connect.Id, name string) {}

// See SocketNamespaceHooks: nothing follows a platform name's last listener.
func (self *socketPlatformNamespace) LastUnlisten(networkId connect.Id, name string) {}

// The grant a ur/ ticket carries, issued at now: the service's lifetime past it, and no grant id, since nothing of §8
// allowed it. False for a service the settings do not name.
func (self *SocketsService) platformGrant(name *socketParsedName, now time.Time) (*socketTicketGrant, bool) {
	service, found := self.settings.Platform.service(name.name)
	if !found {
		return nil, false
	}
	issueMillis := uint64(max(now.UnixMilli(), 0))
	return &socketTicketGrant{grantExpireMillis: issueMillis + uint64(service.GrantLifetime.Milliseconds())}, true
}

// Step 8 for one listener of a ur/ Find (QD-728): field <edge listener> of {svc_<sidecar dialer>}, at position, the
// dialer's own network's, for the service's lifetime. nil when it stands, else the Find's refusal.
func (self *SocketsService) setPlatformPair(callerNetworkId connect.Id, position uint64, passed *socketTicketedListener, dialerClientId connect.Id, name *socketParsedName) *socketRefusal {
	service, found := self.settings.Platform.service(name.name)
	if !found {
		return socketRefusalOf(sidecar.SocketErrorCodeDenied, 0)
	}
	wrote, floor, err := func() (bool, uint64, error) {
		ctx, done := self.storeContext()
		defer done()
		testHookBarrier("sockets.find.pair.before", "")
		defer testHookBarrier("sockets.find.pair.after", "")
		return self.store.SetServicePair(ctx, dialerClientId, passed.listener.Candidate.ListenerClientId, passed.grant.grantExpireMillis, service.GrantLifetime, position)
	}()
	switch {
	case err != nil:
		return socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.MaxRetryAfter)
	case !wrote:
		// a removal of the dialer's pairs at a newer position of its own network's log: this process is behind there,
		// or the dialer's client was removed, whose floor is no position and refuses for good
		self.gate.Observe(callerNetworkId, floor)
		return socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.BehindRetryAfter)
	}
	return nil
}
