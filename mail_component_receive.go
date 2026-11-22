//go:build !sidecar_http && !js && !ios_extension

// The receiver the mail component starts over a Sidecar (MAIL-M7-17; §15.5): MailReceiver on Sidecar.Listen, the
// device's TLS key and POST /dns/key-record through the network's DnsClient, its sessions on mailcfg's Resolve and the
// mail routes, its reception-time checks and mail.strict's chain over a resolver of its own (mail_receiver_resolver.go;
// CODESTYLE's DoH rule: one owner, one cache), and its deposits through the network's EvsClient. Off the js leg, where
// mox's resolver does not build, so a js host runs no receiver; the component there reads mail and ingests it as any
// device does.
//
// The resolver is what MailReceiveSettings.ResolverFactory builds, else a DohCache over connect's default resolvers,
// public ones (§2.8 ext-3). In a test binary that default is refused before any part is built
// (ErrMailReceiverPublicResolver): testing.Testing reads true only in a binary go test linked, so production's
// receivers ask what they always have, while a test that would query public resolvers from the test host gets no
// receiver and fails, the e2e world's included, until it names its own DNS.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/urnetwork/connect"
)

// connect's own cache is what a receiver asks by default.
var _ MailReceiverDoh = (*connect.DohCache)(nil)

// The component builds its receivers here on the legs whose sessions build.
func init() {
	mailSidecarReceiverFactory = newMailSidecarReceiverFactory
}

// A receiver's lookups as its composition builds them, every one over the receiver's one resolver: the reception-time
// checks through their stub, mail.strict's chain where no zone watch holds it, and what releases the resolver once the
// receiver has ended. Safe for concurrent use.
type mailReceiverLookups struct {
	checker   *MailAuthChecker
	validator DnsWatchStrictValidator
	// URnetwork's own zones, beside the zone's root, which hold no customer-signed chain
	platformZones []string
	clock         Clock
	close         func()
}

// The resolver a receiver on settings asks: settings' ResolverFactory's, else a DohCache of the receiver's own over
// connect's default resolvers. inTest, a test binary's, refuses that default with ErrMailReceiverPublicResolver before
// anything is built. A factory's error comes back as it was given, and a resolver without its Doh is refused, released
// first.
func newMailReceiverResolver(settings *MailReceiveSettings, inTest bool) (*MailReceiverResolver, error) {
	if settings.ResolverFactory != nil {
		resolver, err := settings.ResolverFactory()
		if err != nil {
			return nil, err
		}
		if resolver == nil || resolver.Doh == nil {
			if resolver != nil && resolver.Close != nil {
				resolver.Close()
			}
			return nil, fmt.Errorf("%w: a resolver with no Doh", ErrMailReceiverInvalid)
		}
		return resolver, nil
	}
	if inTest {
		return nil, ErrMailReceiverPublicResolver
	}
	cache := connect.NewDohCache(connect.DefaultDohSettings())
	return &MailReceiverResolver{Doh: cache, Close: cache.Close}, nil
}

// A receiver's lookups on settings over newMailReceiverResolver's resolver, their time on clock, real time when nil.
func newMailReceiverLookups(settings *MailReceiveSettings, clock Clock, inTest bool) (*mailReceiverLookups, error) {
	resolver, err := newMailReceiverResolver(settings, inTest)
	if err != nil {
		return nil, err
	}
	clock = clockOrReal(clock)
	stub := NewMailDnsStub(resolver.Doh, clock, settings.Auth)
	return &mailReceiverLookups{
		checker:       NewMailAuthChecker(stub, clock, settings.Auth),
		validator:     NewDnsWatchStrictValidator(resolver.Doh, resolver.Anchors, nil),
		platformZones: DefaultDnsWatchSettings().UrnetworkZones,
		clock:         clock,
		close: func() {
			if resolver.Close != nil {
				resolver.Close()
			}
		},
	}, nil
}

// mail.strict's chain where no zone watch holds it, for the zone's root as it stands now: true only when the
// resolver's DNSSEC-OK answers validate to its anchors for every MX host of every recipient domain and for the SNI
// host's TLSA with this key, in zones outside URnetwork's (dnsWatchStrictChain).
func (self *mailReceiverLookups) strictChain(ctx context.Context, root string, sniHost string, recipientDomains []string, spkiSha256 []byte) bool {
	return dnsWatchStrictChain(ctx, self.validator, self.platformZones, root, self.clock, sniHost, recipientDomains, spkiSha256)
}

// A receiver factory over sidecar.
func newMailSidecarReceiverFactory(sidecar *Sidecar) mailReceiverFactory {
	return func(args *mailReceiverFactoryArgs) (*MailReceiver, func(), error) {
		receive := args.Settings
		if args.Evs == nil || args.Config == nil || args.Api == nil || receive == nil {
			return nil, nil, errors.New("a receiver needs the network's evs, mailcfg and api")
		}
		identity := sidecar.Identity()
		if identity == nil {
			return nil, nil, ErrSidecarNoIdentity
		}
		dns, err := sidecar.Dns()
		if err != nil {
			return nil, nil, err
		}
		// the one guarded resolver every lookup of this receiver asks, which a test binary must name
		lookups, err := newMailReceiverLookups(receive, args.Clock, testing.Testing())
		if err != nil {
			return nil, nil, err
		}
		closeParts := lookups.close
		depositor, err := NewMailDepositor(&MailDepositorArgs{
			Repo:              args.Evs.Repo,
			ReceiverSidecarId: identity.SidecarId,
			Log:               args.Log,
			Settings:          receive.Session,
		})
		if err != nil {
			closeParts()
			return nil, nil, err
		}
		config := args.Config
		root := func() string {
			zone, _, _ := config.zone()
			return zone.Root
		}
		strict := NewMailStrictPolicy(&MailStrictPolicyArgs{
			Strict: func() bool {
				state, err := sidecar.configState()
				if err != nil {
					return false
				}
				settings, known := state.HeadSettings()
				return known && MailStrictSetting(settings)
			},
			Root: root,
			Chain: func(ctx context.Context, sniHost string, recipientDomains []string, spkiSha256 []byte) bool {
				if watch := sidecar.mailDnsWatch(); watch != nil && watch.strict != nil {
					return watch.StrictChain(ctx, sniHost, recipientDomains, spkiSha256)
				}
				return lookups.strictChain(ctx, root(), sniHost, recipientDomains, spkiSha256)
			},
		})
		sessions, err := NewMailSessionServer(&MailSessionArgs{
			ReceiverSidecarId: identity.SidecarId,
			mailConfig:        config,
			// a bare RCPT TO:<Postmaster> with no SNI: this network receiver's own zone, <label>.<root>, under the root
			// Resolve parses with, from GET /dns/zone as the certificate's names are (owner decision 446)
			PostmasterDomain: func(ctx context.Context) (string, error) {
				zone, err := dns.Zone(ctx)
				if err != nil {
					return "", err
				}
				if zone.Label == "" {
					return "", nil
				}
				return MailZone{Root: canonicalNetworkLabelRoot(zone.Root), Net: zone.Label}.Domain(), nil
			},
			Status:      args.Api.MailStatus,
			Limits:      args.Api.Limits,
			Checker:     lookups.checker,
			Slots:       NewMailAuthSlots(receive.Auth),
			Depositor:   depositor,
			SpoolStore:  args.Store,
			StrictChain: strict.StrictChain,
			Clock:       args.Clock,
			Log:         args.Log,
			Settings:    receive.Session,
		})
		if err != nil {
			closeParts()
			return nil, nil, err
		}
		networkId := identity.NetworkId
		receiver, err := NewMailReceiver(&MailReceiverArgs{
			Host: "mx",
			Listen: func(ctx context.Context, address string, settings *SocketListenSettings) (MailReceiverListener, error) {
				listener, err := sidecar.Listen(ctx, address, settings)
				if err != nil {
					return nil, err
				}
				return listener, nil
			},
			Keys:      sidecar.MailReceiverKeys(),
			Publisher: newMailReceiverDnsPublisher(dns, sidecar.Sign, networkId, identity.SidecarId, args.Clock),
			Names: func(ctx context.Context) ([]string, error) {
				return mailReceiverZoneNames(ctx, dns)
			},
			Store: args.Store,
			Watch: func(host string, spkiSha256 []byte) {
				if watch := sidecar.mailDnsWatch(); watch != nil {
					if err := watch.WatchMailHost(host, spkiSha256); err != nil {
						args.Log.Warningf("[mail]the zone watch did not take the mail host: %v", err)
					}
				}
			},
			Serve: sessions.Serve,
			Admit: func(ctx context.Context, metadata []byte, spkiSha256 []byte) bool {
				return strict.AdmitMetadata(ctx, metadata, receive.Session.IngressMaxByteCount, spkiSha256)
			},
			TlsSettings: sidecar.settings.Tls,
			Clock:       args.Clock,
			Log:         args.Log,
			Settings:    receive.Receiver,
		})
		if err != nil {
			closeParts()
			return nil, nil, err
		}
		if args.DirectMxEligible != nil {
			receiver.runDirect = func(ctx context.Context) {
				// A receiver can start before its zone arrives. Its public greeting uses the assigned MX name.
				var zone MailZone
				var err error
				for {
					zone, _, err = config.zone()
					if err == nil {
						break
					}
					select {
					case <-ctx.Done():
						return
					case <-sessions.clock.After(sessions.settings.StatusInterval):
					}
				}
				direct, err := NewMailDirectListener(&MailDirectListenerArgs{
					Receiver: receiver, Sessions: sessions, HostName: "mx." + zone.Domain(),
					Clock: args.Clock, Log: args.Log, Settings: receive.Direct,
				})
				if err != nil {
					sessions.log.Warningf("[mail]direct MX listener settings: %v", err)
					return
				}
				direct.runAssigned(ctx, sessions.settings.StatusInterval, func(ctx context.Context) []netip.Addr {
					if !args.DirectMxEligible() {
						return nil
					}
					status, err := sessions.networkStatus(ctx)
					if err != nil || !status.Enabled {
						return nil
					}
					return status.DirectMxAddresses
				}, (&net.ListenConfig{}).Listen)
			}
		}
		return receiver, closeParts, nil
	}
}
