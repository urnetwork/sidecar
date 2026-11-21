//go:build !sidecar_http && !js && !ios_extension

// The receiver the mail component starts over a Sidecar (MAIL-M7-17; §15.5): MailReceiver on Sidecar.Listen, the
// device's TLS key and POST /dns/key-record through the network's DnsClient, its sessions on mailcfg's Resolve and the
// mail routes, its reception-time checks over a DohCache of its own (CODESTYLE's DoH rule: one owner, one cache), and
// its deposits through the network's EvsClient. Off the js leg, where mox's resolver does not build, so a js host runs
// no receiver; the component there reads mail and ingests it as any device does.

package sidecar

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/urnetwork/connect"
)

// The component builds its receivers here on the legs whose sessions build.
func init() {
	mailSidecarReceiverFactory = newMailSidecarReceiverFactory
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
		dohCache := connect.NewDohCache(connect.DefaultDohSettings())
		closeParts := func() {
			dohCache.Close()
		}
		stub := NewMailDnsStub(dohCache, args.Clock, receive.Auth)
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
		validator := NewDnsWatchStrictValidator(dohCache, nil, nil)
		platformZones := DefaultDnsWatchSettings().UrnetworkZones
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
				return dnsWatchStrictChain(ctx, validator, platformZones, root(), args.Clock, sniHost, recipientDomains, spkiSha256)
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
			Checker:     NewMailAuthChecker(stub, args.Clock, receive.Auth),
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
