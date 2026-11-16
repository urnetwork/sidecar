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
		root := args.Root
		config := args.Config
		strict := NewMailStrictPolicy(&MailStrictPolicyArgs{
			Strict: func() bool {
				state, err := sidecar.configState()
				if err != nil {
					return false
				}
				settings, known := state.HeadSettings()
				return known && MailStrictSetting(settings)
			},
			Root: func() string { return root },
			Chain: func(ctx context.Context, sniHost string, recipientDomains []string, spkiSha256 []byte) bool {
				watch := sidecar.mailDnsWatch()
				return watch != nil && watch.StrictChain(ctx, sniHost, recipientDomains, spkiSha256)
			},
		})
		sessions, err := NewMailSessionServer(&MailSessionArgs{
			ReceiverSidecarId: identity.SidecarId,
			Resolve: func(ctx context.Context, address string) (*MailSessionRecipient, error) {
				recipient, err := ParseMailRecipient(root, address)
				if err != nil {
					// no form of §15.8's under the root: unknown, as an unknown address is (550 5.1.1)
					return &MailSessionRecipient{}, nil
				}
				lookup, err := config.Resolve(ctx, recipient)
				if err != nil {
					return nil, err
				}
				return &MailSessionRecipient{Known: lookup.Known, Address: recipient.Address(), RepoId: lookup.MailboxRepoId}, nil
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
		return receiver, closeParts, nil
	}
}
