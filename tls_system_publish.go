//go:build !sidecar_http && !ios_extension

// §13.9's system publish on the receiver (TLS-M8-02; R-TLS-5, D-TLS-9, D-MAIL-4, I-8): a mail receiver serves its
// network's MTA-STS policy (RFC 8461 §3.2, https://mta-sts.<net>.<root>/.well-known/mta-sts.txt) as tls/443/mta-sts,
// audience public and app mode http, with no tls/ grant, approval or expiry of its own. Its approved smtp/25/mx listen
// grant stands in for the name's grants at registration, Find and admission (SOCK-M8-01, socket_admission.go), and its
// end ends the publish. The receiver's mail component answers each request in place of a local port, and the
// Community notice never shows (§13.7's interstitial row).
//
// ServeTlsSystemPublish composes it, in order: the endpoint's server names, mta-sts under the network's label and each
// live alias; the network's certificate on this device's key, which names *.<net>.<root> and so covers the host,
// ensured first as §13.10's step 3 does; the registration through ListenSystemPublish, which no other caller reaches;
// and §13.7's front on it with the handler as its target. The front's dispatch and audience check run as on any
// endpoint, its grant the receiver's own listen read from this device's config (tlsPublishGrantOf), so a revoked
// smtp/ grant fails the next handshake while the sockets service ends the lease.
//
// No other name takes this path: ListenTls and ur bridge public-tls refuse mta-sts, and the front takes a handler for
// the system publish alone (newTlsFrontTarget). MAIL-M8-08's receiver calls this with its policy handler; nothing
// else does. connect legs only. Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
)

// The system publish's host, the last segment of tlsSystemPublishName.
const tlsSystemPublishHost = "mta-sts"

// What ServeTlsSystemPublish takes beyond the handler.
type TlsSystemPublishSettings struct {
	// The registration's share, 1 to 1000. 0 takes 100 (§9.5).
	Weight int
	// §13.7's limits on the endpoint. Nil takes DefaultTlsFrontSettings. Its target probe is off whatever it says,
	// since a handler in this process always answers.
	Front *TlsFrontSettings
}

// One receiver's system publish: §13.7's front on its tls/443/mta-sts registration.
type TlsSystemPublish struct {
	front *TlsFront
}

// Ends the publish: the front, its connections and the registration, which unlistens.
func (self *TlsSystemPublish) Close() error {
	return self.front.Close()
}

// Serves the network's MTA-STS policy through handler as this receiver's system publish (§13.9): see the file header.
// The sockets service admits the registration only for a receiver with an approved smtp/25/mx listen grant, an
// unexpired certificate row for the network's pair, network_verified and a mail_network row (ValidateListen), so a
// caller that is none of these registers nothing that serves. ErrTlsComponentAbsent on a Sidecar that runs no tls
// component.
func (self *Sidecar) ServeTlsSystemPublish(ctx context.Context, handler http.Handler, settings *TlsSystemPublishSettings) (*TlsSystemPublish, error) {
	component := self.tlsComponent()
	if component == nil {
		return nil, ErrTlsComponentAbsent
	}
	networkId := self.enrolledNetworkId()
	identity := self.currentIdentity()
	if networkId == nil || identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	_, secrets, err := self.tlsDevice()
	if err != nil {
		return nil, err
	}
	sidecarId := identity.SidecarId
	return component.serveSystemPublish(ctx, handler, settings, &tlsListenParts{
		NetworkId: *networkId,
		SidecarId: sidecarId,
		Register: func(ctx context.Context, address string, listenSettings *SocketListenSettings) (tlsListenRegistration, error) {
			// the one way to the name: the receiver's own listen grant, with no approval of the publish's own
			listener, err := self.ListenSystemPublish(ctx, listenSettings)
			if err != nil {
				return nil, err
			}
			return listener, nil
		},
		Policy: NewTlsFrontConfigPolicy(sidecarId, func() *ConfigState {
			state, err := self.configState()
			if err != nil {
				return nil
			}
			return state
		}),
		Secrets:   secrets,
		IssuerUrl: self.settings.AuthUrl,
		Clock:     self.clock,
		Log:       self.log,
	})
}

// The system publish on this component, through parts: its names, the network's certificate, then the registration,
// then the front with handler as its target. Nothing registers without the certificate, and nothing is ordered for a
// caller with no handler.
func (self *TlsComponent) serveSystemPublish(ctx context.Context, handler http.Handler, settings *TlsSystemPublishSettings, parts *tlsListenParts) (*TlsSystemPublish, error) {
	if handler == nil {
		return nil, fmt.Errorf("%w: the system publish needs its component's handler", ErrTlsListenInvalid)
	}
	if settings == nil {
		settings = &TlsSystemPublishSettings{}
	}
	names, err := self.names(ctx)
	if err != nil {
		return nil, err
	}
	serverNames, err := tlsPublishServerNames(tlsSystemPublishHost, names)
	if err != nil {
		return nil, err
	}
	if _, err := self.manager.EnsureTlsCertificate(ctx); err != nil {
		return nil, err
	}
	target := &TlsFrontTarget{
		Name:          tlsSystemPublishName,
		ServerNames:   serverNames,
		AppMode:       socketListenDefaultTlsAppMode,
		SystemPublish: true,
		Handler:       handler,
	}
	listenSettings := TlsFrontListenSettings(target, false)
	listenSettings.Weight = settings.Weight
	registration, err := parts.Register(ctx, tlsSystemPublishName, listenSettings)
	if err != nil {
		return nil, err
	}
	frontSettings := DefaultTlsFrontSettings()
	if settings.Front != nil {
		copied := *settings.Front
		frontSettings = &copied
	}
	frontSettings.TargetProbeInterval = 0
	front, err := NewTlsFront(self.ctx, &TlsFrontArgs{
		Settings:  frontSettings,
		Target:    target,
		Listener:  registration,
		NetworkId: parts.NetworkId,
		SidecarId: parts.SidecarId,
		Policy:    parts.Policy,
		Certificate: func(serverName string) (*tls.Certificate, error) {
			// an issued certificate alone: a sending MTA never meets the self-signed leaf
			return self.manager.PublishCertificate([]string{serverName})
		},
		Secrets:   parts.Secrets,
		IssuerUrl: parts.IssuerUrl,
		Limits:    self.limits,
		Clock:     parts.Clock,
		Log:       parts.Log,
	})
	if err != nil {
		registration.Close()
		return nil, err
	}
	// the front runs on the component's context, so the component's Close ends it with its registration
	return &TlsSystemPublish{front: front}, nil
}
