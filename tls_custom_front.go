//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"
)

// The owner of a live challenge retains the exact ephemeral leaf for its public route probe.
type tlsDesktopChallenge struct {
	front            *TlsFront
	keyAuthorization string
	leaf             []byte
}

type sidecarTlsCustomAlpn struct {
	sidecar   *Sidecar
	stateLock sync.Mutex
	claims    map[string]*tlsDesktopChallenge
}

// The still-open 443 publish for an owner's exact custom host.
func (self *sidecarTlsCustomAlpn) front(host, owner string) *TlsFront {
	component := self.sidecar.tlsComponent()
	if component == nil || component.publisher == nil {
		return nil
	}
	publisher := component.publisher
	publisher.stateLock.Lock()
	defer publisher.stateLock.Unlock()
	publish := publisher.publishes["tls/443/"+owner]
	if publish == nil {
		return nil
	}
	endpoint, ok := publish.endpoint.(*sidecarTlsPublishEndpoint)
	if !ok || endpoint.front.customEntry(host) == nil {
		return nil
	}
	return endpoint.front
}

func (self *sidecarTlsCustomAlpn) CanServe(ctx context.Context, host, owner string) bool {
	return self.readyFront(ctx, host, owner) != nil
}

func (self *sidecarTlsCustomAlpn) readyFront(ctx context.Context, host, owner string) *TlsFront {
	front := self.front(host, owner)
	if front == nil {
		return nil
	}
	client, err := self.sidecar.Dns()
	if err != nil {
		return nil
	}
	zone, err := client.fetchZone(ctx)
	if err != nil || !tlsCustomHostReady(zone, host, owner) {
		return nil
	}
	return front
}

// A ready mapping from the device's own zone view. A pending load-balancer map cannot validate ALPN.
func tlsCustomHostReady(zone *DnsZone, host, owner string) bool {
	for _, mapping := range zone.CustomHosts {
		if mapping.Host == host && mapping.Owner == owner+"."+zone.Apex() &&
			mapping.State == DnsCustomHostStateActive && mapping.Ready {
			return true
		}
	}
	return false
}

// The desktop challenges on its own published 443 endpoint for this owner.
func (self *sidecarTlsCustomAlpn) Serve(ctx context.Context, host, owner, keyAuthorization string, expireTime time.Time, claimSeq uint64) error {
	front := self.readyFront(ctx, host, owner)
	if front == nil {
		return ErrTlsPublishAbsent
	}
	socket, ok := front.listener.(*SocketListener)
	if !ok {
		return ErrTlsPublishAbsent
	}
	if err := front.SetCustomAlpnChallenge(host, keyAuthorization, expireTime, claimSeq); err != nil {
		return err
	}
	certificate := front.responder.certificate(host, front.clock.Now())
	if certificate == nil || len(certificate.Certificate) != 1 {
		front.ClearAlpnChallenge(host)
		return ErrTlsPublishUnavailable
	}
	waitCtx, cancel := context.WithCancel(ctx)
	stop := front.clock.AfterFunc(expireTime.Sub(front.clock.Now()), cancel)
	defer stop()
	defer cancel()
	if err := socket.awaitAcmeClaim(waitCtx, host, claimSeq); err != nil {
		front.ClearAlpnChallenge(host)
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.claims[host] = &tlsDesktopChallenge{front: front, keyAuthorization: keyAuthorization, leaf: bytes.Clone(certificate.Certificate[0])}
	return nil
}

func (self *sidecarTlsCustomAlpn) Clear(host string) {
	claim := func() *tlsDesktopChallenge {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		claim := self.claims[host]
		delete(self.claims, host)
		return claim
	}()
	if claim != nil {
		claim.front.ClearAlpnChallenge(host)
	}
}

func (self *tlsDesktopChallenge) verifyPeer(state tls.ConnectionState) error {
	if state.NegotiatedProtocol != tlsAlpnAcme || len(state.PeerCertificates) != 1 || !bytes.Equal(state.PeerCertificates[0].Raw, self.leaf) {
		return errors.New("the public endpoint did not return this ACME challenge")
	}
	return nil
}

// RFC 8737 uses a self-signed challenge leaf. The probe authenticates the exact DER generated for this
// claim and the negotiated protocol before allowing the ACME acknowledgement.
func (self *sidecarTlsCustomAlpn) Probe(ctx context.Context, host, keyAuthorization string, timeout time.Duration) error {
	claim := func() *tlsDesktopChallenge {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.claims[host]
	}()
	if claim == nil || claim.keyAuthorization != keyAuthorization {
		return ErrTlsPublishUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := &tls.Dialer{Config: &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         host,
		NextProtos:         []string{tlsAlpnAcme},
		InsecureSkipVerify: true, // the locally generated, single-use leaf is pinned in VerifyConnection
		VerifyConnection:   claim.verifyPeer,
	}}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return err
	}
	return conn.Close()
}

// Called with the registrar lock held.
func (self *socketRegistrarEntry) wakeAcme() {
	if self.acmeChanged != nil {
		close(self.acmeChanged)
		self.acmeChanged = nil
	}
}

func (self *SocketListener) awaitAcmeClaim(ctx context.Context, host string, claimSeq uint64) error {
	registrar := self.component.registrar
	for {
		seen, changed, err := func() (bool, <-chan struct{}, error) {
			registrar.stateLock.Lock()
			defer registrar.stateLock.Unlock()
			entry := registrar.state.entries[self.listenId]
			if entry == nil {
				return false, nil, ErrTlsPublishAbsent
			}
			if registrar.state.attached && entry.acmeAttachment == registrar.state.attachmentSeq {
				for _, claim := range entry.acknowledgedAcme {
					if claim != nil && claim.Name == host && claim.ClaimSeq == claimSeq {
						return true, nil, nil
					}
				}
			}
			if entry.acmeChanged == nil {
				entry.acmeChanged = make(chan struct{})
			}
			return false, entry.acmeChanged, nil
		}()
		if err != nil || seen {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-self.closed:
			return ErrTlsPublishAbsent
		case <-changed:
		}
	}
}
