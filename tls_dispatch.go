//go:build !sidecar_http && !ios_extension

// §13.7's dispatch (D-TLS-13, D-TLS-5, R-TLS-7): each handshake routes by the signed registration's AppMode, read
// from the endpoint's target, and the grant this device's own evaluation holds for the endpoint, never by ALPN's
// absence. ALPN negotiates a protocol, not an audience (RFC 7301), so it only picks among what the mode serves:
//
//	acme-tls/1 offered        the TLS-ALPN-01 responder alone, whatever else the hello offers (RFC 8737)
//	http                      h2 or http/1.1, server's order; none reaches the HTTP front too, as HTTP/1.1;
//	                          any other id fails the handshake with no_application_protocol (RFC 7301 §3.2)
//	raw                       one of the declared ids, or none; any other id fails as http's do. Only under a
//	                          public grant, or a link grant with its pin, over TLS 1.3 with a client certificate
//	                          whose SPKI SHA-256 is the pin (§8.4), so the certificate never crosses in the clear
//
// A grant that is missing, names another app mode, or names raw outside public and link refuses the handshake, as
// ValidateListen would have refused the registration (§13.9). The decision is made in GetConfigForClient, where the
// hello is known, and the config it answers pins ALPN to that decision, so crypto/tls negotiates nothing else.
//
// Versions are TLS 1.2 and 1.3, X25519MLKEM768 first. Nothing here logs (I-13). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

// ALPN ids (RFC 7301's registry; RFC 8737's acme-tls/1).
const (
	tlsAlpnH2     = "h2"
	tlsAlpnHttp11 = "http/1.1"
	tlsAlpnAcme   = "acme-tls/1"
	// What NextProtos holds to refuse every offered id: no hello carries an empty id (RFC 7301 §3.1), so crypto/tls
	// finds no overlap and answers no_application_protocol.
	tlsAlpnRefuseAll = ""
)

var (
	// The hello's SNI is not the one the edge routed by, or not one this endpoint serves.
	errTlsDispatchServerName = errors.New("tls front: server name")
	// acme-tls/1 offered with no pending challenge for the name.
	errTlsDispatchNoChallenge = errors.New("tls front: no pending challenge")
	// No grant, or one the registration's mode does not match.
	errTlsDispatchGrant = errors.New("tls front: no grant for the mode")
	// No certificate for the name.
	errTlsDispatchCertificate = errors.New("tls front: no certificate")
	// A raw link visitor's certificate is missing, or hashes to another pin.
	errTlsDispatchLinkPin = errors.New("tls front: link certificate refused")
)

// One front's dispatch.
type tlsDispatch struct {
	front *TlsFront
}

// The config a visitor's handshake starts on: its decision waits for the hello.
func (self *tlsDispatch) config(conn *TlsFrontConn) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		Time:       self.front.clock.Now,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			return self.configFor(conn, hello)
		},
	}
}

// What every decided handshake takes: certificate, nil only where ALPN refuses before one is picked, the ALPN ids the
// decision allows, versions and groups.
func (self *tlsDispatch) baseConfig(certificate *tls.Certificate, nextProtos []string) *tls.Config {
	config := &tls.Config{
		NextProtos:       nextProtos,
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384},
		Time:             self.front.clock.Now,
		// the front keeps no session state between handshakes, so a resumption cannot carry one visitor's
		// standing to another stream
		SessionTicketsDisabled: true,
	}
	if certificate != nil {
		config.Certificates = []tls.Certificate{*certificate}
	}
	return config
}

// The decision for one hello, recorded on conn as its route.
func (self *tlsDispatch) configFor(conn *TlsFrontConn, hello *tls.ClientHelloInfo) (*tls.Config, error) {
	serverName := strings.ToLower(hello.ServerName)
	if serverName != conn.open.GetServerName() || !self.front.target.serves(serverName) {
		return nil, errTlsDispatchServerName
	}
	now := self.front.clock.Now()
	if slices.Contains(hello.SupportedProtos, tlsAlpnAcme) {
		certificate := self.front.responder.certificate(serverName, now)
		if certificate == nil {
			return nil, errTlsDispatchNoChallenge
		}
		conn.route = tlsFrontRouteAcme
		conn.serverName = serverName
		return self.baseConfig(certificate, []string{tlsAlpnAcme}), nil
	}
	grant := self.front.policy.PublishGrant(self.front.target.Name, self.front.target.host(), now)
	route, nextProtos, err := tlsDispatchRoute(self.front.target, grant, hello.SupportedProtos)
	if err != nil {
		return nil, err
	}
	if len(nextProtos) == 1 && nextProtos[0] == tlsAlpnRefuseAll {
		// crypto/tls negotiates ALPN before it picks a certificate, so the handshake fails with
		// no_application_protocol here, and nothing routes
		return self.baseConfig(nil, nextProtos), nil
	}
	certificate, err := self.front.certificate(serverName)
	if err != nil || certificate == nil {
		return nil, errTlsDispatchCertificate
	}
	config := self.baseConfig(certificate, nextProtos)
	if route == tlsFrontRouteRaw && grant.Audience == protocol.AclAudience_ACL_AUDIENCE_LINK {
		config.MinVersion = tls.VersionTLS13
		config.ClientAuth = tls.RequireAnyClientCert
		pin := bytes.Clone(grant.LinkSpkiSha256)
		config.VerifyConnection = func(state tls.ConnectionState) error {
			return tlsLinkPinCheck(state, pin)
		}
	}
	conn.route = route
	conn.serverName = serverName
	return config, nil
}

// The route a grant and the registration's mode give, and the NextProtos that pin ALPN to the decision for offered:
// a one-id list for the id picked, the mode's list when nothing is offered, so crypto/tls selects none, and
// tlsAlpnRefuseAll alone when no offered id is served.
func tlsDispatchRoute(target *TlsFrontTarget, grant *TlsPublishGrant, offered []string) (tlsFrontRoute, []string, error) {
	if grant == nil {
		return tlsFrontRouteNone, nil, errTlsDispatchGrant
	}
	switch target.AppMode {
	case socketListenDefaultTlsAppMode:
		if grant.AppMode != protocol.AclAppMode_ACL_APP_MODE_HTTP {
			return tlsFrontRouteNone, nil, errTlsDispatchGrant
		}
		return tlsFrontRouteHttp, tlsSelectAlpn(offered, []string{tlsAlpnH2, tlsAlpnHttp11}), nil
	case socketListenTlsAppModeRaw:
		if grant.AppMode != protocol.AclAppMode_ACL_APP_MODE_RAW {
			return tlsFrontRouteNone, nil, errTlsDispatchGrant
		}
		switch grant.Audience {
		case protocol.AclAudience_ACL_AUDIENCE_PUBLIC:
		case protocol.AclAudience_ACL_AUDIENCE_LINK:
			if len(grant.LinkSpkiSha256) != sha256.Size {
				return tlsFrontRouteNone, nil, errTlsDispatchGrant
			}
		default:
			return tlsFrontRouteNone, nil, errTlsDispatchGrant
		}
		return tlsFrontRouteRaw, tlsSelectAlpn(offered, target.Alpn), nil
	}
	return tlsFrontRouteNone, nil, errTlsDispatchGrant
}

// NextProtos for offered against served, in served's order: see tlsDispatchRoute.
func tlsSelectAlpn(offered []string, served []string) []string {
	if len(offered) == 0 {
		return slices.Clone(served)
	}
	for _, id := range served {
		if slices.Contains(offered, id) {
			return []string{id}
		}
	}
	return []string{tlsAlpnRefuseAll}
}

// Whether the handshake's client certificate hashes to pin, its SPKI's SHA-256 (§8.4's link_spki_sha256), over
// TLS 1.3, compared in constant time.
func tlsLinkPinCheck(state tls.ConnectionState, pin []byte) error {
	if state.Version != tls.VersionTLS13 || len(state.PeerCertificates) == 0 || len(pin) != sha256.Size {
		return errTlsDispatchLinkPin
	}
	sum := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
	if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
		return errTlsDispatchLinkPin
	}
	return nil
}
