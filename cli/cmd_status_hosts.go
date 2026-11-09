// ur status's host report (§18.9, D-SDK-7): every entry of the host table this ur embeds, probed over the dial the
// daemon itself takes, through HTTPS_PROXY when it is set, with a tls handshake that sends nothing after it; the
// rung that leaves the sidecar on; and interception, a chain to a host that ends outside the issuers the table pins
// for it (§2.4). Interception is reported and never blocks: a cloud agent's proxy may see bearer tokens, never
// Required-mode traffic or repo content. An entry with no pinned issuers yet, which is every entry until the release
// supplies them, reads unpinned: ur cannot tell, and says so.
//
// The probe verifies each chain against the system's roots, since a proxy that intercepts installs its CA there,
// and reads the issuers of the verified chains, or of the chain as presented when none verifies.

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// What a probe found of a reached host's chain.
const (
	// It ends at an issuer the table pins for the host.
	urHostChainPinned = "pinned"
	// It ends elsewhere: someone between this host and the service holds a CA it trusts or presents.
	urHostChainIntercepted = "intercepted"
	// The table pins no issuer for the host yet, so the chain cannot be judged.
	urHostChainUnpinned = "unpinned"
)

// The rungs of §18.9, and none when a required host is out of reach.
const (
	urHostRungNone = 0
	// wss direct: everything.
	urHostRungDirect = 1
	// wss through HTTPS_PROXY's CONNECT (C8): everything.
	urHostRungProxied = 2
	// HTTPS only: evs, records and the long-poll; no streams, sockets or mail send.
	urHostRungHttpsOnly = 3
)

// One entry's probe.
type urHostProbe struct {
	Entry sidecar.SidecarHostListEntry
	// The tls handshake completed.
	Reached bool
	// Why not: a classification that names no address.
	Failure string
	// urHostChainPinned, urHostChainIntercepted or urHostChainUnpinned, when reached.
	Chain string
	// Whether the chain verified against the system's roots.
	Verified bool
	// The common name of the chain's last issuer, for the person.
	Issuer string
}

// What ur status prints of the hosts.
type urHostReport struct {
	// HTTPS_PROXY carried the probes, as it carries the daemon's dials.
	Proxied bool
	// Why no proxy could be used, when HTTPS_PROXY is set and refused: then nothing was probed.
	ProxyRefusal string
	Rung         int
	Probes       []*urHostProbe
}

// How ur status probes: the dial each probe takes, and the roots a chain verifies against. Production's dials
// are connect's, and its roots the system's.
type urHostProber struct {
	// The connect settings a probe dials with, its proxy set: connect's defaults in production. A test maps
	// .example names to its loopback servers here.
	connectSettings func() *connect.ConnectSettings
	// Nil: the system's.
	roots *x509.CertPool
}

// The prober ur runs.
func newUrHostProber() *urHostProber {
	return &urHostProber{connectSettings: connect.DefaultConnectSettings}
}

// Probes one entry: a stream dial through proxySettings, if set, and a tls handshake naming the host, after which
// the connection closes having carried nothing.
func (self *urHostProber) probe(ctx context.Context, entry sidecar.SidecarHostListEntry, proxySettings *connect.ProxySettings) *urHostProbe {
	probe := &urHostProbe{Entry: entry}
	connectSettings := self.connectSettings()
	connectSettings.ProxySettings = proxySettings
	conn, err := connectSettings.DialContext(ctx, "tcp", entry.Address())
	if err != nil {
		var proxyErr *connect.HttpConnectProxyError
		switch {
		case errors.As(err, &proxyErr) && proxyErr.AuthenticationRequired():
			probe.Failure = "the proxy wants credentials (407)"
		case errors.As(err, &proxyErr):
			probe.Failure = fmt.Sprintf("the proxy refused it (%d)", proxyErr.StatusCode)
		case ctx.Err() != nil:
			probe.Failure = "timed out"
		default:
			probe.Failure = "no connection"
		}
		return probe
	}
	// the chain is judged below, after the handshake; nothing is sent over this connection, so an unverified
	// handshake carries nothing to anyone
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         entry.Host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
	})
	err = tlsConn.HandshakeContext(ctx)
	state := tlsConn.ConnectionState()
	tlsConn.Close()
	if err != nil || len(state.PeerCertificates) == 0 {
		probe.Failure = "no tls handshake"
		return probe
	}
	probe.Reached = true

	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	chains, verifyErr := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       entry.Host,
		Roots:         self.roots,
		Intermediates: intermediates,
	})
	probe.Verified = verifyErr == nil && 0 < len(chains)
	if !probe.Verified {
		chains = [][]*x509.Certificate{state.PeerCertificates}
	}
	last := chains[0][len(chains[0])-1]
	probe.Issuer = last.Subject.CommonName
	if probe.Issuer == "" {
		probe.Issuer = last.Issuer.CommonName
	}

	digests, err := entry.IssuerSpkiDigests()
	if err != nil || len(digests) == 0 {
		probe.Chain = urHostChainUnpinned
		return probe
	}
	probe.Chain = urHostChainIntercepted
	for _, chain := range chains {
		for _, certificate := range chain[1:] {
			if slices.Contains(digests, sha256.Sum256(certificate.RawSubjectPublicKeyInfo)) {
				probe.Chain = urHostChainPinned
				return probe
			}
		}
	}
	return probe
}

// Probes every entry of list at once, through the proxy HTTPS_PROXY names, each within HostProbeTimeout.
func (self *urCli) reportHosts(ctx context.Context, list *sidecar.SidecarHostList) *urHostReport {
	report := &urHostReport{}
	apiHost := ""
	if entry, ok := list.ServiceEntry(sidecar.SidecarHostServiceApi); ok {
		apiHost = entry.Host
	}
	proxySettings, err := urHttpsProxy(self.getenv, apiHost)
	if err != nil {
		// a proxy ur cannot use is never gone around, here or in the daemon
		report.ProxyRefusal = err.Error()
		return report
	}
	report.Proxied = proxySettings != nil

	probeCtx, cancel := context.WithTimeout(ctx, self.settings.HostProbeTimeout)
	defer cancel()
	report.Probes = make([]*urHostProbe, len(list.Hosts))
	var waitGroup sync.WaitGroup
	for i, entry := range list.Hosts {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			report.Probes[i] = self.hostProber.probe(probeCtx, entry, proxySettings)
		}()
	}
	waitGroup.Wait()
	report.Rung = urHostRungOf(report.Proxied, report.Probes)
	return report
}

// §18.9's rung the probes leave the sidecar on: none while a required host is out of reach, 3 while the platform
// host is, else 2 through a proxy and 1 without one.
func urHostRungOf(proxied bool, probes []*urHostProbe) int {
	streams := false
	for _, probe := range probes {
		switch probe.Entry.Requirement {
		case sidecar.SidecarHostRequired:
			if !probe.Reached {
				return urHostRungNone
			}
		case sidecar.SidecarHostStreams:
			streams = probe.Reached
		}
	}
	if !streams {
		return urHostRungHttpsOnly
	}
	if proxied {
		return urHostRungProxied
	}
	return urHostRungDirect
}

// What each rung gives, as a person reads it.
func urHostRungText(rung int) string {
	switch rung {
	case urHostRungDirect:
		return "rung 1, wss direct: everything"
	case urHostRungProxied:
		return "rung 2, wss through HTTPS_PROXY: everything"
	case urHostRungHttpsOnly:
		return "rung 3, HTTPS only: evs, records and the long-poll; no streams, sockets or mail send"
	}
	return "none: a required host is out of reach"
}

// The report, as a person reads it: the rung, each host, then a warning for each interception.
func printUrHostReport(cli *urCli, report *urHostReport) {
	out := cli.stdout
	if report.ProxyRefusal != "" {
		fmt.Fprintf(out, "hosts:      not probed: %s\n", report.ProxyRefusal)
		return
	}
	fmt.Fprintf(out, "hosts:      %s\n", urHostRungText(report.Rung))
	intercepted := []string{}
	for _, probe := range report.Probes {
		state := "not reached: " + probe.Failure
		if probe.Reached {
			state = "reached, chain " + probe.Chain
			if !probe.Verified {
				state += ", not trusted by this system"
			}
			if probe.Issuer != "" {
				state += fmt.Sprintf(" (issuer %q)", probe.Issuer)
			}
		}
		fmt.Fprintf(out, "  %-32s %-9s %s\n", probe.Entry.Address(), probe.Entry.Requirement, state)
		if probe.Chain == urHostChainIntercepted {
			intercepted = append(intercepted, fmt.Sprintf("%s (issuer %q)", probe.Entry.Host, probe.Issuer))
		}
	}
	if 0 < len(intercepted) {
		fmt.Fprintf(out, "warning:    interception: the chains to %s end outside the issuers ur pins. Whoever holds "+
			"them can read bearer tokens, never Required-mode traffic or repo content. Nothing was blocked.\n",
			strings.Join(intercepted, ", "))
	}
}
