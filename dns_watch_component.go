//go:build !sidecar_http && !js && !ios_extension

// The zone watch's component (D-TRUST-9; DNS-M5-22): what runs a network's DnsWatch on a host that stays up, over
// NewDnsWatchDohResolver's resolvers, attached to the Sidecar (SetDnsWatch) for SidecarStatus's "zone watch degraded"
// and for the mail receiver's mail-host watches.
//
// Who runs it. D-TRUST-9 has sidecars with a published name or a mail host watch their zone, a pass about every 6 h
// like the CT watch (D-TLS-8), which runs only on a host that stays up (TLS-M8-01). ur daemon is that host: the
// desktop's and the CLI's sidecar role (§18.4), where ur bridge public-tls publishes and the network's mail indexers
// receive, so it adds this component beside the dns component for each network it hosts (cli's daemon_dns.go), and
// sdk's desktop class adds it the same way, as it runs the CT watch (sdk's sidecar_dns_watch.go). An app's sidecar
// role runs only while the app is open (owner decision 197), where a pass about every 6 h would seldom come, so sdk's
// foreground-only classes, iOS and Android, add none and leave the watch to the network's daemons, as they leave the
// CT watch (QD-1384).
//
// The component composes the watch at the first client generation that can: the network known, its DnsClient made
// and the watch's file in the network's dns/ directory read, which a locked keychain refuses. A generation that
// cannot leaves it to the next. Once composed, the watch runs across generations, its passes on the component's own
// context and the Sidecar's clock: it reads GET /dns/zone through the network's DnsClient, watches the names this
// device publishes and what its file holds, and raises its alarms as the Sidecar's dns_alarm events. Close detaches
// it, ends it and releases its resolvers, after any composition under way.
//
// The names this device publishes are its publishes' (TlsPublishedHosts) and its app listeners' (ListenTls), the two
// D-TLS-8's CT watch counts as listening (tlsListening). An sdk host publishes through its tls/ app listeners alone,
// so a watch on the publishes alone would watch none of a desktop app's names.
//
// The resolvers are those the settings' Doh names: production's are connect's first two default remote DoH servers,
// each a DohCache of the watch's own. A test binary refuses those (ErrDnsWatchPublicResolver), so a test names its
// own DNS through DnsWatchDohSettings.ForwarderFactory, and a component left on the defaults composes no watch there.
//
// StrictChain gets no validator here: where the watch holds none, a receiver's own lookups hold mail.strict's chain
// (mail_component_receive.go). Safe for concurrent use.

package sidecar

import (
	"context"
	"slices"
	"sync"
)

// Its keychain namespace and directory, which hold nothing: the watch's file is in the network's dns/ directory, the
// dns component's (dnsDirectoryName).
const dnsWatchComponentName = "dns-watch"

// Tunables of the zone watch's component: the watch's and its resolvers'.
type DnsWatchComponentSettings struct {
	// The watch's: its interval, jitter and bounds.
	Watch *DnsWatchSettings
	// Its resolvers': D-TRUST-9's two over DoH, or a test's own DNS.
	Doh *DnsWatchDohSettings
}

// A fresh value each call, of the watch's defaults and its resolvers'.
func DefaultDnsWatchComponentSettings() *DnsWatchComponentSettings {
	return &DnsWatchComponentSettings{
		Watch: DefaultDnsWatchSettings(),
		Doh:   DefaultDnsWatchDohSettings(),
	}
}

// The zone watch's component.
type dnsWatchComponent struct {
	sidecar  *Sidecar
	settings *DnsWatchComponentSettings
	// the watch's passes run under it until Close
	ctx    context.Context
	cancel context.CancelFunc

	// held across a composition and across Close, which so never meets a watch half made or attaches one after it
	composeLock sync.Mutex
	// nil until a generation composes them
	watch    *DnsWatch
	resolver *DnsWatchDohResolver
	closed   bool
}

// The network's zone watch component, which a host that stays up adds to this Sidecar (AddComponent) before or after
// enrollment: it composes the watch at the first client generation that can, on settings, nil taking the defaults.
func (self *Sidecar) NewDnsWatchComponent(settings *DnsWatchComponentSettings) SidecarComponent {
	if settings == nil {
		settings = DefaultDnsWatchComponentSettings()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &dnsWatchComponent{sidecar: self, settings: settings, ctx: ctx, cancel: cancel}
}

// "dns-watch".
func (self *dnsWatchComponent) Name() string {
	return dnsWatchComponentName
}

// Composes the watch unless a generation has. One that cannot is logged and left to the next generation, and the
// component still attaches.
func (self *dnsWatchComponent) Attach(env *SidecarEnv) error {
	if err := self.compose(); err != nil {
		loggerOrDefault(env.Log).Warningf("[dns]the zone watch did not start this generation: %s", err)
	}
	return nil
}

// Composes the watch and attaches it to the Sidecar, unless it runs or the component has closed.
func (self *dnsWatchComponent) compose() error {
	self.composeLock.Lock()
	defer self.composeLock.Unlock()
	if self.closed || self.watch != nil {
		return nil
	}
	client, err := self.sidecar.Dns()
	if err != nil {
		return err
	}
	store, err := self.sidecar.LocalStore().Directory(dnsDirectoryName, dnsDirectoryName)
	if err != nil {
		return err
	}
	resolver, err := NewDnsWatchDohResolver(self.settings.Doh)
	if err != nil {
		return err
	}
	watch, err := NewDnsWatch(self.ctx, &DnsWatchArgs{
		Resolver:       resolver,
		Store:          store,
		Zone:           client.Zone,
		PublishedHosts: self.sidecar.dnsWatchPublishedHosts,
		Event: func(event SidecarEvent) {
			self.sidecar.Alarm(event)
		},
		Settings: self.settings.Watch,
		Clock:    self.sidecar.clock,
	})
	if err != nil {
		resolver.Close()
		return err
	}
	self.watch = watch
	self.resolver = resolver
	self.sidecar.SetDnsWatch(watch)
	return nil
}

// Detaches the watch, ends its passes and releases its resolvers. No later generation composes one.
func (self *dnsWatchComponent) Close() {
	self.composeLock.Lock()
	defer self.composeLock.Unlock()
	self.closed = true
	if self.watch != nil {
		self.sidecar.detachDnsWatch(self.watch)
		self.watch.Close()
		self.resolver.Close()
		self.watch = nil
		self.resolver = nil
	}
	self.cancel()
}

// The names this device publishes now, each once, sorted: its publishes' and its tls component's app listeners'.
func (self *Sidecar) dnsWatchPublishedHosts() []string {
	hosts := self.TlsPublishedHosts()
	if component := self.tlsComponent(); component != nil {
		hosts = append(hosts, component.listenerServerNames()...)
	}
	slices.Sort(hosts)
	return slices.Compact(hosts)
}

// Detaches watch, unless another has been attached in its place.
func (self *Sidecar) detachDnsWatch(watch *DnsWatch) {
	self.dns.stateLock.Lock()
	defer self.dns.stateLock.Unlock()
	if attached, ok := self.dns.watch.(*DnsWatch); ok && attached == watch {
		self.dns.watch = nil
	}
}
