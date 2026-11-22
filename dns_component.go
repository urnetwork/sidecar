//go:build !sidecar_http && !ios_extension

// The dns SidecarComponent (§12.5's label row, §6.8; DNS-M2-01, DNS-M5-21): what attaches the network's label table and
// its zone hints to the network's DnsClient on each client generation, so the table's row for this network follows
// every zone the client fetches, GET /dns/zone feeding it from M5, and a DNS_ZONE_CHANGED hint above the held version,
// a resync notice or §6.8's hourly resync fetches the zone again. A host adds it once, at its composition, whatever
// else it runs: ur daemon for each network it hosts (cli's daemon_dns.go) and the sdk's local Sidecar, so `network:<net>`
// in a document, `.ur` and §9.4's addresses read a row the network's own zone wrote.
//
// A Sidecar with no dns component still opens the table at its first Sidecar.NetworkLabels, as the ACL writer's label
// read does, and a fetch from then on feeds it; but nothing then refetches its zone on a hint, so a cached zone is up to
// ResyncInterval old when a caller reads it.
//
// The component's directory is §5.9's dns/ (dnsDirectoryName), which holds the label table's file and the zone
// watch's. The sidecar_http leg runs no component (§18.10), and the ios_extension legs no DnsClient.

package sidecar

import (
	"context"
	"sync"
)

// The dns component. Close comes after its last generation is detached (SidecarComponent), so no Attach races it; the
// lock only keeps the client Close reads whole.
type dnsComponent struct {
	sidecar *Sidecar

	stateLock sync.Mutex
	// the client whose hints the latest generation subscribed, which Close ends
	client *DnsClient
}

// The network's dns component, which the host adds to this Sidecar (Sidecar.AddComponent) before or after enrollment:
// it attaches from the first client generation on.
func (self *Sidecar) NewDnsComponent() SidecarComponent {
	return &dnsComponent{sidecar: self}
}

// "dns", the name of its keychain namespace and its directory.
func (self *dnsComponent) Name() string {
	return dnsDirectoryName
}

// Attaches the label table and subscribes the zone's hints on the generation's push. Neither failing detaches the
// component, so the other still holds: a table that does not open now opens at the next generation or at the first
// NetworkLabels, and a push with no client serving it subscribes at the next generation.
func (self *dnsComponent) Attach(env *SidecarEnv) error {
	var subscribe DnsHintSubscribeFunction
	if env.Subprotocol != nil {
		subscribe = env.Subprotocol.Subscribe
	}
	self.attach(env.Ctx, subscribe, env.Log)
	return nil
}

// Attach's work, on the generation's ctx and the push's subscription, nil when the generation has no push.
func (self *dnsComponent) attach(ctx context.Context, subscribe DnsHintSubscribeFunction, log Logger) {
	log = loggerOrDefault(log)
	client, err := self.sidecar.Dns()
	if err != nil {
		log.Warningf("[dns]the network's zone feeds no label table this generation: %s", err)
		return
	}
	if _, err := self.sidecar.NetworkLabels(); err != nil {
		log.Warningf("[dns]the network's label table did not open this generation: %s", err)
	}
	if subscribe == nil {
		return
	}
	// a second subscription replaces the last generation's, whose loop ended with its ctx
	if err := client.SubscribeHints(ctx, subscribe); err != nil {
		if log.V(1).Enabled() {
			log.Infof("[dns]the network's zone takes no hints this generation: %s", err)
		}
		return
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.client = client
	}()
}

// Ends the hint subscription and its refetch loop. The table stays the client's, and its file the network's.
func (self *dnsComponent) Close() {
	var client *DnsClient
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		client = self.client
		self.client = nil
	}()
	if client != nil {
		client.Close()
	}
}
