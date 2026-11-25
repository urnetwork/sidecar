//go:build !sidecar_http && !ios_extension

// The network's label from api (§12.5's label row; plan-DNS-labels-before-m5, QD-021; owner decision 421, QD-935): a
// sidecar reads its network's label, which api allocates on first need, and its alias from GET /sidecar/label, and
// from M5 from the dns block's GET /dns/zone as well, which the dns component's client feeds (dns_component.go). This
// component, which a host adds beside the dns component, reads the first: at each client generation it writes api's
// answer into the network's label table (Sidecar.NetworkLabels) under the user root the Sidecar's settings name
// (SidecarSettings.UserRoot), with the network_name its token carries as the row's legacy name, which only a person's
// typed input matches (D-DNS-2). So the <net> of `.ur`, a git remote and §9.4's addresses resolves from M2, before any
// zone is served, and the table keeps the row through a restart and while api is unreachable.
//
// One read that lands is the generation's last: a label never changes once drawn (owner decision 14), and an alias,
// from M6, comes with the zone, whose hints refetch it. A read that may land later, a 5xx (503 while api links no MG2
// or its root restores), a 408 or 429, no answer, or a table not open while the keychain is locked, is tried again
// after RetryInterval, each failure doubling the wait up to RetryMaxInterval, none shorter than the retry_after an
// answer asked, while the generation lasts. Any other refusal, a forwarding token's 403 among them, and an answer not
// of the route's form or about another network, end the generation's reads, the next generation reading again. With
// no user root set nothing is read, so a host that names none allocates no label.

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

// The component's name, which names a keychain namespace and a directory it never uses: the table is dns/'s.
const networkLabelRefreshComponentName = "dns-label"

// The label refresh's waits after a read that may land later (the file's comment).
type NetworkLabelRefreshSettings struct {
	// The wait before the first read again: 1 min, a reading, since the design sets no number: a daemon starting
	// while api restarts asks a few times, and a person's first `.ur` after a blip finds the row. Non-positive: a
	// failed read is not tried again until the next generation.
	RetryInterval time.Duration
	// The longest wait, each failure doubling the last: 1 h, §6.8's resync, so a daemon whose api links no MG2 asks
	// about once an hour a network. One below RetryInterval holds every wait at RetryInterval.
	RetryMaxInterval time.Duration
}

// A fresh value each call.
func DefaultNetworkLabelRefreshSettings() *NetworkLabelRefreshSettings {
	return &NetworkLabelRefreshSettings{
		RetryInterval:    time.Minute,
		RetryMaxInterval: time.Hour,
	}
}

// The label refresh. Close comes after its last generation is detached (SidecarComponent), so no Attach races it.
type networkLabelRefreshComponent struct {
	sidecar  *Sidecar
	settings *NetworkLabelRefreshSettings
	// each generation's reads, which end with the generation's ctx and which Close joins
	reads sync.WaitGroup
}

// The network's label refresh, which a host adds (Sidecar.AddComponent) beside the dns component, as ur daemon does for
// each network it hosts: it reads from the first client generation on. Nil settings take the defaults.
func (self *Sidecar) NewNetworkLabelRefreshComponent(settings *NetworkLabelRefreshSettings) SidecarComponent {
	if settings == nil {
		settings = DefaultNetworkLabelRefreshSettings()
	}
	return &networkLabelRefreshComponent{sidecar: self, settings: settings}
}

// "dns-label".
func (self *networkLabelRefreshComponent) Name() string {
	return networkLabelRefreshComponentName
}

// Starts the generation's reads on its ctx, unless the Sidecar's settings name no user root or the generation has no
// api. Returns at once: the reads run on their own goroutine.
func (self *networkLabelRefreshComponent) Attach(env *SidecarEnv) error {
	root := self.sidecar.userRoot()
	if root == "" || env.SidecarApi == nil {
		return nil
	}
	log := loggerOrDefault(env.Log)
	self.reads.Add(1)
	go func() {
		defer self.reads.Done()
		self.run(env.Ctx, env.SidecarApi, root, log)
	}()
	return nil
}

// Joins the reads, which ended with their generations.
func (self *networkLabelRefreshComponent) Close() {
	self.reads.Wait()
}

// Reads until one lands, one fails for good, or ctx ends (the file's comment).
func (self *networkLabelRefreshComponent) run(ctx context.Context, api *SidecarApi, root string, log Logger) {
	clock := clockOrReal(self.sidecar.clock)
	wait := self.settings.RetryInterval
	for {
		err := self.sidecar.refreshNetworkLabel(ctx, api, root)
		if err == nil || ctx.Err() != nil {
			return
		}
		retryAfter, retry := networkLabelRefreshRetry(err)
		if !retry || self.settings.RetryInterval <= 0 {
			log.Warningf("[dns]the network's label was not read from api this generation: %s", err)
			return
		}
		if log.V(1).Enabled() {
			log.Infof("[dns]the network's label was not read from api, reading again: %s", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-clock.After(max(wait, retryAfter)):
		}
		wait = max(min(2*wait, self.settings.RetryMaxInterval), self.settings.RetryInterval)
	}
}

// Whether a read that failed with err may land later, and the least wait its answer asked: a refusal's 5xx, 408 or
// 429, with its retry_after, and anything that is no answer of api's, as no answer at all or a table not open yet.
// Any other refusal, and an answer not of the route's form, is for good.
func networkLabelRefreshRetry(err error) (time.Duration, bool) {
	var apiErr *SidecarApiError
	if errors.As(err, &apiErr) {
		if apiErr.Status == http.StatusRequestTimeout || apiErr.Status == http.StatusTooManyRequests || 500 <= apiErr.Status {
			return time.Duration(apiErr.RetryAfterMs) * time.Millisecond, true
		}
		return 0, false
	}
	if errors.Is(err, ErrSidecarApiReply) {
		return 0, false
	}
	return 0, true
}

// The user root the Sidecar's settings name, "" for none.
func (self *Sidecar) userRoot() string {
	if self.settings == nil || !isNetworkLabelRoot(self.settings.UserRoot) {
		return ""
	}
	return self.settings.UserRoot
}

// Reads the network's label and alias from api into its label table under root (NetworkLabelTable.Refresh), with the
// network_name api's token carries as the row's legacy name. ErrSidecarStoreLocked before enrollment and while the
// keychain is locked. The table's write is the read's linearization point: from it the daemon resolves the label.
func (self *Sidecar) refreshNetworkLabel(ctx context.Context, api *SidecarApi, root string) error {
	networkId := self.knownNetworkId()
	if networkId == nil {
		return ErrSidecarStoreLocked
	}
	table, err := self.NetworkLabels()
	if err != nil {
		return err
	}
	legacyName := parseSidecarJwt(api.currentByJwt()).stringClaim("network_name")
	testHookBarrier("dns.label_refresh.before", networkId.String())
	err = table.Refresh(ctx, api, root, *networkId, legacyName)
	testHookBarrier("dns.label_refresh.after", networkId.String())
	return err
}
