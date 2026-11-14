//go:build !ios_extension

// The zone's hints and resync (DNS-M5-21; §6.8, §12.14; plan reading 18): DNS_ZONE_CHANGED rides push topic dns with
// no body, the zone's serial in its version. A hint only prompts a refetch: one at or below the version the client
// holds is ignored, since a durable topic's lower version is the push's to alarm on (I-16), and the zone's state is
// read from GET /dns/zone, never from a hint. A resync notice, after a reset or a refetch of the versions, marks the
// zone stale too. A notice runs on the push's goroutine, so it only marks and wakes; the client's own loop fetches,
// at most once a HintRefetchMinInterval, and again each ResyncInterval with no hint (§6.8's hourly resync).
//
// The subscription is a function value, Subprotocol.Subscribe on a connect leg, so this file stays on every leg but
// the ios_extension legs. The client also feeds DNS-M2-01's NetworkLabelTable from each zone it fetches.

package sidecar

import (
	"context"
	"errors"
	"slices"
)

// Subprotocol.Subscribe's shape.
type DnsHintSubscribeFunction func(topic string, callback PushNoticeFunction) (remove func(), err error)

// The client's subscription and its refetch loop.
type dnsHints struct {
	cancel context.CancelFunc
	remove func()
	wake   chan struct{}
	done   chan struct{}
}

// Subscribes to topic dns through subscribe and starts the refetch loop under ctx (see the file header). A second
// call replaces the first. Close ends both.
func (self *DnsClient) SubscribeHints(ctx context.Context, subscribe DnsHintSubscribeFunction) error {
	if subscribe == nil {
		return errors.New("dns client: no subscription")
	}
	self.Close()
	loopCtx, cancel := context.WithCancel(ctx)
	hints := &dnsHints{
		cancel: cancel,
		wake:   make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
	remove, err := subscribe(PushTopicDns, func(notice PushNotice) {
		self.notice(hints, notice)
	})
	if err != nil {
		cancel()
		return err
	}
	hints.remove = remove
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.hints = hints
	}()
	go self.runHints(loopCtx, hints)
	return nil
}

// Ends the subscription and the refetch loop, and waits for the loop. Safe more than once.
func (self *DnsClient) Close() {
	var hints *dnsHints
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		hints = self.hints
		self.hints = nil
	}()
	if hints == nil {
		return
	}
	if hints.remove != nil {
		hints.remove()
	}
	hints.cancel()
	<-hints.done
}

// A notice of topic dns: a hint above the held version or a resync marks the zone stale and wakes the loop; any other
// is ignored. Never blocks.
func (self *DnsClient) notice(hints *dnsHints, notice PushNotice) {
	if notice.Topic != PushTopicDns {
		return
	}
	stale := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !notice.Resync && self.zone != nil && notice.Version <= self.zone.Version {
			return false
		}
		self.stale = true
		return true
	}()
	if !stale {
		return
	}
	select {
	case hints.wake <- struct{}{}:
	default:
	}
}

// Fetches the zone at each wake, at most once a HintRefetchMinInterval, and each ResyncInterval with none.
func (self *DnsClient) runHints(ctx context.Context, hints *dnsHints) {
	defer close(hints.done)
	for {
		select {
		case <-ctx.Done():
			return
		case <-hints.wake:
		case <-self.clock.After(self.settings.ResyncInterval):
		}
		// a failed fetch leaves the zone stale, so the next wake or Zone fetches again
		self.fetchZone(ctx)
		select {
		case <-ctx.Done():
			return
		case <-self.clock.After(self.settings.HintRefetchMinInterval):
		}
	}
}

// Sets the network's label and alias under the zone's root from GET /dns/zone's answer, keeping its legacy name and
// its retiring aliases but the one that is live again. An answer that names no label changes nothing.
func (self *NetworkLabelTable) SetZoneLabel(zone *DnsZone) error {
	if zone == nil || zone.Label == "" {
		return nil
	}
	row, err := canonicalNetworkLabelRow(NetworkLabelRow{Root: zone.Root, NetworkId: zone.NetworkId, Label: zone.Label, Alias: zone.Alias})
	if err != nil {
		return err
	}
	return self.update(func(rows []NetworkLabelRow) ([]NetworkLabelRow, error) {
		for index := range rows {
			if rows[index].Root == row.Root && rows[index].NetworkId == row.NetworkId {
				row.LegacyName = rows[index].LegacyName
				row.RetiringAliases = slices.DeleteFunc(rows[index].RetiringAliases, func(alias string) bool {
					return alias == row.Alias
				})
				if rows[index].Label == row.Label && rows[index].Alias == row.Alias {
					return rows, nil
				}
				rows[index] = row
				return rows, nil
			}
		}
		return append(rows, row), nil
	})
}
