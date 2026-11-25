//go:build linux

// §17.7.1's advertising proxy on Linux (owner decision 778): discovery_proxy_mdns.go's responder on ur tun's own link,
// with systemd-resolved's MulticastDNS on for that link while it runs (tun_linux.go's SetMulticastDns), and nothing at
// all sent while Avahi's reflector is on, as avahi-daemon.conf sets it.

package main

import (
	"context"

	"github.com/urnetwork/sidecar"
)

// Avahi's configuration, where its reflector is set.
const urAvahiConfigPath = "/etc/avahi/avahi-daemon.conf"

func init() {
	urDiscoveryProxyOf = func(ctx context.Context, log sidecar.Logger, link urDiscoveryProxyLink) urDiscoveryProxy {
		if link == nil {
			return nil
		}
		return newUrMdnsDiscoveryProxy(ctx, log, link, defaultUrMdnsProxySettings(), func() (bool, string) {
			return urAvahiReflectorOn(urAvahiConfigPath)
		}, nil)
	}
}
