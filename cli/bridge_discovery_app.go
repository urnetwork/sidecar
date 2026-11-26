// The macOS app's VPN component as a viewer's way into the overlay (§17.7.1's viewer and default rows, §17.11's yield;
// owner decision 778): where a network's sidecar is paired and the app's device role routes inside the network's block
// on another interface, the device sends into the overlay as it would under ur tun, so the network's discovery watches
// and its advertising proxy runs on macOS. The daemon judges it with the shared blocks, each SharedBlockInterval and at
// each bridge's change; ur tun carrying the network wins, and the app's translator is not this daemon's, so the
// proxy's instances take no IPv6 address there. Linux has no app VPN component of this kind, so it judges nothing.

package main

import (
	"errors"
	"net/netip"
	"runtime"
)

// The link a viewer has through the app's VPN component: no tun of this daemon's, so nothing to hand over or write.
type urAppDiscoveryLink struct{}

var _ urDiscoveryProxyLink = urAppDiscoveryLink{}

func (urAppDiscoveryLink) SetMdnsReceiver(receive func(packet []byte)) {}

func (urAppDiscoveryLink) WritePacket(packet []byte) {}

func (urAppDiscoveryLink) ResolverAddress() netip.Addr {
	return netip.Addr{}
}

func (urAppDiscoveryLink) SetLinkMulticastDns(on bool) error {
	return errors.New("the app's VPN component's link is not this daemon's")
}

// Whether the app's VPN component carries a network for its discovery: on macOS, its sidecar paired, ur tun not
// carrying it, and another interface, holder, routing inside its block.
func urAppViewing(goos string, paired bool, tunCarries bool, block netip.Prefix, holder string) bool {
	return goos == "darwin" && paired && !tunCarries && block.IsValid() && holder != ""
}

// Judges each network's discovery against the app's VPN component (the file's comment): it views through the app where
// urAppViewing says so, and stops where it no longer does.
func (self *urBridgeDaemon) judgeAppViewing(networks []*urBridgeNetwork, tun *urTun) {
	if self.system == nil || runtime.GOOS != "darwin" {
		return
	}
	name := urTunDeviceName(self.instance, self.settings.DeviceNameByteCount)
	for _, network := range networks {
		if network.discovery == nil {
			continue
		}
		block := network.bridge.Status().Block
		paired := network.paired != nil && network.paired()
		tunCarries := tun != nil && tun.networkId == network.networkId
		holder := ""
		if paired && !tunCarries && block.IsValid() {
			if routed, err := self.system.RoutedElsewhere(name, block); err == nil {
				holder = routed
			}
		}
		network.discovery.setAppViewing(urAppViewing(runtime.GOOS, paired, tunCarries, block, holder))
	}
}
