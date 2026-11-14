//go:build windows

// This host's own addresses on Windows, for Bridge.SetLocalAddresses (§17.4's carve, §18.6's SetBridgeLocalAddresses;
// BRIDGE-M6-06): connect.LocalIpv4Networks sees only interface subnets, so the carve also needs the gateways and the
// resolvers the physical path uses. Each comes from every adapter but the tun's own (GetAdaptersAddresses):
//
//	interfaces  its unicast addresses, both families: rule 0 reads them all as this device's own (D-BRIDGE-19), and the
//	            export carves the IPv4 ones
//	gateways    its gateways
//	resolvers   its DNS servers
//
// The watch is IP Helper's change notifications for unicast addresses, routes and interfaces of both families, each a
// change; a resolver that changes with none of those is the tun's LocalPollInterval's to see.

package main

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This host's addresses: every adapter's but name's, its gateways and its resolvers, but exclude, sorted with no
// repeats.
func (self *urTunWindowsSystem) LocalAddresses(name string, exclude []netip.Addr) ([]netip.Addr, error) {
	adapters, err := self.ipHelper.Adapters()
	if err != nil {
		return nil, err
	}
	addresses := []netip.Addr{}
	add := func(address netip.Addr) {
		address = address.Unmap().WithZone("")
		if address.IsValid() && !address.IsUnspecified() && !slices.Contains(exclude, address) &&
			!slices.Contains(addresses, address) {
			addresses = append(addresses, address)
		}
	}
	for _, adapter := range adapters {
		if adapter.name == name {
			continue
		}
		for _, held := range [][]netip.Addr{adapter.addresses, adapter.gateways, adapter.resolvers} {
			for _, address := range held {
				add(address)
			}
		}
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	return addresses, nil
}

// One watch's changed, held where IP Helper's callback finds it by its token's address, which the heap does not move.
type urTunWindowsWatch struct {
	token   *byte
	changed func()
}

// IP Helper's one callback, made once, since windows.NewCallback's are never freed, and the watches it calls.
var urTunWindowsNotify struct {
	once      sync.Once
	callback  uintptr
	stateLock sync.Mutex
	watches   map[uintptr]*urTunWindowsWatch
}

// Calls the watch callerContext names. Windows calls it on a thread of its own; changed never blocks.
func urTunWindowsNotifyCallback(callerContext uintptr, row uintptr, notificationType uintptr) uintptr {
	urTunWindowsNotify.stateLock.Lock()
	watch := urTunWindowsNotify.watches[callerContext]
	urTunWindowsNotify.stateLock.Unlock()
	if watch != nil {
		watch.changed()
	}
	return 0
}

// Calls changed on each unicast address, route or interface notification of either family until ctx ends, and once as
// soon as it watches, for whatever changed before.
func (self *urTunWindowsSystem) WatchLocal(ctx context.Context, changed func()) error {
	urTunWindowsNotify.once.Do(func() {
		urTunWindowsNotify.callback = windows.NewCallback(urTunWindowsNotifyCallback)
		urTunWindowsNotify.watches = map[uintptr]*urTunWindowsWatch{}
	})
	watch := &urTunWindowsWatch{token: new(byte), changed: changed}
	key := uintptr(unsafe.Pointer(watch.token))
	func() {
		urTunWindowsNotify.stateLock.Lock()
		defer urTunWindowsNotify.stateLock.Unlock()
		urTunWindowsNotify.watches[key] = watch
	}()
	handles := []windows.Handle{}
	defer func() {
		// each cancel waits for its callbacks in flight, so none reaches the watch once it is gone
		for _, handle := range handles {
			windows.CancelMibChangeNotify2(handle)
		}
		urTunWindowsNotify.stateLock.Lock()
		defer urTunWindowsNotify.stateLock.Unlock()
		delete(urTunWindowsNotify.watches, key)
	}()
	notifies := []func(family uint16, callback uintptr, callerContext unsafe.Pointer, initialNotification bool,
		notificationHandle *windows.Handle) error{
		windows.NotifyUnicastIpAddressChange,
		windows.NotifyRouteChange2,
		windows.NotifyIpInterfaceChange,
	}
	for _, notify := range notifies {
		var handle windows.Handle
		if err := notify(windows.AF_UNSPEC, urTunWindowsNotify.callback, unsafe.Pointer(watch.token), false, &handle); err != nil {
			return err
		}
		handles = append(handles, handle)
	}
	changed()
	<-ctx.Done()
	return nil
}
