// ur tun's half of §17.5's IPv6 translator (D-BRIDGE-26; owner decision 778): the ULA /48 the device draws at random
// once (RFC 4193) and keeps, in the network's sealed local state as tun/translator beside tun/choices, so a host's
// instances keep their IPv6 addresses across restarts of the tun and the daemon; the tun turns the bridge's translator
// on over it while it carries the network (tun_device.go), and the platform puts the tun's own address of the /48 on
// the device and routes the instances' /96 into it (urTunTranslatorInterface).
//
// The translator gives the Linux advertising proxy its IPv6 on the tun's link too (discovery_proxy_mdns.go's ipv6
// row): it answers from <block>.0.53's address in the /96, which the host routes into the tun as it routes
// <block>.0.53, and the tun hands it the mDNS queries the host sends from the tun's own address of the /48, or from a
// link-local one (tun_device.go's handMdns).

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
)

// The record's name and version in the choices' directory (tun_default.go's urTunChoicesDirectory).
const (
	urTunTranslatorRecordName    = "translator"
	urTunTranslatorRecordVersion = 1
)

// The /48 as the daemon keeps it, JSON.
type urTunTranslatorRecord struct {
	Version int    `json:"version"`
	Prefix  string `json:"prefix"`
}

// Where a network's /48 is kept.
type urTunTranslatorStore interface {
	// The /48 kept, invalid for none.
	Load() (netip.Prefix, error)
	// Keeps prefix, whole, at once.
	Save(prefix netip.Prefix) error
}

// An open tun whose platform carries the translator's IPv6: it puts own, the tun's own address of the /48, on the
// device as a /128 and routes instances, the /96 the instances' addresses sit in, through it. The device's close takes
// both off with it.
type urTunTranslatorInterface interface {
	urTunInterface
	SetTranslator(own netip.Addr, instances netip.Prefix) error
}

// What the tun turns on and translates through of a network's bridge: device.Bridge's.
type urTunTranslatorBridge interface {
	// Turns the translator on over ula for a tun of mtu; an invalid ula turns it off.
	SetTranslator(ula netip.Prefix, mtu int) error
	// The instances' /96 and the tun's own address, invalid while off.
	TranslatorAddresses() (netip.Prefix, netip.Addr)
	// An IPv4 address's IPv6 one in the instances' /96, invalid while off or for no IPv4 address.
	TranslatedAddress(address netip.Addr) netip.Addr
	// Writes into out a reply to <block>.0.46 translated back to IPv6 (device.Bridge.TranslateReply).
	TranslateReply(out []byte, packet []byte) (int, bool)
	// Packets translated out and back, and dropped.
	TranslatorCounts() (outCount uint64, backCount uint64, droppedCount uint64)
}

var _ urTunTranslatorBridge = (*device.Bridge)(nil)

// urDiscoveryProxyLink: <block>.0.53 at its address in the translator's /96, which the advertising proxy answers IPv6
// mDNS from as it answers IPv4's from <block>.0.53 itself; invalid while the translator is off or before a block. Not
// the tun's own address, which the host's mDNS stack would take for its own echo (discovery_proxy_mdns.go's ipv6 row).
func (self *urTun) ResolverIpv6Address() netip.Addr {
	if self.translator == nil {
		return netip.Addr{}
	}
	return self.translator.TranslatedAddress(self.ResolverAddress())
}

// The tun's own address of the /48, which the host's stack may send its mDNS queries on the link from; invalid while
// the translator is off. self.translator is set once before the tun's loops start.
func (self *urTun) translatorOwnAddress() netip.Addr {
	if self.translator == nil {
		return netip.Addr{}
	}
	_, own := self.translator.TranslatorAddresses()
	return own
}

// The /48 in the network's sealed local state, under the choices' class, so a process that cannot open the instance's
// keychain can neither read nor change it.
type urTunSealedTranslator struct {
	store func() (sidecar.SidecarStore, error)
}

var _ urTunTranslatorStore = (*urTunSealedTranslator)(nil)

// The /48 of running's network.
func newUrTunSealedTranslator(running *sidecar.Sidecar) *urTunSealedTranslator {
	return &urTunSealedTranslator{store: func() (sidecar.SidecarStore, error) {
		return running.LocalStore().Directory(urTunChoicesDirectory, urTunChoicesClass)
	}}
}

func (self *urTunSealedTranslator) Load() (netip.Prefix, error) {
	store, err := self.store()
	if err != nil {
		return netip.Prefix{}, err
	}
	reader, err := store.Open(urTunTranslatorRecordName)
	if errors.Is(err, sidecar.ErrSidecarStoreAbsent) {
		return netip.Prefix{}, nil
	}
	if err != nil {
		return netip.Prefix{}, err
	}
	defer reader.Close()
	encoded, err := io.ReadAll(reader)
	if err != nil {
		return netip.Prefix{}, err
	}
	record := &urTunTranslatorRecord{}
	if err := json.Unmarshal(encoded, record); err != nil || record.Version != urTunTranslatorRecordVersion {
		return netip.Prefix{}, fmt.Errorf("the translator's prefix does not read at version %d", urTunTranslatorRecordVersion)
	}
	prefix, err := netip.ParsePrefix(record.Prefix)
	if err != nil || !urTunTranslatorPrefixValid(prefix) {
		return netip.Prefix{}, errors.New("the translator's prefix is no ULA /48")
	}
	return prefix, nil
}

func (self *urTunSealedTranslator) Save(prefix netip.Prefix) error {
	store, err := self.store()
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(&urTunTranslatorRecord{Version: urTunTranslatorRecordVersion, Prefix: prefix.String()})
	if err != nil {
		return err
	}
	writer, err := store.Create(urTunTranslatorRecordName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(encoded); err != nil {
		return err
	}
	return writer.Commit()
}

// The /48 kept for the daemon's life alone: a network whose bridge no Sidecar's state backs, as a test's is.
type urTunMemoryTranslator struct {
	stateLock sync.Mutex
	prefix    netip.Prefix
}

var _ urTunTranslatorStore = (*urTunMemoryTranslator)(nil)

func (self *urTunMemoryTranslator) Load() (netip.Prefix, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.prefix, nil
}

func (self *urTunMemoryTranslator) Save(prefix netip.Prefix) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.prefix = prefix
	return nil
}

// Whether prefix is a /48 of fd00::/8 (RFC 4193 §3.1's locally assigned ULAs).
func urTunTranslatorPrefixValid(prefix netip.Prefix) bool {
	return prefix.IsValid() && prefix.Addr().Is6() && !prefix.Addr().Is4In6() && prefix.Bits() == 48 &&
		prefix.Addr().As16()[0] == 0xFD && prefix.Masked() == prefix
}

// The network's /48: the one kept, else one drawn now (device.NewBridgeTranslatorPrefix) and kept before it is used,
// so it is drawn once. A store that does not read or write answers its error, and the translator stays off.
func urTunTranslatorPrefix(store urTunTranslatorStore) (netip.Prefix, error) {
	if store == nil {
		return netip.Prefix{}, errors.New("no store keeps the translator's prefix")
	}
	prefix, err := store.Load()
	if err != nil {
		return netip.Prefix{}, err
	}
	if prefix.IsValid() {
		return prefix, nil
	}
	prefix, err = device.NewBridgeTranslatorPrefix()
	if err != nil {
		return netip.Prefix{}, err
	}
	if err := store.Save(prefix); err != nil {
		return netip.Prefix{}, err
	}
	return prefix, nil
}
