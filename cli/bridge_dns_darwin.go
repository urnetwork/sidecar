//go:build darwin

// ur tun's names on macOS (§12.9, §17.10; BRIDGE-M6-06): each of the state's name zones, <net>.<root>, resolves through
// <block>.0.53, where device.Bridge's resolver answers it, by a file /etc/resolver/<zone> naming that nameserver, which
// the system's resolver reads as it changes and asks for that zone alone, so no other name goes to the bridge. Writing
// there takes root, which ur tun's daemon has on macOS. Each file ur tun writes begins with its marker line, naming the
// instance's tun, and ur tun removes only such files: a file for the zone that another program wrote is left, and the
// step a person takes is printed instead.
//
// The bridge's resolver passes the names its zone does not hold to this host's own resolvers, those of
// /etc/resolv.conf, which configd keeps for the primary service, never an address routed into the tun.

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
)

func init() {
	urBridgeResolverUpstream = urDarwinResolverUpstream
}

// The system resolver's directory of per-domain files (resolver(5)).
const urTunDarwinResolverDirectory = "/etc/resolver"

// The start of the first line of every resolver file ur tun writes.
const urTunDarwinResolverMarkerPrefix = "# ur tun "

// The first line of the resolver files the tun owner writes: the instance's device name, ur-<instance>.
func urTunDarwinResolverMarker(owner string) string {
	return urTunDarwinResolverMarkerPrefix + owner + ": removed when that tun ends"
}

// The first line of path, "" for a file that is absent or does not read.
func urTunDarwinFirstLine(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		return scanner.Text()
	}
	return ""
}

// Points zones at resolver with a file each in directory, marked as owner's, and removes owner's files for any other
// zone. Answers "" and true when every zone's file is written; else the step a person takes for the rest, and whether
// any file of owner's is there to revert.
func urTunDarwinSetResolver(directory string, owner string, resolver netip.Addr, zones []string, settings *urTunSettings,
	log sidecar.Logger) (string, bool) {
	marker := urTunDarwinResolverMarker(owner)
	wanted := []string{}
	refusedCount := 0
	for _, zone := range zones {
		name, ok := urTunZoneName(zone, settings)
		if !ok {
			refusedCount += 1
			continue
		}
		if !slices.Contains(wanted, name) {
			wanted = append(wanted, name)
		}
	}
	// owner's files for zones no longer wanted go first
	urTunDarwinRemoveResolverFiles(directory, marker, func(zone string) bool {
		return !slices.Contains(wanted, zone)
	})
	if err := os.MkdirAll(directory, 0o755); err != nil {
		if log.V(1).Enabled() {
			log.Infof("[tun]no resolver directory: %v", err)
		}
		return urTunDarwinResolverStep(resolver, wanted), false
	}
	content := []byte(fmt.Sprintf("%s\nnameserver %s\n", marker, resolver))
	written := 0
	unwritten := []string{}
	for _, zone := range wanted {
		path := filepath.Join(directory, zone)
		if line := urTunDarwinFirstLine(path); line != marker {
			if _, err := os.Lstat(path); err == nil {
				// another program's file for the zone, which ur tun leaves as it is
				unwritten = append(unwritten, zone)
				continue
			}
		}
		if err := urTunDarwinWriteFile(directory, zone, content); err != nil {
			if log.V(1).Enabled() {
				log.Infof("[tun]a resolver file did not write: %v", err)
			}
			unwritten = append(unwritten, zone)
			continue
		}
		written += 1
	}
	if 0 < refusedCount && log.V(1).Enabled() {
		// a zone that names no file the system resolver reads: the state's, which the compile checked, so a fault
		log.Infof("[tun]%d zones are not names a resolver file takes", refusedCount)
	}
	if len(unwritten) == 0 {
		return "", 0 < written
	}
	return urTunDarwinResolverStep(resolver, unwritten), 0 < written
}

// Writes content to directory/zone in one step: a file beside it first, renamed over it, so the system resolver never
// reads half of one.
func urTunDarwinWriteFile(directory string, zone string, content []byte) error {
	staged, err := os.CreateTemp(directory, ".ur-tun-*")
	if err != nil {
		return err
	}
	stagedPath := staged.Name()
	_, writeErr := staged.Write(content)
	closeErr := staged.Close()
	if err := errors.Join(writeErr, closeErr, os.Chmod(stagedPath, 0o644)); err != nil {
		os.Remove(stagedPath)
		return err
	}
	if err := os.Rename(stagedPath, filepath.Join(directory, zone)); err != nil {
		os.Remove(stagedPath)
		return err
	}
	return nil
}

// Removes each file in directory whose first line is marker and whose zone remove names.
func urTunDarwinRemoveResolverFiles(directory string, marker string, remove func(zone string) bool) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.Type()&fs.ModeType != 0 || !remove(entry.Name()) {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		if urTunDarwinFirstLine(path) == marker {
			os.Remove(path)
		}
	}
}

// Removes every resolver file owner wrote.
func urTunDarwinRevertResolver(directory string, owner string) {
	urTunDarwinRemoveResolverFiles(directory, urTunDarwinResolverMarker(owner), func(zone string) bool {
		return true
	})
}

// The nameservers of directory's files that no ur tun wrote: this host's resolvers for other domains, a VPN's
// among them.
func urTunDarwinScopedResolvers(directory string) []netip.Addr {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil
	}
	resolvers := []netip.Addr{}
	for _, entry := range entries {
		if entry.Type()&fs.ModeType != 0 || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		if strings.HasPrefix(urTunDarwinFirstLine(path), urTunDarwinResolverMarkerPrefix) {
			continue
		}
		resolvers = append(resolvers, urReadResolvConf(path)...)
	}
	return resolvers
}

// The step a person takes where ur tun did not write a zone's file.
func urTunDarwinResolverStep(resolver netip.Addr, zones []string) string {
	paths := []string{}
	for _, zone := range zones {
		paths = append(paths, filepath.Join(urTunDarwinResolverDirectory, zone))
	}
	return fmt.Sprintf("as root, make each of %s hold the line: nameserver %s", strings.Join(paths, ", "), resolver)
}

// The bridge's pass-through (device.BridgeResolverUpstream) to /etc/resolv.conf's resolvers outside the tun; routed
// says which addresses the tun carries.
func urDarwinResolverUpstream(routed func(address netip.Addr) bool) device.BridgeResolverUpstream {
	return urResolverUpstream(func() []netip.Addr {
		servers := []netip.Addr{}
		for _, resolver := range urReadResolvConf(urResolvConfPath) {
			if (routed != nil && routed(resolver)) || slices.Contains(servers, resolver) {
				continue
			}
			servers = append(servers, resolver)
		}
		return servers
	})
}
