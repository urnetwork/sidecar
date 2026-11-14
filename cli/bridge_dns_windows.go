//go:build windows

// ur tun's names on Windows (§12.9, §17.10; BRIDGE-M6-06): the state's name zones, <net>.<root>, resolve through
// <block>.0.53, where device.Bridge's resolver answers them, by one rule of the Name Resolution Policy Table, which
// sends a suffix's names to the servers it names and no other name there, so no other name goes to the bridge. The rule
// is the instance's, a key under the DNS client's own DnsPolicyConfig whose name is derived from the tun's, so a rule a
// crashed daemon left is the next one's to replace; the client is asked to read its parameters again and its cache is
// flushed. Writing there takes an administrator, which ur tun's daemon is on Windows. Where group policy holds rules of
// its own, which override the local ones, or the rule does not write, the step a person takes is printed instead.
//
// The bridge's resolver passes the names its zone does not hold to this host's own resolvers, each adapter's DNS
// servers, never an address routed into the tun.

package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/urnetwork/sidecar/device"
)

func init() {
	urBridgeResolverUpstream = urWindowsResolverUpstream
}

// The DNS client's own rules, and group policy's, which override them.
const (
	urTunWindowsNrptPath       = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	urTunWindowsNrptPolicyPath = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
)

// A rule's format: its version, and ConfigOptions' bit for generic DNS servers.
const (
	urTunWindowsNrptVersion       = 2
	urTunWindowsNrptGenericServer = 0x8
)

// The domain of a rule name's hash.
const urTunWindowsRuleNameDomain = "urnetwork-sidecar-v1/nrpt-rule/"

// The rule the tun name keeps: a GUID's shape, as the client's own rules are named, from a hash of the name.
func urTunWindowsRuleName(name string) string {
	digest := sha256.Sum256([]byte(urTunWindowsRuleNameDomain + name))
	return fmt.Sprintf("{%x-%x-%x-%x-%x}", digest[0:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

// The step a person takes where ur tun did not set the rule.
func urTunWindowsResolverStep(resolver netip.Addr, zones []string) string {
	commands := []string{}
	for _, zone := range zones {
		commands = append(commands, fmt.Sprintf("Add-DnsClientNrptRule -Namespace .%s -NameServers %s", zone, resolver))
	}
	return "in PowerShell as administrator, run: " + strings.Join(commands, "; ")
}

// The resolver's policy table in the registry.
type urTunWindowsNrpt struct {
	settings *urTunSettings
}

var _ urTunWindowsResolver = (*urTunWindowsNrpt)(nil)

// Writes the rule: each zone a suffix, the resolver its generic server. Group policy's rules override the local ones,
// so where it holds any the step is printed instead.
func (self *urTunWindowsNrpt) Set(rule string, resolver netip.Addr, zones []string) (string, error) {
	if urTunWindowsPolicyRules() {
		return urTunWindowsResolverStep(resolver, zones) + ", in the group policy whose name resolution rules " +
			"override ur's own", nil
	}
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, urTunWindowsNrptPath+`\`+rule, registry.SET_VALUE)
	if err != nil {
		return "", err
	}
	defer key.Close()
	suffixes := []string{}
	for _, zone := range zones {
		suffixes = append(suffixes, "."+zone)
	}
	err = errors.Join(
		key.SetDWordValue("Version", urTunWindowsNrptVersion),
		key.SetStringsValue("Name", suffixes),
		key.SetStringValue("GenericDNSServers", resolver.String()),
		key.SetDWordValue("ConfigOptions", urTunWindowsNrptGenericServer),
		key.SetStringValue("IPSECCARestriction", ""),
		key.SetStringValue("Comment", "ur tun: removed when that tun ends"),
	)
	if err != nil {
		return "", err
	}
	urTunWindowsReloadResolver()
	return "", nil
}

// Removes the rule; one that is not there is no error.
func (self *urTunWindowsNrpt) Remove(rule string) error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, urTunWindowsNrptPath+`\`+rule)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	urTunWindowsReloadResolver()
	return err
}

// Whether group policy holds rules of its own.
func urTunWindowsPolicyRules() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, urTunWindowsNrptPolicyPath, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	defer key.Close()
	names, err := key.ReadSubKeyNames(1)
	return err == nil && 0 < len(names)
}

// The calls x/sys/windows does not wrap, from dnsapi.dll in System32.
var (
	urTunWindowsDnsapiDll             = windows.NewLazySystemDLL("dnsapi.dll")
	urTunWindowsDnsFlushResolverCache = urTunWindowsDnsapiDll.NewProc("DnsFlushResolverCache")
)

// The DNS client's service.
const urTunWindowsDnsClientServiceName = "Dnscache"

// Has the DNS client read its parameters again, and flushes its cache, so a rule's change holds at once. Each is best
// effort: the client also reads the rules as they change.
func urTunWindowsReloadResolver() {
	if manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT); err == nil {
		if name, err := windows.UTF16PtrFromString(urTunWindowsDnsClientServiceName); err == nil {
			if service, err := windows.OpenService(manager, name, windows.SERVICE_PAUSE_CONTINUE); err == nil {
				var status windows.SERVICE_STATUS
				windows.ControlService(service, windows.SERVICE_CONTROL_PARAMCHANGE, &status)
				windows.CloseServiceHandle(service)
			}
		}
		windows.CloseServiceHandle(manager)
	}
	if urTunWindowsDnsFlushResolverCache.Find() == nil {
		urTunWindowsDnsFlushResolverCache.Call()
	}
}

// The bridge's pass-through (device.BridgeResolverUpstream) to each adapter's DNS servers outside the tun; routed says
// which addresses the tun carries.
func urWindowsResolverUpstream(routed func(address netip.Addr) bool) device.BridgeResolverUpstream {
	ipHelper := &urTunWindowsIphlpapi{settings: defaultUrTunSettings()}
	return urResolverUpstream(func() []netip.Addr {
		adapters, err := ipHelper.Adapters()
		if err != nil {
			return nil
		}
		servers := []netip.Addr{}
		for _, adapter := range adapters {
			for _, resolver := range adapter.resolvers {
				resolver = resolver.Unmap()
				if (routed != nil && routed(resolver)) || slices.Contains(servers, resolver) {
					continue
				}
				servers = append(servers, resolver)
			}
		}
		return servers
	})
}
