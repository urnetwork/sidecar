//go:build !ios_extension && !sidecar_http

// Listeners' settings, DESIGN-COMPUTE §26's, which LSTN's tasks fill. Every limit, size, count, time, interval,
// threshold, retry or budget the component reads is a field here, its default set only in DefaultListenersSettings,
// protocol and format limits included; only identifiers stay constants (QD-702). The struct is created empty by the
// compute skeleton (CARCH-M11-01, CONTRACTS C-38), so no later task edits settings.go: SidecarSettings holds it, and
// DefaultSidecarSettings sets it from DefaultListenersSettings.
//
// The listeners file's limits (EntryMaxCount, DescriptionMaxCharCount, FieldMaxByteCount, FileMaxByteCount) are a
// format's: the device that writes a list and every device that reads it hold them alike, so a deployment never changes
// one on one side alone. The file's writer and its readers are both this package (listeners_file.go), so this object
// is the one place they live.
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go).

package sidecar

import (
	"fmt"
	"time"
)

// DESIGN-COMPUTE §26, listeners: discovery, the list, the listeners repo, publishing and hiding, the live ask, the
// viewer and the agents' tool. A settings value is read, never changed, once a component holds it.
type ListenersSettings struct {
	// Discovery (§26.5).

	// How often the bridge dumps its OS's socket tables while it runs: 15 s (§26.5's poll). A live ask (§26.8) and a
	// destruction notice dump at once beside it. Positive.
	PollInterval time.Duration
	// The most one dump may take before it is cut; a cut dump is no change, never every socket gone. 5 s, proposed: the
	// design names none, and a dump of a few hundred sockets takes a few milliseconds. Positive.
	DumpTimeout time.Duration
	// The most owner lookups one dump makes: on Linux the /proc/<pid>/fd links read, on macOS the socket fds asked of
	// libproc. 4,096, proposed: the design names none. A dump that spends it before every new socket has an owner
	// resumes at the next, the rest unnamed until then. Positive.
	OwnerScanMaxCount int
	// The most bytes one OS table may take: a sysctl pcblist, an iphlpapi table, a libproc pid or fd list. 16 MiB,
	// proposed: a table past it is a failed dump, which changes nothing. Positive.
	TableMaxByteCount int
	// The buffer one netlink read takes on Linux: 64 KiB. A message the kernel cut to fit it (MSG_TRUNC) fails the dump,
	// which changes nothing. Positive.
	NetlinkReadByteCount int
	// The longest program path, in UTF-16 units, QueryFullProcessImageNameW is asked for on Windows: 32,768, Windows'
	// longest path. A longer one reads as "a system program". Positive.
	ImageNameMaxCharCount int
	// The first port of the OS's ephemeral range on macOS and Windows, and on any OS whose discoverer reads none:
	// 49152 (§26.5, IANA's dynamic range). A UDP server's port is under it (Q-LSTN-6). Positive.
	EphemeralFirstPort uint16
	// Linux's, where /proc/sys/net/ipv4/ip_local_port_range cannot be read: 32768, the kernel's default (§26.5).
	// Positive.
	LinuxEphemeralFirstPort uint16
	// The platforms' own UDP responders, which are never a listed UDP server: DHCP 67 and 68, NetBIOS 137 and 138, SSDP
	// 1900, mDNS 5353 and LLMNR 5355 (§26.5).
	UdpResponderPorts []uint16

	// The list and its file (§26.4, §26.6).

	// The most entries a device lists: 512 (§26.5's caps), maps, forwards, tls, ssh and sock entries first, then sockets
	// by port, truncated set past it. A file holding more is refused. The own view takes as many. Positive.
	EntryMaxCount int
	// The longest description, in characters (Unicode code points): 64 (§26.5's caps, D-LSTN-2). A writer cuts a
	// description to it, and a reader refuses a file holding a longer one. A label is held to it too. Positive.
	DescriptionMaxCharCount int
	// The longest bind, target, to or name an entry holds, in bytes: 255, a DNS name's bound, proposed: the design
	// names none. A writer drops an entry whose field is longer; a reader refuses the file. Positive.
	FieldMaxByteCount int
	// The most bytes a listeners file may hold: 256 KiB, proposed: the design names none; 512 entries of the longest
	// fields fit. A reader refuses a longer file before it parses it, and a writer refuses to write one. Positive.
	FileMaxByteCount int
	// The most labels a device keeps (`ur listeners label`), and the most hides where no discovery component keeps
	// them: 1,024, proposed, as discovery's HideCount. Positive.
	LabelMaxCount int
	// The common web ports, by which an entry is openable in the system browser (§26.10): 80, 443, 3000, 5173, 8000,
	// 8080, 8443 and 8888, judged by port and label and never by connecting.
	WebPorts []uint16

	// Publishing (§26.6's When).

	// How long after the last change a list is written: 10 s. Positive.
	PublishDelay time.Duration
	// The least time between two writes of a device's list: 1 min. A hide is written at once whatever it says.
	// Positive.
	PublishMinInterval time.Duration
	// How often an unchanged list is written again: 6 h. Positive.
	PublishRefreshInterval time.Duration

	// The viewer and the live ask (§26.7, §26.8).

	// How old a host's list is before its entries read offline, unless the host answers a live ask: 30 min. Positive.
	OfflineAge time.Duration
	// The least time between two answers a host gives one asker; a repeat inside it is answered from the last answer,
	// not a new dump: 10 s (D-LSTN-7). Positive.
	AskMinInterval time.Duration

	// The agents' tool (§26.9).

	// The longest description token a model reads, in characters: 32 (§26.9). Positive.
	ModelTokenMaxCharCount int
	// The most bytes of description tokens one listeners_list result carries, the rest withheld and counted: 2 KiB
	// (§26.9). Positive.
	ModelDescriptionMaxByteCount int
}

// The component's defaults, the only place one is set.
func DefaultListenersSettings() *ListenersSettings {
	return &ListenersSettings{
		PollInterval:            15 * time.Second,
		DumpTimeout:             5 * time.Second,
		OwnerScanMaxCount:       4096,
		TableMaxByteCount:       16 * 1024 * 1024,
		NetlinkReadByteCount:    64 * 1024,
		ImageNameMaxCharCount:   32768,
		EphemeralFirstPort:      49152,
		LinuxEphemeralFirstPort: 32768,
		UdpResponderPorts:       []uint16{67, 68, 137, 138, 1900, 5353, 5355},

		EntryMaxCount:           512,
		DescriptionMaxCharCount: 64,
		FieldMaxByteCount:       255,
		FileMaxByteCount:        256 * 1024,
		LabelMaxCount:           1024,
		WebPorts:                []uint16{80, 443, 3000, 5173, 8000, 8080, 8443, 8888},

		PublishDelay:           10 * time.Second,
		PublishMinInterval:     1 * time.Minute,
		PublishRefreshInterval: 6 * time.Hour,

		OfflineAge:     30 * time.Minute,
		AskMinInterval: 10 * time.Second,

		ModelTokenMaxCharCount:       32,
		ModelDescriptionMaxByteCount: 2 * 1024,
	}
}

// An error naming the first field out of its range, nil for settings the component may run on.
func (self *ListenersSettings) validate() error {
	if self == nil {
		return fmt.Errorf("%w: no listeners settings", errInvalidSettings)
	}
	durations := []struct {
		name  string
		value time.Duration
	}{
		{name: "PollInterval", value: self.PollInterval},
		{name: "DumpTimeout", value: self.DumpTimeout},
		{name: "PublishDelay", value: self.PublishDelay},
		{name: "PublishMinInterval", value: self.PublishMinInterval},
		{name: "PublishRefreshInterval", value: self.PublishRefreshInterval},
		{name: "OfflineAge", value: self.OfflineAge},
		{name: "AskMinInterval", value: self.AskMinInterval},
	}
	for _, duration := range durations {
		if duration.value <= 0 {
			return fmt.Errorf("%w: listeners %s is not positive", errInvalidSettings, duration.name)
		}
	}
	counts := []struct {
		name  string
		value int
	}{
		{name: "OwnerScanMaxCount", value: self.OwnerScanMaxCount},
		{name: "TableMaxByteCount", value: self.TableMaxByteCount},
		{name: "NetlinkReadByteCount", value: self.NetlinkReadByteCount},
		{name: "ImageNameMaxCharCount", value: self.ImageNameMaxCharCount},
		{name: "EntryMaxCount", value: self.EntryMaxCount},
		{name: "DescriptionMaxCharCount", value: self.DescriptionMaxCharCount},
		{name: "FieldMaxByteCount", value: self.FieldMaxByteCount},
		{name: "FileMaxByteCount", value: self.FileMaxByteCount},
		{name: "LabelMaxCount", value: self.LabelMaxCount},
		{name: "ModelTokenMaxCharCount", value: self.ModelTokenMaxCharCount},
		{name: "ModelDescriptionMaxByteCount", value: self.ModelDescriptionMaxByteCount},
	}
	for _, count := range counts {
		if count.value <= 0 {
			return fmt.Errorf("%w: listeners %s is not positive", errInvalidSettings, count.name)
		}
	}
	if self.EphemeralFirstPort == 0 || self.LinuxEphemeralFirstPort == 0 {
		return fmt.Errorf("%w: listeners' ephemeral thresholds are not positive", errInvalidSettings)
	}
	return nil
}
