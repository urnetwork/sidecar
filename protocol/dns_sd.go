//go:build !ios_extension

// The watch's format limits and its instance rule (§12.9.1, §17.7.1; owner decision 778), which a host's answer and a
// viewer's check share, so each side's settings carry one DnsSdWireSettings and its defaults stay here. A viewer holds
// every instance a host sends to CheckDnsSdInstance before it keeps one: names and TXT are the host's words, never
// trusted (§17.7.1's who sees what).

package protocol

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

// The watch's limits that both ends hold alike (§17.7.1). Changing one is a protocol change, so a deployment never
// changes it on one side alone.
type DnsSdWireSettings struct {
	// The most instances one answer carries: 256 (InstanceCount). A host truncates past it, setting truncated, and a
	// viewer keeps none past it. Positive.
	InstanceCount int
	// The most bytes one answer's marshalled instances take: 64 KiB (AnswerByteCount). A host truncates past it.
	// Positive.
	AnswerByteCount int
	// The most a TXT record's rdata takes: 1,300 B (TxtByteCount; RFC 6763 §6.2). Positive.
	TxtByteCount int
	// The most an instance's name takes: 63 octets, one DNS label (RFC 6763 §4.1.1). Positive.
	NameByteCount int
	// The longest a host holds a watch before it answers unchanged: 50 s (WatchHoldTimeout), under §6.6's 55 s call
	// bound. A viewer asks for no longer, and a host holds no longer whatever it is asked. Positive.
	WatchHoldTimeout time.Duration
}

// The protocol's values (§17.7.1).
func DefaultDnsSdWireSettings() *DnsSdWireSettings {
	return &DnsSdWireSettings{
		InstanceCount:    256,
		AnswerByteCount:  64 * 1024,
		TxtByteCount:     1300,
		NameByteCount:    63,
		WatchHoldTimeout: 50 * time.Second,
	}
}

// An instance a viewer must not keep, or a host must not publish.
var ErrDnsSdInstanceInvalid = errors.New("dns-sd instance invalid")

// The longest LDH label DNS carries (RFC 1035 §2.3.4): a protocol fact, so a constant.
const dnsSdLabelMaxByteCount = 63

// Holds instance to the watch's rule: a name of one label of UTF-8, at most NameByteCount octets and free of control
// characters; a service type by dns_sd_name.go's rule; subtypes each one such label free of dots; a port; a TXT rdata
// of whole character-strings within TxtByteCount, or none; an LDH host label; an IPv4 address. The error says which
// field, never its value.
func CheckDnsSdInstance(instance *DnsSdInstance, settings *DnsSdWireSettings) error {
	if settings == nil {
		settings = DefaultDnsSdWireSettings()
	}
	if instance == nil {
		return fmt.Errorf("%w: none", ErrDnsSdInstanceInvalid)
	}
	if !ValidDnsSdInstanceName(instance.GetName(), settings) {
		return fmt.Errorf("%w: its name", ErrDnsSdInstanceInvalid)
	}
	if !ValidDnsSdServiceType(instance.GetService()) {
		return fmt.Errorf("%w: its service type", ErrDnsSdInstanceInvalid)
	}
	for _, subtype := range instance.GetSubtypes() {
		if !validDnsSdSubtype(subtype) {
			return fmt.Errorf("%w: a subtype", ErrDnsSdInstanceInvalid)
		}
	}
	if instance.GetPort() == 0 || 0xFFFF < instance.GetPort() {
		return fmt.Errorf("%w: its port", ErrDnsSdInstanceInvalid)
	}
	if !ValidDnsSdTxt(instance.GetTxt(), settings) {
		return fmt.Errorf("%w: its txt", ErrDnsSdInstanceInvalid)
	}
	if !ValidDnsSdHostLabel(instance.GetHostLabel()) {
		return fmt.Errorf("%w: its host label", ErrDnsSdInstanceInvalid)
	}
	if instance.GetIpv4() == 0 {
		return fmt.Errorf("%w: its address", ErrDnsSdInstanceInvalid)
	}
	return nil
}

// Whether name is an instance name: valid UTF-8 of one to NameByteCount octets, with no control character (RFC 6763
// §4.1.1).
func ValidDnsSdInstanceName(name string, settings *DnsSdWireSettings) bool {
	if name == "" || settings.NameByteCount < len(name) || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7F {
			return false
		}
	}
	return true
}

// Whether label is a subtype: one label of UTF-8, at most 63 octets, with no control character and no dot, so its
// presentation form needs no escape.
func validDnsSdSubtype(label string) bool {
	if label == "" || dnsSdLabelMaxByteCount < len(label) || !utf8.ValidString(label) {
		return false
	}
	for _, r := range label {
		if r < 0x20 || r == 0x7F || r == '.' || r == '\\' {
			return false
		}
	}
	return true
}

// Whether label is an LDH host label: ASCII letters, digits and hyphens, one to 63, with no hyphen at either end.
func ValidDnsSdHostLabel(label string) bool {
	if label == "" || dnsSdLabelMaxByteCount < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i += 1 {
		c := label[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// Whether txt is a TXT rdata the watch carries: empty, which reads as one empty string (RFC 6763 §6.1), or whole
// length-prefixed character-strings within TxtByteCount.
func ValidDnsSdTxt(txt []byte, settings *DnsSdWireSettings) bool {
	if settings.TxtByteCount < len(txt) {
		return false
	}
	for at := 0; at < len(txt); {
		at += 1 + int(txt[at])
		if len(txt) < at {
			return false
		}
	}
	return true
}
