//go:build !ios_extension

package protocol

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// §12.9.1's field lists, name for name and number for number, until a design fold fences them (owner decision 778).
func TestDnsSdWatchMessagesHaveTheDesignsFields(t *testing.T) {
	cases := []struct {
		name   string
		fields []string
	}{
		{name: "DnsSdWatch", fields: []string{"since", "hold_ms"}},
		{name: "DnsSdWatchResult", fields: []string{"version", "serving", "instances", "truncated"}},
		{
			name:   "DnsSdInstance",
			fields: []string{"name", "service", "subtypes", "port", "txt", "host_label", "ipv4", "own", "ttl"},
		},
	}
	for _, c := range cases {
		fields := testMessage(t, c.name).Fields()
		if fields.Len() != len(c.fields) {
			t.Errorf("%s has %d fields, and §12.9.1 lists %d", c.name, fields.Len(), len(c.fields))
			continue
		}
		for i, want := range c.fields {
			if field := fields.ByNumber(protoreflect.FieldNumber(i + 1)); field == nil || string(field.Name()) != want {
				t.Errorf("%s's field %d should be %s", c.name, i+1, want)
			}
		}
	}
	if kind := testMessage(t, "DnsSdInstance").Fields().ByName("ipv4").Kind(); kind != protoreflect.Fixed32Kind {
		t.Errorf("ipv4 is %v", kind)
	}
	if MessageType_DNS_SD_WATCH != 0x1B02 || MessageType_DNS_SD_WATCH_RESULT != MessageType_DNS_SD_WATCH+1 {
		t.Errorf("the watch's numbers are %#x and %#x", MessageType_DNS_SD_WATCH, MessageType_DNS_SD_WATCH_RESULT)
	}
}

// The service type rule: RFC 6335's names under one DNS label, either transport, any case in, lowercase out.
func TestDnsSdServiceTypes(t *testing.T) {
	accepted := map[string]string{
		"_ipp._tcp":                             "ipp",
		"_IPP._TCP":                             "ipp",
		"_remotepairing._tcp":                   "remotepairing",
		"_remotepairing-manual-pairing._tcp":    "remotepairing-manual-pairing",
		"_apple-mobdev2._tcp":                   "apple-mobdev2",
		"_sftp-ssh._tcp":                        "sftp-ssh",
		"_x1._udp":                              "x1",
		"_" + strings.Repeat("a", 62) + "._tcp": strings.Repeat("a", 62),
	}
	for text, want := range accepted {
		name, _, ok := ParseDnsSdServiceType(text)
		if !ok || name != want {
			t.Errorf("%q read as %q, %t", text, name, ok)
		}
	}
	refused := []string{
		"", "_ipp", "ipp._tcp", "_ipp._sctp", "_ipp._tcp.", "_-ipp._tcp", "_ipp-._tcp", "_ip--p._tcp", "_123._tcp",
		"__ipp._tcp", "_ip p._tcp", "_ipp._tcp._tcp", "_" + strings.Repeat("a", 63) + "._tcp", "_._tcp", "_ipp_._tcp",
	}
	for _, text := range refused {
		if ValidDnsSdServiceType(text) {
			t.Errorf("%q passed", text)
		}
	}
}

// A good instance passes, and each field's fault is refused by name, never by value.
func TestCheckDnsSdInstanceRefusesEachFault(t *testing.T) {
	settings := DefaultDnsSdWireSettings()
	good := func() *DnsSdInstance {
		return &DnsSdInstance{
			Name:      "Synthetic Phone (2)",
			Service:   "_remotepairing._tcp",
			Subtypes:  []string{"_printer"},
			Port:      49152,
			Txt:       []byte("\x07authTag\x00"),
			HostLabel: "phone-1",
			Ipv4:      0xC0000201,
			Own:       false,
			Ttl:       120,
		}
	}
	if err := CheckDnsSdInstance(good(), settings); err != nil {
		t.Fatalf("a good instance: %v", err)
	}
	empty := good()
	empty.Txt = nil
	if err := CheckDnsSdInstance(empty, settings); err != nil {
		t.Errorf("an empty txt: %v", err)
	}
	faults := map[string]func(instance *DnsSdInstance){
		"name":       func(instance *DnsSdInstance) { instance.Name = "" },
		"long name":  func(instance *DnsSdInstance) { instance.Name = strings.Repeat("é", 32) },
		"control":    func(instance *DnsSdInstance) { instance.Name = "a\x01b" },
		"bad utf-8":  func(instance *DnsSdInstance) { instance.Name = "a\xffb" },
		"service":    func(instance *DnsSdInstance) { instance.Service = "_ipp" },
		"subtype":    func(instance *DnsSdInstance) { instance.Subtypes = []string{"a.b"} },
		"port":       func(instance *DnsSdInstance) { instance.Port = 0 },
		"high port":  func(instance *DnsSdInstance) { instance.Port = 0x10000 },
		"cut txt":    func(instance *DnsSdInstance) { instance.Txt = []byte("\x09short") },
		"long txt":   func(instance *DnsSdInstance) { instance.Txt = append([]byte{}, make([]byte, 1301)...) },
		"host label": func(instance *DnsSdInstance) { instance.HostLabel = "phone.local" },
		"no address": func(instance *DnsSdInstance) { instance.Ipv4 = 0 },
	}
	for name, fault := range faults {
		instance := good()
		fault(instance)
		err := CheckDnsSdInstance(instance, settings)
		if err == nil {
			t.Errorf("%s passed", name)
			continue
		}
		if strings.Contains(err.Error(), "Synthetic") || strings.Contains(err.Error(), "authTag") {
			t.Errorf("%s's refusal names a value: %v", name, err)
		}
	}
	if err := CheckDnsSdInstance(nil, settings); err == nil {
		t.Errorf("no instance passed")
	}
}
