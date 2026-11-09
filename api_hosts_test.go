// §18.9's host list: the embedded table's shape, the format's refusals, the urls a list fills, and the published
// copy. Every list a test builds names .example hosts; the embedded one is read only for its shape, never dialed.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A list naming every service under hosttest.example, the platform on another port.
func testSidecarHostListJson() string {
	digest := sha256.Sum256([]byte("synthetic issuer spki"))
	return `{
  "version": 1,
  "hosts": [
    {"host": "api.hosttest.example", "tcp": 443, "need": "required: api", "service": "api", "requirement": "required"},
    {"host": "auth.hosttest.example", "tcp": 443, "need": "required: auth", "service": "auth", "requirement": "required"},
    {"host": "evs.hosttest.example", "tcp": 443, "need": "required: evs", "service": "evs", "requirement": "required"},
    {"host": "gkm.hosttest.example", "tcp": 443, "need": "required: gkm", "service": "gkm", "requirement": "required"},
    {"host": "connect.hosttest.example", "tcp": 8443, "need": "rungs 1-2", "service": "platform", "requirement": "streams"},
    {"host": "sockets.hosttest.example", "tcp": 443, "need": "with sockets", "service": "sockets", "requirement": "sockets"},
    {"host": "dns.hosttest.example", "tcp": 443, "need": "with records & TLSA", "service": "dns", "requirement": "dns",
     "issuer_spki_sha256": ["` + base64.StdEncoding.EncodeToString(digest[:]) + `"]},
    {"host": "ct.hosttest.example", "tcp": 443, "need": "with tls", "requirement": "tls"},
    {"host": "hosttest.example", "tcp": 443, "need": "optional", "requirement": "optional"}
  ]
}`
}

// The table this binary embeds parses, names every service once, holds §18.9's rungs, and fills settings that
// validate. It is read for its shape only: no test names or dials its hosts.
func TestEmbeddedHostListHoldsEveryService(t *testing.T) {
	list, err := SidecarHostListV1()
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range sidecarHostServices {
		entry, ok := list.ServiceEntry(service)
		if !ok {
			t.Fatalf("no %s host", service)
		}
		want := SidecarHostRequired
		switch service {
		case SidecarHostServicePlatform:
			want = SidecarHostStreams
		case SidecarHostServiceSockets:
			want = SidecarHostWithSockets
		case SidecarHostServiceDns:
			want = SidecarHostWithDns
		}
		if entry.Requirement != want || entry.Tcp != 443 {
			t.Errorf("the %s host needs %s on %d", service, entry.Requirement, entry.Tcp)
		}
	}
	requirements := map[SidecarHostRequirement]int{}
	for _, entry := range list.Hosts {
		requirements[entry.Requirement] += 1
	}
	// §18.9: four required hosts, the platform's rungs, and the CT watch's two
	if requirements[SidecarHostRequired] != 4 || requirements[SidecarHostStreams] != 1 || requirements[SidecarHostWithTls] != 2 {
		t.Errorf("requirements %v", requirements)
	}

	settings := DefaultSidecarSettings()
	if err := list.ApplyServiceUrls(settings); err != nil {
		t.Fatal(err)
	}
	if err := settings.validate(); err != nil {
		t.Errorf("the embedded urls do not validate: %v", err)
	}
	if !strings.HasPrefix(settings.PlatformUrl, "wss://") || !strings.HasPrefix(settings.ApiUrl, "https://") {
		t.Errorf("schemes %s, %s", settings.PlatformUrl, settings.ApiUrl)
	}
}

// Each call is a copy, so a caller's edit reaches no other.
func TestEmbeddedHostListIsACopyEachCall(t *testing.T) {
	first, err := SidecarHostListV1()
	if err != nil {
		t.Fatal(err)
	}
	first.Hosts[0].Host = "edited.hosttest.example"
	first.Hosts[0].IssuerSpkiSha256 = append(first.Hosts[0].IssuerSpkiSha256, "edited")
	second, err := SidecarHostListV1()
	if err != nil {
		t.Fatal(err)
	}
	if second.Hosts[0].Host == "edited.hosttest.example" || slices.Contains(second.Hosts[0].IssuerSpkiSha256, "edited") {
		t.Error("an edit to one copy reached the next")
	}
}

// ur.io's published copy is PublishedJson of the embedded table, byte for byte (SDK-M4-06 publishes it from mmm).
func TestHostListMatchesPublished(t *testing.T) {
	path := filepath.Join("..", "mmm", "ur.io", "astro", "public", "recurd", "hosts", "v1.json")
	published, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("no published copy at %s: SDK-M4-06 publishes it from mmm", path)
	}
	if err != nil {
		t.Fatal(err)
	}
	list, err := SidecarHostListV1()
	if err != nil {
		t.Fatal(err)
	}
	want, err := list.PublishedJson()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(published, want) {
		t.Errorf("the published copy differs from the embedded table:\n%s\nwant\n%s", published, want)
	}
}

// A fixture list fills every url, the platform as wss with its port, and the result validates.
func TestApplyServiceUrlsFillsEveryUrl(t *testing.T) {
	list, err := ParseSidecarHostList([]byte(testSidecarHostListJson()))
	if err != nil {
		t.Fatal(err)
	}
	settings := DefaultSidecarSettings()
	if err := list.ApplyServiceUrls(settings); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		settings.ApiUrl:      "https://api.hosttest.example",
		settings.PlatformUrl: "wss://connect.hosttest.example:8443",
		settings.AuthUrl:     "https://auth.hosttest.example",
		settings.EvsUrl:      "https://evs.hosttest.example",
		settings.GkmUrl:      "https://gkm.hosttest.example",
		settings.SocketsUrl:  "https://sockets.hosttest.example",
		settings.DnsUrl:      "https://dns.hosttest.example",
	}
	for got, wanted := range want {
		if got != wanted {
			t.Errorf("a url is %q, not %q", got, wanted)
		}
	}
	if len(want) != 7 {
		t.Errorf("%d distinct urls", len(want))
	}
	if err := settings.validate(); err != nil {
		t.Error(err)
	}
	label, err := list.ServiceLabel(SidecarHostServicePlatform)
	if err != nil || label != "connect" {
		t.Errorf("the platform's label is %q, %v", label, err)
	}
}

// A list missing a service fills nothing and refuses.
func TestApplyServiceUrlsRefusesAPartialList(t *testing.T) {
	partial := strings.Replace(testSidecarHostListJson(), `"service": "gkm", `, ``, 1)
	list, err := ParseSidecarHostList([]byte(partial))
	if err != nil {
		t.Fatal(err)
	}
	settings := DefaultSidecarSettings()
	if err := list.ApplyServiceUrls(settings); !errors.Is(err, ErrSidecarHostList) {
		t.Fatalf("a list with no gkm host applied: %v", err)
	}
	if settings.ApiUrl != "" || settings.EvsUrl != "" {
		t.Error("a refused list filled urls")
	}
	if _, err := list.ServiceLabel(SidecarHostServiceGkm); err == nil {
		t.Error("a label for a service the list does not name")
	}
}

// Each thing the format forbids refuses the whole list.
func TestParseHostListRefusesWhatBreaksTheFormat(t *testing.T) {
	valid := testSidecarHostListJson()
	cases := map[string]string{
		"version":           strings.Replace(valid, `"version": 1`, `"version": 2`, 1),
		"no hosts":          `{"version": 1, "hosts": []}`,
		"uppercase host":    strings.Replace(valid, `"api.hosttest.example"`, `"Api.hosttest.example"`, 1),
		"one label":         strings.Replace(valid, `"hosttest.example", "tcp"`, `"hosttest", "tcp"`, 1),
		"dash edge":         strings.Replace(valid, `"api.hosttest.example"`, `"-api.hosttest.example"`, 1),
		"twice":             strings.Replace(valid, `"auth.hosttest.example"`, `"api.hosttest.example"`, 1),
		"no port":           strings.Replace(valid, `"tcp": 8443`, `"tcp": 0`, 1),
		"empty need":        strings.Replace(valid, `"need": "optional"`, `"need": " "`, 1),
		"control in need":   strings.Replace(valid, `"need": "optional"`, `"need": "opt\u0007ional"`, 1),
		"requirement":       strings.Replace(valid, `"requirement": "optional"`, `"requirement": "sometimes"`, 1),
		"service":           strings.Replace(valid, `"service": "dns"`, `"service": "ntp"`, 1),
		"service twice":     strings.Replace(valid, `"service": "dns"`, `"service": "api"`, 1),
		"short digest":      strings.Replace(valid, `"issuer_spki_sha256": ["`, `"issuer_spki_sha256": ["AAAA", "`, 1),
		"unknown field":     strings.Replace(valid, `"version": 1,`, `"version": 1, "extra": true,`, 1),
		"two values":        valid + valid,
		"not an object":     `[]`,
		"no requirement":    strings.Replace(valid, `, "requirement": "optional"`, ``, 1),
		"port out of range": strings.Replace(valid, `"tcp": 8443`, `"tcp": 65536`, 1),
	}
	for name, data := range cases {
		if _, err := ParseSidecarHostList([]byte(data)); !errors.Is(err, ErrSidecarHostList) {
			t.Errorf("%s: parsed, %v", name, err)
		}
	}
	if _, err := ParseSidecarHostList([]byte(valid)); err != nil {
		t.Errorf("the valid list: %v", err)
	}
}

// The published copy carries the version and each host's host, tcp and need, in order, and nothing ur keeps for
// itself; a need's words stay as written.
func TestPublishedJsonCarriesOnlyThePublishedFields(t *testing.T) {
	list, err := ParseSidecarHostList([]byte(testSidecarHostListJson()))
	if err != nil {
		t.Fatal(err)
	}
	published, err := list.PublishedJson()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(published, []byte("}\n")) || !bytes.Contains(published, []byte("with records & TLSA")) {
		t.Errorf("published %s", published)
	}
	decoder := json.NewDecoder(bytes.NewReader(published))
	decoder.DisallowUnknownFields()
	read := &struct {
		Version int `json:"version"`
		Hosts   []struct {
			Host string `json:"host"`
			Tcp  int    `json:"tcp"`
			Need string `json:"need"`
		} `json:"hosts"`
	}{}
	if err := decoder.Decode(read); err != nil {
		t.Fatalf("the published copy holds more than its schema: %v", err)
	}
	if read.Version != 1 || len(read.Hosts) != len(list.Hosts) {
		t.Fatalf("published %+v", read)
	}
	for i, host := range read.Hosts {
		entry := list.Hosts[i]
		if host.Host != entry.Host || host.Tcp != entry.Tcp || host.Need != entry.Need {
			t.Errorf("host %d published as %+v", i, host)
		}
	}
}

// An entry's digests decode to 32 bytes each; one that does not refuses.
func TestIssuerSpkiDigestsDecode(t *testing.T) {
	digest := sha256.Sum256([]byte("synthetic issuer spki"))
	entry := &SidecarHostListEntry{Host: "dns.hosttest.example", IssuerSpkiSha256: []string{base64.StdEncoding.EncodeToString(digest[:])}}
	digests, err := entry.IssuerSpkiDigests()
	if err != nil || len(digests) != 1 || digests[0] != digest {
		t.Errorf("digests %x, %v", digests, err)
	}
	entry.IssuerSpkiSha256 = []string{"not base64!"}
	if _, err := entry.IssuerSpkiDigests(); err == nil {
		t.Error("a digest that does not decode")
	}
	if entry.Address() != "dns.hosttest.example:0" {
		t.Errorf("address %s", entry.Address())
	}
}
