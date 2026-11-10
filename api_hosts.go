//go:build !ios_extension

// §18.9's host list (D-SDK-7, R-SDK-10): the hosts a sidecar reaches, what each is needed for, and the issuer SPKIs
// a chain to each may end at. api_hosts_v1.json is the one copy of these names (QD-119): ur fills its service urls
// from it, sdk takes each service's label from it and puts that under its NetworkSpace's host, mmm publishes it at
// ur.io's /recurd/hosts/v1.json as PublishedJson writes it (QD-566), and ur status probes each entry. No other file
// names a production host: tests build lists of .example names (CODESTYLE's test data rule).
//
// The issuer SPKIs are data the release supplies (§18.9). Until it does an entry has none, and a probe cannot tell
// an intercepted chain from a real one, which ur status says rather than guesses.
//
// On every leg: it names no connect type and reads no certificate, so the page Worker links only encoding/json here.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
)

//go:embed api_hosts_v1.json
var sidecarHostListV1Json []byte

// The list's format version, which its published path also carries (/recurd/hosts/v1.json).
const sidecarHostListVersion = 1

// A list that does not hold to its format.
var ErrSidecarHostList = errors.New("host list refused")

// Which of SidecarSettings' urls a host is.
type SidecarHostService string

const (
	SidecarHostServiceApi  SidecarHostService = "api"
	SidecarHostServiceAuth SidecarHostService = "auth"
	SidecarHostServiceEvs  SidecarHostService = "evs"
	SidecarHostServiceGkm  SidecarHostService = "gkm"
	// PlatformUrl, a wss url, where every other service's is https.
	SidecarHostServicePlatform SidecarHostService = "platform"
	SidecarHostServiceSockets  SidecarHostService = "sockets"
	SidecarHostServiceDns      SidecarHostService = "dns"
)

// Every service a list must name for ApplyServiceUrls, in SidecarSettings' order.
var sidecarHostServices = []SidecarHostService{
	SidecarHostServiceApi,
	SidecarHostServicePlatform,
	SidecarHostServiceAuth,
	SidecarHostServiceEvs,
	SidecarHostServiceGkm,
	SidecarHostServiceSockets,
	SidecarHostServiceDns,
}

// When a host is needed: §18.9's need column, as a value.
type SidecarHostRequirement string

const (
	// On every rung: without it a sidecar runs nothing.
	SidecarHostRequired SidecarHostRequirement = "required"
	// Rungs 1 and 2: RPC, streams, sockets, mail and bridge. Without it a sidecar is on rung 3, HTTPS-only.
	SidecarHostStreams SidecarHostRequirement = "streams"
	// With sockets (§9).
	SidecarHostWithSockets SidecarHostRequirement = "sockets"
	// With records or TLSA (§12.8).
	SidecarHostWithDns SidecarHostRequirement = "dns"
	// With tls: the CT watch (§13).
	SidecarHostWithTls SidecarHostRequirement = "tls"
	// Never needed to run.
	SidecarHostOptional SidecarHostRequirement = "optional"
)

// Every requirement a list may name.
var sidecarHostRequirements = []SidecarHostRequirement{
	SidecarHostRequired,
	SidecarHostStreams,
	SidecarHostWithSockets,
	SidecarHostWithDns,
	SidecarHostWithTls,
	SidecarHostOptional,
}

// One host of the list.
type SidecarHostListEntry struct {
	// A lowercase DNS name.
	Host string `json:"host"`
	// The TCP port, 443 for every host today.
	Tcp int `json:"tcp"`
	// Why a sidecar reaches it, in §18.9's words, as the list is published.
	Need string `json:"need"`
	// The url it fills, or empty for a host no setting names.
	Service     SidecarHostService     `json:"service,omitempty"`
	Requirement SidecarHostRequirement `json:"requirement"`
	// Standard base64 of SHA-256 over each issuer's SubjectPublicKeyInfo a chain to this host may end at. Empty
	// until the release supplies them.
	IssuerSpkiSha256 []string `json:"issuer_spki_sha256,omitempty"`
}

// host:tcp, for a dial.
func (self *SidecarHostListEntry) Address() string {
	return net.JoinHostPort(self.Host, strconv.Itoa(self.Tcp))
}

// The SHA-256 digests IssuerSpkiSha256 carries.
func (self *SidecarHostListEntry) IssuerSpkiDigests() ([][sha256.Size]byte, error) {
	digests := [][sha256.Size]byte{}
	for _, encoded := range self.IssuerSpkiSha256 {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(decoded) != sha256.Size {
			return nil, fmt.Errorf("%w: an issuer digest of %s is not base64 of 32 bytes", ErrSidecarHostList, self.Host)
		}
		digests = append(digests, [sha256.Size]byte(decoded))
	}
	return digests, nil
}

// §18.9's table.
type SidecarHostList struct {
	Version int                    `json:"version"`
	Hosts   []SidecarHostListEntry `json:"hosts"`
}

// A copy sharing no slice.
func (self *SidecarHostList) clone() *SidecarHostList {
	clone := &SidecarHostList{Version: self.Version, Hosts: slices.Clone(self.Hosts)}
	for i := range clone.Hosts {
		clone.Hosts[i].IssuerSpkiSha256 = slices.Clone(self.Hosts[i].IssuerSpkiSha256)
	}
	return clone
}

// The list data holds, refusing a field it does not know, a second value, and anything that breaks the format.
func ParseSidecarHostList(data []byte) (*SidecarHostList, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	list := &SidecarHostList{}
	if err := decoder.Decode(list); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrSidecarHostList, err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("%w: more than one value", ErrSidecarHostList)
	}
	if err := list.validate(); err != nil {
		return nil, err
	}
	return list, nil
}

// The embedded list, parsed once.
var sidecarHostListV1 = sync.OnceValues(func() (*SidecarHostList, error) {
	return ParseSidecarHostList(sidecarHostListV1Json)
})

// The list this binary was built with, a copy each call.
func SidecarHostListV1() (*SidecarHostList, error) {
	list, err := sidecarHostListV1()
	if err != nil {
		return nil, err
	}
	return list.clone(), nil
}

// The format's rules: version 1, at least one host, each a lowercase DNS name once, a port, words for its need, a
// known requirement, a service at most once and only a known one, and issuer digests of 32 bytes.
func (self *SidecarHostList) validate() error {
	refuse := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrSidecarHostList, fmt.Sprintf(format, args...))
	}
	if self.Version != sidecarHostListVersion {
		return refuse("version %d", self.Version)
	}
	if len(self.Hosts) == 0 {
		return refuse("no hosts")
	}
	hosts := map[string]bool{}
	services := map[SidecarHostService]bool{}
	for i := range self.Hosts {
		entry := &self.Hosts[i]
		if !isSidecarHostName(entry.Host) {
			return refuse("host %d is not a lowercase DNS name", i)
		}
		if hosts[entry.Host] {
			return refuse("host %d is listed twice", i)
		}
		hosts[entry.Host] = true
		if entry.Tcp < 1 || 65535 < entry.Tcp {
			return refuse("host %d has no port", i)
		}
		if strings.TrimSpace(entry.Need) == "" || strings.ContainsFunc(entry.Need, func(r rune) bool { return r < ' ' || r == 0x7f }) {
			return refuse("host %d's need is not a line of text", i)
		}
		if !slices.Contains(sidecarHostRequirements, entry.Requirement) {
			return refuse("host %d's requirement %q", i, entry.Requirement)
		}
		if entry.Service != "" {
			if !slices.Contains(sidecarHostServices, entry.Service) {
				return refuse("host %d's service %q", i, entry.Service)
			}
			if services[entry.Service] {
				return refuse("service %q is listed twice", entry.Service)
			}
			services[entry.Service] = true
		}
		if _, err := entry.IssuerSpkiDigests(); err != nil {
			return err
		}
	}
	return nil
}

// Whether name is a lowercase DNS name of two or more labels, each 1 to 63 of [a-z0-9-] with no dash at either end.
func isSidecarHostName(name string) bool {
	if len(name) == 0 || 253 < len(name) {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || 63 < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i += 1 {
			c := label[i]
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// The entry of service, if the list names it.
func (self *SidecarHostList) ServiceEntry(service SidecarHostService) (*SidecarHostListEntry, bool) {
	for i := range self.Hosts {
		if self.Hosts[i].Service == service {
			return &self.Hosts[i], true
		}
	}
	return nil, false
}

// The first label of service's host, which an sdk host puts under its NetworkSpace's host as it does api and connect
// (sdk's ServiceUrl), so a test space's urls stay its own.
func (self *SidecarHostList) ServiceLabel(service SidecarHostService) (string, error) {
	entry, ok := self.ServiceEntry(service)
	if !ok {
		return "", fmt.Errorf("%w: no %s host", ErrSidecarHostList, service)
	}
	label, _, _ := strings.Cut(entry.Host, ".")
	return label, nil
}

// Sets every service url of settings from the list: https://<host>, wss://<host> for the platform, with :<tcp> unless
// it is 443. A list missing a service changes nothing and refuses, so a host never runs on half a list.
func (self *SidecarHostList) ApplyServiceUrls(settings *SidecarSettings) error {
	urls := map[SidecarHostService]string{}
	for _, service := range sidecarHostServices {
		entry, ok := self.ServiceEntry(service)
		if !ok {
			return fmt.Errorf("%w: no %s host", ErrSidecarHostList, service)
		}
		scheme := "https"
		if service == SidecarHostServicePlatform {
			scheme = "wss"
		}
		authority := entry.Host
		if entry.Tcp != 443 {
			authority = entry.Address()
		}
		urls[service] = scheme + "://" + authority
	}
	settings.ApiUrl = urls[SidecarHostServiceApi]
	settings.PlatformUrl = urls[SidecarHostServicePlatform]
	settings.AuthUrl = urls[SidecarHostServiceAuth]
	settings.EvsUrl = urls[SidecarHostServiceEvs]
	settings.GkmUrl = urls[SidecarHostServiceGkm]
	settings.SocketsUrl = urls[SidecarHostServiceSockets]
	settings.DnsUrl = urls[SidecarHostServiceDns]
	return nil
}

// The list as mmm publishes it (QD-566): {"version":1,"hosts":[{"host","tcp","need"}]}, indented, with a final
// newline. Requirement, service and the issuer digests stay in ur.
func (self *SidecarHostList) PublishedJson() ([]byte, error) {
	type publishedHost struct {
		Host string `json:"host"`
		Tcp  int    `json:"tcp"`
		Need string `json:"need"`
	}
	type publishedList struct {
		Version int             `json:"version"`
		Hosts   []publishedHost `json:"hosts"`
	}
	published := &publishedList{Version: self.Version, Hosts: []publishedHost{}}
	for _, entry := range self.Hosts {
		published.Hosts = append(published.Hosts, publishedHost{Host: entry.Host, Tcp: entry.Tcp, Need: entry.Need})
	}
	encoded := &bytes.Buffer{}
	encoder := json.NewEncoder(encoded)
	// a need's words as written, never as & and its kind
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(published); err != nil {
		return nil, err
	}
	return encoded.Bytes(), nil
}
