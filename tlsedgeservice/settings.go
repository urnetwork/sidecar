// config/<env>/tlsedge.yml (§13.5), with the engine's own tunables beside it. DefaultTlsEdgeSettings is
// the only source of a default (connect/CODESTYLE.md:144), and LoadTlsEdgeSettings lays a file over it
// in the shape §13.5 writes: clients, max_connections, proxy_header, client_hello, find, accept,
// idle_timeout_s and drain_s, plus blocks (reading 12) and root. The engine's own fields have no key
// in the file, since the design's file has none for them, and a host sets them in code.
//
// Ports are not settings: 443, 8443, 8883 and 5671 are owner decisions 68 and 121, the same list the lb
// renders (TLS-M5-04), so they stay a constant in service.go.
//
// Validate refuses a zero or a negative in every count and duration, so none reads as unlimited or off.

package tlsedgeservice

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// A tlsedge.yml or settings the engine cannot serve from. The wrapping error names the field, never its
// value.
var ErrTlsEdgeSettingsRefused = errors.New("tlsedge settings refused")

// What the engine runs on. Safe to read concurrently once built, and never changed after.
type TlsEdgeSettings struct {
	// <root>, the registered domain every published name sits under (§12.4): the label map is read for
	// this root and a name maps only below it. No default: it is a production name, which the file sets.
	// A lowercase dotted LDH name with no trailing dot.
	Root string
	// clients: K, the connect clients each process runs in urnetwork-edge (§13.6). The engine is ready
	// only while its dialer holds this many.
	Clients int
	// max_connections: connections this process serves at once (§13.9), past which a new one gets
	// internal_error before its hello is read.
	MaxConnectionCount int
	// blocks: the number of lb hosts running tlsedge, each host's full-weight g1 block counted once
	// (reading 12). Endpoint concurrency and bandwidth caps divide by it. No default: tlsedge refuses to
	// start without it.
	Blocks int
	// proxy_header: timeout_s and max_bytes, for the host's PROXY listener (§13.4). Its Clock is the
	// host's to set.
	ProxyHeader *ProxyHeaderSettings
	// client_hello.timeout_s: from accept to the hello's last byte.
	ClientHelloTimeout time.Duration
	// client_hello.max_bytes: the most hello bytes read, record headers included.
	ClientHelloMaxByteCount int
	// find.timeout_s and find.max_finds: one Find's wait, and Finds per connection (D-SOCK-6).
	FindTimeout  time.Duration
	FindMaxCount int
	// accept.ticket_timeout_s and accept.setup_timeout_s: one ticket's accept wait, and the whole setup's.
	AcceptTicketTimeout time.Duration
	AcceptSetupTimeout  time.Duration
	// idle_timeout_s: a spliced stream with no byte either way this long ends, as the lb's
	// proxy_timeout does.
	IdleTimeout time.Duration
	// drain_s: how long Drain lets streams run before it resets them.
	DrainTimeout time.Duration

	// The engine's own.

	// How long a no_listener or denied answer refuses its key without a Find (§13.5's 30 s).
	NegativeCacheTtl time.Duration
	// Negative entries held at most, past which the oldest goes, so a name scan costs bounded memory.
	// Default 65,536, about 20 MiB at the longest names.
	NegativeCacheMaxCount int
	// How often the label map's changes are read (plan-TLS-edge-data-source: 5 s, so a withdrawn name
	// stops mapping within 10 s). A failed read waits this long before the next.
	NameReloadInterval time.Duration
	// How often network_tls_suspension's rows and their networks' {tes_} keys are reread (§13.9: 60 s).
	KillReloadInterval time.Duration
	// The wait before a failed {tes_} read is tried again. Default 1 s, so a kill that failed to read once
	// still lands inside §13.9's 5 s.
	KillRetryDelay time.Duration
	// How long one store call may take before it reads as failed. Default 30 s, since a first snapshot
	// reads the whole label map.
	StoreTimeout time.Duration
	// How long one Redis read may take before it reads as failed. Default 1 s.
	RedisTimeout time.Duration
	// The pause after a failed Accept, which keeps a run of them from spinning. Default 100 ms.
	AcceptRetryDelay time.Duration
}

// The design's numbers. Root and Blocks stay unset, so these alone do not pass Validate.
func DefaultTlsEdgeSettings() *TlsEdgeSettings {
	return &TlsEdgeSettings{
		Clients:                 4,
		MaxConnectionCount:      50000,
		ProxyHeader:             DefaultProxyHeaderSettings(),
		ClientHelloTimeout:      10 * time.Second,
		ClientHelloMaxByteCount: 16 * 1024,
		FindTimeout:             2 * time.Second,
		FindMaxCount:            3,
		AcceptTicketTimeout:     5 * time.Second,
		AcceptSetupTimeout:      15 * time.Second,
		IdleTimeout:             900 * time.Second,
		DrainTimeout:            600 * time.Second,
		NegativeCacheTtl:        30 * time.Second,
		NegativeCacheMaxCount:   64 * 1024,
		NameReloadInterval:      5 * time.Second,
		KillReloadInterval:      60 * time.Second,
		KillRetryDelay:          1 * time.Second,
		StoreTimeout:            30 * time.Second,
		RedisTimeout:            1 * time.Second,
		AcceptRetryDelay:        100 * time.Millisecond,
	}
}

// tlsedge.yml as §13.5 writes it: whole seconds and byte counts, nested as in the design's sketch. A
// pointer left nil keeps its default.
type tlsEdgeSettingsFile struct {
	Root           *string `yaml:"root"`
	Clients        *int    `yaml:"clients"`
	MaxConnections *int    `yaml:"max_connections"`
	Blocks         *int    `yaml:"blocks"`
	ProxyHeader    *struct {
		TimeoutS *int `yaml:"timeout_s"`
		MaxBytes *int `yaml:"max_bytes"`
	} `yaml:"proxy_header"`
	ClientHello *struct {
		TimeoutS *int `yaml:"timeout_s"`
		MaxBytes *int `yaml:"max_bytes"`
	} `yaml:"client_hello"`
	Find *struct {
		TimeoutS *int `yaml:"timeout_s"`
		MaxFinds *int `yaml:"max_finds"`
	} `yaml:"find"`
	Accept *struct {
		TicketTimeoutS *int `yaml:"ticket_timeout_s"`
		SetupTimeoutS  *int `yaml:"setup_timeout_s"`
	} `yaml:"accept"`
	IdleTimeoutS *int `yaml:"idle_timeout_s"`
	DrainS       *int `yaml:"drain_s"`
}

// Settings from tlsedge.yml, over the defaults. A key left out keeps its default, so root and blocks
// must be there, and a key not listed here is refused rather than ignored: a misspelled cap would
// otherwise run at its default, unseen.
func LoadTlsEdgeSettings(data []byte) (*TlsEdgeSettings, error) {
	file := &tlsEdgeSettingsFile{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(file); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: %w", ErrTlsEdgeSettingsRefused, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: more than one document", ErrTlsEdgeSettingsRefused)
	}

	settings := DefaultTlsEdgeSettings()
	seconds := func(value *int, target *time.Duration) {
		if value != nil {
			*target = time.Duration(*value) * time.Second
		}
	}
	count := func(value *int, target *int) {
		if value != nil {
			*target = *value
		}
	}
	if file.Root != nil {
		settings.Root = *file.Root
	}
	count(file.Clients, &settings.Clients)
	count(file.MaxConnections, &settings.MaxConnectionCount)
	count(file.Blocks, &settings.Blocks)
	if file.ProxyHeader != nil {
		seconds(file.ProxyHeader.TimeoutS, &settings.ProxyHeader.Timeout)
		count(file.ProxyHeader.MaxBytes, &settings.ProxyHeader.MaxByteCount)
	}
	if file.ClientHello != nil {
		seconds(file.ClientHello.TimeoutS, &settings.ClientHelloTimeout)
		count(file.ClientHello.MaxBytes, &settings.ClientHelloMaxByteCount)
	}
	if file.Find != nil {
		seconds(file.Find.TimeoutS, &settings.FindTimeout)
		count(file.Find.MaxFinds, &settings.FindMaxCount)
	}
	if file.Accept != nil {
		seconds(file.Accept.TicketTimeoutS, &settings.AcceptTicketTimeout)
		seconds(file.Accept.SetupTimeoutS, &settings.AcceptSetupTimeout)
	}
	seconds(file.IdleTimeoutS, &settings.IdleTimeout)
	seconds(file.DrainS, &settings.DrainTimeout)
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	return settings, nil
}

// Whether a name is a lowercase dotted LDH name of at least two labels with no trailing dot: what a
// root must be for a suffix match on normalized names to mean what it says.
func tlsEdgeRootValid(root string) bool {
	if !strings.Contains(root, ".") {
		return false
	}
	normalized, ok := NormalizeSni(root)
	return ok && normalized == root
}

// Whether these settings can run the engine. A refusal names the field, never its value.
func (self *TlsEdgeSettings) Validate() error {
	if self == nil {
		return fmt.Errorf("%w: no settings", ErrTlsEdgeSettingsRefused)
	}
	if !tlsEdgeRootValid(self.Root) {
		return fmt.Errorf("%w: root is not a lowercase registered domain", ErrTlsEdgeSettingsRefused)
	}
	if self.ProxyHeader == nil {
		return fmt.Errorf("%w: proxy_header is missing", ErrTlsEdgeSettingsRefused)
	}
	if err := self.ProxyHeader.validate(); err != nil {
		return fmt.Errorf("%w: proxy_header: %w", ErrTlsEdgeSettingsRefused, err)
	}
	for name, value := range map[string]int64{
		"clients":                 int64(self.Clients),
		"max_connections":         int64(self.MaxConnectionCount),
		"blocks":                  int64(self.Blocks),
		"client_hello.timeout_s":  int64(self.ClientHelloTimeout),
		"client_hello.max_bytes":  int64(self.ClientHelloMaxByteCount),
		"find.timeout_s":          int64(self.FindTimeout),
		"find.max_finds":          int64(self.FindMaxCount),
		"accept.ticket_timeout_s": int64(self.AcceptTicketTimeout),
		"accept.setup_timeout_s":  int64(self.AcceptSetupTimeout),
		"idle_timeout_s":          int64(self.IdleTimeout),
		"drain_s":                 int64(self.DrainTimeout),
		"NegativeCacheTtl":        int64(self.NegativeCacheTtl),
		"NegativeCacheMaxCount":   int64(self.NegativeCacheMaxCount),
		"NameReloadInterval":      int64(self.NameReloadInterval),
		"KillReloadInterval":      int64(self.KillReloadInterval),
		"KillRetryDelay":          int64(self.KillRetryDelay),
		"StoreTimeout":            int64(self.StoreTimeout),
		"RedisTimeout":            int64(self.RedisTimeout),
		"AcceptRetryDelay":        int64(self.AcceptRetryDelay),
	} {
		if value <= 0 {
			return fmt.Errorf("%w: %s is not positive", ErrTlsEdgeSettingsRefused, name)
		}
	}
	return nil
}
