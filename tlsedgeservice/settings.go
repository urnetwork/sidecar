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
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/urnetwork/sidecar"
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

	// The caps' (§13.9).

	// What a network gets until its own caps load (reading 11): Community's. Each field -1 or positive,
	// since a cold network is never refused for being cold.
	ColdLimits *TlsEndpointLimits
	// How often a network's caps load again while it is in use. Default 5 s, §20.7's producer cache.
	LimitsRefreshInterval time.Duration
	// A network unused this long is forgotten, and cold again at its next connection. Default 10 min.
	LimitsActiveWindow time.Duration
	// Networks whose caps are held at most, the oldest going first. Default 65,536.
	LimitsMaxNetworkCount int
	// Token buckets of visitor /64s or /32s held at most, and the same of /48s or /24s. Default 65,536
	// each, so a scan of distinct prefixes costs a few MiB.
	VisitorRateMaxCount int
	// Token buckets of endpoints held at most. Default 65,536.
	EndpointRateMaxCount int
	// What an endpoint's bandwidth bucket holds when full, as time at its rate. Default 1 s.
	BandwidthBurst time.Duration

	// The connection path's (§13.5, §13.6).

	// How long an alert's write may take before the connection is closed without it. Default 2 s.
	AlertTimeout time.Duration
	// The most bytes one read of the splice moves. Default 16 KiB, a TLS record and §6's initial window.
	SpliceBufferByteCount int
	// How long one Quota.Lease call may take before the connection is refused. Default 2 s.
	LeaseTimeout time.Duration
	// The usage windows of meter tls (§20.6): 60 s windows retried for 10 min.
	Usage *sidecar.QuotaUsageBatcherSettings
	// How long Drain and Close wait for the last usage window and the last records to be sent. Default
	// 10 s.
	FlushTimeout time.Duration
	// How often connection records leave for the store (§13.9: 10 s batches).
	RecordFlushInterval time.Duration
	// Records in one write. Default 1,000.
	RecordBatchCount int
	// Records waiting at most, past which a new one is dropped and counted, so a store that lags costs
	// records and never a connection. Default 65,536.
	RecordQueueCount int
	// How long one write of records may take before it reads as failed. Default 10 s.
	RecordWriteTimeout time.Duration
	// urnetwork_tlsedge_setup_seconds's bucket bounds, in seconds, rising.
	SetupSecondsBuckets []float64
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
		ColdLimits:              DefaultColdTlsEndpointLimits(),
		LimitsRefreshInterval:   5 * time.Second,
		LimitsActiveWindow:      10 * time.Minute,
		LimitsMaxNetworkCount:   64 * 1024,
		VisitorRateMaxCount:     64 * 1024,
		EndpointRateMaxCount:    64 * 1024,
		BandwidthBurst:          1 * time.Second,
		AlertTimeout:            2 * time.Second,
		SpliceBufferByteCount:   16 * 1024,
		LeaseTimeout:            2 * time.Second,
		Usage:                   sidecar.DefaultQuotaUsageBatcherSettings(),
		FlushTimeout:            10 * time.Second,
		RecordFlushInterval:     10 * time.Second,
		RecordBatchCount:        1000,
		RecordQueueCount:        64 * 1024,
		RecordWriteTimeout:      10 * time.Second,
		SetupSecondsBuckets:     []float64{0.025, 0.05, 0.1, 0.2, 0.3, 0.5, 1, 1.5, 2.5, 5, 10, 15},
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
		"LimitsRefreshInterval":   int64(self.LimitsRefreshInterval),
		"LimitsActiveWindow":      int64(self.LimitsActiveWindow),
		"LimitsMaxNetworkCount":   int64(self.LimitsMaxNetworkCount),
		"VisitorRateMaxCount":     int64(self.VisitorRateMaxCount),
		"EndpointRateMaxCount":    int64(self.EndpointRateMaxCount),
		"BandwidthBurst":          int64(self.BandwidthBurst),
		"AlertTimeout":            int64(self.AlertTimeout),
		"SpliceBufferByteCount":   int64(self.SpliceBufferByteCount),
		"LeaseTimeout":            int64(self.LeaseTimeout),
		"FlushTimeout":            int64(self.FlushTimeout),
		"RecordFlushInterval":     int64(self.RecordFlushInterval),
		"RecordBatchCount":        int64(self.RecordBatchCount),
		"RecordQueueCount":        int64(self.RecordQueueCount),
		"RecordWriteTimeout":      int64(self.RecordWriteTimeout),
	} {
		if value <= 0 {
			return fmt.Errorf("%w: %s is not positive", ErrTlsEdgeSettingsRefused, name)
		}
	}
	if self.Usage == nil || self.Usage.WindowTimeout <= 0 || self.Usage.RetryTimeout <= 0 {
		return fmt.Errorf("%w: Usage needs a positive window and retry timeout", ErrTlsEdgeSettingsRefused)
	}
	if len(self.SetupSecondsBuckets) == 0 || !slices.IsSorted(self.SetupSecondsBuckets) || self.SetupSecondsBuckets[0] <= 0 {
		return fmt.Errorf("%w: SetupSecondsBuckets is not a rising list of positive bounds", ErrTlsEdgeSettingsRefused)
	}
	if self.ColdLimits == nil {
		return fmt.Errorf("%w: ColdLimits is missing", ErrTlsEdgeSettingsRefused)
	}
	for name, value := range map[string]int64{
		"EndpointConcurrent":       self.ColdLimits.EndpointConcurrent,
		"EndpointNewPerS":          self.ColdLimits.EndpointNewPerS,
		"EndpointMbitPerS":         self.ColdLimits.EndpointMbitPerS,
		"VisitorConcurrent":        self.ColdLimits.VisitorConcurrent,
		"VisitorNewPerS":           self.ColdLimits.VisitorNewPerS,
		"VisitorAggregateMultiple": self.ColdLimits.VisitorAggregateMultiple,
	} {
		if value == 0 || value < tlsLimitNone {
			return fmt.Errorf("%w: ColdLimits.%s is neither positive nor none", ErrTlsEdgeSettingsRefused, name)
		}
	}
	return nil
}
