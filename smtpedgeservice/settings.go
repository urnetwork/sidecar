// config/<env>/smtpedge.yml (§14.14). DefaultSmtpEdgeSettings is the only source of a default
// (connect/CODESTYLE.md:144), and LoadSmtpEdgeSettings lays a file over it. Protocol and format sizes
// are not settings: they stay constants beside the code that reads them.
//
// One file serves both roles that load it: the edge (SMTP-M9-13 on), and the report intake in
// mxedge's platform block (plan-SMTP-report-intake-home), which reads the names, the sending
// addresses, the loop allowlist and the report bounds.
//
// Every number must be positive. Validate refuses anything else, so a zero is never unlimited or off,
// and no reader has to decide what one means.

package smtpedgeservice

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// RFC 1035's longest name.
	smtpHostNameMaxByteCount = 253
	// RFC 1035's longest label.
	smtpHostLabelMaxByteCount = 63
)

// An smtpedge.yml that cannot be served from. The wrapping error names the field, never its value.
var ErrSmtpEdgeSettingsRefused = errors.New("smtpedge.yml refused")

// One sending address (owner decision 124) with the PTR name its HELO repeats and the fwmark that
// source-routes a dial from it (plan-SMTP-small-readings#18). Fwmark 0 is the block's own mark.
type SmtpSendingAddress struct {
	// A shared lb IPv4 address.
	Address netip.Addr `yaml:"address"`
	// o<k>.out.bringyour.com in production (§14.6): the address's PTR name.
	HeloName string `yaml:"helo"`
	Fwmark   int    `yaml:"fwmark"`
}

// What config/<env>/smtpedge.yml sets, by the yaml names here. A duration takes Go's form, as 10m.
// DefaultSmtpEdgeSettings or LoadSmtpEdgeSettings make one, and the constructors refuse what Validate
// refuses. Safe to read concurrently once loaded, and never changed after.
type SmtpEdgeSettings struct {
	// <root>, the zone networks' names sit under (§12). No default: it is a production name, which the
	// file sets. An LDH name, compared without case.
	Root string `yaml:"root"`
	// rpt.bringyour.com in production (D-SMTP-19): the host every network's rua names. No default.
	ReportHostName string `yaml:"report_host"`
	// The sending set (§14.6). Report rows from any other source IP are dropped at parse, since
	// third-party addresses are never stored (§2.8 smtp-5). The edge is not ready with none.
	SendingAddresses []SmtpSendingAddress `yaml:"sending_addresses"`
	// Feedback-loop operators, by the DKIM d= their reports verify under (§14.8). Only these count
	// for an ARF report. Empty by default, so no complaint counts until the file names one.
	LoopAllowlist []string `yaml:"loop_allowlist"`

	// How long a stream may take to send its SmtpPreamble once open (§14.5). Default 30 s, the
	// ticket's own (plan-SMTP-data-connection-lifetime).
	PreambleTimeout time.Duration `yaml:"preamble_timeout"`
	// How long the edge's pre-TLS dialog may take for each MX it tries, from the dial to STARTTLS's
	// 220 (§14.4). Default 5 min, RFC 5321 §4.5.3.2's command timeouts.
	PreTlsTimeout time.Duration `yaml:"pre_tls_timeout"`
	// How long a connection may idle after a client record (§14.4, RFC 5321 §4.5.3.2.6). Default 10 min.
	ClientIdleTimeout time.Duration `yaml:"client_idle_timeout"`
	// How long a connection may idle after a server record (§14.4, RFC 5321 §4.5.3.2.7). Default 5 min.
	ServerIdleTimeout time.Duration `yaml:"server_idle_timeout"`
	// The longest a BDAT connection lives (§14.4). Default 30 min.
	ConnectionTimeout time.Duration `yaml:"connection_timeout"`
	// The longest a DATA-mode connection lives (§14.4, D-SMTP-20). Default 2 h.
	DataConnectionTimeout time.Duration `yaml:"data_connection_timeout"`
	// How often an edge reloads ActiveHalts (§14.8). Default 60 s, as §14.8 has it. The skeleton's
	// readiness probe runs on it too, until SMTP-M9-16's reloader takes it over.
	HaltReloadInterval time.Duration `yaml:"halt_reload_interval"`
	// How long one store call may take before it reads as an error. Default 5 s: every store call is
	// off the connection path, so this bounds a batch or a report, never a preamble.
	StoreTimeout time.Duration `yaml:"store_timeout"`
	// The most send records in one InsertSends. Default 500, a batch Postgres takes in one statement.
	SendBatchCount int `yaml:"send_batch_count"`
	// How long a send record may wait for its batch. Default 10 s, as §15.4's connection records.
	SendBatchInterval time.Duration `yaml:"send_batch_interval"`
	// How long Drain waits for connections before Close resets them. Default 10 min, tlsedge's drain_s
	// (§13.5): a longer send retries on the §9 backup ticket (§14.9).
	DrainTimeout time.Duration `yaml:"drain_timeout"`

	// The most bytes read of a header block: a report's own, a part's, or the enclosed message's up
	// to its first CRLF CRLF (§14.8). Default 64 KiB, as §14.8 has it.
	ReportHeaderByteCount int `yaml:"report_header_bytes"`
	// report_inflate_bytes: the most an aggregate attachment inflates to (§14.8). Default 8 MiB.
	ReportInflateByteCount int `yaml:"report_inflate_bytes"`
	// The most an attachment may inflate per compressed byte (§14.8). Default 100.
	ReportInflateRatio int `yaml:"report_inflate_ratio"`
	// The deepest XML or JSON nesting an aggregate may have (§14.8). Default 32.
	ReportNestingDepth int `yaml:"report_nesting_depth"`
	// The deepest a report's multiparts may nest, the top level being 1. Default 8, deeper than any
	// report shape needs (RFC 5965's is 2).
	ReportMimeDepth int `yaml:"report_mime_depth"`
	// The most leaf parts one report may have. Default 32.
	ReportMimePartCount int `yaml:"report_mime_parts"`
	// The most DKIM signatures checked in one header block. Default 8, D-MAIL-14's bound for mail.
	ReportDkimSignatureCount int `yaml:"report_dkim_signatures"`
	// The most TXT records tried at one key name. Default 4.
	ReportDkimKeyRecordCount int `yaml:"report_dkim_key_records"`
	// The largest RSA key a signature may use, in bits, which bounds a verify's cost. Default 4096.
	ReportDkimRsaKeyBitCount int `yaml:"report_dkim_rsa_key_bits"`
	// How long one report's DNS reads may take in all. Default 30 s, D-MAIL-14's bound for mail.
	ReportDnsTimeout time.Duration `yaml:"report_dns_timeout"`
}

// The defaults every number here is read from. Root and ReportHostName stay empty, so these alone do
// not pass Validate.
func DefaultSmtpEdgeSettings() *SmtpEdgeSettings {
	return &SmtpEdgeSettings{
		PreambleTimeout:          30 * time.Second,
		PreTlsTimeout:            5 * time.Minute,
		ClientIdleTimeout:        10 * time.Minute,
		ServerIdleTimeout:        5 * time.Minute,
		ConnectionTimeout:        30 * time.Minute,
		DataConnectionTimeout:    2 * time.Hour,
		HaltReloadInterval:       60 * time.Second,
		StoreTimeout:             5 * time.Second,
		SendBatchCount:           500,
		SendBatchInterval:        10 * time.Second,
		DrainTimeout:             10 * time.Minute,
		ReportHeaderByteCount:    64 * 1024,
		ReportInflateByteCount:   8 * 1024 * 1024,
		ReportInflateRatio:       100,
		ReportNestingDepth:       32,
		ReportMimeDepth:          8,
		ReportMimePartCount:      32,
		ReportDkimSignatureCount: 8,
		ReportDkimKeyRecordCount: 4,
		ReportDkimRsaKeyBitCount: 4096,
		ReportDnsTimeout:         30 * time.Second,
	}
}

// Settings from smtpedge.yml. A key left out keeps its default, so root and report_host must be
// there, and a key not listed here is refused rather than ignored: a misspelled bound would otherwise
// run at its default, unseen.
func LoadSmtpEdgeSettings(data []byte) (*SmtpEdgeSettings, error) {
	settings := DefaultSmtpEdgeSettings()
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(settings); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSmtpEdgeSettingsRefused, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: more than one document", ErrSmtpEdgeSettingsRefused)
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	return settings, nil
}

// Whether name is a dotted LDH name, which also keeps a CR, LF or space out of everything it enters.
func smtpLdhName(name string) bool {
	if name == "" || smtpHostNameMaxByteCount < len(name) {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || smtpHostLabelMaxByteCount < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			c := label[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Whether these settings can run the edge or the intake. A refusal names the field, never its value.
func (self *SmtpEdgeSettings) Validate() error {
	if self == nil {
		return fmt.Errorf("%w: no settings", ErrSmtpEdgeSettingsRefused)
	}
	if !smtpLdhName(self.Root) {
		return fmt.Errorf("%w: root is not an LDH name", ErrSmtpEdgeSettingsRefused)
	}
	if !smtpLdhName(self.ReportHostName) {
		return fmt.Errorf("%w: report_host is not an LDH name", ErrSmtpEdgeSettingsRefused)
	}
	seenAddresses := map[netip.Addr]bool{}
	for _, sendingAddress := range self.SendingAddresses {
		// IPv4 only, as the edge dials (owner decision 34), and never a broadcast or private range's
		// special forms
		address := sendingAddress.Address
		if !address.Is4() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast() {
			return fmt.Errorf("%w: sending_addresses holds an address that cannot send", ErrSmtpEdgeSettingsRefused)
		}
		if seenAddresses[address] {
			return fmt.Errorf("%w: sending_addresses repeats an address", ErrSmtpEdgeSettingsRefused)
		}
		seenAddresses[address] = true
		if !smtpLdhName(sendingAddress.HeloName) {
			return fmt.Errorf("%w: a sending address's helo is not an LDH name", ErrSmtpEdgeSettingsRefused)
		}
		if sendingAddress.Fwmark < 0 {
			return fmt.Errorf("%w: a sending address's fwmark is negative", ErrSmtpEdgeSettingsRefused)
		}
	}
	for _, domain := range self.LoopAllowlist {
		if !smtpLdhName(domain) {
			return fmt.Errorf("%w: loop_allowlist holds a name that is not LDH", ErrSmtpEdgeSettingsRefused)
		}
	}
	value := reflect.ValueOf(self).Elem()
	for i := range value.NumField() {
		field := value.Field(i)
		if (field.Kind() == reflect.Int || field.Kind() == reflect.Int64) && field.Int() <= 0 {
			return fmt.Errorf("%w: %s is not positive", ErrSmtpEdgeSettingsRefused, value.Type().Field(i).Tag.Get("yaml"))
		}
	}
	return nil
}

// Whether address is in the sending set.
func (self *SmtpEdgeSettings) isSendingAddress(address netip.Addr) bool {
	address = address.Unmap()
	for _, sendingAddress := range self.SendingAddresses {
		if sendingAddress.Address == address {
			return true
		}
	}
	return false
}

// Whether a report verified under domain comes from an allowlisted feedback loop.
func (self *SmtpEdgeSettings) isLoopReporter(domain string) bool {
	for _, allowed := range self.LoopAllowlist {
		if strings.EqualFold(allowed, domain) {
			return true
		}
	}
	return false
}
