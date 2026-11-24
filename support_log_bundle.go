//go:build !ios_extension && !sidecar_http

// The support log's bundle (DESIGN-COMPUTE §28.7): the window of the ring a message asks for, rendered as JSON from
// the registry's own words and compressed, which the support client attaches and `ur support logs` shows a person
// whole. The support client builds it outside every agent's context, and an agent learns only its manifest, so
// whatever a bug might write reaches no model (I-7).
//
// The window is since the message's item began, or else the last BundleDefaultWindow, never more than
// BundleMaxWindow. Each token is the first BundleTokenByteCount bytes of HMAC-SHA256 under a salt drawn for the bundle
// and kept in none, over the ring's own HMAC of the id, so a bundle relates its own events and no two bundles share a
// token, as the sdk's redactor draws its salt per upload. Past BundleMaxByteCount compressed, the oldest events are
// left out and the header counts them.
//
// The header names ur's version and channel, the OS and arch, the Harness's and the gateway's versions, the
// registry's version, the window's first and last times and the event count: each version format-checked, the
// channel one of four words, the OS and arch Go's own, so the header holds no free text either.

package sidecar

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"time"
)

// What a bundle's document says it is.
const SupportLogBundleFormat = "urnetwork-support-log-bundle-v1"

// The channels a bundle's header names; any other is "other".
var supportLogChannels = []string{"stable", "beta", "nightly", "development"}

// What a host says of itself in a bundle's header. Each version is format-checked and a channel must be a lowercase
// word; either is held as "invalid" otherwise, and as "" where the host has none.
type SupportLogBundleHost struct {
	// ur's version, or the app's sdk's.
	Version string
	// stable, beta, nightly or development, as the host's release names it; any other is held as "other".
	Channel string
	// The Harness's version, where this process runs one.
	HarnessVersion string
	// The gateway's version, where this process runs one.
	GatewayVersion string
}

// What a bundle is built for.
type SupportLogBundleArgs struct {
	// The window's start: the first message of the item a message continues. Zero takes the last
	// BundleDefaultWindow; anything before BundleMaxWindow ago takes BundleMaxWindow.
	Since time.Time
	Host  *SupportLogBundleHost
}

// A bundle's header.
type SupportLogBundleHeader struct {
	Version        string `json:"version"`
	Channel        string `json:"channel"`
	Os             string `json:"os"`
	Arch           string `json:"arch"`
	HarnessVersion string `json:"harness_version"`
	GatewayVersion string `json:"gateway_version"`
	Registry       int    `json:"registry"`
	// The window's first and last events, unix seconds; 0 with none.
	First  int64 `json:"first"`
	Last   int64 `json:"last"`
	Events int   `json:"events"`
	// The oldest events the window held that the size bound left out.
	Omitted int `json:"omitted,omitempty"`
}

// One event of a bundle: its time in unix seconds, component, code and severity by the registry's names, and each
// field by its name: an enum's value, a bucket's label, a version, a boolean or a token in hex.
type SupportLogBundleEvent struct {
	T         int64          `json:"t"`
	Component string         `json:"component"`
	Code      string         `json:"code"`
	Severity  string         `json:"severity"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// A bundle's document: what its compressed bytes hold.
type SupportLogBundleDocument struct {
	Format string                   `json:"format"`
	Header *SupportLogBundleHeader  `json:"header"`
	Events []*SupportLogBundleEvent `json:"events"`
}

// How many events of one code a bundle holds.
type SupportLogCodeCount struct {
	Component string `json:"component"`
	Code      string `json:"code"`
	Count     int    `json:"count"`
}

// What an agent and a card learn of a bundle (§28.7, §16.3's BundleManifest): its events, window, size and SHA-256,
// and its codes by component. Never an event's fields.
type SupportLogManifest struct {
	Events    int                    `json:"events"`
	First     int64                  `json:"first"`
	Last      int64                  `json:"last"`
	ByteCount int64                  `json:"bytes"`
	Sha256    []byte                 `json:"sha256"`
	Codes     []*SupportLogCodeCount `json:"codes"`
}

// A bundle as built: the compressed bytes a message carries, their manifest, and the document they hold, which `ur
// support logs` renders.
type SupportLogBundle struct {
	Bytes    []byte
	Manifest *SupportLogManifest
	Document *SupportLogBundleDocument
}

// Builds a bundle of the ring's window. A nil log answers an error, so a caller with no ring attaches none.
func (self *SupportLog) Bundle(args *SupportLogBundleArgs) (*SupportLogBundle, error) {
	if self == nil {
		return nil, errors.New("no support log runs in this process")
	}
	if args == nil {
		args = &SupportLogBundleArgs{}
	}
	now := self.clock.Now()
	from := now.Add(-self.settings.BundleDefaultWindow)
	if !args.Since.IsZero() {
		from = args.Since
	}
	if earliest := now.Add(-self.settings.BundleMaxWindow); from.Before(earliest) {
		from = earliest
	}
	records := self.read(from.Unix(), now.Unix())
	salt := make([]byte, self.settings.BundleSaltByteCount)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("support log: %w", err)
	}
	events := make([]*SupportLogBundleEvent, 0, len(records))
	for _, record := range records {
		if event := self.renderRecord(record, salt); event != nil {
			events = append(events, event)
		}
	}
	clear(salt)
	host := args.Host
	if host == nil {
		host = &SupportLogBundleHost{}
	}
	header := &SupportLogBundleHeader{
		Version:        self.headerVersion(host.Version),
		Channel:        supportLogHeaderChannel(host.Channel),
		Os:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		HarnessVersion: self.headerVersion(host.HarnessVersion),
		GatewayVersion: self.headerVersion(host.GatewayVersion),
		Registry:       self.registry.version,
	}
	omitted := 0
	for attempt := 0; ; attempt += 1 {
		kept := events[omitted:]
		header.Events = len(kept)
		header.Omitted = omitted
		header.First, header.Last = 0, 0
		if 0 < len(kept) {
			header.First, header.Last = kept[0].T, kept[len(kept)-1].T
		}
		document := &SupportLogBundleDocument{Format: SupportLogBundleFormat, Header: header, Events: kept}
		compressed, err := supportLogCompress(document)
		if err != nil {
			return nil, err
		}
		if int64(len(compressed)) <= self.settings.BundleMaxByteCount {
			return &SupportLogBundle{Bytes: compressed, Manifest: supportLogManifestOf(document, compressed), Document: document}, nil
		}
		if len(kept) == 0 || self.settings.BundleFitAttemptCount <= attempt {
			return nil, errors.New("support log: the bundle does not fit its bound")
		}
		// the newer half stays
		omitted += max(len(kept)/2, 1)
	}
}

// A version for the header, "" for none and "invalid" for one that fails the format check.
func (self *SupportLog) headerVersion(version string) string {
	if version == "" || supportLogVersionValid(version, self.settings) {
		return version
	}
	return "invalid"
}

// A channel for the header, "" for none and "other" for one it does not name.
func supportLogHeaderChannel(channel string) string {
	if channel == "" || slices.Contains(supportLogChannels, channel) {
		return channel
	}
	return "other"
}

// One record in the registry's words, its tokens under salt. Nil for a code this build's registry does not hold, which
// a ring written by a newer build could carry.
func (self *SupportLog) renderRecord(record *supportLogRecord, salt []byte) *SupportLogBundleEvent {
	component, name, severity, ok := self.registry.code(record.code)
	if !ok {
		return nil
	}
	event := &SupportLogBundleEvent{
		T:         record.t,
		Component: component,
		Code:      name,
		Severity:  supportLogSeverityNames[severity],
	}
	for _, field := range record.fields {
		row, ok := self.registry.fields[field.number]
		if !ok || row.fieldType != field.fieldType {
			continue
		}
		var value any
		switch field.fieldType {
		case supportLogFieldTypeEnum:
			values := self.registry.enums[row.enum]
			if field.value == 0 || uint64(len(values)) < field.value {
				continue
			}
			value = values[field.value-1]
		case supportLogFieldTypeCount:
			value = supportLogBucketLabel(self.registry.countBuckets, field.value)
		case supportLogFieldTypeDuration:
			value = supportLogBucketLabel(self.registry.durationBuckets, field.value)
		case supportLogFieldTypeSize:
			value = supportLogBucketLabel(self.registry.sizeBuckets, field.value)
		case supportLogFieldTypeBoolean:
			value = field.value != 0
		case supportLogFieldTypeVersion:
			switch field.state {
			case supportLogValueKept:
				value = field.version
			case supportLogValueInvalid:
				value = "invalid"
			default:
				value = ""
			}
		case supportLogFieldTypeToken:
			if field.state != supportLogValueKept {
				value = ""
				break
			}
			mac := hmac.New(sha256.New, salt)
			mac.Write(field.token)
			value = hex.EncodeToString(mac.Sum(nil)[:self.settings.BundleTokenByteCount])
		}
		if value == nil {
			continue
		}
		if event.Fields == nil {
			event.Fields = map[string]any{}
		}
		event.Fields[row.name] = value
	}
	return event
}

// A bucket's label by its index, "" for an index the registry does not hold.
func supportLogBucketLabel(buckets []supportLogBucket, index uint64) string {
	if uint64(len(buckets)) <= index {
		return ""
	}
	return buckets[index].label
}

// The document as JSON, gzip-compressed.
func supportLogCompress(document *SupportLogBundleDocument) ([]byte, error) {
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("support log: %w", err)
	}
	compressed := &bytes.Buffer{}
	writer := gzip.NewWriter(compressed)
	if _, err := writer.Write(encoded); err != nil {
		return nil, fmt.Errorf("support log: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("support log: %w", err)
	}
	return compressed.Bytes(), nil
}

// A bundle's manifest: its counts by component and code, in the registry's order.
func supportLogManifestOf(document *SupportLogBundleDocument, compressed []byte) *SupportLogManifest {
	sha := sha256.Sum256(compressed)
	counts := map[[2]string]int{}
	for _, event := range document.Events {
		counts[[2]string{event.Component, event.Code}] += 1
	}
	codes := make([]*SupportLogCodeCount, 0, len(counts))
	for key, count := range counts {
		codes = append(codes, &SupportLogCodeCount{Component: key[0], Code: key[1], Count: count})
	}
	slices.SortFunc(codes, func(a *SupportLogCodeCount, b *SupportLogCodeCount) int {
		if a.Component != b.Component {
			if a.Component < b.Component {
				return -1
			}
			return 1
		}
		if a.Code < b.Code {
			return -1
		}
		if a.Code > b.Code {
			return 1
		}
		return 0
	})
	return &SupportLogManifest{
		Events:    document.Header.Events,
		First:     document.Header.First,
		Last:      document.Header.Last,
		ByteCount: int64(len(compressed)),
		Sha256:    sha[:],
		Codes:     codes,
	}
}

// A bundle's compressed bytes back to its document, refusing more than maxByteCount decompressed: what a person's
// viewer and a test read.
func SupportLogBundleOpen(compressed []byte, maxByteCount int64) (*SupportLogBundleDocument, error) {
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("support log bundle: %w", err)
	}
	defer reader.Close()
	decompressed, err := io.ReadAll(io.LimitReader(reader, maxByteCount+1))
	if err != nil {
		return nil, fmt.Errorf("support log bundle: %w", err)
	}
	if maxByteCount < int64(len(decompressed)) {
		return nil, errors.New("support log bundle: past its bound")
	}
	document := &SupportLogBundleDocument{}
	if err := json.Unmarshal(decompressed, document); err != nil {
		return nil, fmt.Errorf("support log bundle: %w", err)
	}
	if document.Format != SupportLogBundleFormat || document.Header == nil {
		return nil, errors.New("support log bundle: not a bundle of this format")
	}
	return document, nil
}
