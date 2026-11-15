//go:build !js && !ios && !android && !sdk_mobile_bind

// The telemetry pair (§16.18's harness OpenTelemetry; I-17; QD-822, which reads I-7's credential as one that
// administers, reads or signs): the bearer token and loopback port `ur install-harness` draws once for the instance
// and seals in <state>/harness/telemetry.json, beside the harness seals (harness_hash.go). Each harness's exporter
// settings name both, and the daemon's telemetry listener (ingest_telemetry.go) binds 127.0.0.1 at the port and takes
// the token, for model_call entries alone.
//
//	draw       Ingest.TelemetryTokenByteCount random bytes, hex, and a port the loopback interface had free when it
//	           was drawn: cli's, at the first install of a harness that exports telemetry while Ingest.ModelCalls is
//	           on
//	restore    every later install reads the pair back and writes the same settings, so a re-install changes nothing,
//	           and every harness installed for the instance names one pair, which the daemon's one listener serves
//	seal       the pair is a template input of each install that wrote exporter settings, and its seal names the port
//	           (HarnessSeal.TelemetryPort): the config check renders the template from the pair as it stands, so a
//	           pair drawn again, or files no longer holding it, read as changed
//	scope      a user install's alone: a project's files are committed, and the token is never committed. Cursor
//	           documents no OpenTelemetry exporter setting, so a Cursor install writes none and draws no pair
//
// The file is local state, never synced or sent, 0600 under a 0700 directory, like the seals; it holds the token
// itself, since every exporter's settings do too and the daemon must read it while locked, as capture goes on then.
//
// Package-level functions are safe for concurrent use.

package mcp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
)

// The pair file's format version.
const harnessTelemetryVersion = 1

// The pair file's name under <state>/harness/, beside the seals.
const harnessTelemetryFileName = "telemetry.json"

// The only address the listener binds and every exporter's endpoint names: the IPv4 loopback, never a name a resolver
// could answer otherwise.
const harnessTelemetryHost = "127.0.0.1"

// The token's scheme in an Authorization header, which IngestTelemetry checks.
const harnessTelemetryBearerScheme = "Bearer "

// The harnesses whose exporter settings ur writes: Claude Code's env block and Codex's [otel] table. Cursor documents
// no OpenTelemetry exporter setting.
var harnessTelemetryHarnesses = map[string]bool{
	claudeHookHarness: true,
	codexHookHarness:  true,
}

// Whether ur writes exporter settings into harness (QD-822): false for Cursor, which documents none.
func HarnessExportsTelemetry(harness string) bool {
	return harnessTelemetryHarnesses[harness]
}

// The instance's telemetry pair: the listener's loopback port and the bearer token, hex.
type HarnessTelemetry struct {
	Version int `json:"version"`
	Port    int `json:"port"`
	// hex of Ingest.TelemetryTokenByteCount random bytes
	Token string `json:"token"`
}

// A pair of port and the token's bytes, hex-encoded.
func NewHarnessTelemetry(port int, token []byte) *HarnessTelemetry {
	encoded := hex.EncodeToString(token)
	testHookSecret("telemetry_token", []byte(encoded))
	return &HarnessTelemetry{Version: harnessTelemetryVersion, Port: port, Token: encoded}
}

// Where the pair lives under state.
func HarnessTelemetryPath(stateDirectory string) string {
	return filepath.Join(stateDirectory, harnessSealDirectoryName, harnessTelemetryFileName)
}

// Whether the pair can be served and written into a harness's files: a port a TCP listener can bind, and a token of
// lowercase hex, which no header or TOML or JSON string needs to escape.
func (self *HarnessTelemetry) validate() error {
	if self.Version != harnessTelemetryVersion {
		return fmt.Errorf("%w: a telemetry pair of version %d", ErrHarnessConfig, self.Version)
	}
	if self.Port < 1 || 65535 < self.Port {
		return fmt.Errorf("%w: a telemetry port out of range", ErrHarnessConfig)
	}
	if self.Token == "" || len(self.Token)%2 != 0 {
		return fmt.Errorf("%w: a telemetry token that is no hex", ErrHarnessConfig)
	}
	for _, c := range self.Token {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return fmt.Errorf("%w: a telemetry token that is no hex", ErrHarnessConfig)
		}
	}
	return nil
}

// Whether two pairs are one.
func (self *HarnessTelemetry) equal(other *HarnessTelemetry) bool {
	return self != nil && other != nil && *self == *other
}

// The listener's address: 127.0.0.1 at the port.
func (self *HarnessTelemetry) Address() string {
	return net.JoinHostPort(harnessTelemetryHost, strconv.Itoa(self.Port))
}

// OTLP/HTTP's base endpoint, to which an exporter adds /v1/logs: Claude Code's OTEL_EXPORTER_OTLP_ENDPOINT.
func (self *HarnessTelemetry) Endpoint() string {
	return "http://" + self.Address()
}

// The logs endpoint itself: Codex's otlp-http endpoint, which it takes whole.
func (self *HarnessTelemetry) LogsEndpoint() string {
	return self.Endpoint() + ingestTelemetryLogsPath
}

// The Authorization header's value an exporter presents.
func (self *HarnessTelemetry) Authorization() string {
	return harnessTelemetryBearerScheme + self.Token
}

// The pair under state, read up to byteCount bytes: an error wrapping os.ErrNotExist where none was drawn, and one
// wrapping ErrHarnessConfig where the file does not read as a pair.
func ReadHarnessTelemetry(stateDirectory string, byteCount int64) (*HarnessTelemetry, error) {
	file, err := os.Open(HarnessTelemetryPath(stateDirectory))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, byteCount+1))
	if err != nil {
		return nil, err
	}
	if byteCount < int64(len(content)) {
		return nil, fmt.Errorf("%w: a telemetry pair past %d bytes", ErrHarnessConfig, byteCount)
	}
	telemetry := &HarnessTelemetry{}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(telemetry); err != nil {
		return nil, fmt.Errorf("%w: a telemetry pair that does not read", ErrHarnessConfig)
	}
	if err := telemetry.validate(); err != nil {
		return nil, err
	}
	testHookSecret("telemetry_token", []byte(telemetry.Token))
	return telemetry, nil
}

// Writes the pair under state, private, by a temporary file renamed over it.
func writeHarnessTelemetry(stateDirectory string, telemetry *HarnessTelemetry) error {
	if err := telemetry.validate(); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(telemetry, "", "  ")
	if err != nil {
		return err
	}
	return harnessWriteFile(HarnessTelemetryPath(stateDirectory), append(encoded, '\n'), 0o600, true)
}

// The pair an install's args name, checked against the install's scope: nil where it writes no exporter settings.
func checkHarnessTelemetry(args *HarnessInstallArgs) (*HarnessTelemetry, error) {
	telemetry := args.Telemetry
	if telemetry == nil {
		return nil, nil
	}
	if args.ProjectDirectory != "" {
		return nil, errors.New("a project install writes no telemetry token: its files are committed")
	}
	if !HarnessExportsTelemetry(args.Harness) {
		return nil, fmt.Errorf("%s documents no OpenTelemetry exporter setting, so ur writes none", args.Harness)
	}
	if err := telemetry.validate(); err != nil {
		return nil, err
	}
	copied := *telemetry
	return &copied, nil
}
