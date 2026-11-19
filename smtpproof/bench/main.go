// Command bench runs D-SMTP-16's speed rows and DESIGN-DETAILS 3.6's bench rows (SMTP-M9-32), so that a
// person on a reference machine (the Apple M1 MacBook Air, the AWS m5.large) only runs it:
//
//	bench -keys <directory> [-host <directory>] [-runs 20] [-legs tls13-chacha,tls13-aes,tls12-aes] [-modes bdat,data] [-shared] [-json <file>]
//
// -keys is a key set that smtpproof/setup made for the purpose. The bench takes it as a prover host does:
// PrepareKeys at idle until every family is ready, each call one shape's EnsureKeys, timed; then sends through
// smtpproof's Prover, smtpproof's Verifier holding the same set, the edge's record gate between them as smtpedge
// splices, and a scripted MX (sidecartest's ScriptedMx) on the leg's TLS version and suite: D-SMTP-16's BDAT send,
// a 4 KiB header block to 10 recipients, and its DATA send, a 100 KiB message, each -runs times on each leg. It
// reports, per leg and mode, the key part's and the whole send's p50, p95 and most, with the failures beside them;
// per shape, a unit's p50 and p95 and the edge's verification beside its constraints, public inputs and domain,
// read from the host's cache; and the host: its CPU, cores, memory and load, labelled shared when another load
// was on it, which -shared states and a load average past a quarter of its cores implies. Peak resident memory is
// the process's after each send. Settings are the effective defaults, as CODESTYLE's benchmark rule asks.
//
// A part's time is the time from the part before's answer to its own submission: proving it, which the default
// ProveConcurrency of 1 runs one at a time, and the dialog's in-process round trips, which are small beside it.
// Nothing here logs a key, a blind or plaintext: the messages are synthetic and the MX takes them in memory.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpproof"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, nil))
}

// One TLS leg a send runs on: the suite the client offers alone, and the server's version.
type benchLeg struct {
	name    string
	suite   uint16
	version uint16
}

func benchLegs() []*benchLeg {
	return []*benchLeg{
		{name: "tls13-chacha", suite: tls.TLS_CHACHA20_POLY1305_SHA256, version: tls.VersionTLS13},
		{name: "tls13-aes", suite: tls.TLS_AES_128_GCM_SHA256, version: tls.VersionTLS13},
		{name: "tls12-aes", suite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, version: tls.VersionTLS12},
	}
}

// What a run measures with: a prover and a verifier under one key set, and the host's directory whose cache the
// shapes' figures come from. A test gives fakes.
type benchWorld struct {
	prover   sidecar.SmtpProver
	verifier sidecar.SmtpProofVerifier
	// Where the host keeps its cache, and the key set's keyset.json, or empty for a world with neither.
	cacheDirectory string
	manifestPath   string
	// Builds the prover a leg sends with, offering the leg's suite alone. Nil sends every leg with prover.
	proverFor func(ctx context.Context, leg *benchLeg) (sidecar.SmtpProver, error)
}

// The run's options, from its flags: D-SMTP-16's rows at their sizes by default.
type benchOptions struct {
	runs   int
	legs   []*benchLeg
	modes  []string
	shared bool
	json   string
	// BDAT's header block, the recipients, and DATA's whole message, in octets.
	headerByteCount  int
	recipientCount   int
	messageByteCount int
}

// Parses the flags, builds the world unless one is given, runs and reports. The exit code: 0 a report, 1 a
// failure to run, 64 usage.
func run(ctx context.Context, args []string, out io.Writer, world *benchWorld) int {
	flags := flag.NewFlagSet("bench", flag.ContinueOnError)
	flags.SetOutput(out)
	keys := flags.String("keys", "", "a key set directory smtpproof/setup made for the bench")
	host := flags.String("host", "", "the prover host's directory, keys/ and cache/; empty makes one")
	runs := flags.Int("runs", 20, "sends of each row, of which the percentiles are")
	legNames := flags.String("legs", "tls13-chacha,tls13-aes,tls12-aes", "the TLS legs to send on")
	modes := flags.String("modes", "bdat,data", "the modes to send in")
	shared := flags.Bool("shared", false, "label the report as run on a host other load shares")
	jsonPath := flags.String("json", "", "also write the report as JSON to this file")
	headerBytes := flags.Int("header-bytes", 4095, "the header block's octets, D-SMTP-16's 4 KiB")
	recipients := flags.Int("recipients", 10, "the recipients a send names, D-SMTP-16's 10")
	dataBytes := flags.Int("data-bytes", 100*1024, "a DATA send's whole message, D-SMTP-16's 100 KiB")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *runs <= 0 || *recipients <= 0 || *headerBytes < 1024 || *dataBytes < *headerBytes {
		return 64
	}
	options := &benchOptions{runs: *runs, shared: *shared, json: *jsonPath, modes: strings.Split(*modes, ","),
		headerByteCount: *headerBytes, recipientCount: *recipients, messageByteCount: *dataBytes}
	for _, name := range strings.Split(*legNames, ",") {
		index := slices.IndexFunc(benchLegs(), func(leg *benchLeg) bool { return leg.name == name })
		if index < 0 {
			fmt.Fprintf(out, "bench: no leg %q\n", name)
			return 64
		}
		options.legs = append(options.legs, benchLegs()[index])
	}
	for _, mode := range options.modes {
		if mode != "bdat" && mode != "data" {
			fmt.Fprintf(out, "bench: no mode %q\n", mode)
			return 64
		}
	}
	report := &benchReport{Host: benchHostReport(options.shared), Settings: "smtpproof's defaults"}
	if world == nil {
		if *keys == "" {
			fmt.Fprintln(out, "bench: -keys names the key set to run under")
			return 64
		}
		made, prepares, err := newBenchWorld(ctx, *keys, *host)
		if err != nil {
			fmt.Fprintf(out, "bench: %v\n", err)
			return 1
		}
		world = made
		report.Prepares = prepares
	}
	if err := report.measure(ctx, world, options); err != nil {
		fmt.Fprintf(out, "bench: %v\n", err)
		return 1
	}
	report.write(out)
	if options.json != "" {
		encoded, err := json.MarshalIndent(report, "", " ")
		if err == nil {
			err = os.WriteFile(options.json, encoded, 0o644)
		}
		if err != nil {
			fmt.Fprintf(out, "bench: %v\n", err)
			return 1
		}
	}
	return 0
}

// The host a key set is checked on, its files linked or copied into keys/<id>/ as a fetch would leave them,
// every family made ready by PrepareKeys, each call timed, and a verifier holding the same set.
func newBenchWorld(ctx context.Context, keysDirectory string, hostDirectory string) (*benchWorld, []*benchPrepare, error) {
	manifestPath := filepath.Join(keysDirectory, "keyset.json")
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(manifest)
	id := sum[:]
	if hostDirectory == "" {
		if hostDirectory, err = os.MkdirTemp("", "smtpproof-bench-"); err != nil {
			return nil, nil, err
		}
	}
	fetched := filepath.Join(hostDirectory, "keys", hex.EncodeToString(id))
	if err := os.MkdirAll(fetched, 0o700); err != nil {
		return nil, nil, err
	}
	entries, err := os.ReadDir(keysDirectory)
	if err != nil {
		return nil, nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		from, to := filepath.Join(keysDirectory, entry.Name()), filepath.Join(fetched, entry.Name())
		if _, err := os.Stat(to); err == nil {
			continue
		}
		if err := os.Link(from, to); err != nil {
			content, err := os.ReadFile(from)
			if err != nil {
				return nil, nil, err
			}
			if err := os.WriteFile(to, content, 0o600); err != nil {
				return nil, nil, err
			}
		}
	}
	keySettings := smtpproof.DefaultKeySettings()
	pins := [][]byte{id}
	prover := smtpproof.NewProver(smtpproof.DefaultProverSettings(), keySettings, pins, hostDirectory)
	var prepares []*benchPrepare
	for {
		start := time.Now()
		readiness, err := prover.PrepareKeys(ctx)
		elapsed := time.Since(start)
		if err != nil {
			return nil, prepares, err
		}
		ready := []string{}
		for _, keySet := range readiness.KeySets {
			for _, suite := range keySet.ReadySuites {
				ready = append(ready, tls.CipherSuiteName(suite))
			}
		}
		prepares = append(prepares, &benchPrepare{Seconds: elapsed.Seconds(), ReadySuites: ready})
		if readiness.Done {
			break
		}
	}
	keySet, err := smtpproof.OpenKeySet(keysDirectory, id)
	if err != nil {
		return nil, prepares, err
	}
	verifier, err := smtpproof.NewVerifier(smtpproof.DefaultVerifierSettings(), []*smtpproof.VerifierKeySet{{KeySet: keySet}})
	if err != nil {
		return nil, prepares, err
	}
	world := &benchWorld{
		prover:         prover,
		verifier:       verifier,
		cacheDirectory: filepath.Join(hostDirectory, "cache"),
		manifestPath:   manifestPath,
	}
	// a leg's prover offers its suite alone, and takes the cache the first check wrote, compiling each shape
	// again to hold the cache to this build before it names the set (DESIGN-DETAILS 3.2.7's load)
	world.proverFor = func(ctx context.Context, leg *benchLeg) (sidecar.SmtpProver, error) {
		settings := smtpproof.DefaultProverSettings()
		settings.SuiteOrder = []uint16{leg.suite}
		legProver := smtpproof.NewProver(settings, keySettings, pins, hostDirectory)
		for {
			readiness, err := legProver.PrepareKeys(ctx)
			if err != nil {
				return nil, err
			}
			if readiness.Done {
				return legProver, nil
			}
		}
	}
	return world, prepares, nil
}

// One PrepareKeys call: a shape's check, and what was ready after it.
type benchPrepare struct {
	Seconds     float64  `json:"seconds"`
	ReadySuites []string `json:"ready_suites"`
}

// What a run found.
type benchReport struct {
	Host     *benchHost      `json:"host"`
	Settings string          `json:"settings"`
	Prepares []*benchPrepare `json:"ensure_keys"`
	Rows     []*benchRow     `json:"rows"`
	Shapes   []*benchShape   `json:"shapes"`
	// The process's peak resident memory over the run, in MiB.
	PeakResidentMebibytes int64 `json:"peak_resident_mib"`
}

// One leg and mode's sends.
type benchRow struct {
	Leg       string            `json:"leg"`
	Mode      string            `json:"mode"`
	Runs      int               `json:"runs"`
	Failures  int               `json:"failures"`
	Units     int               `json:"units"`
	KeyPart   *benchPercentiles `json:"key_part_seconds"`
	WholeSend *benchPercentiles `json:"send_seconds"`
	// The first failure's error.
	FirstError string `json:"first_error,omitempty"`
}

// One shape's units across every send.
type benchShape struct {
	Name          string            `json:"name"`
	Units         int               `json:"units"`
	Prove         *benchPercentiles `json:"prove_seconds"`
	Verify        *benchPercentiles `json:"verify_seconds"`
	Constraints   int               `json:"constraints,omitempty"`
	PublicInputs  int               `json:"public_inputs,omitempty"`
	DomainSize    int               `json:"domain_size,omitempty"`
	proveSeconds  []float64
	verifySeconds []float64
}

type benchPercentiles struct {
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	Max float64 `json:"max"`
}

// The nearest-rank percentiles of what was measured, or nil for nothing.
func benchPercentilesOf(values []float64) *benchPercentiles {
	if len(values) == 0 {
		return nil
	}
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	rank := func(percent int) float64 {
		index := (percent*len(sorted) + 99) / 100
		return sorted[max(index, 1)-1]
	}
	return &benchPercentiles{P50: rank(50), P95: rank(95), Max: sorted[len(sorted)-1]}
}

// Every leg and mode's sends, -runs times each, and the shapes' figures.
func (self *benchReport) measure(ctx context.Context, world *benchWorld, options *benchOptions) error {
	shapes := map[string]*benchShape{}
	for _, leg := range options.legs {
		prover := world.prover
		if world.proverFor != nil {
			var err error
			if prover, err = world.proverFor(ctx, leg); err != nil {
				return err
			}
		}
		for _, mode := range options.modes {
			row := &benchRow{Leg: leg.name, Mode: mode, Runs: options.runs}
			var keySeconds, sendSeconds []float64
			for range options.runs {
				send, err := benchSend(ctx, world.verifier, prover, leg, mode, options)
				switch {
				case err != nil:
				case !send.result.Accepted:
					err = fmt.Errorf("the MX did not take the message: %+v", send.result)
				case len(send.parts) == 0:
					err = fmt.Errorf("the send took no part")
				}
				if err != nil {
					row.Failures += 1
					if row.FirstError == "" {
						row.FirstError = err.Error()
					}
					if ctx.Err() != nil {
						return ctx.Err()
					}
					continue
				}
				row.Units = len(send.parts)
				keySeconds = append(keySeconds, send.parts[0].proveSeconds)
				sendSeconds = append(sendSeconds, send.seconds)
				for _, part := range send.parts {
					shape := shapes[part.shape]
					if shape == nil {
						shape = &benchShape{Name: part.shape}
						shapes[part.shape] = shape
					}
					shape.Units += 1
					shape.proveSeconds = append(shape.proveSeconds, part.proveSeconds)
					shape.verifySeconds = append(shape.verifySeconds, part.verifySeconds)
				}
				self.PeakResidentMebibytes = max(self.PeakResidentMebibytes, benchPeakResidentBytes()/1024/1024)
			}
			row.KeyPart = benchPercentilesOf(keySeconds)
			row.WholeSend = benchPercentilesOf(sendSeconds)
			self.Rows = append(self.Rows, row)
		}
	}
	figures := benchShapeFigures(world)
	for _, shape := range shapes {
		shape.Prove = benchPercentilesOf(shape.proveSeconds)
		shape.Verify = benchPercentilesOf(shape.verifySeconds)
		if figure, ok := figures[shape.Name]; ok {
			shape.Constraints, shape.PublicInputs, shape.DomainSize = figure.Constraints, figure.PublicInputs, figure.DomainSize
		}
		self.Shapes = append(self.Shapes, shape)
	}
	slices.SortFunc(self.Shapes, func(a *benchShape, b *benchShape) int { return strings.Compare(a.Name, b.Name) })
	return nil
}

// The report as a person reads it.
func (self *benchReport) write(out io.Writer) {
	host := self.Host
	fmt.Fprintf(out, "host: %s, %d cores, %d MiB, %s/%s, %s, load %s", host.Cpu, host.Cores, host.MemoryMebibytes, host.Os, host.Arch, host.GoVersion, host.Load)
	if host.Shared {
		fmt.Fprint(out, ", shared: other load ran beside this, so its times read high")
	}
	fmt.Fprintf(out, "\nsettings: %s\n", self.Settings)
	for i, prepare := range self.Prepares {
		fmt.Fprintf(out, "ensure_keys %d: %.1f s, ready %s\n", i+1, prepare.Seconds, strings.Join(prepare.ReadySuites, " "))
	}
	seconds := func(percentiles *benchPercentiles) string {
		if percentiles == nil {
			return "none"
		}
		return fmt.Sprintf("p50 %.2f s, p95 %.2f s, max %.2f s", percentiles.P50, percentiles.P95, percentiles.Max)
	}
	for _, row := range self.Rows {
		fmt.Fprintf(out, "%s %s: %d runs, %d failed, %d units; key part %s; send %s\n", row.Leg, row.Mode, row.Runs, row.Failures, row.Units, seconds(row.KeyPart), seconds(row.WholeSend))
		if row.FirstError != "" {
			fmt.Fprintf(out, "  first failure: %s\n", row.FirstError)
		}
	}
	for _, shape := range self.Shapes {
		fmt.Fprintf(out, "unit %s: %d units; prove %s; verify %s; %d constraints, %d public inputs, domain %d\n",
			shape.Name, shape.Units, seconds(shape.Prove), seconds(shape.Verify), shape.Constraints, shape.PublicInputs, shape.DomainSize)
	}
	fmt.Fprintf(out, "peak resident: %d MiB\n", self.PeakResidentMebibytes)
}

// One shape's compiled figures.
type benchFigure struct {
	Constraints  int
	PublicInputs int
	DomainSize   int
}

// Each cached shape's figures: keyset.json names each shape's circuit digest and domain, and the host's cache
// holds the compiled circuit its own check wrote, which this reads. Nothing for a world with no cache.
func benchShapeFigures(world *benchWorld) map[string]*benchFigure {
	figures := map[string]*benchFigure{}
	if world.manifestPath == "" {
		return figures
	}
	encoded, err := os.ReadFile(world.manifestPath)
	if err != nil {
		return figures
	}
	manifest := &struct {
		Shapes []struct {
			Name          string `json:"name"`
			CircuitSha256 string `json:"circuit_sha256"`
			DomainSize    int    `json:"domain_size"`
		} `json:"shapes"`
	}{}
	if json.Unmarshal(encoded, manifest) != nil {
		return figures
	}
	entries, _ := os.ReadDir(world.cacheDirectory)
	for _, shape := range manifest.Shapes {
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), shape.CircuitSha256+"-") || !strings.HasSuffix(entry.Name(), ".r1cs") {
				continue
			}
			file, err := os.Open(filepath.Join(world.cacheDirectory, entry.Name()))
			if err != nil {
				continue
			}
			compiled := groth16.NewCS(ecc.BN254)
			_, err = compiled.ReadFrom(file)
			file.Close()
			if err != nil {
				continue
			}
			figures[shape.Name] = &benchFigure{Constraints: compiled.GetNbConstraints(), PublicInputs: compiled.GetNbPublicVariables(), DomainSize: shape.DomainSize}
		}
	}
	return figures
}

// The host a run is on.
type benchHost struct {
	Cpu             string `json:"cpu"`
	Cores           int    `json:"cores"`
	MemoryMebibytes int64  `json:"memory_mib"`
	Os              string `json:"os"`
	Arch            string `json:"arch"`
	GoVersion       string `json:"go_version"`
	Load            string `json:"load_average"`
	Shared          bool   `json:"shared"`
}

// The host's CPU, cores, memory and load: sysctl on darwin, /proc on linux, unknown elsewhere. A load average
// past a quarter of the cores labels the run shared, as -shared does.
func benchHostReport(shared bool) *benchHost {
	host := &benchHost{Cpu: "unknown", Cores: runtime.NumCPU(), Os: runtime.GOOS, Arch: runtime.GOARCH, GoVersion: runtime.Version(), Load: "unknown", Shared: shared}
	read := func(name string, args ...string) string {
		output, err := exec.Command(name, args...).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(output))
	}
	var load1 float64
	switch runtime.GOOS {
	case "darwin":
		if cpu := read("sysctl", "-n", "machdep.cpu.brand_string"); cpu != "" {
			host.Cpu = cpu
		}
		if memory, err := strconv.ParseInt(read("sysctl", "-n", "hw.memsize"), 10, 64); err == nil {
			host.MemoryMebibytes = memory / 1024 / 1024
		}
		if load := strings.Trim(read("sysctl", "-n", "vm.loadavg"), "{} "); load != "" {
			host.Load = load
			load1, _ = strconv.ParseFloat(strings.Fields(load)[0], 64)
		}
	case "linux":
		if cpuinfo, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			for _, line := range strings.Split(string(cpuinfo), "\n") {
				if name, value, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(name) == "model name" {
					host.Cpu = strings.TrimSpace(value)
					break
				}
			}
		}
		if meminfo, err := os.ReadFile("/proc/meminfo"); err == nil {
			for _, line := range strings.Split(string(meminfo), "\n") {
				if fields := strings.Fields(line); 2 <= len(fields) && fields[0] == "MemTotal:" {
					kibibytes, _ := strconv.ParseInt(fields[1], 10, 64)
					host.MemoryMebibytes = kibibytes / 1024
				}
			}
		}
		if loadavg, err := os.ReadFile("/proc/loadavg"); err == nil {
			fields := strings.Fields(string(loadavg))
			if 3 <= len(fields) {
				host.Load = strings.Join(fields[:3], " ")
				load1, _ = strconv.ParseFloat(fields[0], 64)
			}
		}
	}
	if float64(host.Cores)/4 < load1 {
		host.Shared = true
	}
	return host
}

// This process's peak resident memory so far, in octets: getrusage's maxrss, octets on darwin and KiB elsewhere.
func benchPeakResidentBytes() int64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	if runtime.GOOS == "darwin" {
		return int64(usage.Maxrss)
	}
	return int64(usage.Maxrss) * 1024
}

// One send's parts as the edge took them, and how it ended.
type benchSendResult struct {
	result  *sidecar.SmtpProofResult
	parts   []*benchPart
	seconds float64
}

type benchPart struct {
	shape         string
	proveSeconds  float64
	verifySeconds float64
}

// The values a bench send declares, of SPEC.md section 6's forms, naming no real network or person.
const (
	benchRecipientDomain = "recipient.example"
	benchNetworkDomain   = "net.root.example"
	benchHeloName        = "o1.out.relay.example"
	benchMxHost          = "mx.recipient.example"
	benchMessageId       = "abcdefghijklmnopqrstuvwxyz@net.root.example"
	benchSelector        = "s1"
	benchXUrRef          = "1.aeibceqtcqkrmfyydenbxifbukr2jjngu4"
	benchFeedbackId      = "n:c:gaytemzugu3doobzhi5typj6h4:urnetwork"
)

// D-SMTP-16's sends at the options' sizes: BDAT with a header block of headerByteCount octets to recipientCount
// recipients; DATA with a message of messageByteCount octets, its body whole lines. The single fields and the
// fixed signature come first, in the header block's first record.
func benchJob(mode string, options *benchOptions) *sidecar.SmtpProofJob {
	header := "From: Bench Sender <sender@" + benchNetworkDomain + ">\r\n" +
		"Message-ID: <" + benchMessageId + ">\r\n" +
		"X-UR-Ref: " + benchXUrRef + "\r\n" +
		"Feedback-ID: " + benchFeedbackId + "\r\n" +
		"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:date:message-id:x-ur-ref:feedback-id; d=" +
		benchNetworkDomain + "; s=" + benchSelector + "; t=1; x=2; bh=AAAA; b=BBBB\r\n" +
		"To: <recipient-0@" + benchRecipientDomain + ">\r\n" +
		"Subject: A synthetic message for the bench\r\n" +
		"Date: Thu, 19 Nov 2026 12:00:00 +0000\r\n"
	const fill = "X-Padding: a line of filler to reach the gate's header size, no field the scan reads\r\n"
	for len(header)+len(fill)+len("\r\n") <= options.headerByteCount {
		header += fill
	}
	if short := options.headerByteCount - len(header) - len("\r\n"); len("X-Padding: a\r\n") <= short {
		header += "X-Padding: " + strings.Repeat("a", short-len("X-Padding: \r\n")) + "\r\n"
	}
	header += "\r\n"
	body := "a body line\r\n"
	if mode == "data" {
		const line = "a line of the body, whole, no dot first, ending CRLF as DATA's lines do\r\n"
		left := options.messageByteCount - len(header)
		body = strings.Repeat(line, left/len(line)-1)
		body += strings.Repeat("b", left-len(body)-len("\r\n")) + "\r\n"
	}
	recipients := make([]string, options.recipientCount)
	for i := range recipients {
		recipients[i] = "recipient-" + strconv.Itoa(i)
	}
	message := []byte(header + body)
	return &sidecar.SmtpProofJob{
		SendId: []byte("bench-send-id"),
		Preamble: &sidecar.SmtpProofPreamble{
			RecipientDomain:  benchRecipientDomain,
			RecipientCount:   uint32(len(recipients)),
			MessageId:        benchMessageId,
			HeaderFromDomain: benchNetworkDomain,
			DkimSelector:     benchSelector,
			MessageByteCount: uint64(len(message)),
			HeloName:         benchHeloName,
			XUrRef:           benchXUrRef,
			FeedbackId:       benchFeedbackId,
			EnvelopeDomain:   "b." + benchNetworkDomain,
			MxHost:           benchMxHost,
		},
		SenderLocal:     "bounce-1",
		RecipientLocals: recipients,
		Message:         message,
		// the bench measures proofs, not TL levels: the MX's chain is the scripted MX's own
		VerifyPeer: func(chain []*x509.Certificate) error { return nil },
	}
}

// One send through the edge's gate to a scripted MX on the leg, its parts timed.
func benchSend(ctx context.Context, verifier sidecar.SmtpProofVerifier, prover sidecar.SmtpProver, leg *benchLeg, mode string, options *benchOptions) (*benchSendResult, error) {
	mxSettings := sidecartest.DefaultScriptedMxSettings()
	mxSettings.MinVersion, mxSettings.MaxVersion = leg.version, leg.version
	if leg.version == tls.VersionTLS12 {
		mxSettings.CipherSuites = []uint16{leg.suite}
	}
	script := sidecartest.DefaultMxScript()
	if mode == "data" {
		script.Keywords = slices.DeleteFunc(slices.Clone(script.Keywords), func(keyword string) bool { return keyword == "CHUNKING" })
	}
	mx, err := sidecartest.NewScriptedMx(benchMxHost, script, mxSettings)
	if err != nil {
		return nil, err
	}
	job := benchJob(mode, options)
	job.KeySet = prover.KeySet()
	job.Preamble.ProofKeySet = job.KeySet
	if mode == "data" {
		job.Preamble.MessageByteCount = uint64(len(benchDotStuffed(job.Message)))
	}
	session, err := verifier.NewSmtpProofSession(job.Preamble)
	if err != nil {
		return nil, err
	}
	sidecarConn, edgeSidecarConn := net.Pipe()
	edgeMxConn, mxConn := sidecartest.NewMxPipe(nil, nil)
	mxDone := make(chan struct{})
	go func() {
		defer close(mxDone)
		mx.ServeMx(mxConn)
	}()
	defer func() {
		sidecarConn.Close()
		edgeSidecarConn.Close()
		edgeMxConn.Close()
		<-mxDone
	}()
	if err := benchPreTls(edgeMxConn); err != nil {
		return nil, err
	}
	relay := &benchRelay{session: session, sidecarConn: edgeSidecarConn, mxConn: edgeMxConn, leg: leg, start: time.Now()}
	relay.run()
	start := time.Now()
	result, err := prover.SendSmtp(ctx, sidecarConn, job, relay)
	elapsed := time.Since(start)
	sidecarConn.Close()
	relay.wait()
	if err != nil {
		return nil, err
	}
	return &benchSendResult{result: result, parts: relay.timedParts(), seconds: elapsed.Seconds()}, nil
}

// A message as DATA carries it: a leading dot doubled on each line.
func benchDotStuffed(message []byte) []byte {
	stuffed := make([]byte, 0, len(message))
	lineStart := true
	for _, octet := range message {
		if lineStart && octet == '.' {
			stuffed = append(stuffed, '.')
		}
		stuffed = append(stuffed, octet)
		lineStart = octet == '\n'
	}
	return stuffed
}

// The edge's pre-TLS dialog: the banner, EHLO and STARTTLS's 220, with nothing after it.
func benchPreTls(conn net.Conn) error {
	expect := func(code string) error {
		for {
			line, err := benchReadLine(conn)
			if err != nil {
				return err
			}
			if !strings.HasPrefix(line, code) {
				return fmt.Errorf("the MX answered %q", line)
			}
			if len(line) < 4 || line[3] != '-' {
				return nil
			}
		}
	}
	if err := expect("220"); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("EHLO " + benchHeloName + "\r\n")); err != nil {
		return err
	}
	if err := expect("250"); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("STARTTLS\r\n")); err != nil {
		return err
	}
	return expect("220")
}

// One line, read an octet at a time so that nothing past it is taken from the stream TLS goes on.
func benchReadLine(conn net.Conn) (string, error) {
	var line []byte
	octet := make([]byte, 1)
	for {
		if _, err := io.ReadFull(conn, octet); err != nil {
			return "", err
		}
		line = append(line, octet[0])
		if octet[0] == '\n' {
			return strings.TrimRight(string(line), "\r\n"), nil
		}
	}
}

// The edge between the prover and the MX for one connection, as smtpedge splices it: each record through the
// session, which releases records for the MX in its order, and each part to the session, timed.
type benchRelay struct {
	session     sidecar.SmtpProofSession
	sidecarConn net.Conn
	mxConn      net.Conn
	leg         *benchLeg
	start       time.Time

	relays sync.WaitGroup
	// held around each session call and the writes it releases, since the gate's order is the MX's
	forwardLock sync.Mutex

	stateLock         sync.Mutex
	parts             []*sidecar.SmtpProofPart
	timings           []*benchPart
	last              time.Time
	headerRecordCount uint32
	carriedParts      uint32
}

func benchReadRecord(conn net.Conn) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	record := make([]byte, 5+(int(header[3])<<8|int(header[4])))
	copy(record, header)
	if _, err := io.ReadFull(conn, record[5:]); err != nil {
		return nil, err
	}
	return record, nil
}

func (self *benchRelay) forward(call func() ([][]byte, error)) error {
	self.forwardLock.Lock()
	defer self.forwardLock.Unlock()
	records, err := call()
	if err != nil {
		return err
	}
	for _, record := range records {
		if _, err := self.mxConn.Write(record); err != nil {
			return err
		}
	}
	return nil
}

func (self *benchRelay) run() {
	self.last = self.start
	self.relays.Add(2)
	go func() {
		defer self.relays.Done()
		defer self.mxConn.Close()
		for {
			record, err := benchReadRecord(self.sidecarConn)
			if err != nil {
				return
			}
			if err := self.forward(func() ([][]byte, error) { return self.session.ClientRecord(record) }); err != nil {
				return
			}
		}
	}()
	go func() {
		defer self.relays.Done()
		defer self.sidecarConn.Close()
		for {
			record, err := benchReadRecord(self.mxConn)
			if err != nil {
				self.session.ServerClosed()
				return
			}
			if err := self.session.ServerRecord(record); err != nil {
				return
			}
			if _, err := self.sidecarConn.Write(record); err != nil {
				return
			}
		}
	}()
}

func (self *benchRelay) wait() {
	self.mxConn.Close()
	self.sidecarConn.Close()
	self.relays.Wait()
}

// DiscloseShts of sidecar.SmtpProofChannel: the handshake's end, from which the key part is timed.
func (self *benchRelay) DiscloseShts(ctx context.Context, shts []byte) error {
	err := self.forward(func() ([][]byte, error) { return self.session.DiscloseShts(shts) })
	self.stateLock.Lock()
	self.last = time.Now()
	self.stateLock.Unlock()
	return err
}

// SubmitPart of sidecar.SmtpProofChannel: the part's time since the answer before, and its verification's.
func (self *benchRelay) SubmitPart(ctx context.Context, part *sidecar.SmtpProofPart) error {
	submitted := time.Now()
	err := self.forward(func() ([][]byte, error) { return self.session.VerifyPart(ctx, part) })
	answered := time.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.parts = append(self.parts, part)
	self.timings = append(self.timings, &benchPart{
		shape:         self.shapeOfWithLock(part),
		proveSeconds:  submitted.Sub(self.last).Seconds(),
		verifySeconds: answered.Sub(submitted).Seconds(),
	})
	self.last = answered
	return err
}

// The catalog shape a part proves under, by what its fields say of its kind and the leg's family: the key part
// is part 1; the msg part names k; a part with a carry after it opens a header record, the next k - 1 of them,
// then a body record; every other an env part.
func (self *benchRelay) shapeOfWithLock(part *sidecar.SmtpProofPart) string {
	kind := smtpproof.ShapeKindEnvelope
	switch {
	case part.Index == 1:
		kind = smtpproof.ShapeKindKey
	case part.HeaderRecordCount != 0:
		kind = smtpproof.ShapeKindMessage
		self.headerRecordCount = part.HeaderRecordCount
	case 0 < len(part.Carry) || (part.Last && len(part.Records) != 0 && self.headerRecordCount != 0):
		self.carriedParts += 1
		kind = smtpproof.ShapeKindBody
		if self.carriedParts < self.headerRecordCount {
			kind = smtpproof.ShapeKindHeader
		}
	}
	family := smtpproof.ShapeFamilyAes128Gcm
	if self.leg.suite == tls.TLS_CHACHA20_POLY1305_SHA256 {
		family = smtpproof.ShapeFamilyChacha20
	}
	version := uint16(0)
	if kind == smtpproof.ShapeKindKey {
		version = self.leg.version
	}
	for _, entry := range smtpproof.DefaultProofSettings().Shapes {
		if entry.Kind == kind && entry.Family == family && entry.Version == version {
			return entry.Name()
		}
	}
	return string(kind) + "-" + string(family)
}

func (self *benchRelay) timedParts() []*benchPart {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.timings)
}

var _ sidecar.SmtpProofChannel = (*benchRelay)(nil)
