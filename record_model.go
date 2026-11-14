//go:build !ios_extension

// Model receipts' manifest half (RECORD-M6-08; RECORD.md section 12; D-RECORD-11, R-MCP-7, I-7, I-20). D-CTX-5 keeps
// per-request signing out of scope, so a model receipt is three records joined by run, grant and time: the `model`
// entry written here, the host's `reach` entry for a forward to the port, whose header content names the manifest in
// force (RecordReachNote.Manifest), and the harness's `model_call` entries (mcp's ingest). A reader's join of a run
// to a manifest is an inference, since no byte ties one request to one window, and RecordModelJoinLabel says so
// wherever a join is shown.
//
//	evidence   1 declared: a person typed it, confirmed on /dev/tty or in an app. 2 reported: the engine said so over
//	           loopback, through a RecordModelListing. 3 measured: this daemon hashed the files a person named,
//	           RecordModelWeightsDigest; it shows the bytes on disk at hashing, not what the engine loaded. 4 attested
//	           is reserved for hardware attestation: nothing here sets it, the writer refuses a manifest carrying it,
//	           and software evidence is never presented as it
//	change     a port's manifest is rebuilt at each Declare, Probe and Remeasure, and an entry is written only when
//	           its stored bytes differ from the last one's; the entry in force is what later receipts name
//	probing    at most once a ListingInterval for a port, and never a port that needs a credential: a listing that
//	           answers ErrRecordModelCredential marks the port, its reported fields stay empty, and no later probe
//	           reaches it until a person declares it again (I-7). No adapter ships yet: the listing is a seam
//	hosted     a hosted model has no manifest: the record stops at harness and model name
//
// A port's state is the record component's file model/<port>: what was declared and reported, the weight files' paths,
// sizes and times, and the entry in force. Weight paths stay in that file and reach no entry and no server. Safe for
// concurrent use.

package sidecar

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// How a reader's join of a run to a manifest is labeled wherever it is shown.
const RecordModelJoinLabel = "inferred from the run's sidecar, the grant and the window: no byte ties a request to a manifest"

const (
	recordModelWeightsContext = "urnetwork-sidecar-v1/model-weights"
	recordModelStatePrefix    = "model/"
	recordModelStateVersion   = 1
)

var (
	ErrRecordModelInvalid = errors.New("record: model manifest invalid")
	// A listing's answer for a port whose engine asks for a credential: the port is not probed.
	ErrRecordModelCredential = errors.New("record: the model port needs a credential")
	ErrRecordModelHarness    = errors.New("record: a model manifest is declared by a person, not under a harness")
)

// The manifest's caps and the probe's pace.
type RecordModelSettings struct {
	// A ModelField's value in bytes: 128 (RECORD.md section 12).
	FieldByteCount int
	// The ports a host keeps manifests of.
	PortCount int
	// The files, and a relative path's bytes, a port's --weights arguments may hold together. A path's length is
	// written as a u16, so the bytes stay under 65,536.
	WeightsFileCount     int
	WeightsPathByteCount int
	// The buffer a file is hashed through.
	HashByteCount int
	// A port is probed at most once in this: the reach receipts' window, 5 min.
	ListingInterval time.Duration
}

// RECORD.md section 12's field size and the receipts' window.
func DefaultRecordModelSettings() *RecordModelSettings {
	return &RecordModelSettings{
		FieldByteCount:       128,
		PortCount:            64,
		WeightsFileCount:     4096,
		WeightsPathByteCount: 4096,
		HashByteCount:        1024 * 1024,
		ListingInterval:      5 * time.Minute,
	}
}

// One weight file as the digest takes it.
type RecordModelWeightFile struct {
	// Relative to its --weights argument, UTF-8 with / between components.
	Path   string
	Sha256 [sha256.Size]byte
	// What a later look compares, to hash again only on a change.
	ByteCount int64
	ModMillis int64
}

// Section 5.1's weights_digest: lowercase hex of SHA-256 over the context, a zero byte, the file count as a u32, and
// per file, ascending by path bytes, the path's length as a u16, the path and the file's SHA-256.
func RecordModelWeightsDigest(files []*RecordModelWeightFile) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("%w: no weight file", ErrRecordModelInvalid)
	}
	sorted := slices.Clone(files)
	slices.SortFunc(sorted, func(a *RecordModelWeightFile, b *RecordModelWeightFile) int { return strings.Compare(a.Path, b.Path) })
	hash := sha256.New()
	hash.Write([]byte(recordModelWeightsContext))
	hash.Write([]byte{0})
	hash.Write(binary.BigEndian.AppendUint32(nil, uint32(len(sorted))))
	for i, file := range sorted {
		if file.Path == "" || !utf8.ValidString(file.Path) || 0xffff < len(file.Path) {
			return "", fmt.Errorf("%w: a weight path of %d bytes, or not UTF-8", ErrRecordModelInvalid, len(file.Path))
		}
		if 0 < i && sorted[i-1].Path == file.Path {
			return "", fmt.Errorf("%w: two weight files at one path", ErrRecordModelInvalid)
		}
		hash.Write(binary.BigEndian.AppendUint16(nil, uint16(len(file.Path))))
		hash.Write([]byte(file.Path))
		hash.Write(file.Sha256[:])
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// One --weights argument: a tree, or one file.
type RecordModelWeights struct {
	// The tree at the argument, or for a file argument its directory.
	Fs fs.FS
	// "." for a tree; a file argument's name.
	Root string
}

// The --weights argument at a local path.
func RecordModelWeightsAt(path string) (*RecordModelWeights, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecordModelInvalid, err)
	}
	if info.IsDir() {
		return &RecordModelWeights{Fs: os.DirFS(path), Root: "."}, nil
	}
	return &RecordModelWeights{Fs: os.DirFS(filepath.Dir(path)), Root: filepath.Base(path)}, nil
}

// Walks each argument's regular files, hashing each when hashed, in argument order. Anything but a directory and a
// regular file is refused, a link among them: a digest that skipped a file would say less than it seems to.
func recordModelWalk(ctx context.Context, weights []*RecordModelWeights, settings *RecordModelSettings, hashed bool) ([]*RecordModelWeightFile, error) {
	files := []*RecordModelWeightFile{}
	pathByteCount := 0
	buffer := make([]byte, max(settings.HashByteCount, 4096))
	for _, argument := range weights {
		if argument == nil || argument.Fs == nil {
			return nil, fmt.Errorf("%w: a weights argument with no tree", ErrRecordModelInvalid)
		}
		err := fs.WalkDir(argument.Fs, argument.Root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("%w: %s is no regular file", ErrRecordModelInvalid, path)
			}
			pathByteCount += len(path)
			if settings.WeightsFileCount <= len(files) || settings.WeightsPathByteCount < pathByteCount {
				return fmt.Errorf("%w: more weight files than %d, or paths past %d bytes", ErrRecordModelInvalid, settings.WeightsFileCount, settings.WeightsPathByteCount)
			}
			file := &RecordModelWeightFile{Path: path, ByteCount: info.Size(), ModMillis: info.ModTime().UnixMilli()}
			if hashed {
				opened, err := argument.Fs.Open(path)
				if err != nil {
					return err
				}
				hash := sha256.New()
				_, err = io.CopyBuffer(hash, opened, buffer)
				opened.Close()
				if err != nil {
					return err
				}
				copy(file.Sha256[:], hash.Sum(nil))
			}
			files = append(files, file)
			return nil
		})
		if err != nil {
			if errors.Is(err, ErrRecordModelInvalid) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			return nil, fmt.Errorf("%w: %w", ErrRecordModelInvalid, err)
		}
	}
	return files, nil
}

// Hashes the files a person named: each file's SHA-256, then their weights_digest and total bytes. Evidence 3.
func RecordModelMeasure(ctx context.Context, weights []*RecordModelWeights, settings *RecordModelSettings) (string, uint64, []*RecordModelWeightFile, error) {
	if settings == nil {
		settings = DefaultRecordModelSettings()
	}
	files, err := recordModelWalk(ctx, weights, settings, true)
	if err != nil {
		return "", 0, nil, err
	}
	digest, err := RecordModelWeightsDigest(files)
	if err != nil {
		return "", 0, nil, err
	}
	byteCount := uint64(0)
	for _, file := range files {
		byteCount += uint64(max(file.ByteCount, 0))
	}
	return digest, byteCount, files, nil
}

// What a person states of a port, each empty for unstated, and what an engine's listing reports.
type RecordModelFields struct {
	ServedName    string `json:"served_name,omitempty"`
	Engine        string `json:"engine,omitempty"`
	EngineVersion string `json:"engine_version,omitempty"`
	Quantization  string `json:"quantization,omitempty"`
}

// Reads an engine's model listing over loopback on the host, never sending a credential: ErrRecordModelCredential
// for a port that asks for one. M6's entry fixes the adapters (vllm, sglang, ollama, llama.cpp).
type RecordModelListing interface {
	List(ctx context.Context, port uint32) (*RecordModelFields, error)
}

// One weight file's place, size and time, as the port's state keeps it.
type recordModelWeightStat struct {
	Path      string `json:"path"`
	ByteCount int64  `json:"byte_count"`
	ModMillis int64  `json:"mod_millis"`
}

// The entry in force for a port.
type RecordModelRef struct {
	LogId      Id     `json:"log_id"`
	EntryId    Id     `json:"entry_id"`
	Commitment []byte `json:"commitment"`
}

// A port's state file.
type recordModelDocument struct {
	Version  int               `json:"version"`
	Port     uint32            `json:"port"`
	Declared RecordModelFields `json:"declared"`
	Reported RecordModelFields `json:"reported"`
	// the --weights arguments as local paths, their digest and bytes, and each file as it was at hashing
	WeightPaths   []string                 `json:"weight_paths,omitempty"`
	WeightsDigest string                   `json:"weights_digest,omitempty"`
	WeightsBytes  uint64                   `json:"weights_bytes,omitempty"`
	WeightFiles   []*recordModelWeightStat `json:"weight_files,omitempty"`
	// the engine asked for a credential: not probed
	Credential   bool  `json:"credential,omitempty"`
	ProbedMillis int64 `json:"probed_millis,omitempty"`
	// SHA-256 of the last manifest written as stored, and where it went; Ref is nil while that entry waits in the
	// spool
	ManifestSha256 []byte          `json:"manifest_sha256,omitempty"`
	Ref            *RecordModelRef `json:"ref,omitempty"`
}

// A port's manifest and its entry, as `ur record model show` prints them.
type RecordModelStatus struct {
	Port     uint32
	Manifest *protocol.ModelManifest
	// The entry later receipts name; nil before any, and while one waits in the spool.
	Ref *RecordModelRef
	// The port asked for a credential, so nothing is reported of it.
	Credential bool
	// Whether this call wrote a new entry.
	Written bool
}

// What `ur record model set` states.
type RecordModelDeclareArgs struct {
	Port   uint32
	Fields RecordModelFields
	// Local paths of the --weights arguments; empty keeps what was measured before.
	WeightPaths []string
	// The caller runs under a harness process: refused, since a person declares.
	HarnessAncestor bool
	// A person confirmed on /dev/tty or in an app.
	Confirmed bool
}

// The manifests of the ports this host serves models on.
type RecordModels struct {
	writer   RecordWriter
	store    SidecarStore
	chain    *RecordChainStore
	clock    Clock
	settings *RecordModelSettings

	// one change of a port at a time, across its hashing and its entry
	changeLock sync.Mutex

	stateLock sync.Mutex
	listing   RecordModelListing
	// how a weights path opens: RecordModelWeightsAt, or a test's
	open func(path string) (*RecordModelWeights, error)
}

// The manifests kept in store, the record component's directory, their entries written through writer.
func NewRecordModels(writer RecordWriter, store SidecarStore, writerSidecarId Id, clock Clock, settings *RecordModelSettings) *RecordModels {
	if settings == nil {
		settings = DefaultRecordModelSettings()
	}
	return &RecordModels{
		writer:   writer,
		store:    store,
		chain:    NewRecordChainStore(store, writerSidecarId),
		clock:    clock,
		settings: settings,
		open:     RecordModelWeightsAt,
	}
}

// The record's model manifests, made at the first call.
func (self *SidecarRecord) Models() *RecordModels {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	models, _ := self.models.(*RecordModels)
	if models == nil {
		models = NewRecordModels(self.writer, self.writer.store, self.writer.sidecarId, self.writer.clock, nil)
		self.models = models
	}
	return models
}

// Sets the engine listing probes read, nil for none.
func (self *RecordModels) SetListing(listing RecordModelListing) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.listing = listing
}

// Replaces how a weights path opens: a test's fixture tree.
func (self *RecordModels) SetWeightsOpener(open func(path string) (*RecordModelWeights, error)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if open != nil {
		self.open = open
	}
}

// The state file of port.
func recordModelStateName(port uint32) string {
	return recordModelStatePrefix + strconv.FormatUint(uint64(port), 10)
}

// The port's state, empty for a port never set.
func (self *RecordModels) load(port uint32) (*recordModelDocument, bool, error) {
	content, err := self.chain.readFile(recordModelStateName(port))
	if err != nil {
		return nil, false, err
	}
	document := &recordModelDocument{Version: recordModelStateVersion, Port: port}
	if content == nil {
		return document, false, nil
	}
	if err := recordChainDecode(content, document); err != nil || document.Version != recordModelStateVersion || document.Port != port {
		return nil, false, fmt.Errorf("%w: model state of port %d", ErrRecordChainCorrupt, port)
	}
	return document, true, nil
}

// Writes a port's state durably.
func (self *RecordModels) keep(document *recordModelDocument) error {
	content, err := json.Marshal(document)
	if err != nil {
		return err
	}
	if err := self.chain.writeFile(recordModelStateName(document.Port), content); err != nil {
		return fmt.Errorf("record: model state: %w", err)
	}
	return nil
}

// A field's value and evidence: what the engine reported where it reported, else what a person declared, else unset.
func recordModelField(reported string, declared string) *protocol.ModelField {
	if reported != "" {
		return &protocol.ModelField{Value: reported, Evidence: RecordModelEvidenceReported}
	}
	if declared != "" {
		return &protocol.ModelField{Value: declared, Evidence: RecordModelEvidenceDeclared}
	}
	return nil
}

// The manifest a port's state comes to.
func (self *recordModelDocument) manifest() *protocol.ModelManifest {
	manifest := &protocol.ModelManifest{
		Port:          self.Port,
		ServedName:    recordModelField(self.Reported.ServedName, self.Declared.ServedName),
		Engine:        recordModelField(self.Reported.Engine, self.Declared.Engine),
		EngineVersion: recordModelField(self.Reported.EngineVersion, self.Declared.EngineVersion),
		Quantization:  recordModelField(self.Reported.Quantization, self.Declared.Quantization),
	}
	if self.WeightsDigest != "" {
		manifest.WeightsDigest = &protocol.ModelField{Value: self.WeightsDigest, Evidence: RecordModelEvidenceMeasured}
		manifest.WeightsBytes = self.WeightsBytes
	}
	return manifest
}

// Holds a manifest to RECORD.md section 12 as a v1 writer writes one: a port, each field's value an identifier within
// byteCount, evidence declared, reported or measured, and measured on the weights digest alone. Attested is refused:
// no v1 writer has hardware evidence to present.
func RecordModelManifestValidate(manifest *protocol.ModelManifest, byteCount int) error {
	if err := recordModelManifestValidate(manifest, true); err != nil {
		return fmt.Errorf("%w: %v", ErrRecordModelInvalid, err)
	}
	fields := []*protocol.ModelField{
		manifest.GetServedName(), manifest.GetEngine(), manifest.GetEngineVersion(), manifest.GetQuantization(), manifest.GetWeightsDigest(),
	}
	for _, field := range fields {
		if field != nil && (byteCount < len(field.GetValue()) || !utf8.ValidString(field.GetValue())) {
			return fmt.Errorf("%w: a field of %d bytes", ErrRecordModelInvalid, len(field.GetValue()))
		}
	}
	return nil
}

// Writes the port's manifest as a model entry when its stored bytes differ from the last one's, and keeps the state.
// changeLock is held.
func (self *RecordModels) settle(document *recordModelDocument) (*RecordModelStatus, error) {
	manifest := document.manifest()
	status := &RecordModelStatus{Port: document.Port, Manifest: manifest, Ref: document.Ref, Credential: document.Credential}
	if err := RecordModelManifestValidate(manifest, self.settings.FieldByteCount); err != nil {
		return nil, err
	}
	stored, err := proto.MarshalOptions{Deterministic: true}.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(stored)
	if slices.Equal(digest[:], document.ManifestSha256) {
		return status, self.keep(document)
	}
	refs, err := self.writer.Append(&RecordDraft{
		Kind:      RecordKindModel,
		Source:    RecordSourceObserved,
		NoSession: true,
		Body:      manifest,
	})
	if err != nil {
		return nil, err
	}
	document.ManifestSha256 = digest[:]
	document.Ref = nil
	for _, ref := range refs {
		if !ref.Spooled {
			document.Ref = &RecordModelRef{LogId: ref.LogId, EntryId: ref.EntryId, Commitment: slices.Clone(ref.Commitment[:])}
			break
		}
	}
	status.Ref = document.Ref
	status.Written = true
	return status, self.keep(document)
}

// The ports that hold state, ascending.
func (self *RecordModels) ports() ([]uint32, error) {
	entries, err := self.store.List(recordModelStatePrefix)
	if err != nil {
		return nil, err
	}
	ports := []uint32{}
	for _, entry := range entries {
		port, err := strconv.ParseUint(strings.TrimPrefix(entry.Name, recordModelStatePrefix), 10, 16)
		if err != nil || port == 0 {
			continue
		}
		ports = append(ports, uint32(port))
	}
	slices.Sort(ports)
	return ports, nil
}

// Hashes the port's weight paths into its state.
func (self *RecordModels) measure(ctx context.Context, document *recordModelDocument, paths []string) error {
	open := func() func(path string) (*RecordModelWeights, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.open
	}()
	weights := []*RecordModelWeights{}
	for _, path := range paths {
		argument, err := open(path)
		if err != nil {
			return err
		}
		weights = append(weights, argument)
	}
	digest, byteCount, files, err := RecordModelMeasure(ctx, weights, self.settings)
	if err != nil {
		return err
	}
	document.WeightPaths = slices.Clone(paths)
	document.WeightsDigest = digest
	document.WeightsBytes = byteCount
	document.WeightFiles = nil
	for _, file := range files {
		document.WeightFiles = append(document.WeightFiles, &recordModelWeightStat{Path: file.Path, ByteCount: file.ByteCount, ModMillis: file.ModMillis})
	}
	return nil
}

// A person's statement of a port: its declared fields replace the port's, the weights named are hashed, and a manifest
// that changed is written. A declaration also clears the credential mark, so the port is probed again.
func (self *RecordModels) Declare(ctx context.Context, args *RecordModelDeclareArgs) (*RecordModelStatus, error) {
	if args == nil || args.Port == 0 || 0xffff < args.Port {
		return nil, fmt.Errorf("%w: no port", ErrRecordModelInvalid)
	}
	if args.HarnessAncestor {
		return nil, ErrRecordModelHarness
	}
	if !args.Confirmed {
		return nil, fmt.Errorf("%w: a declaration takes a person's confirmation", ErrRecordModelInvalid)
	}
	self.changeLock.Lock()
	defer self.changeLock.Unlock()
	document, held, err := self.load(args.Port)
	if err != nil {
		return nil, err
	}
	if !held {
		ports, err := self.ports()
		if err != nil {
			return nil, err
		}
		if self.settings.PortCount <= len(ports) {
			return nil, fmt.Errorf("%w: %d ports hold a manifest already", ErrRecordModelInvalid, len(ports))
		}
	}
	document.Declared = args.Fields
	document.Credential = false
	if 0 < len(args.WeightPaths) {
		if err := self.measure(ctx, document, args.WeightPaths); err != nil {
			return nil, err
		}
	}
	return self.settle(document)
}

// Reads the engine's listing for a port a person declared, at most once a ListingInterval, and writes a manifest that
// changed. A port marked as needing a credential is not probed; one whose listing asks for a credential is marked and
// its reported fields emptied. Called while the port's grant has flows.
func (self *RecordModels) Probe(ctx context.Context, port uint32) (*RecordModelStatus, error) {
	listing := func() RecordModelListing {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.listing
	}()
	self.changeLock.Lock()
	defer self.changeLock.Unlock()
	document, held, err := self.load(port)
	if err != nil {
		return nil, err
	}
	if !held {
		return nil, fmt.Errorf("%w: port %d has no manifest", ErrRecordModelInvalid, port)
	}
	now := self.clock.Now().UnixMilli()
	due := document.ProbedMillis == 0 || self.settings.ListingInterval.Milliseconds() <= now-document.ProbedMillis
	if listing == nil || document.Credential || !due {
		return &RecordModelStatus{Port: port, Manifest: document.manifest(), Ref: document.Ref, Credential: document.Credential}, nil
	}
	document.ProbedMillis = now
	reported, err := listing.List(ctx, port)
	switch {
	case errors.Is(err, ErrRecordModelCredential):
		document.Credential = true
		document.Reported = RecordModelFields{}
	case err != nil:
		// an engine that is down reports nothing new: what it last reported stands
		if storeErr := self.keep(document); storeErr != nil {
			return nil, storeErr
		}
		return nil, err
	case reported != nil:
		document.Reported = *reported
	}
	return self.settle(document)
}

// Looks at the port's weight files again and hashes them only when one's size or time changed, or one came or went;
// a manifest that changed is written.
func (self *RecordModels) Remeasure(ctx context.Context, port uint32) (*RecordModelStatus, error) {
	self.changeLock.Lock()
	defer self.changeLock.Unlock()
	document, held, err := self.load(port)
	if err != nil {
		return nil, err
	}
	if !held {
		return nil, fmt.Errorf("%w: port %d has no manifest", ErrRecordModelInvalid, port)
	}
	status := &RecordModelStatus{Port: port, Manifest: document.manifest(), Ref: document.Ref, Credential: document.Credential}
	if len(document.WeightPaths) == 0 {
		return status, nil
	}
	open := func() func(path string) (*RecordModelWeights, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.open
	}()
	weights := []*RecordModelWeights{}
	for _, path := range document.WeightPaths {
		argument, err := open(path)
		if err != nil {
			return nil, err
		}
		weights = append(weights, argument)
	}
	seen, err := recordModelWalk(ctx, weights, self.settings, false)
	if err != nil {
		return nil, err
	}
	same := len(seen) == len(document.WeightFiles)
	for i := 0; same && i < len(seen); i += 1 {
		kept := document.WeightFiles[i]
		same = seen[i].Path == kept.Path && seen[i].ByteCount == kept.ByteCount && seen[i].ModMillis == kept.ModMillis
	}
	if same {
		return status, nil
	}
	if err := self.measure(ctx, document, document.WeightPaths); err != nil {
		return nil, err
	}
	return self.settle(document)
}

// A port's manifest and entry, and false for a port never set.
func (self *RecordModels) Show(port uint32) (*RecordModelStatus, bool, error) {
	document, held, err := self.load(port)
	if err != nil || !held {
		return nil, false, err
	}
	return &RecordModelStatus{Port: port, Manifest: document.manifest(), Ref: document.Ref, Credential: document.Credential}, true, nil
}

// Every port's, ascending.
func (self *RecordModels) List() ([]*RecordModelStatus, error) {
	ports, err := self.ports()
	if err != nil {
		return nil, err
	}
	statuses := []*RecordModelStatus{}
	for _, port := range ports {
		status, held, err := self.Show(port)
		if err != nil {
			return nil, err
		}
		if held {
			statuses = append(statuses, status)
		}
	}
	return statuses, nil
}

// The manifest in force for a port, as a reach receipt's header content names it: nil for a port with none, or
// whose entry waits in the spool.
func (self *RecordModels) InForce(port uint32) *RecordContentRef {
	document, held, err := self.load(port)
	if err != nil || !held || document.Ref == nil || len(document.Ref.Commitment) != sha256.Size {
		return nil
	}
	ref := &RecordContentRef{LogId: document.Ref.LogId, EntryId: document.Ref.EntryId}
	copy(ref.Commitment[:], document.Ref.Commitment)
	return ref
}
