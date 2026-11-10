// RECORD.md section 9's exports, on every leg: a reader's device writes what it decrypts as lines, to a file or to
// stdout, never to a network address. No server takes part, and no route, webhook or queue carries an entry.
//
//	who         a reader of the log, by a person's command; no MCP tool exports
//	confirm     bodies, the ocsf and otel formats, which carry body data, and a follow job only from a confirmed
//	            command; the caller taints a harness ancestor's runs first (Sidecar.TaintAncestorRuns); a plain jsonl
//	            export holds header fields alone and needs neither
//	record      write-ahead, before the first line is returned: a device that writes or deposits to the log files a
//	            disclosure entry with act 3, naming the range, kinds, run, format and whether bodies leave, and holds
//	            its commit; a receipt-only reader deposits read receipts, purpose 3, instead; a reader that can do
//	            neither exports nothing, and an export whose record cannot land is refused
//	target      the caller writes the lines to a file or stdout: nothing here dials
//	follow      a job in the record's loop, confirmed once, resumed from a cursor in the record component's state, a
//	            line per entry as it verifies, appended to a file through the sink the host gave; it ends with the
//	            sidecar's read of the log
//	copies      an exported line is a copy beyond recall; a later erasure does not reach it
//
// jsonl is the canonical form every other format maps from: one JSON object a line, keys sorted, no insignificant
// whitespace, ids in lowercase hex, header, salt and body in standard base64, times in RFC 3339 UTC with
// milliseconds. header, salt and body verify a line given its writer's public key, which no line carries. salt, body,
// fields and agent_label appear only with bodies, so a plain line holds what the header holds. fields is the body by
// proto field name, a convenience: body is what verifies. An erased entry is a stub: its state and its header's
// fields while the header is held, and nothing of its body. Slot rows are never exported: a line holds a salt, never
// a key. §11.12's token_path and entry_hash, which an evs export's stub names, are not on RecordStreams and are left
// out.
//
// ocsf (record_export_ocsf.go) and otel (record_export_otel.go) carry, of a body, only its numbers, booleans, ids,
// hashes and listed identifier strings, never prose, captured bytes, an action, relays or cidrs, and no string that
// parses as an IP address, so neither carries an address the record holds (I-13).
//
// Format 4 is `ur evs export`'s: each entry's file holds its canonical line with bodies, and the same who, confirm,
// record and copies rows bind it. Lines with Format git gives those lines; the evs export writes the files.
//
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// DisclosureBody.format: what an export wrote.
type RecordExportFormat uint32

const (
	RecordExportFormatJsonl RecordExportFormat = 1
	RecordExportFormatOcsf  RecordExportFormat = 2
	RecordExportFormatOtel  RecordExportFormat = 3
	// `ur evs export` of a log: each entry's file holds its canonical line with bodies.
	RecordExportFormatGit RecordExportFormat = 4
)

// The export's format values: the canonical line's version and time layout, and the follow jobs' state files.
const (
	recordExportLineVersion    = 1
	recordExportTimeLayout     = "2006-01-02T15:04:05.000Z"
	recordExportJobDirectory   = "export"
	recordExportJobVersion     = 1
	recordExportJobByteCount   = 1024 * 1024
	recordExportReceiptIdCount = 64
)

var (
	// The request names a format, a range or a kind an export does not take.
	ErrRecordExportArgs = errors.New("record export request invalid")
	// Bodies, ocsf, otel and a follow job take a command confirmed on /dev/tty or in an app's UI.
	ErrRecordExportUnconfirmed = errors.New("record export of body data takes a confirmed command")
	// A follow job has nowhere to write: this host gave the record no file sink.
	ErrRecordExportNoSink = errors.New("record export has no file sink on this host")
)

// The format a name on a command line means, false for a name that is none.
func RecordExportFormatNamed(name string) (RecordExportFormat, bool) {
	switch name {
	case "", "jsonl":
		return RecordExportFormatJsonl, true
	case "ocsf":
		return RecordExportFormatOcsf, true
	case "otel":
		return RecordExportFormatOtel, true
	}
	return 0, false
}

// What a person asks to export.
type RecordExportArgs struct {
	LogId Id
	// Entries whose time_millis is at or after since and before until; 0 for no bound.
	SinceMillis int64
	UntilMillis int64
	RunId       *Id
	// Empty for every kind.
	Kinds  []RecordKind
	Bodies bool
	Format RecordExportFormat
	// The person confirmed the command on /dev/tty or in an app's UI.
	Confirmed bool
}

// An export as made, its record landed.
type RecordExported struct {
	// One line an entry, in the log's read order, none ending in a newline.
	Lines [][]byte
	// The record is read receipts alone: this device files no disclosure entry in the log.
	ReceiptsOnly bool
}

// Exports what this device reads.
type RecordExport struct {
	record *SidecarRecord
	sink   func(path string) (io.WriteCloser, error)

	stateLock sync.Mutex
	// the follow jobs, once loaded
	jobs       []*recordExportJob
	jobsLoaded bool
	// a log a job follows may have moved
	due bool
}

// The record's export (RECORD-M6-07).
func (self *SidecarRecord) Export() *RecordExport {
	return self.export
}

// An export over record. A follow job has no sink until SetExportSink gives one.
func newRecordExport(record *SidecarRecord) *RecordExport {
	return &RecordExport{record: record, due: true}
}

// Gives the follow jobs where their lines go: sink opens the file at path to append to, and each batch of lines is
// one Write and a Close. Nil, the state until this is called, refuses a new job and leaves the held ones waiting.
func (self *SidecarRecord) SetExportSink(sink func(path string) (io.WriteCloser, error)) {
	self.export.stateLock.Lock()
	defer self.export.stateLock.Unlock()
	self.export.sink = sink
	self.export.due = true
}

// The sink now.
func (self *RecordExport) fileSink() func(path string) (io.WriteCloser, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sink
}

// Whether an export of args carries body data, and so takes a confirmed command.
func (self *RecordExportArgs) carriesBodies() bool {
	return self.Bodies || self.Format != RecordExportFormatJsonl
}

// The request's own rules.
func (self *RecordExportArgs) check() error {
	if self == nil {
		return fmt.Errorf("%w: no request", ErrRecordExportArgs)
	}
	if self.Format < RecordExportFormatJsonl || RecordExportFormatGit < self.Format {
		return fmt.Errorf("%w: format %d", ErrRecordExportArgs, uint32(self.Format))
	}
	if self.Format == RecordExportFormatGit && !self.Bodies {
		return fmt.Errorf("%w: an evs export's lines carry bodies", ErrRecordExportArgs)
	}
	if self.SinceMillis < 0 || self.UntilMillis < 0 || (0 < self.UntilMillis && self.UntilMillis <= self.SinceMillis) {
		return fmt.Errorf("%w: a range from %d to %d", ErrRecordExportArgs, self.SinceMillis, self.UntilMillis)
	}
	for _, kind := range self.Kinds {
		if kind == RecordKindUnspecified || kind.Derived() {
			return fmt.Errorf("%w: kind %d is in no header", ErrRecordExportArgs, uint32(kind))
		}
	}
	if self.carriesBodies() && !self.Confirmed {
		return ErrRecordExportUnconfirmed
	}
	return nil
}

// Whether the request takes entry.
func (self *RecordExportArgs) takes(entry *RecordReadEntry) bool {
	header := entry.Header.Header
	if header.GetTimeMillis() < self.SinceMillis || (0 < self.UntilMillis && self.UntilMillis <= header.GetTimeMillis()) {
		return false
	}
	if self.RunId != nil && !bytes.Equal(header.GetRunId(), self.RunId[:]) {
		return false
	}
	return len(self.Kinds) == 0 || slices.Contains(self.Kinds, entry.Kind())
}

// The disclosure entry's body for an export of args.
func (self *RecordExportArgs) disclosure() *protocol.DisclosureBody {
	body := &protocol.DisclosureBody{
		Act: RecordDisclosureActExport, SinceMillis: self.SinceMillis, UntilMillis: self.UntilMillis, Format: uint32(self.Format), Bodies: self.carriesBodies(),
	}
	for _, kind := range self.Kinds {
		body.Kinds = append(body.Kinds, uint32(kind))
	}
	if self.RunId != nil {
		body.RunId = self.RunId.Bytes()
	}
	return body
}

// An id as a line carries it: lowercase hex, empty for none.
func recordExportHex(value []byte) string {
	return hex.EncodeToString(value)
}

// A proto value as fields carries it: bytes as lowercase hex, enumerations as numbers, a message as an object by
// field name, a repeated field as an array.
func recordExportValue(field protoreflect.FieldDescriptor, value protoreflect.Value) any {
	switch field.Kind() {
	case protoreflect.BoolKind:
		return value.Bool()
	case protoreflect.BytesKind:
		return hex.EncodeToString(value.Bytes())
	case protoreflect.StringKind:
		return value.String()
	case protoreflect.EnumKind:
		return int64(value.Enum())
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return recordExportFields(value.Message())
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		return value.Float()
	case protoreflect.Uint32Kind, protoreflect.Uint64Kind, protoreflect.Fixed32Kind, protoreflect.Fixed64Kind:
		return value.Uint()
	}
	return value.Int()
}

// A message by proto field name, the fields it sets alone; unknown fields are left out, and stay in body.
func recordExportFields(message protoreflect.Message) map[string]any {
	fields := map[string]any{}
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		name := string(field.Name())
		switch {
		case field.IsList():
			items := []any{}
			for i := 0; i < value.List().Len(); i += 1 {
				items = append(items, recordExportValue(field, value.List().Get(i)))
			}
			fields[name] = items
		case field.IsMap():
			entries := map[string]any{}
			value.Map().Range(func(key protoreflect.MapKey, item protoreflect.Value) bool {
				entries[key.String()] = recordExportValue(field.MapValue(), item)
				return true
			})
			fields[name] = entries
		default:
			fields[name] = recordExportValue(field, value)
		}
		return true
	})
	return fields
}

// The fields of an entry's stored body, by its kind's one message: for a kind whose stored body is a Signed, what it
// signs. Nil for a kind this build does not name or a body that does not parse, which body still carries.
func recordExportBodyFields(kind RecordKind, body []byte) map[string]any {
	if signedBody, _, ok := kind.NewSignedBody(); ok {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(body, signed); err != nil || proto.Unmarshal(signed.GetBody(), signedBody) != nil {
			return nil
		}
		return recordExportFields(signedBody.ProtoReflect())
	}
	message, ok := kind.NewBody()
	if !ok || proto.Unmarshal(body, message) != nil {
		return nil
	}
	return recordExportFields(message.ProtoReflect())
}

// One entry's canonical line as a map, and the fields of its body when it is held, which the ocsf and otel maps read
// whether or not the line carries them.
func recordExportLine(entry *RecordReadEntry, bodies bool, agentLabel string) (map[string]any, map[string]any) {
	header := entry.Header.Header
	kind := entry.Kind()
	kindName := ""
	if kind.Known() {
		kindName = kind.String()
	}
	content := []any{}
	for _, ref := range header.GetContent() {
		content = append(content, map[string]any{
			"repo": recordExportHex(ref.GetRepoId()), "object": recordExportHex(ref.GetObjectId()), "commitment": recordExportHex(ref.GetCommitment()),
		})
	}
	line := map[string]any{
		"v":              recordExportLineVersion,
		"log":            recordExportHex(header.GetLogId()),
		"entry":          recordExportHex(header.GetEntryId()),
		"writer":         recordExportHex(header.GetWriterSidecarId()),
		"seq":            header.GetSeq(),
		"prev":           recordExportHex(header.GetPrevSha256()),
		"agent":          recordExportHex(header.GetAgentId()),
		"run":            recordExportHex(header.GetRunId()),
		"action":         recordExportHex(header.GetActionId()),
		"grant":          recordExportHex(header.GetGrantId()),
		"kind":           kindName,
		"kind_no":        uint32(kind),
		"time":           time.UnixMilli(header.GetTimeMillis()).UTC().Format(recordExportTimeLayout),
		"source":         header.GetSource(),
		"agent_source":   header.GetAgentSource(),
		"tainted":        header.GetTainted(),
		"policy_version": header.GetPolicyVersion(),
		"content":        content,
		"leaf":           recordExportHex(entry.Leaf[:]),
		"header":         base64.StdEncoding.EncodeToString(entry.SignedBytes),
		"state":          string(entry.State),
	}
	if entry.Body == nil || entry.State == RecordEntryErased {
		return line, nil
	}
	fields := recordExportBodyFields(kind, entry.Body)
	if bodies {
		line["salt"] = base64.StdEncoding.EncodeToString(entry.Salt)
		line["body"] = base64.StdEncoding.EncodeToString(entry.Body)
		if fields != nil {
			line["fields"] = fields
		}
		if agentLabel != "" {
			line["agent_label"] = agentLabel
		}
	}
	return line, fields
}

// A line's canonical bytes: keys sorted, no insignificant whitespace, nothing escaped that JSON does not require,
// and no newline.
func recordExportCanonical(line map[string]any) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(line); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

// Each run's agent label, from the context entries held: what a line's agent_label says.
func recordExportAgentLabels(entries []*RecordReadEntry) map[string]string {
	labels := map[string]string{}
	for _, entry := range entries {
		if entry.Kind() != RecordKindContext || entry.Body == nil || len(entry.Header.Header.GetRunId()) == 0 {
			continue
		}
		context := &protocol.ContextBody{}
		if err := proto.Unmarshal(entry.Body, context); err == nil && context.GetAgentLabel() != "" {
			labels[string(entry.Header.Header.GetRunId())] = context.GetAgentLabel()
		}
	}
	return labels
}

// The lines of entries in format, each as the format writes one entry.
func (self *RecordExport) lines(auth RecordAuthView, args *RecordExportArgs, entries []*RecordReadEntry, labels map[string]string) ([][]byte, error) {
	lines := [][]byte{}
	for _, entry := range entries {
		label := labels[string(entry.Header.Header.GetRunId())]
		line, fields := recordExportLine(entry, args.Bodies, label)
		switch args.Format {
		case RecordExportFormatOcsf:
			line = recordExportOcsf(auth, entry, fields)
		case RecordExportFormatOtel:
			line = recordExportOtel(entry, fields, label)
		}
		encoded, err := recordExportCanonical(line)
		if err != nil {
			return nil, err
		}
		lines = append(lines, encoded)
	}
	return lines, nil
}

// Files section 9's record of an export of entries and waits for it to land: a disclosure entry, or a receipt-only
// reader's receipts, 64 entries to one. True when receipts alone stand as the record.
func (self *RecordExport) recordExport(ctx context.Context, args *RecordExportArgs, entries []*RecordReadEntry) (bool, error) {
	record := self.record
	auth := record.writer.auth()
	sidecarId := record.writer.sidecarId
	if auth.Deposits(args.LogId, sidecarId) && auth.ReceiptOnly(args.LogId, sidecarId) {
		objectIds := [][]byte{}
		for _, entry := range entries {
			objectIds = append(objectIds, entry.EntryId.Bytes())
		}
		if len(objectIds) == 0 {
			// nothing is read, so nothing is receipted
			return true, nil
		}
		return true, record.receipts.Deposit(ctx, &RecordReceiptRequest{RepoId: args.LogId, Purpose: RecordReadPurposeExport, ObjectIds: objectIds, NoSession: true})
	}
	return (&RecordDisclosure{record: record}).recordAct(ctx, args.LogId, args.disclosure(), RecordReadPurposeExport, nil, args.Confirmed)
}

// Exports what args takes of the log as it stands, filing the export's record first: when this returns nil the log
// holds the act, and the caller writes the lines. See the file's header.
func (self *RecordExport) Export(ctx context.Context, args *RecordExportArgs) (*RecordExported, error) {
	if err := args.check(); err != nil {
		return nil, err
	}
	record := self.record
	auth := record.writer.auth()
	if !auth.Reads(args.LogId, record.writer.sidecarId) {
		return nil, fmt.Errorf("%w: %s", ErrRecordNotReader, args.LogId)
	}
	if err := record.reader.Sync(ctx, args.LogId); err != nil {
		return nil, err
	}
	all := record.reader.Entries(args.LogId)
	taken := []*RecordReadEntry{}
	for _, entry := range all {
		if args.takes(entry) {
			taken = append(taken, entry)
		}
	}
	receiptsOnly, err := self.recordExport(ctx, args, taken)
	if err != nil {
		return nil, err
	}
	lines, err := self.lines(auth, args, taken, recordExportAgentLabels(all))
	if err != nil {
		return nil, err
	}
	return &RecordExported{Lines: lines, ReceiptsOnly: receiptsOnly}, nil
}

// One follow job. Its fields are the export's stateLock's.
type recordExportJob struct {
	document *recordExportJobDocument
	// the log's subscription, which marks the export due
	unsubscribe func()
}

// A follow job's state, the record component's sealed file export/<job id>.
type recordExportJobDocument struct {
	Version     int      `json:"version"`
	JobId       Id       `json:"job_id"`
	LogId       Id       `json:"log_id"`
	SinceMillis int64    `json:"since_millis,omitempty"`
	RunId       *Id      `json:"run_id,omitempty"`
	Kinds       []uint32 `json:"kinds,omitempty"`
	Bodies      bool     `json:"bodies,omitempty"`
	Format      uint32   `json:"format"`
	// where its lines go: a file on this device
	Path string `json:"path"`
	// the cursor: each stream's version this job has exported through
	Streams []*recordExportJobStream `json:"streams,omitempty"`
}

// How far a job has exported one stream.
type recordExportJobStream struct {
	SidecarId Id     `json:"sidecar_id"`
	Version   uint64 `json:"version"`
}

// The job's request.
func (self *recordExportJobDocument) args() *RecordExportArgs {
	args := &RecordExportArgs{
		LogId: self.LogId, SinceMillis: self.SinceMillis, RunId: self.RunId, Bodies: self.Bodies, Format: RecordExportFormat(self.Format), Confirmed: true,
	}
	for _, kind := range self.Kinds {
		args.Kinds = append(args.Kinds, RecordKind(kind))
	}
	return args
}

// The state file of a job.
func recordExportJobName(jobId Id) string {
	return recordExportJobDirectory + "/" + recordChainIdText(jobId)
}

// Writes a job's state, durably.
func (self *RecordExport) writeJob(document *recordExportJobDocument) error {
	content, err := json.Marshal(document)
	if err != nil {
		return err
	}
	writer, err := self.record.writer.store.Create(recordExportJobName(document.JobId))
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(content); err != nil {
		return err
	}
	return writer.Commit()
}

// Reads the jobs the state holds, once: a file that does not decode is passed over, and its job does not run.
func (self *RecordExport) loadJobs() error {
	if func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.jobsLoaded
	}() {
		return nil
	}
	store := self.record.writer.store
	files, err := store.List(recordExportJobDirectory + "/")
	if err != nil {
		return err
	}
	documents := []*recordExportJobDocument{}
	for _, file := range files {
		reader, err := store.Open(file.Name)
		if err != nil {
			return err
		}
		content, err := io.ReadAll(io.LimitReader(reader, recordExportJobByteCount))
		reader.Close()
		if err != nil {
			return err
		}
		document := &recordExportJobDocument{}
		if err := recordChainDecode(content, document); err != nil || document.Version != recordExportJobVersion || recordExportJobName(document.JobId) != file.Name {
			self.record.writer.log.Warningf("[record]an export job's state does not read: %s", file.Name)
			continue
		}
		documents = append(documents, document)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.jobsLoaded {
		return nil
	}
	self.jobsLoaded = true
	for _, document := range documents {
		self.jobs = append(self.jobs, self.subscribeWithLock(document))
	}
	return nil
}

// A job over document, marking the export due whenever its log moves.
func (self *RecordExport) subscribeWithLock(document *recordExportJobDocument) *recordExportJob {
	job := &recordExportJob{document: document}
	job.unsubscribe = self.record.writer.boundStreams().Subscribe(document.LogId, func(repoId Id) {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.due = true
		}()
		self.record.writer.signal()
	})
	return job
}

// Starts a follow job: an export of args that goes on, appending a line per entry to the file at path as each
// verifies. Confirmed once, here; its disclosure entry lands before this returns and before any line is written,
// and the job's first lines go at the record's next pass. The job's id.
func (self *RecordExport) Follow(ctx context.Context, args *RecordExportArgs, path string) (Id, error) {
	if err := args.check(); err != nil {
		return Id{}, err
	}
	if !args.Confirmed {
		return Id{}, ErrRecordExportUnconfirmed
	}
	if args.UntilMillis != 0 || args.Format == RecordExportFormatGit || path == "" {
		return Id{}, fmt.Errorf("%w: a follow job takes a file, a format of lines and no end", ErrRecordExportArgs)
	}
	if self.fileSink() == nil {
		return Id{}, ErrRecordExportNoSink
	}
	record := self.record
	auth := record.writer.auth()
	if !auth.Reads(args.LogId, record.writer.sidecarId) {
		return Id{}, fmt.Errorf("%w: %s", ErrRecordNotReader, args.LogId)
	}
	if err := self.loadJobs(); err != nil {
		return Id{}, err
	}
	// the record of the job as a whole; a receipt-only reader's receipts go with each batch of lines instead
	if _, err := self.recordExport(ctx, args, nil); err != nil {
		return Id{}, err
	}
	jobId, err := record.writer.drawId()
	if err != nil {
		return Id{}, err
	}
	document := &recordExportJobDocument{
		Version: recordExportJobVersion, JobId: jobId, LogId: args.LogId, SinceMillis: args.SinceMillis, RunId: args.RunId,
		Bodies: args.Bodies, Format: uint32(args.Format), Path: path,
	}
	for _, kind := range args.Kinds {
		document.Kinds = append(document.Kinds, uint32(kind))
	}
	if err := self.writeJob(document); err != nil {
		return Id{}, err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.jobs = append(self.jobs, self.subscribeWithLock(document))
		self.due = true
	}()
	record.writer.signal()
	return jobId, nil
}

// The follow jobs' part of the record's loop: when a followed log may have moved, each job exports what it has not,
// in order, and saves its cursor after its lines are written. A job whose sidecar reads the log no longer ends. A
// kill between a write and its cursor writes those lines again at the next pass: a follower's file holds each entry
// at least once.
func (self *RecordExport) Tick(ctx context.Context) {
	if err := self.loadJobs(); err != nil {
		return
	}
	jobs := func() []*recordExportJob {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.due {
			return nil
		}
		self.due = false
		return slices.Clone(self.jobs)
	}()
	for _, job := range jobs {
		ended, err := self.step(ctx, job)
		if err != nil && self.record.writer.log.V(1).Enabled() {
			self.record.writer.log.Infof("[record]export job %s stopped for now: %s", job.document.JobId, err)
		}
		if ended {
			self.end(job)
		}
	}
}

// Ends a job: its state goes and it follows nothing more.
func (self *RecordExport) end(job *recordExportJob) {
	job.unsubscribe()
	if err := self.record.writer.store.Remove(recordExportJobName(job.document.JobId)); err != nil {
		self.record.writer.log.Warningf("[record]an ended export job's state stays: %s", err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.jobs = slices.DeleteFunc(self.jobs, func(held *recordExportJob) bool { return held == job })
}

// One pass of a job: true when it ended.
func (self *RecordExport) step(ctx context.Context, job *recordExportJob) (bool, error) {
	record := self.record
	document := job.document
	auth := record.writer.auth()
	if !auth.Reads(document.LogId, record.writer.sidecarId) {
		return true, nil
	}
	sink := self.fileSink()
	if sink == nil {
		return false, ErrRecordExportNoSink
	}
	if err := record.reader.Sync(ctx, document.LogId); err != nil {
		return false, err
	}
	args := document.args()
	streamVersions := map[Id]uint64{}
	for _, stream := range document.Streams {
		streamVersions[stream.SidecarId] = stream.Version
	}
	all := record.reader.Entries(document.LogId)
	taken := []*RecordReadEntry{}
	reached := map[Id]uint64{}
	for _, entry := range all {
		if len(entry.Copies) == 0 {
			continue
		}
		place := entry.Copies[0]
		reached[place.StreamSidecarId] = max(reached[place.StreamSidecarId], place.Version)
		if place.Version <= streamVersions[place.StreamSidecarId] || !args.takes(entry) {
			continue
		}
		taken = append(taken, entry)
	}
	if 0 < len(taken) {
		if auth.Deposits(document.LogId, record.writer.sidecarId) && auth.ReceiptOnly(document.LogId, record.writer.sidecarId) {
			// a receipt that cannot land stops the export
			if _, err := self.recordExport(ctx, args, taken); err != nil {
				return false, err
			}
		}
		lines, err := self.lines(auth, args, taken, recordExportAgentLabels(all))
		if err != nil {
			return false, err
		}
		writer, err := sink(document.Path)
		if err != nil {
			return false, err
		}
		_, err = writer.Write(append(bytes.Join(lines, []byte("\n")), '\n'))
		if closeErr := writer.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return false, err
		}
	}
	moved := false
	for streamId, version := range reached {
		if streamVersions[streamId] < version {
			streamVersions[streamId] = version
			moved = true
		}
	}
	if !moved {
		return false, nil
	}
	document.Streams = nil
	for streamId, version := range streamVersions {
		document.Streams = append(document.Streams, &recordExportJobStream{SidecarId: streamId, Version: version})
	}
	slices.SortFunc(document.Streams, func(a *recordExportJobStream, b *recordExportJobStream) int { return a.SidecarId.Cmp(b.SidecarId) })
	return false, self.writeJob(document)
}
