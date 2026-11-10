// RECORD.md section 10.2's witness step, on every leg: the checkpointer sends each note it filed to the witnesses the
// governing log_settings names, by c2sp.org/tlog-witness's POST add-checkpoint over HTTPS, and keeps the cosignature
// line each returns, which rides the next checkpoint entry's cosigned.
//
//	request   "old <size>", the size this witness last cosigned, then a consistency proof from that size to the
//	          note's, a base64 hash a line, an empty line, and the signed note
//	200       its cosignature lines: the one under its key is verified over the note before it is kept
//	409       it holds another size, named in the body: the proof is rebuilt from that size once
//	403       it does not trust this log key: a successor's key waits on the witness's operator (successor row)
//	other     a miss; 409 past the note's size and 422 mean it holds something this log does not extend, which alarms
//
// A witness is a customer's or an auditor's service, which a log admin named in a signed log_settings: no URnetwork
// server takes part, and the request holds a note, never an entry. The owner ruled the call no URnetwork carrier
// (record-md-witness-carrier, QD-242). A witness learns the origin, the tree's size and when it grew.
//
// A witness that fails is left out of this note, and alarms log_check past WitnessMissCount misses in a row. The
// whole step takes at most WitnessTimeout on the record's clock.

package sidecar

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// c2sp.org/tlog-witness's values.
const (
	recordLogWitnessPath       = "/add-checkpoint"
	recordLogWitnessOldPrefix  = "old "
	recordLogWitnessUrlScheme  = "https"
	recordLogWitnessAttemptMax = 2
)

// What a witness answered: the HTTP status and the body, as sent.
type RecordLogWitnessAnswer struct {
	Status int
	Body   []byte
}

// Reaches a witness's add-checkpoint: the HTTPS client, or a test's witness. Safe for concurrent use.
type RecordLogWitness interface {
	// POSTs request to the submission prefix url. An error is a witness that could not be reached; every answer
	// it gave, whatever its status, is an answer.
	AddCheckpoint(ctx context.Context, url string, request []byte) (*RecordLogWitnessAnswer, error)
}

// Whether a witness's submission prefix is one a log_settings may name: an absolute https url with a host, no query
// and no credentials.
func recordLogWitnessUrlValid(witnessUrl string) bool {
	parsed, err := url.Parse(witnessUrl)
	return err == nil && parsed.Scheme == recordLogWitnessUrlScheme && parsed.Host != "" && parsed.User == nil &&
		parsed.RawQuery == "" && parsed.Fragment == ""
}

// The add-checkpoint request for note, from the size the witness last cosigned.
func recordLogWitnessRequest(oldSize uint64, proof [][]byte, note []byte) []byte {
	request := []byte(recordLogWitnessOldPrefix + strconv.FormatUint(oldSize, 10) + "\n")
	for _, hash := range proof {
		request = append(request, base64.StdEncoding.EncodeToString(hash)...)
		request = append(request, '\n')
	}
	request = append(request, '\n')
	return append(request, note...)
}

// An add-checkpoint request as a witness reads it: the old size, the proof and the note. What a test's witness
// parses; nothing is verified.
func ParseRecordLogWitnessRequest(request []byte) (oldSize uint64, proof [][]byte, note []byte, err error) {
	head, note, ok := bytes.Cut(request, []byte("\n\n"))
	lines := strings.Split(string(head), "\n")
	sizeText, hasOld := strings.CutPrefix(lines[0], recordLogWitnessOldPrefix)
	oldSize, sizeErr := strconv.ParseUint(sizeText, 10, 64)
	if !ok || !hasOld || sizeErr != nil || recordLogPathHashCount < len(lines)-1 {
		return 0, nil, nil, fmt.Errorf("%w: an add-checkpoint request", ErrRecordLogNote)
	}
	for _, line := range lines[1:] {
		hash, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("%w: an add-checkpoint proof line", ErrRecordLogNote)
		}
		proof = append(proof, hash)
	}
	return oldSize, proof, note, nil
}

// Tunables of the HTTPS witness client. RECORD.md section 18 names SidecarRecordSettings' fields, so a bound that is
// this client's alone sits here.
type RecordLogWitnessHttpSettings struct {
	// The most of a witness's answer that is read, in bytes: 64 KiB, far past the few cosignature lines or the size
	// one holds. A longer answer counts as a witness not reached. Non-positive reads nothing, so every answer is
	// one.
	AnswerByteCount int
}

// The defaults, a fresh value each call.
func DefaultRecordLogWitnessHttpSettings() *RecordLogWitnessHttpSettings {
	return &RecordLogWitnessHttpSettings{AnswerByteCount: 64 * 1024}
}

// The witness client over HTTPS.
type recordLogWitnessHttp struct {
	client   *http.Client
	settings *RecordLogWitnessHttpSettings
}

// A witness client over client, http's default when nil, with the default settings when nil. It follows no
// redirect: a witness is the host a log admin named.
func NewRecordLogWitnessHttp(client *http.Client, settings *RecordLogWitnessHttpSettings) RecordLogWitness {
	if client == nil {
		client = &http.Client{}
	}
	if settings == nil {
		settings = DefaultRecordLogWitnessHttpSettings()
	}
	bound := *client
	bound.CheckRedirect = func(request *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	return &recordLogWitnessHttp{client: &bound, settings: settings}
}

func (self *recordLogWitnessHttp) AddCheckpoint(ctx context.Context, witnessUrl string, request []byte) (*RecordLogWitnessAnswer, error) {
	if !recordLogWitnessUrlValid(witnessUrl) {
		return nil, fmt.Errorf("%w: a witness url that is not https", ErrRecordLogSettings)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(witnessUrl, "/")+recordLogWitnessPath, bytes.NewReader(request))
	if err != nil {
		return nil, err
	}
	response, err := self.client.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(max(self.settings.AnswerByteCount, 0))+1))
	if err != nil {
		return nil, err
	}
	if max(self.settings.AnswerByteCount, 0) < len(body) {
		return nil, errors.New("record log witness: an answer past its bound")
	}
	return &RecordLogWitnessAnswer{Status: response.StatusCode, Body: body}, nil
}

// Step 6 for one filed batch: each witness governing names, in order, within WitnessTimeout in all. Answers the
// cosignature lines got, each verified, and their witnesses' names, and updates state's witness rows, which the
// caller writes. A witness past WitnessMissCount misses in a row, or holding what this log does not extend, alarms.
func (self *RecordLog) witnessNote(ctx context.Context, view *recordLogView, state *recordLogStateDocument, governing *recordLogSettings, number uint64) ([]byte, []string) {
	writer := self.record.writer
	stepCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := writer.clock.AfterFunc(writer.settings.WitnessTimeout, cancel)
	defer stop()
	batch := func() *recordLogBatch {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return view.batches[number-1]
	}()
	lines := []byte{}
	names := []string{}
	alarmed := false
	for _, witness := range governing.witnesses {
		row := state.witness(witness.name)
		line, refusal, holdsOther := self.witnessOne(stepCtx, view, witness, row, batch)
		if line != nil {
			row.Size, row.MissCount, row.Refusal = batch.size, 0, ""
			lines = append(lines, line...)
			names = append(names, witness.name)
			continue
		}
		row.MissCount += 1
		row.Refusal = refusal
		if writer.log.V(1).Enabled() {
			writer.log.Infof("[record]witness %s did not cosign batch %d of %s: %s", witness.name, number, view.logId, refusal)
		}
		if holdsOther || writer.settings.WitnessMissCount < row.MissCount {
			alarmed = true
		}
	}
	if alarmed {
		sidecarId := writer.sidecarId
		writer.raise(SidecarRecordAlarmLogCheck, view.logId, &sidecarId)
	}
	return lines, names
}

// One witness for one note: its cosignature line, verified, or why there is none, and whether it holds something this
// log's note does not extend.
func (self *RecordLog) witnessOne(ctx context.Context, view *recordLogView, witness *recordLogWitnessSetting, row *recordLogWitnessDocument, batch *recordLogBatch) (line []byte, refusal string, holdsOther bool) {
	oldSize := row.Size
	for attempt := 0; attempt < recordLogWitnessAttemptMax; attempt += 1 {
		if batch.size < oldSize {
			return nil, fmt.Sprintf("it holds size %d, past this note's %d", oldSize, batch.size), true
		}
		proof, err := func() ([][]byte, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			path, err := view.tree.consistencyPath(oldSize, batch.size)
			return recordLogPathBytes(path), err
		}()
		if err != nil {
			return nil, err.Error(), false
		}
		answer, err := self.witness.AddCheckpoint(ctx, witness.url, recordLogWitnessRequest(oldSize, proof, batch.note))
		if err != nil {
			return nil, "not reached", false
		}
		switch answer.Status {
		case http.StatusOK:
			signatures, err := ParseRecordLogSignatureLines(answer.Body)
			if err != nil {
				return nil, "its answer does not parse", false
			}
			for _, signature := range signatures {
				if _, err := witness.key.Verify(batch.noteBody, signature); err == nil {
					return signature.line(), "", false
				}
			}
			return nil, "its answer holds no cosignature under its key", false
		case http.StatusConflict:
			size, err := strconv.ParseUint(strings.TrimSpace(string(answer.Body)), 10, 64)
			if err != nil {
				return nil, "409 with no size", false
			}
			if size == oldSize {
				return nil, "409 naming the size it was sent", false
			}
			oldSize = size
		case http.StatusForbidden:
			return nil, "403: it does not trust this log key, which its operator adds", false
		case http.StatusUnprocessableEntity:
			return nil, "422: it holds a checkpoint this log does not extend", true
		case http.StatusNotFound:
			return nil, "404: it does not know this origin", false
		default:
			return nil, fmt.Sprintf("%d", answer.Status), false
		}
	}
	return nil, "409 again after the proof was rebuilt", true
}
