// Run: a transcript replayed against a gateway (see doc.go). Each session takes a token of its own before its first
// request, from the target, as a harness's credential command mints one for its process; each request is sent with the
// manifest's headers, its own, the session header and the bearer, its body exactly as recorded but for an earlier
// answer's reasoning blob where a placeholder asks; each answer is read whole, a stream parsed as Server-Sent Events,
// and held to the harness's profile and the request's expectation. A contract broken is a failure in the report,
// never an error: Run errs only where the target cannot be asked at all.

package conformance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

var (
	// No profile is registered for a transcript's harness.
	ErrHarnessUnknown = errors.New("conformance: no profile for the harness")
)

// The runner's settings (QD-702).
type RunSettings struct {
	// The most bytes of one answer read: 32 MiB, the gateway's own request bound (§8.7), far past any answer a
	// transcript asks.
	AnswerByteCount int64
	// The most bytes of one SSE line: 4 MiB, past any one event a transcript's answer holds.
	LineByteCount int
}

// The defaults, the only place one is set.
func DefaultRunSettings() *RunSettings {
	return &RunSettings{
		AnswerByteCount: 32 * 1024 * 1024,
		LineByteCount:   4 * 1024 * 1024,
	}
}

// What a replay sends to.
type Target struct {
	// The gateway's base URL, http://127.0.0.1:<port>: a transcript's path is under it.
	BaseUrl string
	// Nil takes a plain client.
	Client *http.Client
	// A bearer for session, asked once before its first request: a run handle's token minted for the session's
	// harness process, as its credential command mints one.
	Token func(ctx context.Context, session *TranscriptSession) (string, error)
	// Called before each request is sent, to script the model's answer from request.Model in an in-process replay;
	// nil for a gateway whose models answer themselves.
	BeforeRequest func(ctx context.Context, session *TranscriptSession, request *TranscriptRequest) error
	// Nil takes DefaultRunSettings.
	Settings *RunSettings
}

// One answer as received.
type Answer struct {
	Status int
	Header http.Header
	Body   []byte
	// A stream's events in order, and the comments (`: ping`) among them.
	Events       []*SseEvent
	CommentCount int
}

// One Server-Sent Event: its event field and its data, the data lines joined.
type SseEvent struct {
	Event string
	Data  []byte
}

// What a profile found in one answer.
type Checked struct {
	Failures []string
	// The response's id, from its first event or its body.
	ResponseId string
	// The encrypted_content of each reasoning item the answer completed, in order: what the harness sends back.
	Reasoning []string
}

// What a harness needs of each answer (codex.go's for Codex). Safe for concurrent use.
type HarnessProfile interface {
	// The failures of answer to request, whose body was sent as sent.
	Check(request *TranscriptRequest, sent []byte, answer *Answer) *Checked
}

var (
	profilesLock    sync.Mutex
	harnessProfiles = map[string]HarnessProfile{}
)

// Registers harness's profile, from its file's init. A second one, or a nil one, panics.
func registerHarnessProfile(harness string, profile HarnessProfile) {
	profilesLock.Lock()
	defer profilesLock.Unlock()
	if profile == nil || harnessProfiles[harness] != nil {
		panic(fmt.Errorf("conformance: harness profile %q registered twice or nil", harness))
	}
	harnessProfiles[harness] = profile
}

// harness's profile, nil for none.
func ProfileOf(harness string) HarnessProfile {
	profilesLock.Lock()
	defer profilesLock.Unlock()
	return harnessProfiles[harness]
}

// What one request came to.
type RequestReport struct {
	Session    string
	Name       string
	Status     int
	ResponseId string
	Failures   []string
}

// What a replay came to.
type Report struct {
	Harness  string
	Version  string
	Pin      string
	Requests []*RequestReport
}

// Every failure, each naming its session and request.
func (self *Report) Failures() []string {
	failures := []string{}
	for _, request := range self.Requests {
		for _, failure := range request.Failures {
			failures = append(failures, fmt.Sprintf("%s/%s: %s", request.Session, request.Name, failure))
		}
	}
	return failures
}

// Whether every request's answer held to the contract.
func (self *Report) Passed() bool {
	return len(self.Failures()) == 0
}

// Replays transcript against target (see the file header).
func Run(ctx context.Context, transcript *Transcript, target *Target) (*Report, error) {
	profile := ProfileOf(transcript.Manifest.Harness)
	if profile == nil {
		return nil, fmt.Errorf("%w: %s", ErrHarnessUnknown, transcript.Manifest.Harness)
	}
	settings := target.Settings
	if settings == nil {
		settings = DefaultRunSettings()
	}
	client := target.Client
	if client == nil {
		client = &http.Client{}
	}
	report := &Report{Harness: transcript.Manifest.Harness, Version: transcript.Manifest.Version, Pin: transcript.Manifest.Pin}
	for _, session := range transcript.Sessions {
		token, err := target.Token(ctx, session)
		if err != nil {
			return report, fmt.Errorf("conformance: a token for session %s: %w", session.Id, err)
		}
		blobs := map[string]string{}
		for _, request := range session.Requests {
			requestReport := &RequestReport{Session: session.Id, Name: request.Name}
			report.Requests = append(report.Requests, requestReport)
			body, err := substitutePlaceholders(request.Body, blobs)
			if err != nil {
				requestReport.Failures = append(requestReport.Failures, err.Error())
				continue
			}
			if target.BeforeRequest != nil {
				if err := target.BeforeRequest(ctx, session, request); err != nil {
					return report, fmt.Errorf("conformance: scripting %s/%s: %w", session.Id, request.Name, err)
				}
			}
			answer, err := send(ctx, client, settings, target.BaseUrl+transcript.Manifest.Path, transcript.Manifest, session, request, body, token)
			if err != nil {
				return report, fmt.Errorf("conformance: %s/%s: %w", session.Id, request.Name, err)
			}
			requestReport.Status = answer.Status
			checked := profile.Check(request, body, answer)
			requestReport.ResponseId = checked.ResponseId
			requestReport.Failures = append(requestReport.Failures, checked.Failures...)
			if 0 < len(checked.Reasoning) {
				blobs[request.Name] = checked.Reasoning[0]
			}
		}
	}
	return report, nil
}

// Sends one request and reads its answer whole.
func send(ctx context.Context, client *http.Client, settings *RunSettings, url string, manifest *TranscriptManifest, session *TranscriptSession, request *TranscriptRequest, body []byte, token string) (*Answer, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for name, value := range manifest.Headers {
		httpRequest.Header.Set(name, value)
	}
	for name, value := range request.Headers {
		httpRequest.Header.Set(name, value)
	}
	httpRequest.Header.Set(manifest.SessionHeader, session.Id)
	httpRequest.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	answerBody, err := io.ReadAll(io.LimitReader(response.Body, settings.AnswerByteCount))
	if err != nil {
		return nil, err
	}
	answer := &Answer{Status: response.StatusCode, Header: response.Header.Clone(), Body: answerBody}
	if strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		answer.Events, answer.CommentCount, err = parseSse(answerBody, settings.LineByteCount)
		if err != nil {
			return nil, err
		}
	}
	return answer, nil
}

// The events of an SSE body: event and data fields, data lines joined by a newline, an event dispatched at a blank
// line, a comment counted; a last event with no blank line after it is dispatched too.
func parseSse(body []byte, lineByteCount int) ([]*SseEvent, int, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	// the scanner grows its own buffer, up to the line's bound
	scanner.Buffer(nil, lineByteCount)
	events := []*SseEvent{}
	commentCount := 0
	var current *SseEvent
	dataLines := [][]byte{}
	dispatch := func() {
		if current == nil && len(dataLines) == 0 {
			return
		}
		if current == nil {
			current = &SseEvent{}
		}
		current.Data = bytes.Join(dataLines, []byte("\n"))
		events = append(events, current)
		current, dataLines = nil, [][]byte{}
	}
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		switch {
		case line == "":
			dispatch()
		case strings.HasPrefix(line, ":"):
			commentCount += 1
		default:
			field, value, _ := strings.Cut(line, ":")
			value = strings.TrimPrefix(value, " ")
			if current == nil {
				current = &SseEvent{}
			}
			switch field {
			case "event":
				current.Event = value
			case "data":
				dataLines = append(dataLines, []byte(value))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, err
	}
	dispatch()
	return events, commentCount, nil
}

// An OpenAI-shaped error body's error, nil where the body is none.
type openAiError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Param   string `json:"param"`
	Code    string `json:"code"`
}

// The error an OpenAI-shaped body holds, nil for none.
func readOpenAiError(body []byte) *openAiError {
	wrapper := struct {
		Error *openAiError `json:"error"`
	}{}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil
	}
	return wrapper.Error
}
