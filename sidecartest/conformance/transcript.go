// Transcripts: one harness's recorded sessions at one pinned release, a directory testdata/<harness>/<version>/
// holding manifest.json and sessions/*.json, each session's requests in the order the harness sends them.
//
//	manifest   the harness and the version its path names, the release it pins (its tag and release date), whether
//	           it is the current or the previous pin, the API and path it calls, the headers every request of that
//	           release carries, the header naming its session, and where its shapes were read and when
//	session    its id, which the session header carries, and its requests
//	request    its own headers beside the manifest's, its body exactly as the harness sends it (a later request's
//	           {{reasoning:<request>}} placeholder carries the encrypted_content of that earlier request's first
//	           reasoning item, as the harness sends back what the gateway gave it), the model's answer an in-process
//	           replay scripts, and what the answer must be
//
// Every value is synthetic: .example hosts, made-up ids and texts. No transcript is captured traffic.

package conformance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

var (
	// A transcript directory that does not hold a whole transcript: a manifest naming another harness or version than
	// its path, no session, a request with no body or no expectation.
	ErrTranscriptInvalid = errors.New("conformance: a transcript that does not read whole")
)

// The roles a pinned release plays: identifiers.
const (
	TranscriptRoleCurrent  = "current"
	TranscriptRolePrevious = "previous"
)

// A placeholder a request's body carries for what an earlier answer gave: {{reasoning:<request name>}}.
const (
	transcriptPlaceholderPrefix = "{{reasoning:"
	transcriptPlaceholderSuffix = "}}"
)

// What a transcript is: see the file header.
type TranscriptManifest struct {
	Harness string `json:"harness"`
	// The directory's name: the release's version.
	Version string `json:"version"`
	// The release's tag, and its date (yyyy-mm-dd).
	Pin      string `json:"pin"`
	Released string `json:"released"`
	// current or previous.
	Role string `json:"role"`
	// The API and the path every request calls, under the gateway's base URL.
	Api  string `json:"api"`
	Path string `json:"path"`
	// The headers every request of this release carries, synthetic values; the runner adds the session header and
	// the bearer.
	Headers map[string]string `json:"headers"`
	// The header that names the request's session, which the gateway binds runs by (§8.9).
	SessionHeader string `json:"session_header"`
	// Where the request shapes were read, and when.
	Sources []string `json:"sources"`
	Read    string   `json:"read"`
	// How the bytes were made: synthetic, never captured.
	Recorded string `json:"recorded"`
}

// One session: a harness's conversation, its requests in the order sent.
type TranscriptSession struct {
	// The session's file, sessions/<file>.
	File string `json:"-"`
	// The session's id, which the session header carries.
	Id       string               `json:"session_id"`
	Title    string               `json:"title"`
	Requests []*TranscriptRequest `json:"requests"`
}

// One request: its headers, its bytes, the model's scripted answer and the answer's expectation.
type TranscriptRequest struct {
	Name string `json:"name"`
	// Headers beside the manifest's.
	Headers map[string]string `json:"headers"`
	// The body exactly as the harness sends it, but for {{reasoning:<request>}} placeholders.
	Body json.RawMessage `json:"body"`
	// What the model answers in an in-process replay; nil where the call never reaches a model (a refusal).
	Model *TranscriptModelTurn `json:"model"`
	// What the answer must be.
	Expect *TranscriptExpect `json:"expect"`
}

// A model's scripted answer, as computetest.ScriptedTurn plays one: reasoning deltas, text deltas, tool calls with
// fixed ids, a usage of fixed counts, and a failure after the deltas.
type TranscriptModelTurn struct {
	Reasoning []string              `json:"reasoning"`
	Text      []string              `json:"text"`
	ToolCalls []*TranscriptToolCall `json:"tool_calls"`
	Usage     *TranscriptUsage      `json:"usage"`
	// The router's error code the call fails with once its deltas are out; empty ends it.
	FailCode string `json:"fail_code"`
}

// One tool call the model makes.
type TranscriptToolCall struct {
	Id        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// A usage of fixed counts.
type TranscriptUsage struct {
	InputTokens  uint64 `json:"input_tokens"`
	OutputTokens uint64 `json:"output_tokens"`
}

// What an answer must be: the wire contract, never the model's words.
type TranscriptExpect struct {
	// The HTTP status: 200 for an answer, else the refusal's.
	Status int `json:"status"`
	// For a 200 stream that completes: the output items' types in order.
	Output []string `json:"output"`
	// The function calls' names and call ids, in order.
	FunctionCalls []*TranscriptToolCall `json:"function_calls"`
	// A refusal's or a failed terminal's error code.
	ErrorCode string `json:"error_code"`
	// A refusal's param.
	ErrorParam string `json:"error_param"`
	// The tools the model must not receive: the hosted ones the gateway drops (§21.7).
	DroppedTools []string `json:"dropped_tools"`
}

// One harness's sessions at one pinned release.
type Transcript struct {
	Directory string
	Manifest  *TranscriptManifest
	Sessions  []*TranscriptSession
}

// The transcript at directory, testdata/<harness>/<version>/: its manifest held to its path, every session file in
// name order, every request whole.
func LoadTranscript(directory string) (*Transcript, error) {
	manifestBytes, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return nil, err
	}
	manifest := &TranscriptManifest{}
	if err := strictJson(manifestBytes, manifest); err != nil {
		return nil, fmt.Errorf("%w: %s's manifest: %w", ErrTranscriptInvalid, directory, err)
	}
	cleaned := filepath.Clean(directory)
	if manifest.Version != filepath.Base(cleaned) || manifest.Harness != filepath.Base(filepath.Dir(cleaned)) {
		return nil, fmt.Errorf("%w: %s names %s %s", ErrTranscriptInvalid, directory, manifest.Harness, manifest.Version)
	}
	if manifest.Pin == "" || manifest.Path == "" || manifest.SessionHeader == "" || !slices.Contains([]string{TranscriptRoleCurrent, TranscriptRolePrevious}, manifest.Role) {
		return nil, fmt.Errorf("%w: %s's manifest names no pin, path, session header or role", ErrTranscriptInvalid, directory)
	}
	sessionPaths, err := filepath.Glob(filepath.Join(directory, "sessions", "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(sessionPaths)
	transcript := &Transcript{Directory: directory, Manifest: manifest}
	for _, sessionPath := range sessionPaths {
		sessionBytes, err := os.ReadFile(sessionPath)
		if err != nil {
			return nil, err
		}
		session := &TranscriptSession{File: filepath.Base(sessionPath)}
		if err := strictJson(sessionBytes, session); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrTranscriptInvalid, sessionPath, err)
		}
		if session.Id == "" || len(session.Requests) == 0 {
			return nil, fmt.Errorf("%w: %s holds no session id or no request", ErrTranscriptInvalid, sessionPath)
		}
		names := map[string]bool{}
		for _, request := range session.Requests {
			if request.Name == "" || names[request.Name] || len(request.Body) == 0 || request.Expect == nil || request.Expect.Status == 0 {
				return nil, fmt.Errorf("%w: %s: a request with no name, a name twice, no body or no expectation", ErrTranscriptInvalid, sessionPath)
			}
			names[request.Name] = true
			if !json.Valid(request.Body) {
				return nil, fmt.Errorf("%w: %s: request %s's body is not JSON", ErrTranscriptInvalid, sessionPath, request.Name)
			}
		}
		transcript.Sessions = append(transcript.Sessions, session)
	}
	if len(transcript.Sessions) == 0 {
		return nil, fmt.Errorf("%w: %s holds no session", ErrTranscriptInvalid, directory)
	}
	return transcript, nil
}

// The transcripts of harness under root (testdata/), one per version directory, in version order.
func LoadTranscripts(root string, harness string) ([]*Transcript, error) {
	manifestPaths, err := filepath.Glob(filepath.Join(root, harness, "*", "manifest.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(manifestPaths)
	transcripts := []*Transcript{}
	for _, manifestPath := range manifestPaths {
		transcript, err := LoadTranscript(filepath.Dir(manifestPath))
		if err != nil {
			return nil, err
		}
		transcripts = append(transcripts, transcript)
	}
	return transcripts, nil
}

// The transcript of role among transcripts, nil for none.
func TranscriptOfRole(transcripts []*Transcript, role string) *Transcript {
	for _, transcript := range transcripts {
		if transcript.Manifest.Role == role {
			return transcript
		}
	}
	return nil
}

// Decodes data into value, refusing a field value does not name and anything after it.
func strictJson(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("more after the document")
	}
	return nil
}

// body with each {{reasoning:<request>}} placeholder replaced by blobs' value for that request: an error naming one
// no earlier answer gave.
func substitutePlaceholders(body []byte, blobs map[string]string) ([]byte, error) {
	text := string(body)
	for {
		start := strings.Index(text, transcriptPlaceholderPrefix)
		if start < 0 {
			return []byte(text), nil
		}
		end := strings.Index(text[start:], transcriptPlaceholderSuffix)
		if end < 0 {
			return nil, fmt.Errorf("%w: a placeholder that never closes", ErrTranscriptInvalid)
		}
		name := text[start+len(transcriptPlaceholderPrefix) : start+end]
		blob, ok := blobs[name]
		if !ok {
			return nil, fmt.Errorf("no earlier answer of %q gave an encrypted reasoning item to send back", name)
		}
		encoded, err := json.Marshal(blob)
		if err != nil {
			return nil, err
		}
		// the placeholder sits inside a JSON string: replace it with the blob's escaped content
		text = text[:start] + string(encoded[1:len(encoded)-1]) + text[start+end+len(transcriptPlaceholderSuffix):]
	}
}
