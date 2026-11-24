//go:build !ios_extension && !sidecar_http

// The engine helper's protocol (DESIGN-COMPUTE §6.5, D-INFER-2): JSON lines on the ur-engine helper's stdio, one
// request a line from the daemon, one answer a line from the helper, each answer naming the request it answers.
//
//	capabilities  → result: InferDeviceCapabilities, as the helper's OS reports them
//	load          {libraries, dawn, gpu_plugins, model, settings} → result {handle}: the engine's libraries and every
//	              file beside them and the model, each with the SHA-256 the release manifest pins, which the helper
//	              checks before it loads anything, and the engine's settings
//	generate      {handle, conversation, messages, tools, tool_choice, schema, max_output, sampling, effort}
//	              → events: InferEvent JSON, ending in exactly one end or error
//	cancel        {id} → result {}: stops the generate of that id, which then ends canceled
//	unload        {handle} → result {}: frees the engine
//
// and any method registerInferEngineMethod adds, such as SAFE's classifier's, each answering a result or an error. An
// answer is an event of a generate's stream, a method's result, or its error, an InferError. The protocol carries no
// secret: paths, hashes, the conversation and its answer. A generate's conversation key is the daemon's opaque name for
// an agent's conversation, never a run's or an agent's id.
//
// Lines are bounded: a request at InferSettings.EngineRequestMaxByteCount, room for a whole conversation with its
// images; an answer at EngineAnswerMaxByteCount. A line past its bound ends the connection: the helper exits, and the
// daemon ends the helper, every call on it answering engine_failed. JSON escapes every control character in a string,
// so no line holds a newline but its last byte.

package sidecar

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// The protocol's methods.
const (
	inferEngineMethodCapabilities = "capabilities"
	inferEngineMethodLoad         = "load"
	inferEngineMethodGenerate     = "generate"
	inferEngineMethodCancel       = "cancel"
	inferEngineMethodUnload       = "unload"
)

// The protocol's own methods, which no extension may take.
var inferEngineBuiltInMethods = []string{
	inferEngineMethodCapabilities,
	inferEngineMethodLoad,
	inferEngineMethodGenerate,
	inferEngineMethodCancel,
	inferEngineMethodUnload,
}

// A line past its bound.
var errInferEngineLineTooLong = errors.New("engine protocol line past its bound")

// One request line, daemon to helper.
type inferEngineRequest struct {
	// Unique among the requests in flight on one helper, never 0.
	Id     uint64          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// One answer line, helper to daemon: exactly one of an event of a generate's stream, a method's result and its error.
type inferEngineAnswer struct {
	Id     uint64          `json:"id"`
	Event  *InferEvent     `json:"event,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *InferError     `json:"error,omitempty"`
}

// A file the helper loads, with the SHA-256 the manifest pins, which the helper checks before it opens it to load.
type inferEngineFile struct {
	Path   string `json:"path"`
	Sha256 string `json:"sha256"`
}

// What a load configures (§6.5): the engine's backend and bounds, and how many engines of the model it holds.
type inferEngineLoadSettings struct {
	// cpu or gpu.
	Backend string `json:"backend"`
	// The model's context window, in tokens.
	MaxTokenCount int64 `json:"max_token_count"`
	// How many engines of the model the helper holds, each running one call at a time with one live conversation
	// (#2807): 1 on a phone, up to 2 on a desktop with the memory for both.
	InstanceCount int `json:"instance_count"`
	// The engine's CPU threads; 0 for its own default.
	ThreadCount int `json:"thread_count,omitempty"`
}

// load's params.
type inferEngineLoadParams struct {
	// The engine's libraries: its C library first, which the helper loads, and those it loads from beside it.
	Libraries []*inferEngineFile `json:"libraries"`
	// Dawn's WebGPU library, where the pinned version needs it even for CPU or Metal (#4611).
	Dawn *inferEngineFile `json:"dawn,omitempty"`
	// The closed GPU plugins.
	GpuPlugins []*inferEngineFile `json:"gpu_plugins,omitempty"`
	// The model's file.
	Model    *inferEngineFile         `json:"model"`
	Settings *inferEngineLoadSettings `json:"settings"`
}

// load's result.
type inferEngineLoadResult struct {
	Handle uint64 `json:"handle"`
}

// generate's params: the call's conversation, with its effort resolved, and no run's or agent's id.
type inferEngineGenerateParams struct {
	Handle uint64 `json:"handle"`
	// The daemon's opaque key for the agent's conversation: calls of one key continue its conversation while it is
	// live, and reopen it from their messages otherwise.
	Conversation string          `json:"conversation"`
	Messages     []*InferMessage `json:"messages"`
	Tools        []*InferTool    `json:"tools,omitempty"`
	ToolChoice   string          `json:"tool_choice,omitempty"`
	Schema       json.RawMessage `json:"schema,omitempty"`
	MaxOutput    int             `json:"max_output,omitempty"`
	Sampling     *InferSampling  `json:"sampling,omitempty"`
	Effort       InferEffort     `json:"effort"`
}

// cancel's params: the generate to stop.
type inferEngineCancelParams struct {
	Id uint64 `json:"id"`
}

// unload's params.
type inferEngineUnloadParams struct {
	Handle uint64 `json:"handle"`
}

// Reads one line of at most maxByteCount bytes, its newline dropped; errInferEngineLineTooLong past it, after which the
// reader is out of step and the connection is ended. A last line without its newline is read as one.
func inferEngineReadLine(reader *bufio.Reader, maxByteCount int) ([]byte, error) {
	line := []byte{}
	for {
		fragment, err := reader.ReadSlice('\n')
		line = append(line, fragment...)
		content := len(line)
		if err == nil {
			// the newline is no content
			content -= 1
		}
		if maxByteCount < content {
			return nil, fmt.Errorf("%w: more than %d bytes", errInferEngineLineTooLong, maxByteCount)
		}
		switch {
		case err == nil:
			return line[:content], nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && 0 < content:
			return line, nil
		}
		return nil, err
	}
}

// Writes JSON lines, one whole line at a time, from any goroutine.
type inferEngineLineWriter struct {
	stateLock sync.Mutex
	out       io.Writer
	// past it a line is not written
	maxByteCount int
}

// A writer to out, its lines bounded.
func newInferEngineLineWriter(out io.Writer, maxByteCount int) *inferEngineLineWriter {
	return &inferEngineLineWriter{out: out, maxByteCount: maxByteCount}
}

// Writes value as one line; refuses one past the bound.
func (self *inferEngineLineWriter) write(value any) error {
	line, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if self.maxByteCount < len(line) {
		return fmt.Errorf("%w: a line of %d bytes, past %d", errInferEngineLineTooLong, len(line), self.maxByteCount)
	}
	line = append(line, '\n')
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	_, err = self.out.Write(line)
	return err
}
