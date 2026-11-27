//go:build !ios_extension && !sidecar_http

// The classifier's runtime seam (DESIGN-COMPUTE §27.5, §27.6; SAFE-M13-01): SafetyScorer, what scores token windows
// with the release's model, two logits a window, and nothing else. The tokenizer and the views are the daemon's and the
// sdk's own Go code (safety_tokenizer.go, safety_normalize.go), so a runtime holds no text logic: it is given windows of
// token ids and answers numbers.
//
// Its implementations:
//
//   - SafetyEngineScorer (safety_engine.go; SAFE-M13-03): ONNX Runtime in the ur-engine helper on desktops and in an
//     enclave's daemon, over the helper's classify methods (infer_engine_classify.go);
//   - the app's SidecarSafetyClassifierHost (infer_host.go), the reduced ONNX Runtime the iOS, macOS and Android apps
//     embed, through SAFE-M13-04's adapter;
//   - a scripted stand-in in tests; the real models run only at the bench (External).
//
// Where none is set, or one fails, crashes or takes too long, the answer is ErrSafetyUnavailable, which every verdict
// reads as ask, reason unavailable (§27.5's falling back): never an allow.
//
// The JSON the app's host takes and gives is the contract with the apps, and the helper's classify methods carry the
// same shapes:
//
//	windows  [[1, 1234, 567, 2], ...]: each window's token ids, the model's two special tokens included, at most
//	         SafetySettings.WindowTokenCount ids a window and EngineWindowMaxCount windows a call
//	logits   [[benign, malicious], ...]: one pair a window, in the windows' order, each a finite number
//
// The model's two outputs are Prompt Guard 2's labels in their order: 0 benign, 1 malicious.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
)

// The classifier cannot answer: no model or runtime verified, none for this device, a crash, a refusal or a call past
// its time. Every verdict that meets it asks, reason unavailable (§27.5), never allows.
var ErrSafetyUnavailable = errors.New("safety classifier unavailable")

// An error that says why the classifier is unavailable, matching ErrSafetyUnavailable.
func safetyUnavailable(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrSafetyUnavailable, fmt.Sprintf(format, a...))
}

// One window's answer: the model's two logits, before softmax.
type SafetyLogits struct {
	Benign    float64 `json:"benign"`
	Malicious float64 `json:"malicious"`
}

// The probability the window is malicious, in basis points from 0 to 10,000: the softmax of the two logits, rounded
// up, so the score never understates the model. A logit that is not a finite number is refused.
func (self SafetyLogits) MaliciousBasisPoints() (int, error) {
	if math.IsNaN(self.Benign) || math.IsInf(self.Benign, 0) || math.IsNaN(self.Malicious) || math.IsInf(self.Malicious, 0) {
		return 0, safetyUnavailable("a logit that is not a finite number")
	}
	// 1 / (1 + e^(benign - malicious)), which neither overflows nor loses the small end
	probability := 1 / (1 + math.Exp(self.Benign-self.Malicious))
	basisPoints := math.Ceil(probability * 10000)
	return int(min(max(basisPoints, 0), 10000)), nil
}

// What scores windows with the release's model (see the file comment). Each method may be called from any goroutine,
// never under a lock of the caller's.
type SafetyScorer interface {
	// Readies the model whose verified file is at modelPath, answering a handle. A handle stays good until Unload,
	// whatever becomes of the runtime under it: a scorer whose runtime ended loads the model again at the next
	// Classify.
	Load(ctx context.Context, modelPath string) (int64, error)
	// Scores windows on handle's model: one SafetyLogits a window, in their order. Every error matches
	// ErrSafetyUnavailable.
	Classify(ctx context.Context, handle int64, windows [][]int64) ([]SafetyLogits, error)
	// Lets the model go.
	Unload(handle int64)
}

// Nil when windows is something a runtime may be given: at least one window and at most the call's bound, each of 2
// (an empty text's two special tokens) to WindowTokenCount ids, none negative or past an int32.
func safetyCheckWindows(windows [][]int64, settings *SafetySettings) error {
	if len(windows) == 0 || settings.EngineWindowMaxCount < len(windows) {
		return safetyUnavailable("a call of %d windows, not 1 to %d", len(windows), settings.EngineWindowMaxCount)
	}
	for _, window := range windows {
		if len(window) < 2 || settings.WindowTokenCount < len(window) {
			return safetyUnavailable("a window of %d tokens, not 2 to %d", len(window), settings.WindowTokenCount)
		}
		for _, id := range window {
			if id < 0 || math.MaxInt32 < id {
				return safetyUnavailable("a token id outside a vocabulary's")
			}
		}
	}
	return nil
}

// windows as the hosts' JSON: one array of ids a window.
func safetyWindowsJson(windows [][]int64) (string, error) {
	encoded, err := json.Marshal(windows)
	if err != nil {
		return "", safetyUnavailable("the windows do not encode")
	}
	return string(encoded), nil
}

// The windows in data, the hosts' JSON, refused unless safetyCheckWindows passes them; the helper's reading of what it
// is asked.
func parseSafetyWindowsJson(data []byte, settings *SafetySettings) ([][]int64, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	windows := [][]int64{}
	if err := decoder.Decode(&windows); err != nil {
		return nil, safetyUnavailable("windows that do not read")
	}
	if decoder.More() {
		return nil, safetyUnavailable("something after the windows")
	}
	if err := safetyCheckWindows(windows, settings); err != nil {
		return nil, err
	}
	return windows, nil
}

// logits as the hosts' JSON: one [benign, malicious] pair a window.
func safetyLogitsJson(logits []SafetyLogits) (string, error) {
	pairs := make([][2]float64, len(logits))
	for i, pair := range logits {
		pairs[i] = [2]float64{pair.Benign, pair.Malicious}
	}
	encoded, err := json.Marshal(pairs)
	if err != nil {
		// a NaN or an infinity, which JSON cannot hold
		return "", safetyUnavailable("logits that do not encode")
	}
	return string(encoded), nil
}

// The logits in data, a host's or the helper's answer to windowCount windows: exactly one pair a window, each two
// finite numbers, and nothing else. Anything else matches ErrSafetyUnavailable.
func parseSafetyLogitsJson(data []byte, windowCount int) ([]SafetyLogits, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	pairs := [][]float64{}
	if err := decoder.Decode(&pairs); err != nil {
		return nil, safetyUnavailable("logits that do not read")
	}
	if decoder.More() {
		return nil, safetyUnavailable("something after the logits")
	}
	if len(pairs) != windowCount {
		return nil, safetyUnavailable("%d pairs of logits for %d windows", len(pairs), windowCount)
	}
	logits := make([]SafetyLogits, len(pairs))
	for i, pair := range pairs {
		if len(pair) != 2 {
			return nil, safetyUnavailable("a window answered with %d logits, not 2", len(pair))
		}
		logits[i] = SafetyLogits{Benign: pair[0], Malicious: pair[1]}
		if _, err := logits[i].MaliciousBasisPoints(); err != nil {
			return nil, err
		}
	}
	return logits, nil
}
