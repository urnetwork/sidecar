//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// Each API's error shapes (DESIGN-COMPUTE §8.4, §8.5; D-GW-4, D-GW-6, R-GW-5; GW-M12-03): one gatewayError for every
// refusal and failure a front answers, written in the words of the API the request came through, since Codex and
// Claude Code act on their own API's words alone (a reworded overflow stops their compaction, an unknown quota code is
// retried).
//
//	shapes     Responses and Chat Completions: OpenAI's {"error": {"message", "type", "param", "code"}}; Messages:
//	           Anthropic's {"type": "error", "error": {"type", "message"}}, the code leading its message, since that
//	           shape has no code member
//	router     the router's codes (§6.4) map to each API's words: insufficient_quota a 429 insufficient_quota (Codex
//	           does not retry it) and Messages' 402 billing_error; context_length Responses' and Chat Completions'
//	           context_length_exceeded and Messages' "prompt is too long" (gatewayMessagesOverflow); tee_unverified a
//	           503 naming the model; disclosure_required a 403 naming the disclosure, its summary line and the fix
//	           (Messages' permission_error); model_refused and service_model 403s; capacity a 503 with Retry-After where
//	           the router gave a time; engine_failed a 502. Nothing here sends a call to another model, provider or
//	           label (R-GW-5)
//	in stream  once a stream has carried any of the model's output, a failure is its terminal event with a code
//	           Codex does not retry (insufficient_quota, context_length_exceeded, else invalid_prompt), so a harness
//	           never re-runs a call that ran, and was charged, on its own; before any output it keeps the router's code
//
// A message is the gateway's or the router's own words, never text a provider sent. Package-level functions are safe
// for concurrent use.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// The APIs' error types and codes the gateway writes: format values of OpenAI's and Anthropic's APIs, and the
// gateway's own codes beside the router's.
const (
	gatewayErrorTypeInvalidRequest    = "invalid_request_error"
	gatewayErrorTypeInsufficientQuota = "insufficient_quota"
	gatewayErrorTypeServer            = "server_error"
	gatewayErrorTypePermission        = "permission_error"
	gatewayErrorTypeBilling           = "billing_error"
	gatewayErrorTypeApi               = "api_error"
	gatewayErrorTypeOverloaded        = "overloaded_error"
	gatewayErrorTypeTooLarge          = "request_too_large"
	gatewayErrorTypeNotFound          = "not_found_error"

	// The codes of a failed stream Codex does not retry (codex-api's error.rs at 5f645d73): the quota's, the overflow's,
	// and invalid_prompt for every other failure once the call began, which ended a call that ran.
	GatewayErrorCodeInsufficientQuota = "insufficient_quota"
	GatewayErrorCodeContextLength     = "context_length_exceeded"
	gatewayErrorCodeNotRetried        = "invalid_prompt"

	// The gateway's own refusals, beside the router's codes (InferErrorCode).
	GatewayErrorCodeUnsupportedParameter = "unsupported_parameter"
	GatewayErrorCodeInvalidJson          = "invalid_json"
	GatewayErrorCodeMissingParameter     = "missing_required_parameter"
	GatewayErrorCodeInvalidValue         = "invalid_value"
	GatewayErrorCodeInvalidImage         = "invalid_image"
	GatewayErrorCodeTooLarge             = "request_too_large"
	GatewayErrorCodeModelNotInGrant      = "model_not_in_grant"
	GatewayErrorCodeRecordUnavailable    = "record_unavailable"
	GatewayErrorCodeBindingUnavailable   = "binding_unavailable"
	GatewayErrorCodeRouterUnavailable    = "router_unavailable"
	GatewayErrorCodeDraining             = "gateway_restarting"
	GatewayErrorCodeIdempotencyKeyReused = "idempotency_key_reused"
	GatewayErrorCodeCanceled             = "canceled"

	gatewayContentTypeJson = "application/json"
)

// One refusal or failure a front answers: its status, its words in each API's shape, and when to come back.
type gatewayError struct {
	Status int
	// OpenAI's type and code (Responses, Chat Completions).
	Type string
	Code string
	// The request member it concerns, or empty.
	Param string
	// Anthropic's error type (Messages).
	MessagesType string
	Message      string
	// Retry-After, rounded up to whole seconds; zero sends none.
	RetryAfter time.Duration
}

// The error in the gateway's own words.
func (self *gatewayError) Error() string {
	return fmt.Sprintf("%s: %s", self.Code, self.Message)
}

// A 400 for a request a front does not take, naming param where one is at fault.
func gatewayInvalidRequest(code string, param string, format string, a ...any) *gatewayError {
	return &gatewayError{
		Status:       http.StatusBadRequest,
		Type:         gatewayErrorTypeInvalidRequest,
		Code:         code,
		Param:        param,
		MessagesType: gatewayErrorTypeInvalidRequest,
		Message:      fmt.Sprintf(format, a...),
	}
}

// A 400 unsupported_parameter for a member that needs state the gateway does not keep (Q-CTXH-9, D-GW-2).
func gatewayUnsupportedParameter(param string, why string) *gatewayError {
	return gatewayInvalidRequest(GatewayErrorCodeUnsupportedParameter, param, "%s is not supported: %s", param, why)
}

// A 503 for a part of the gateway that cannot serve now: a harness retries it.
func gatewayUnavailable(code string, format string, a ...any) *gatewayError {
	return &gatewayError{
		Status:       http.StatusServiceUnavailable,
		Type:         gatewayErrorTypeServer,
		Code:         code,
		MessagesType: gatewayErrorTypeApi,
		Message:      fmt.Sprintf(format, a...),
	}
}

// A 413 for a body past GatewaySettings.RequestByteCount.
func gatewayTooLarge(byteCount int64) *gatewayError {
	return &gatewayError{
		Status:       http.StatusRequestEntityTooLarge,
		Type:         gatewayErrorTypeInvalidRequest,
		Code:         GatewayErrorCodeTooLarge,
		MessagesType: gatewayErrorTypeTooLarge,
		Message:      fmt.Sprintf("a request's body is at most %d bytes", byteCount),
	}
}

// What a body's read failed with: a 413 past the guard's bound, else a 400.
func gatewayReadError(err error, byteCount int64) *gatewayError {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return gatewayTooLarge(byteCount)
	}
	return gatewayInvalidRequest(GatewayErrorCodeInvalidJson, "", "the request's body did not read whole")
}

// The disclosure words a network gives: CTRUST's check, whose refusal names the summary line in the caller's locale.
// *Sidecar is one.
type gatewayDisclosureNetwork interface {
	ComputeDisclosureCheck() (*ComputeDisclosureCheck, error)
}

// The router's error in the gateway's words (see the file header's router row). network gives a disclosure's summary
// line where it can; nil names the id and the fix alone. now is the gateway's clock, which capacity's retry time is
// counted from.
func gatewayErrorOfInfer(ctx context.Context, inferError *InferError, network any, now time.Time) *gatewayError {
	if inferError == nil {
		return gatewayUnavailable(GatewayErrorCodeRouterUnavailable, "the call failed")
	}
	message := inferError.Message
	if inferError.Model != "" {
		message = inferError.Model + ": " + message
	}
	switch inferError.Code {
	case InferErrorInsufficientQuota:
		quota := &gatewayError{
			Status:       http.StatusTooManyRequests,
			Type:         gatewayErrorTypeInsufficientQuota,
			Code:         GatewayErrorCodeInsufficientQuota,
			MessagesType: gatewayErrorTypeBilling,
			Message:      message,
		}
		if inferError.Reason == InferQuotaReasonBalance {
			// Messages' word for an empty balance (D-GW-4)
			quota.Message = "the network's compute balance cannot pay: " + message
		}
		return quota
	case InferErrorContextLength:
		return &gatewayError{
			Status:       http.StatusBadRequest,
			Type:         gatewayErrorTypeInvalidRequest,
			Code:         GatewayErrorCodeContextLength,
			Param:        "input",
			MessagesType: gatewayErrorTypeInvalidRequest,
			Message:      message,
		}
	case InferErrorTeeUnverified:
		return &gatewayError{
			Status:       http.StatusServiceUnavailable,
			Type:         gatewayErrorTypeServer,
			Code:         string(InferErrorTeeUnverified),
			MessagesType: gatewayErrorTypeApi,
			Message:      fmt.Sprintf("%s: no instance of the model passed attestation, and the gateway sends the call to no other model, provider or label", message),
		}
	case InferErrorDisclosureRequired:
		return &gatewayError{
			Status:       http.StatusForbidden,
			Type:         gatewayErrorTypeInvalidRequest,
			Code:         string(InferErrorDisclosureRequired),
			MessagesType: gatewayErrorTypePermission,
			Message:      gatewayDisclosureMessage(ctx, inferError, network),
		}
	case InferErrorModelRefused, InferErrorServiceModel:
		return &gatewayError{
			Status:       http.StatusForbidden,
			Type:         gatewayErrorTypeInvalidRequest,
			Code:         string(inferError.Code),
			Param:        "model",
			MessagesType: gatewayErrorTypePermission,
			Message:      message,
		}
	case InferErrorCapacity:
		capacity := &gatewayError{
			Status:       http.StatusServiceUnavailable,
			Type:         gatewayErrorTypeServer,
			Code:         string(InferErrorCapacity),
			MessagesType: gatewayErrorTypeOverloaded,
			Message:      message,
		}
		if 0 < inferError.RetryAtMs {
			capacity.RetryAfter = time.Duration(inferError.RetryAtMs-now.UnixMilli()) * time.Millisecond
		}
		return capacity
	case InferErrorCanceled:
		return &gatewayError{
			Status:       http.StatusServiceUnavailable,
			Type:         gatewayErrorTypeServer,
			Code:         GatewayErrorCodeCanceled,
			MessagesType: gatewayErrorTypeApi,
			Message:      message,
		}
	}
	// engine_failed, and a code this build does not know
	return &gatewayError{
		Status:       http.StatusBadGateway,
		Type:         gatewayErrorTypeServer,
		Code:         string(InferErrorEngineFailed),
		MessagesType: gatewayErrorTypeApi,
		Message:      message,
	}
}

// disclosure_required's words (§8.4, D-GW-6): the model, the disclosure's id, its summary line where the network's
// check gives it, and the fix, `ur disclosures ack <id>` or the app's settings, --network on a tagged or cloud sidecar.
func gatewayDisclosureMessage(ctx context.Context, inferError *InferError, network any) string {
	if disclosures, ok := network.(gatewayDisclosureNetwork); ok && inferError.DisclosureId != "" {
		if check, err := disclosures.ComputeDisclosureCheck(); err == nil {
			var required *DisclosureRequiredError
			if errors.As(check.Require(ctx, inferError.DisclosureId, ""), &required) && required.Summary != "" {
				return fmt.Sprintf("%s needs the disclosure %s version %d acknowledged first (%s): %s", inferError.Model,
					required.Id, required.Version, required.Summary, required.Fix())
			}
		}
	}
	return inferError.Message
}

// Messages' overflow words, exact, since Claude Code compacts only on them (§8.5): n the prompt's tokens, max the
// model's window.
func gatewayMessagesOverflow(tokenCount int64, maxTokenCount int64) string {
	return fmt.Sprintf("prompt is too long: %d tokens > %d maximum", tokenCount, maxTokenCount)
}

// The code a stream's terminal event carries for a failure (see the file header's in stream row): once the model's
// output began, one Codex does not retry; before, the error's own.
func (self *gatewayError) streamCode(began bool) string {
	if !began {
		return self.Code
	}
	switch self.Code {
	case GatewayErrorCodeInsufficientQuota, GatewayErrorCodeContextLength:
		return self.Code
	}
	return gatewayErrorCodeNotRetried
}

// The error's body in api's shape.
func (self *gatewayError) body(api SessionGatewayApi) []byte {
	var value any
	if api == SessionGatewayApiMessages {
		message := self.Message
		if self.Code != GatewayErrorCodeContextLength && self.Code != "" {
			// the shape has no code member: the code leads, so a harness shows it
			message = self.Code + ": " + message
		}
		value = map[string]any{"type": "error", "error": map[string]string{"type": self.MessagesType, "message": message}}
	} else {
		var param any
		if self.Param != "" {
			param = self.Param
		}
		value = map[string]any{"error": map[string]any{"message": self.Message, "type": self.Type, "param": param, "code": self.Code}}
	}
	encoded, _ := gatewayMarshal(value)
	return encoded
}

// Writes the error as a whole answer: its status, Retry-After where it has one, and its body in api's shape.
func (self *gatewayError) write(writer http.ResponseWriter, api SessionGatewayApi) {
	header := writer.Header()
	header.Set("Content-Type", gatewayContentTypeJson)
	if 0 < self.RetryAfter {
		header.Set("Retry-After", strconv.FormatInt(int64((self.RetryAfter+time.Second-1)/time.Second), 10))
	}
	writer.WriteHeader(self.Status)
	writer.Write(self.body(api))
}

// JSON as the APIs write it: no HTML escaping, no trailing newline.
func gatewayMarshal(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return gatewayUnescapeHtml(encoded), nil
}

// encoding/json's <, > and & back to <, > and &, which the APIs send as they are. Only those three
// escapes are undone, and only outside a preceding backslash, so a literal backslash-u sequence a string held stays.
func gatewayUnescapeHtml(encoded []byte) []byte {
	out := make([]byte, 0, len(encoded))
	for i := 0; i < len(encoded); i++ {
		if encoded[i] == '\\' && i+1 < len(encoded) {
			if encoded[i+1] == 'u' && i+5 < len(encoded) {
				switch string(encoded[i+2 : i+6]) {
				case "003c":
					out = append(out, '<')
					i += 5
					continue
				case "003e":
					out = append(out, '>')
					i += 5
					continue
				case "0026":
					out = append(out, '&')
					i += 5
					continue
				}
			}
			// any other escape is copied whole, its second byte included
			out = append(out, encoded[i], encoded[i+1])
			i++
			continue
		}
		out = append(out, encoded[i])
	}
	return out
}
