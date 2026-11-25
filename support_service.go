//go:build !ios_extension && !sidecar_http

// The device's side of FB's feedback service (FEEDBACK-SYSTEM.md section 12, with DESIGN-COMPUTE Appendix J's
// additions): every call over TLS to the host the newest verified policy names, under this sidecar's token, never
// through an agent. The service is FB's to build (§28.21), so this is its interface as FB section 12 sketches it and
// Appendix J extends it, a reading where FB names no route:
//
//	POST /v1/entries                       a new item: the SupportBody, tier human, released or agent, under
//	                                       Idempotency-Key: <client_ref>; 201 {id, status, seq}, or 200 with replayed
//	POST /v1/entries/{id}/followups        a message continuing an item, the same body and key (Appendix J)
//	POST /v1/entries/{id}/attachments      a bundle or file of a message, after its entry is known, its key the message's
//	                                       client_ref and the attachment's place (a reading: FB section 9 names none)
//	GET  /v1/entries?client_ref=<ref>      the entry a client_ref made, the outbox's and kind 27's lookup (Appendix J)
//	GET  /v1/events?scope=member&cursor=   the member's conversation's events, server-sent, notes' and bodies' text
//	     &include=note,body                included, a device reading its member's (Appendix J's scope=member)
//	DELETE /v1/entries/{id}                an item's bodies and attachments removed (FB section 10.4; a reading)
//
// A 429 carries retry_after; 404 is the same for missing and not-yours; every answer is read within its bound, and no
// error carries the service's text, which the support log could not hold anyway. Safe for concurrent use.

package sidecar

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// What a post came to, as the support log's post_result enumerates it.
type supportServiceError struct {
	result SupportLogPostResult
	status int
	// a 429's retry_after
	retryAfter time.Duration
}

// The class and the status, never the service's text.
func (self *supportServiceError) Error() string {
	return fmt.Sprintf("feedback service: %s (%d)", supportPostResultWords[self.result], self.status)
}

// The post results' words, for an error.
var supportPostResultWords = map[SupportLogPostResult]string{
	SupportLogPostResultAccepted:     "accepted",
	SupportLogPostResultReplayed:     "replayed",
	SupportLogPostResultClientError:  "refused",
	SupportLogPostResultRateLimited:  "rate limited",
	SupportLogPostResultServerError:  "server error",
	SupportLogPostResultUnreachable:  "unreachable",
	SupportLogPostResultTlsFailed:    "tls failed",
	SupportLogPostResultTimeout:      "timed out",
	SupportLogPostResultUnauthorized: "unauthorized",
}

// The class of a call's failure, for the support log and the outbox's retry rule.
func supportServiceResultOf(err error) SupportLogPostResult {
	var serviceError *supportServiceError
	if errors.As(err, &serviceError) {
		return serviceError.result
	}
	var netError net.Error
	var tlsError *tls.CertificateVerificationError
	switch {
	case errors.As(err, &tlsError):
		return SupportLogPostResultTlsFailed
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netError) && netError.Timeout()):
		return SupportLogPostResultTimeout
	}
	return SupportLogPostResultUnreachable
}

// Whether a failure is worth another try: the service or the network, never a refusal of the message itself.
func supportServiceRetryable(err error) bool {
	switch supportServiceResultOf(err) {
	case SupportLogPostResultServerError, SupportLogPostResultUnreachable, SupportLogPostResultTimeout,
		SupportLogPostResultTlsFailed, SupportLogPostResultUnauthorized:
		return true
	}
	return false
}

// What a post or lookup answers: the entry's id, its status and seq, and whether a repeat found the first.
type supportEntryAnswer struct {
	Id       string `json:"id"`
	Status   string `json:"status"`
	Seq      uint32 `json:"seq"`
	Replayed bool   `json:"replayed"`
	FixedIn  string `json:"fixed_in"`
}

// One event of the member's conversation as the service sends it (FB section 4, with Appendix J's body and sender).
type SupportServiceEvent struct {
	Entry string `json:"entry"`
	Seq   uint32 `json:"seq"`
	// submitted, status, fixed_in, note, followup, linked, merged, attachment, deleted
	Type    string `json:"type"`
	Status  string `json:"status"`
	FixedIn string `json:"fixed_in"`
	Final   bool   `json:"final"`
	// a note's text as support wrote it, or a message's body, with include
	Note string `json:"note"`
	Body string `json:"body"`
	// support for a note; the person, or an agent's name, for a message
	By        string      `json:"by"`
	Agent     string      `json:"agent"`
	Tier      SupportTier `json:"tier"`
	ClientRef string      `json:"client_ref"`
	At        time.Time   `json:"at"`
}

// FB section 4's event types, as their place gives them, from 1: SupportMessageBody.type.
var supportEventTypes = []string{"submitted", "status", "fixed_in", "note", "followup", "linked", "merged", "attachment", "deleted"}

// An event type's number, 0 for one FB does not name.
func supportEventTypeNumber(eventType string) uint32 {
	for i, known := range supportEventTypes {
		if known == eventType {
			return uint32(i + 1)
		}
	}
	return 0
}

// FB section 6's statuses, as their place gives them, from 1: SupportMessageBody.status.
var supportStatuses = []string{"received", "in_progress", "fixed", "wont_fix", "closed"}

// A status's number, 0 for one FB does not name.
func supportStatusNumber(status string) uint32 {
	for i, known := range supportStatuses {
		if known == status {
			return uint32(i + 1)
		}
	}
	return 0
}

// The service's client: its http client, which dials TLS alone, and the bounds it reads answers within.
type supportService struct {
	client   *http.Client
	settings *SupportSettings
}

// A client over httpClient, nil for one of its own that verifies the host's certificate against the system's roots.
func newSupportService(httpClient *http.Client, settings *SupportSettings) *supportService {
	if httpClient == nil {
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
				ForceAttemptHTTP2:   true,
				TLSHandshakeTimeout: settings.PostTimeout,
			},
		}
	}
	return &supportService{client: httpClient, settings: settings}
}

// https://<host><path>, refusing a host that is no DNS name: the policy's host alone, over TLS alone.
func supportServiceUrl(host string, path string, query url.Values) (string, error) {
	if !supportPolicyHostPattern.MatchString(host) {
		return "", errors.New("feedback service: no host of DNS labels")
	}
	target := &url.URL{Scheme: "https", Host: host, Path: path}
	if query != nil {
		target.RawQuery = query.Encode()
	}
	return target.String(), nil
}

// One call: its answer's body, within ResponseMaxByteCount, for a 2xx; a supportServiceError for any other status.
func (self *supportService) call(ctx context.Context, method string, target string, token string, idempotencyKey string,
	contentType string, body []byte) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, self.settings.PostTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := self.client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, self.settings.ResponseMaxByteCount+1))
	if err != nil {
		return nil, response.StatusCode, err
	}
	if self.settings.ResponseMaxByteCount < int64(len(answer)) {
		return nil, response.StatusCode, &supportServiceError{result: SupportLogPostResultServerError, status: response.StatusCode}
	}
	switch {
	case 200 <= response.StatusCode && response.StatusCode < 300:
		return answer, response.StatusCode, nil
	case response.StatusCode == http.StatusTooManyRequests:
		retryAfter := time.Duration(0)
		if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && 0 < seconds {
			retryAfter = time.Duration(seconds) * time.Second
		}
		return nil, response.StatusCode, &supportServiceError{result: SupportLogPostResultRateLimited, status: response.StatusCode, retryAfter: retryAfter}
	case response.StatusCode == http.StatusUnauthorized:
		return nil, response.StatusCode, &supportServiceError{result: SupportLogPostResultUnauthorized, status: response.StatusCode}
	case 500 <= response.StatusCode:
		return nil, response.StatusCode, &supportServiceError{result: SupportLogPostResultServerError, status: response.StatusCode}
	}
	return nil, response.StatusCode, &supportServiceError{result: SupportLogPostResultClientError, status: response.StatusCode}
}

// Posts a message: a new item, or with entry a follow-up on it, under its client_ref.
func (self *supportService) postMessage(ctx context.Context, host string, token string, clientRef string, entry string, body []byte) (*supportEntryAnswer, error) {
	path := "/v1/entries"
	if entry != "" {
		path = "/v1/entries/" + url.PathEscape(entry) + "/followups"
	}
	target, err := supportServiceUrl(host, path, nil)
	if err != nil {
		return nil, err
	}
	answer, _, err := self.call(ctx, http.MethodPost, target, token, clientRef, "application/json", body)
	if err != nil {
		return nil, err
	}
	entryAnswer := &supportEntryAnswer{}
	if err := json.Unmarshal(answer, entryAnswer); err != nil || !supportEntryPattern.MatchString(entryAnswer.Id) {
		return nil, &supportServiceError{result: SupportLogPostResultServerError}
	}
	return entryAnswer, nil
}

// Posts one attachment of a message whose entry is known, under its own key.
func (self *supportService) postAttachment(ctx context.Context, host string, token string, entry string, key string, contentType string, data []byte) error {
	target, err := supportServiceUrl(host, "/v1/entries/"+url.PathEscape(entry)+"/attachments", nil)
	if err != nil {
		return err
	}
	_, _, err = self.call(ctx, http.MethodPost, target, token, key, contentType, data)
	return err
}

// The entry a client_ref made, nil where the service holds none.
func (self *supportService) lookup(ctx context.Context, host string, token string, clientRef string) (*supportEntryAnswer, error) {
	target, err := supportServiceUrl(host, "/v1/entries", url.Values{"client_ref": {clientRef}})
	if err != nil {
		return nil, err
	}
	answer, status, err := self.call(ctx, http.MethodGet, target, token, "", "", nil)
	if status == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	entries := &struct {
		Entries []*supportEntryAnswer `json:"entries"`
	}{}
	if err := json.Unmarshal(answer, entries); err != nil {
		return nil, &supportServiceError{result: SupportLogPostResultServerError}
	}
	for _, entry := range entries.Entries {
		if entry != nil && supportEntryPattern.MatchString(entry.Id) {
			return entry, nil
		}
	}
	return nil, nil
}

// Removes an item's bodies and attachments at the service (FB section 10.4).
func (self *supportService) deleteEntry(ctx context.Context, host string, token string, entry string) error {
	target, err := supportServiceUrl(host, "/v1/entries/"+url.PathEscape(entry), nil)
	if err != nil {
		return err
	}
	_, _, err = self.call(ctx, http.MethodDelete, target, token, "", "", nil)
	return err
}

// Reads the member's events from cursor, server-sent, handing each to handle in order, until the stream ends, ctx ends
// or EventsMaxCount have come; answers the cursor after the last one handled. An event that does not parse ends the
// read, its cursor not taken, so it is read again.
func (self *supportService) events(ctx context.Context, host string, token string, cursor string, handle func(event *SupportServiceEvent)) (string, error) {
	query := url.Values{"scope": {"member"}, "include": {"note,body"}}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	target, err := supportServiceUrl(host, "/v1/events", query)
	if err != nil {
		return cursor, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return cursor, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "text/event-stream")
	response, err := self.client.Do(request)
	if err != nil {
		return cursor, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(response.Body, self.settings.ResponseMaxByteCount))
		switch {
		case response.StatusCode == http.StatusUnauthorized:
			return cursor, &supportServiceError{result: SupportLogPostResultUnauthorized, status: response.StatusCode}
		case response.StatusCode == http.StatusTooManyRequests:
			return cursor, &supportServiceError{result: SupportLogPostResultRateLimited, status: response.StatusCode}
		case 500 <= response.StatusCode:
			return cursor, &supportServiceError{result: SupportLogPostResultServerError, status: response.StatusCode}
		}
		return cursor, &supportServiceError{result: SupportLogPostResultClientError, status: response.StatusCode}
	}
	reader := bufio.NewReaderSize(io.LimitReader(response.Body, self.settings.EventStreamMaxByteCount), 4096)
	id, data := "", &strings.Builder{}
	count := 0
	for count < self.settings.EventsMaxCount {
		line, err := reader.ReadString('\n')
		if err != nil {
			return cursor, nil
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "":
			if data.Len() == 0 {
				continue
			}
			event := &SupportServiceEvent{}
			if err := json.Unmarshal([]byte(data.String()), event); err != nil || !supportEntryPattern.MatchString(event.Entry) {
				return cursor, &supportServiceError{result: SupportLogPostResultServerError}
			}
			handle(event)
			count += 1
			if id != "" {
				cursor = id
			}
			id = ""
			data.Reset()
		case strings.HasPrefix(line, "id:"):
			id = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
		case strings.HasPrefix(line, "data:"):
			if self.settings.EventMaxByteCount < data.Len()+len(line) {
				return cursor, &supportServiceError{result: SupportLogPostResultServerError}
			}
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	return cursor, nil
}
