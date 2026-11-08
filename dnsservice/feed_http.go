// DnsFeed over HTTP: how a dns edge reaches the API block's internal routes (api_feed.go), with the
// bearer from its credential file. Every answer is read under a bound and decoded by wire.go's rules,
// so an answer of a format this release does not read stops the edge where it is, and a snapshot is
// read a line at a time as it streams. No error carries the bearer.

package dnsservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// The block answered something other than what the route promises.
var ErrDnsFeedRefused = errors.New("dns feed refused")

// The edges' client. Safe for concurrent use, as its http.Client is.
type dnsFeedHttp struct {
	baseUrl    string
	credential string
	client     *http.Client
	settings   *DnsSettings
}

// A feed over client to the block at baseUrl, its scheme and host, sending credential, the current
// bearer LoadDnsInternalCredential read. client must not time a request out before the block's 25 s
// hold ends; ctx bounds each call.
func NewDnsFeedHttp(baseUrl string, credential string, client *http.Client, settings *DnsSettings) (DnsFeed, error) {
	parsed, err := url.Parse(baseUrl)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("%w: the block's url is not one", ErrDnsFeedRefused)
	}
	if credential == "" {
		return nil, fmt.Errorf("%w: no credential", ErrDnsFeedRefused)
	}
	return &dnsFeedHttp{baseUrl: strings.TrimSuffix(baseUrl, "/"), credential: credential, client: client, settings: settings}, nil
}

// Sends a request with the bearer, and fails on any status but want, reading at most a small body
// from a refusal so the error says what the block said.
func (self *dnsFeedHttp) do(request *http.Request, want int) (*http.Response, error) {
	request.Header.Set("Authorization", "Bearer "+self.credential)
	response, err := self.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != want {
		response.Body.Close()
		return nil, fmt.Errorf("%w: %s answered %d", ErrDnsFeedRefused, request.URL.Path, response.StatusCode)
	}
	return response, nil
}

func (self *dnsFeedHttp) Journal(ctx context.Context, root string, after uint64) (*DnsFeedAnswer, error) {
	query := url.Values{"root": {root}, "after": {strconv.FormatUint(after, 10)}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, self.baseUrl+DnsJournalPath+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	response, err := self.do(request, http.StatusOK)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	limit := int64(self.settings.Api.AnswerMaxByteCount)
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if limit < int64(len(data)) {
		return nil, fmt.Errorf("%w: an answer past api.answer_max_bytes", ErrDnsRowMalformed)
	}
	return DecodeDnsFeedAnswer(data)
}

func (self *dnsFeedHttp) Snapshot(ctx context.Context, root string) (DnsSnapshotRows, error) {
	query := url.Values{"root": {root}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, self.baseUrl+DnsSnapshotPath+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	response, err := self.do(request, http.StatusOK)
	if err != nil {
		return nil, err
	}
	rows, err := NewDnsSnapshotReader(response.Body)
	if err != nil {
		response.Body.Close()
		return nil, err
	}
	return rows, nil
}

func (self *dnsFeedHttp) ReloadDiff(ctx context.Context, diff *DnsReloadDiff) error {
	body, err := json.Marshal(diff)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, self.baseUrl+DnsReloadDiffPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := self.do(request, http.StatusNoContent)
	if err != nil {
		return err
	}
	response.Body.Close()
	return nil
}
