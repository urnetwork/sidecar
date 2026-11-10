//go:build !sidecar_http && !ios_extension

// AclGateSource over api's internal gate surface (plan-SOCK-gate-data, QD-055): how a gate service with no reach to the
// metadata tier (§8.9, §2.8 evs-10) reads a network's authorization log, connect's contract gate first, and sockets,
// tlsedge, certs, dns, smtpedge and mxedge after it. Two routes, under a prefix the lb refuses from outside, each
// request carrying the caller's own bearer, which api verifies by its hash (plan-TLS-internal-credentials):
//
//	GET <base>/internal/gate/projection/<network_id>?after=<n>
//	    the entries after n, a page at most and from the retention point when n is before it, the rows of each base
//	    among them and, from 0, the Signed Genesis: GET /network/config/projection's body (TEAM-M2-13),
//	    {genesis, entries, rows, tip: {n, chain}, more}, every message verbatim in base64
//	GET <base>/internal/gate/rows/<network_id>/<rows_sha256>
//	    one base's ProjectionRows, verbatim, the hash in lower-case hex
//
// api is a carrier and decides nothing: AclGateCache checks every entry's chain from its own pin wherever it read it
// (ConfigLog.ApplyRun), so a stale, short or forged answer costs a load and never a lower n, and rows are held to
// their hash here. Answers are bounded in bytes and in pages. A source with no credential sends nothing and fails
// every call, so a host with no bearer loads nothing and its gate stays not ready, the closed direction.
//
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// api's internal gate surface, each followed by its network id.
const (
	AclGateApiProjectionPath = "/internal/gate/projection/"
	AclGateApiRowsPath       = "/internal/gate/rows/"
)

// The source holds no bearer, so it sends nothing.
var ErrAclGateApiNoCredential = errors.New("acl gate api source: no credential")

// api answered something that is no page or no rows of the route's: bytes that do not decode, a bound passed, a
// page that says more and moves nothing, or rows whose hash is another's.
var ErrAclGateApiReply = errors.New("acl gate api source: a reply that does not hold")

// The source's tunables, each with its default here and nowhere else.
type AclGateApiSettings struct {
	// The most bytes one projection page may answer before the read fails: 64 MiB, api's page of 1,024 entries and
	// the rows of the bases among them, at §8.8's 4 MiB each, in base64. Non-positive bounds nothing.
	PageMaxByteCount int64
	// The most bytes one base's rows may answer: 4 MiB and 64 KiB, §8.8's bound on ProjectionRows with room for
	// framing. Non-positive bounds nothing.
	RowsMaxByteCount int64
	// The most pages one Entries call reads before it fails, so an api that keeps answering more cannot hold a load:
	// 4,096, some four million entries, past any log a store retains. Non-positive bounds nothing.
	PageMaxCount int
}

// The defaults.
func DefaultAclGateApiSettings() *AclGateApiSettings {
	return &AclGateApiSettings{
		PageMaxByteCount: 64 * 1024 * 1024,
		RowsMaxByteCount: 4*1024*1024 + 64*1024,
		PageMaxCount:     4096,
	}
}

// AclGateSource over api's internal gate surface.
type AclGateApiSource struct {
	baseUrl    string
	client     *http.Client
	credential func() (string, error)
	settings   *AclGateApiSettings
}

// A source reading api at baseUrl, an absolute URL such as the internal api's origin, through client, each request
// carrying the bearer credential answers, which the host reads from its secret_files and may rotate. A nil client is
// a client of its own on the default transport, a nil credential one that answers none.
func NewAclGateApiSource(baseUrl string, client *http.Client, credential func() (string, error), settings *AclGateApiSettings) (*AclGateApiSource, error) {
	parsed, err := url.Parse(baseUrl)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("acl gate api source: a base that is no absolute url")
	}
	if client == nil {
		client = &http.Client{}
	}
	if settings == nil {
		settings = DefaultAclGateApiSettings()
	}
	return &AclGateApiSource{
		baseUrl:    strings.TrimSuffix(baseUrl, "/"),
		client:     client,
		credential: credential,
		settings:   settings,
	}, nil
}

// The projection route's first page's Signed Genesis. ErrBlobNotFound when api holds none for the network.
func (self *AclGateApiSource) Genesis(ctx context.Context, networkId Id) ([]byte, error) {
	page, err := self.page(ctx, networkId, 0)
	if err != nil {
		return nil, err
	}
	if len(page.Genesis) == 0 {
		return nil, ErrBlobNotFound
	}
	return page.Genesis, nil
}

// The entries after after, page by page through the tip: for a cold start, after nil, every entry api retains from
// its retention point on. The caller checks every link.
func (self *AclGateApiSource) Entries(ctx context.Context, networkId Id, after *bridge.AuthPin) ([][]byte, error) {
	position := uint64(0)
	if after != nil {
		position = after.GetVersion()
	}
	entries := [][]byte{}
	for pageCount := 0; ; pageCount += 1 {
		if 0 < self.settings.PageMaxCount && self.settings.PageMaxCount <= pageCount {
			return nil, fmt.Errorf("%w: more than %d pages", ErrAclGateApiReply, self.settings.PageMaxCount)
		}
		page, err := self.page(ctx, networkId, position)
		if err != nil {
			return nil, err
		}
		entries = append(entries, page.Entries...)
		if !page.More {
			return entries, nil
		}
		if page.Tip == nil || page.Tip.N <= position || len(page.Entries) == 0 {
			return nil, fmt.Errorf("%w: a page that says more and moves nothing", ErrAclGateApiReply)
		}
		position = page.Tip.N
	}
}

// A base's rows by their hash, held to it. ErrBlobNotFound when api has none by that hash.
func (self *AclGateApiSource) Rows(ctx context.Context, networkId Id, rowsSha256 []byte) ([]byte, error) {
	if len(rowsSha256) != sha256.Size {
		return nil, fmt.Errorf("acl gate api source: a rows hash of %d bytes", len(rowsSha256))
	}
	rows, err := self.get(ctx, AclGateApiRowsPath+networkId.String()+"/"+hex.EncodeToString(rowsSha256), self.settings.RowsMaxByteCount)
	if err != nil {
		return nil, err
	}
	if sum := sha256.Sum256(rows); !bytes.Equal(sum[:], rowsSha256) {
		return nil, fmt.Errorf("%w: rows that hash to another", ErrAclGateApiReply)
	}
	return rows, nil
}

// One projection page.
func (self *AclGateApiSource) page(ctx context.Context, networkId Id, after uint64) (*sidecarConfigProjectionReply, error) {
	body, err := self.get(ctx, AclGateApiProjectionPath+networkId.String()+"?after="+strconv.FormatUint(after, 10), self.settings.PageMaxByteCount)
	if err != nil {
		return nil, err
	}
	page := &sidecarConfigProjectionReply{}
	if err := json.Unmarshal(body, page); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAclGateApiReply, err)
	}
	if page.Tip != nil && (page.Tip.N == 0 || len(page.Tip.Chain) != sha256.Size) {
		return nil, fmt.Errorf("%w: a tip that is no pin", ErrAclGateApiReply)
	}
	return page, nil
}

// One GET of path under the base with the bearer, its body read to at most maxByteCount bytes. 404 is
// ErrBlobNotFound; anything but 200 else fails with its status, never with the bearer.
func (self *AclGateApiSource) get(ctx context.Context, path string, maxByteCount int64) ([]byte, error) {
	bearer := ""
	if self.credential != nil {
		var err error
		if bearer, err = self.credential(); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrAclGateApiNoCredential, err)
		}
	}
	if bearer == "" {
		return nil, ErrAclGateApiNoCredential
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, self.baseUrl+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	response, err := self.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrBlobNotFound
	default:
		return nil, fmt.Errorf("acl gate api source: api answered %d", response.StatusCode)
	}
	reader := io.Reader(response.Body)
	if 0 < maxByteCount {
		reader = io.LimitReader(response.Body, maxByteCount+1)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if 0 < maxByteCount && maxByteCount < int64(len(body)) {
		return nil, fmt.Errorf("%w: an answer over %d bytes", ErrAclGateApiReply, maxByteCount)
	}
	return body, nil
}
