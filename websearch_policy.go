//go:build !ios_extension && !sidecar_http

// What web search reads of the signed compute policy and the catalog (DESIGN-COMPUTE §5.4's search line, §6.3's search
// ids, §21.5, §21.8, §21.11; SRCH-M13-01, SRCH-M13-02).
//
//	line       §5.4's search line, which ATTEST keeps as the raw JSON the verified document holds and SRCH decodes here,
//	           strictly: exactly one object, every member one this file declares, none twice, nothing after it. Its
//	           members are this file's reading of §5.4's list, which names their contents and no names:
//	             host            the gateway's host, lowercase DNS labels
//	             asset           {network, contract, name, version}: USDC's CAIP-2 network, its contract, and the
//	                             EIP-712 domain's name and version
//	             ceiling_amount  the most a search may pay, in the asset's units (6 decimals)
//	             payer           URnetwork's payer address, to which every authorization must recover
//	             signer_key      searchsigner's HPKE key, X-Wing, lowercase hex, to which devices seal payees
//	             payee_fresh     set once G-SRCH-parallel shows every gateway payee fresh; absent is false
//	           Addresses are 0x and lowercase hex, as ATTEST writes hashes, so the signed bytes have one spelling.
//	           Until G-SRCH-parallel passes the policy carries no search line, and every search answers search_off
//	section    the catalog's search section (protocol.WebSearchCatalogSection), which the broker builds and the
//	           device reads into search endpoints, search/<engine>/<mode> at a price per search, through INFER's
//	           section registry
//	policy     WebSearchPolicy: what one search reads before it sends a byte, the line under a current freshness ticket
//	           (§5.4: a lapse stops searches) and the catalog's version and price for its mode, each refusing
//	           search_off where it is missing. webSearchSidecarPolicy is a Sidecar's, over ATTEST's gate and INFER's
//	           remote catalog; a test gives its own
//
// Safe for concurrent use: a line is immutable once parsed, and the Sidecar's policy reads at use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/hpke"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The engine this client pays and calls (Q-SRCH-12: one adapter), and the catalog's section name: identifiers.
const (
	WebSearchEngineParallel  = "parallel"
	webSearchCatalogSection  = "search"
	webSearchDisclosureId    = "search:parallel"
	webSearchAddressHexCount = 2 * webSearchAddressByteCount
)

// The gateway's modes (§21.6), fast by default: identifiers.
const (
	WebSearchModeFast     = "fast"
	WebSearchModeTurbo    = "turbo"
	WebSearchModeBasic    = "basic"
	WebSearchModeAdvanced = "advanced"
)

// Every mode, in §21.6's order.
var WebSearchModes = []string{WebSearchModeFast, WebSearchModeTurbo, WebSearchModeBasic, WebSearchModeAdvanced}

// A host of lowercase DNS labels, as ATTEST's pattern.
var webSearchHostPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]([a-z0-9-]*[a-z0-9])?$`)

var (
	// The policy's search line does not read: a member unknown, missing or twice, a value not of its format.
	ErrWebSearchPolicyLine = errors.New("web search: the policy's search line does not read")
)

// The refusal codes a search answers (§21.5, §21.9, §21.6): the broker's, the device's own and the tool's.
const (
	WebSearchCodeSearchOff          = "search_off"
	WebSearchCodeInsufficientQuota  = "insufficient_quota"
	WebSearchCodeRateLimited        = "rate_limited"
	WebSearchCodePayeeRefused       = "payee_refused"
	WebSearchCodeCapacity           = "capacity"
	WebSearchCodeCatalogStale       = "catalog_stale"
	WebSearchCodeBadOffer           = "bad_offer"
	WebSearchCodeRefused            = "refused"
	WebSearchCodeDisclosureRequired = "disclosure_required"
	WebSearchCodeQueryRefused       = "query_refused"
	WebSearchCodeUnlistedUrl        = "unlisted_url_in_query"
	WebSearchCodeLimit              = "limit"
	WebSearchCodeInvalid            = "invalid_arguments"
)

// A search that did not run, by its code, with what it can say: never a query, an objective, a payee or a result.
type WebSearchError struct {
	Code    string
	Message string
	// When to ask again, zero for no time.
	RetryAfter time.Duration
	// The refusal beneath, where one is.
	cause error
}

// See error.
func (self *WebSearchError) Error() string {
	text := "web search: " + self.Code
	if self.Message != "" {
		text += ": " + self.Message
	}
	return text
}

// A *WebSearchError target matches one of its code.
func (self *WebSearchError) Is(target error) bool {
	other, ok := target.(*WebSearchError)
	return ok && other.Code == self.Code
}

func (self *WebSearchError) Unwrap() error {
	return self.cause
}

// A refusal of code saying message, wrapping cause where one is.
func webSearchRefusal(code string, cause error, format string, args ...any) *WebSearchError {
	return &WebSearchError{Code: code, Message: fmt.Sprintf(format, args...), cause: cause}
}

// The code of err where it is a *WebSearchError, else empty.
func WebSearchErrorCode(err error) string {
	var refusal *WebSearchError
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return ""
}

// §5.4's search line, decoded (see the file header's line row).
type WebSearchPolicyLine struct {
	Host         string
	Network      string
	ChainId      uint64
	Asset        WebSearchAddress
	AssetName    string
	AssetVersion string
	// In the asset's units.
	CeilingAmount uint64
	Payer         WebSearchAddress
	SignerKey     hpke.PublicKey
	PayeeFresh    bool
}

// The asset's EIP-712 domain.
func (self *WebSearchPolicyLine) Domain() *WebSearchEip712Domain {
	return &WebSearchEip712Domain{Name: self.AssetName, Version: self.AssetVersion, ChainId: self.ChainId, VerifyingContract: self.Asset}
}

// The line's JSON, its members as the file header names them.
type webSearchPolicyLineJson struct {
	Host          *string                       `json:"host"`
	Asset         *webSearchPolicyLineAssetJson `json:"asset"`
	CeilingAmount *uint64                       `json:"ceiling_amount"`
	Payer         *string                       `json:"payer"`
	SignerKey     *string                       `json:"signer_key"`
	PayeeFresh    *bool                         `json:"payee_fresh,omitempty"`
}

type webSearchPolicyLineAssetJson struct {
	Network  *string `json:"network"`
	Contract *string `json:"contract"`
	Name     *string `json:"name"`
	Version  *string `json:"version"`
}

// A policy address: 0x and 40 lowercase hex digits.
func webSearchPolicyAddress(value string) (WebSearchAddress, error) {
	digits, _ := strings.CutPrefix(value, "0x")
	if len(digits) != webSearchAddressHexCount || strings.ToLower(digits) != digits {
		return WebSearchAddress{}, fmt.Errorf("%w: an address that is not 0x and 40 lowercase hex digits", ErrWebSearchPolicyLine)
	}
	return ParseWebSearchAddress(value)
}

// The line's member names once each, in every object, and no null anywhere, which encoding/json would take as its
// last value and as absent.
func webSearchPolicyLineNamesOnce(raw []byte) error {
	type frame struct {
		object  bool
		keyNext bool
		names   map[string]bool
	}
	stack := []*frame{}
	valueDone := func() {
		if 0 < len(stack) && stack[len(stack)-1].object {
			stack[len(stack)-1].keyNext = true
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrWebSearchPolicyLine, err)
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				stack = append(stack, &frame{object: true, keyNext: true, names: map[string]bool{}})
			case '[':
				stack = append(stack, &frame{})
			default:
				stack = stack[:len(stack)-1]
				valueDone()
			}
			continue
		}
		if 0 < len(stack) && stack[len(stack)-1].keyNext {
			top := stack[len(stack)-1]
			name, _ := token.(string)
			if top.names[name] {
				return fmt.Errorf("%w: member %q twice", ErrWebSearchPolicyLine, name)
			}
			top.names[name] = true
			top.keyNext = false
			continue
		}
		if token == nil {
			return fmt.Errorf("%w: a null", ErrWebSearchPolicyLine)
		}
		valueDone()
	}
}

// The search line raw holds, decoded strictly (see the file header). ErrWebSearchPolicyLine for anything else.
func ParseWebSearchPolicyLine(raw []byte, settings *WebSearchSettings) (*WebSearchPolicyLine, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: no search line", ErrWebSearchPolicyLine)
	}
	if settings.PolicyLineMaxByteCount < len(raw) {
		return nil, fmt.Errorf("%w: a line of %d bytes", ErrWebSearchPolicyLine, len(raw))
	}
	if err := webSearchPolicyLineNamesOnce(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoded := &webSearchPolicyLineJson{}
	if err := decoder.Decode(decoded); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWebSearchPolicyLine, err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: more than one value", ErrWebSearchPolicyLine)
	}
	asset := decoded.Asset
	if decoded.Host == nil || asset == nil || asset.Network == nil || asset.Contract == nil || asset.Name == nil ||
		asset.Version == nil || decoded.CeilingAmount == nil || decoded.Payer == nil || decoded.SignerKey == nil {
		return nil, fmt.Errorf("%w: a member missing", ErrWebSearchPolicyLine)
	}
	line := &WebSearchPolicyLine{
		Host:          *decoded.Host,
		Network:       *asset.Network,
		AssetName:     *asset.Name,
		AssetVersion:  *asset.Version,
		CeilingAmount: *decoded.CeilingAmount,
	}
	if settings.PolicyHostMaxByteCount < len(line.Host) || !webSearchHostPattern.MatchString(line.Host) {
		return nil, fmt.Errorf("%w: a host that is not lowercase DNS labels", ErrWebSearchPolicyLine)
	}
	if settings.NetworkMaxByteCount < len(line.Network) {
		return nil, fmt.Errorf("%w: a network of %d bytes", ErrWebSearchPolicyLine, len(line.Network))
	}
	chainId, err := WebSearchChainId(line.Network)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWebSearchPolicyLine, err)
	}
	line.ChainId = chainId
	if line.AssetName == "" || line.AssetVersion == "" {
		return nil, fmt.Errorf("%w: an asset without its EIP-712 name or version", ErrWebSearchPolicyLine)
	}
	if line.CeilingAmount == 0 {
		return nil, fmt.Errorf("%w: a ceiling of nothing", ErrWebSearchPolicyLine)
	}
	if line.Asset, err = webSearchPolicyAddress(*asset.Contract); err != nil {
		return nil, err
	}
	if line.Payer, err = webSearchPolicyAddress(*decoded.Payer); err != nil {
		return nil, err
	}
	keyHex := *decoded.SignerKey
	if strings.ToLower(keyHex) != keyHex {
		return nil, fmt.Errorf("%w: a signer key that is not lowercase hex", ErrWebSearchPolicyLine)
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("%w: a signer key that is not hex", ErrWebSearchPolicyLine)
	}
	if line.SignerKey, err = hpke.MLKEM768X25519().NewPublicKey(keyBytes); err != nil {
		return nil, fmt.Errorf("%w: a signer key that is not X-Wing", ErrWebSearchPolicyLine)
	}
	if decoded.PayeeFresh != nil {
		line.PayeeFresh = *decoded.PayeeFresh
	}
	return line, nil
}

// A search line's JSON for line's values, as the policy's signers would write it: for the fakes and the tests that
// build a policy, and the signer's own check of what it reads.
func WebSearchPolicyLineJson(line *WebSearchPolicyLine) ([]byte, error) {
	if line == nil || line.SignerKey == nil {
		return nil, fmt.Errorf("%w: no line or no signer key", ErrWebSearchPolicyLine)
	}
	host, network, contract, name, version := line.Host, line.Network, line.Asset.Hex(), line.AssetName, line.AssetVersion
	ceiling, payer, key := line.CeilingAmount, line.Payer.Hex(), hex.EncodeToString(line.SignerKey.Bytes())
	encoded := &webSearchPolicyLineJson{
		Host:          &host,
		Asset:         &webSearchPolicyLineAssetJson{Network: &network, Contract: &contract, Name: &name, Version: &version},
		CeilingAmount: &ceiling,
		Payer:         &payer,
		SignerKey:     &key,
	}
	if line.PayeeFresh {
		fresh := true
		encoded.PayeeFresh = &fresh
	}
	return json.Marshal(encoded)
}

// The catalog's price of a search endpoint as one search reads it: the version its entries came from, which the
// authorization names (§6.3, §9.6), and the price per search in nano-USD.
type WebSearchPrice struct {
	CatalogVersion   uint64
	NanoUsdPerSearch int64
}

// What one search reads before it sends a byte (see the file header's policy row). Safe for concurrent use.
type WebSearchPolicy interface {
	// The newest verified policy's search line, while a freshness ticket is current; a *WebSearchError search_off
	// otherwise, saying why.
	Line(ctx context.Context) (*WebSearchPolicyLine, error)
	// The catalog's version and price of search/<engine>/<mode>; a *WebSearchError search_off where the catalog lists
	// none, or lists it unavailable.
	Price(ctx context.Context, engine string, mode string) (*WebSearchPrice, error)
	// Fetches the catalog again, after the broker answered catalog_stale.
	RefreshCatalog(ctx context.Context) error
}

// The catalog's search section's body read into search endpoints, through INFER's registry: each entry's engine and
// mode as INFER's search id grammar takes them, a price of zero or less left out.
func webSearchReadCatalogSection(body []byte, settings *InferSettings) ([]*InferCatalogEntry, error) {
	section := &protocol.WebSearchCatalogSection{}
	if err := proto.Unmarshal(body, section); err != nil {
		return nil, fmt.Errorf("web search: the catalog's search section does not read: %w", err)
	}
	entries := []*InferCatalogEntry{}
	for _, entry := range section.GetEntries() {
		if entry.GetNanoUsdPerSearch() <= 0 {
			continue
		}
		id := (&InferSearchId{Engine: entry.GetEngine(), Kind: entry.GetMode()}).String()
		if _, err := InferParseSearchId(id, settings); err != nil {
			continue
		}
		entries = append(entries, &InferCatalogEntry{
			Provider: entry.GetEngine(),
			Kind:     InferCatalogKindSearch,
			Label:    ComputeLabelNone,
			Search:   &InferSearchEndpoint{Kind: entry.GetMode(), NanoUsdPerSearch: entry.GetNanoUsdPerSearch()},
		})
	}
	return entries, nil
}

func init() {
	registerInferCatalogSection(webSearchCatalogSection, webSearchReadCatalogSection)
}

// A Sidecar's WebSearchPolicy, read at use: ATTEST's gate and newest policy, INFER's router's catalog and its remote
// catalog's version.
type webSearchSidecarPolicy struct {
	sidecar  *Sidecar
	settings *WebSearchSettings
}

// See WebSearchPolicy.
func (self *webSearchSidecarPolicy) Line(ctx context.Context) (*WebSearchPolicyLine, error) {
	gate, err := self.sidecar.ComputePolicyGate()
	if err != nil {
		return nil, webSearchRefusal(WebSearchCodeSearchOff, err, "no compute policy gate")
	}
	if err := gate.RemoteWork(ctx, ComputeRemoteSearch); err != nil {
		return nil, webSearchRefusal(WebSearchCodeSearchOff, err, "%s", err)
	}
	policy, err := gate.PolicyCurrent()
	if err != nil {
		return nil, webSearchRefusal(WebSearchCodeSearchOff, err, "%s", err)
	}
	if len(policy.Search) == 0 {
		return nil, webSearchRefusal(WebSearchCodeSearchOff, nil, "the signed policy carries no search line")
	}
	line, err := ParseWebSearchPolicyLine(policy.Search, self.settings)
	if err != nil {
		return nil, webSearchRefusal(WebSearchCodeSearchOff, err, "%s", err)
	}
	return line, nil
}

// The remote catalog's version, which INFER keeps inside its router.
type webSearchCatalogVersions interface {
	Version(ctx context.Context) (uint64, error)
	fetchNow(ctx context.Context) error
}

// The Sidecar's remote catalog, as its version reads.
func (self *webSearchSidecarPolicy) remoteCatalog() (webSearchCatalogVersions, error) {
	infer, err := sidecarComputeComponent[sidecarInfer](self.sidecar, computeInferComponentName)
	if err != nil {
		return nil, err
	}
	if infer.router == nil || infer.router.remoteCatalog == nil {
		return nil, errors.New("no remote catalog")
	}
	versions, ok := infer.router.remoteCatalog.(webSearchCatalogVersions)
	if !ok {
		return nil, errors.New("the remote catalog keeps no version")
	}
	return versions, nil
}

// See WebSearchPolicy.
func (self *webSearchSidecarPolicy) Price(ctx context.Context, engine string, mode string) (*WebSearchPrice, error) {
	router, err := self.sidecar.InferRouter()
	if err != nil {
		return nil, webSearchRefusal(WebSearchCodeSearchOff, err, "no catalog")
	}
	catalog, err := router.Catalog(ctx)
	if err != nil {
		return nil, webSearchRefusal(WebSearchCodeSearchOff, err, "no catalog")
	}
	id := (&InferSearchId{Engine: engine, Kind: mode}).String()
	entry, err := catalog.SearchEndpoint(id)
	if err != nil {
		return nil, webSearchRefusal(WebSearchCodeSearchOff, err, "the catalog lists no %s", id)
	}
	if entry.Unavailable != "" || entry.Search == nil || entry.Search.NanoUsdPerSearch <= 0 {
		return nil, webSearchRefusal(WebSearchCodeSearchOff, nil, "the catalog lists %s unavailable: %s", id, entry.Unavailable)
	}
	versions, err := self.remoteCatalog()
	if err != nil {
		return nil, webSearchRefusal(WebSearchCodeSearchOff, err, "the catalog's version does not read")
	}
	version, err := versions.Version(ctx)
	if err != nil {
		return nil, webSearchRefusal(WebSearchCodeSearchOff, err, "the catalog's version does not read")
	}
	return &WebSearchPrice{CatalogVersion: version, NanoUsdPerSearch: entry.Search.NanoUsdPerSearch}, nil
}

// See WebSearchPolicy.
func (self *webSearchSidecarPolicy) RefreshCatalog(ctx context.Context) error {
	versions, err := self.remoteCatalog()
	if err != nil {
		return err
	}
	return versions.fetchNow(ctx)
}
