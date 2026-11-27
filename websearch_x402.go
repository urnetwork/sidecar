//go:build !ios_extension && !sidecar_http

// x402 v2 as the device speaks it to Parallel's keyless gateway (DESIGN-COMPUTE §21.3, §21.5's What the device checks
// and The device's request, R-SRCH-7, D-SRCH-3, CF-13; SRCH-M13-02):
//
//	challenge  a 402's PAYMENT-REQUIRED header, base64 of x402 v2's PaymentRequired, else its JSON body, at most
//	           ChallengeMaxByteCount; its MPP challenge (WWW-Authenticate) is never read
//	offer      the accepts entry whose scheme is exact, whose network, asset and EIP-712 name and version are the policy's,
//	           whose maxTimeoutSeconds reaches OfferMinTimeout, whose payTo is 20 bytes, and whose amount is above 0,
//	           within the policy's ceiling and, times the compute markup and rounded up to a search's step, within the
//	           catalog's price per search: the plan's reading of §21.5's "no more than the catalog's price", since the
//	           catalog prices a search at retail (§21.8). A challenge naming a resource on another host or path is no
//	           offer for this search. Anything else refuses the search unpaid, bad_offer, before a byte reaches the broker
//	payment    x402 v2's PaymentPayload for the exact scheme: x402Version 2, accepted the offer taken as the gateway wrote
//	           it, byte for byte, and payload the signature and the authorization, base64 in the header the settings
//	           name (PAYMENT-SIGNATURE until G-SRCH-parallel's load test says otherwise)
//	receipt    PAYMENT-RESPONSE, base64 of x402's SettleResponse, where the gateway sends it: its transaction hash, which
//	           the tool's stub keeps
//
// No other x402 field, rail or extension is sent. Nothing here reads a clock. Package-level functions are safe for
// concurrent use.

package sidecar

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

// x402's names: identifiers of its v2 wire.
const (
	webSearchX402Version              = 2
	webSearchX402SchemeExact          = "exact"
	webSearchPaymentRequiredHeader    = "PAYMENT-REQUIRED"
	webSearchPaymentResponseHeader    = "PAYMENT-RESPONSE"
	webSearchX402ExtraName            = "name"
	webSearchX402ExtraVersion         = "version"
	webSearchTransactionHashByteCount = 32
	webSearchSearchPath               = "/api/search"
)

var (
	// A 402 whose challenge does not read as x402 v2.
	ErrWebSearchChallenge = errors.New("web search: the gateway's challenge does not read")
)

// x402 v2's PaymentRequired, as a 402 carries it.
type X402PaymentRequired struct {
	X402Version int    `json:"x402Version"`
	Error       string `json:"error,omitempty"`
	// What the challenge is for; its url, where given, is the search's.
	Resource *X402Resource `json:"resource,omitempty"`
	// Each entry as the gateway wrote it, so the one taken goes back byte for byte.
	Accepts []json.RawMessage `json:"accepts"`
}

// x402 v2's resource.
type X402Resource struct {
	Url         string `json:"url"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// One accepts entry: x402 v2's PaymentRequirements for the exact scheme.
type X402PaymentRequirements struct {
	Scheme            string         `json:"scheme"`
	Network           string         `json:"network"`
	Amount            string         `json:"amount"`
	Asset             string         `json:"asset"`
	PayTo             string         `json:"payTo"`
	MaxTimeoutSeconds int64          `json:"maxTimeoutSeconds"`
	Extra             map[string]any `json:"extra"`
}

// x402 v2's PaymentPayload for the exact scheme on an EVM chain.
type X402PaymentPayload struct {
	X402Version int               `json:"x402Version"`
	Accepted    json.RawMessage   `json:"accepted"`
	Payload     *X402ExactPayload `json:"payload"`
}

// The exact scheme's payload: the signature, 0x and hex of r ‖ s ‖ v, and the authorization it signs.
type X402ExactPayload struct {
	Signature     string             `json:"signature"`
	Authorization *X402Authorization `json:"authorization"`
}

// EIP-3009's authorization as x402 writes it: addresses 0x and hex, integers decimal, the nonce 0x and hex.
type X402Authorization struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	ValidAfter  string `json:"validAfter"`
	ValidBefore string `json:"validBefore"`
	Nonce       string `json:"nonce"`
}

// The offer a search takes: the requirements read, the bytes they came as, and what they name.
type webSearchOffer struct {
	raw          json.RawMessage
	requirements *X402PaymentRequirements
	payTo        WebSearchAddress
	amount       uint64
}

// A 402's challenge: header holds PAYMENT-REQUIRED's value, empty for none, and body the answer's body, each within
// ChallengeMaxByteCount.
func webSearchReadChallenge(header string, body []byte, settings *WebSearchSettings) (*X402PaymentRequired, error) {
	raw := body
	if header != "" {
		if base64.StdEncoding.DecodedLen(len(header)) > settings.ChallengeMaxByteCount {
			return nil, fmt.Errorf("%w: a header of %d bytes", ErrWebSearchChallenge, len(header))
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header))
		if err != nil {
			return nil, fmt.Errorf("%w: a header that is not base64", ErrWebSearchChallenge)
		}
		raw = decoded
	}
	if settings.ChallengeMaxByteCount < len(raw) {
		return nil, fmt.Errorf("%w: %d bytes", ErrWebSearchChallenge, len(raw))
	}
	challenge := &X402PaymentRequired{}
	if err := json.Unmarshal(raw, challenge); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWebSearchChallenge, err)
	}
	if challenge.X402Version != webSearchX402Version {
		return nil, fmt.Errorf("%w: x402 version %d", ErrWebSearchChallenge, challenge.X402Version)
	}
	return challenge, nil
}

// What a search of amount costs the network, in nano-USD (§21.8): amount's value times the markup, rounded up to a
// search's step; false where it passes 64 bits.
func webSearchRetailNanoUsd(amount uint64, settings *WebSearchSettings) (int64, bool) {
	if settings.MarkupNumerator <= 0 || settings.MarkupDenominator <= 0 || settings.SearchPriceStepNanoUsd <= 0 || settings.AssetUnitNanoUsd <= 0 {
		return 0, false
	}
	product := new(big.Int).SetUint64(amount)
	product.Mul(product, big.NewInt(settings.AssetUnitNanoUsd))
	product.Mul(product, big.NewInt(settings.MarkupNumerator))
	divisor := new(big.Int).Mul(big.NewInt(settings.MarkupDenominator), big.NewInt(settings.SearchPriceStepNanoUsd))
	steps, remainder := new(big.Int).QuoRem(product, divisor, new(big.Int))
	if remainder.Sign() != 0 {
		steps.Add(steps, big.NewInt(1))
	}
	retail := steps.Mul(steps, big.NewInt(settings.SearchPriceStepNanoUsd))
	if !retail.IsInt64() {
		return 0, false
	}
	return retail.Int64(), true
}

// The offer of challenge this search takes under line and price (see the file header's offer row), or why none: a
// *WebSearchError bad_offer.
func webSearchTakeOffer(challenge *X402PaymentRequired, line *WebSearchPolicyLine, price *WebSearchPrice, settings *WebSearchSettings) (*webSearchOffer, error) {
	if challenge.Resource != nil && challenge.Resource.Url != "" {
		resource, err := url.Parse(challenge.Resource.Url)
		if err != nil || resource.Scheme != "https" || resource.Hostname() != line.Host || resource.Path != webSearchSearchPath ||
			(resource.Port() != "" && resource.Port() != "443") {
			return nil, webSearchRefusal(WebSearchCodeBadOffer, nil, "the challenge is for another resource")
		}
	}
	reasons := []string{}
	for _, raw := range challenge.Accepts {
		offer, reason := webSearchCheckOffer(raw, line, price, settings)
		if offer != nil {
			return offer, nil
		}
		reasons = append(reasons, reason)
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "no offer")
	}
	return nil, webSearchRefusal(WebSearchCodeBadOffer, nil, "%s", strings.Join(reasons, "; "))
}

// One accepts entry checked, or why it is not taken.
func webSearchCheckOffer(raw json.RawMessage, line *WebSearchPolicyLine, price *WebSearchPrice, settings *WebSearchSettings) (*webSearchOffer, string) {
	requirements := &X402PaymentRequirements{}
	if err := json.Unmarshal(raw, requirements); err != nil {
		return nil, "an offer that does not read"
	}
	if requirements.Scheme != webSearchX402SchemeExact {
		return nil, "a scheme other than exact"
	}
	if requirements.Network != line.Network {
		return nil, "another network"
	}
	asset, err := ParseWebSearchAddress(requirements.Asset)
	if err != nil || asset != line.Asset {
		return nil, "another asset"
	}
	name, _ := requirements.Extra[webSearchX402ExtraName].(string)
	version, _ := requirements.Extra[webSearchX402ExtraVersion].(string)
	if name != line.AssetName || version != line.AssetVersion {
		return nil, "another EIP-712 domain"
	}
	if requirements.MaxTimeoutSeconds < int64(settings.OfferMinTimeout.Seconds()) {
		return nil, "a timeout short of the window"
	}
	payTo, err := ParseWebSearchAddress(requirements.PayTo)
	if err != nil {
		return nil, "a payee that is not an address"
	}
	amount, err := strconv.ParseUint(requirements.Amount, 10, 64)
	if err != nil || amount == 0 || strconv.FormatUint(amount, 10) != requirements.Amount {
		return nil, "an amount that does not read"
	}
	if line.CeilingAmount < amount {
		return nil, "an amount past the policy's ceiling"
	}
	retail, ok := webSearchRetailNanoUsd(amount, settings)
	if !ok || price == nil || price.NanoUsdPerSearch < retail {
		return nil, "an amount past the catalog's price"
	}
	return &webSearchOffer{raw: raw, requirements: requirements, payTo: payTo, amount: amount}, ""
}

// The paid retry's header value for offer and the signer's authorization: base64 of the payment payload.
func webSearchPaymentHeaderValue(offer *webSearchOffer, authorization *protocol.ComputeSearchAuthorization) (string, error) {
	from, err := WebSearchAddressOf(authorization.GetFrom())
	if err != nil {
		return "", err
	}
	to, err := WebSearchAddressOf(authorization.GetTo())
	if err != nil {
		return "", err
	}
	payload := &X402PaymentPayload{
		X402Version: webSearchX402Version,
		Accepted:    offer.raw,
		Payload: &X402ExactPayload{
			Signature: "0x" + hex.EncodeToString(authorization.GetSignature()),
			Authorization: &X402Authorization{
				From:        from.ChecksumHex(),
				To:          to.ChecksumHex(),
				Value:       strconv.FormatUint(authorization.GetValue(), 10),
				ValidAfter:  strconv.FormatInt(authorization.GetValidAfterS(), 10),
				ValidBefore: strconv.FormatInt(authorization.GetValidBeforeS(), 10),
				Nonce:       "0x" + hex.EncodeToString(authorization.GetNonce()),
			},
		},
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encoded), nil
}

// x402's SettleResponse, as PAYMENT-RESPONSE carries it.
type webSearchSettleResponse struct {
	Success     bool   `json:"success"`
	Transaction string `json:"transaction"`
}

// The transaction a PAYMENT-RESPONSE names, 32 bytes, and false where it names none or does not read: a receipt is
// shown, never trusted, and its absence changes nothing.
func webSearchReadPaymentResponse(value string, settings *WebSearchSettings) ([]byte, bool) {
	if value == "" || base64.StdEncoding.DecodedLen(len(value)) > settings.ChallengeMaxByteCount {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, false
	}
	response := &webSearchSettleResponse{}
	if err := json.Unmarshal(decoded, response); err != nil || !response.Success {
		return nil, false
	}
	digits, ok := strings.CutPrefix(response.Transaction, "0x")
	if !ok || len(digits) != 2*webSearchTransactionHashByteCount {
		return nil, false
	}
	transaction, err := hex.DecodeString(digits)
	if err != nil {
		return nil, false
	}
	return transaction, true
}
