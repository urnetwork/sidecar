// GET /sidecar/limits (§20.7, §20.14): the network's effective limits, for local pre-checks, on every leg,
// since the page Worker decodes it too. It names no connect type: QuotaLimits and QuotaRefusal are
// api_quota.go's. A refusal by one of these limits anywhere in api is a *SidecarApiError whose QuotaRefusal
// is set (api_client.go).

package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
)

// The route as errors name it.
const sidecarLimitsRoute = "GET /sidecar/limits"

// GET /sidecar/limits: the token's network's tier and every limit after its network_sidecar_limit rows,
// sidecar_abuse:'s directory_* keys among them (D-QUOTA-11). An answer with a tier this build does not know,
// or no limits, is not the route's. A key the answer lacks reads 0, not included, so a limit this build does
// not know fails closed. Never the packet path.
func (self *SidecarApi) Limits(ctx context.Context) (*QuotaLimits, error) {
	answer := &QuotaLimits{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     sidecarLimitsRoute,
		operation: "limits",
		method:    "GET",
		url:       self.settings.ApiUrl + "/sidecar/limits",
		bearer:    true,
	}, nil, answer)
	if err != nil {
		return nil, err
	}
	switch answer.Tier {
	case "free", "pro", "team":
	default:
		return nil, fmt.Errorf("sidecar api %s: %w", sidecarLimitsRoute, ErrSidecarApiReply)
	}
	if answer.Limits == nil {
		return nil, fmt.Errorf("sidecar api %s: %w", sidecarLimitsRoute, ErrSidecarApiReply)
	}
	for limitKey, limit := range answer.Limits {
		if !isSidecarApiCode(limitKey) || limit < -1 {
			return nil, fmt.Errorf("sidecar api %s: %w", sidecarLimitsRoute, ErrSidecarApiReply)
		}
	}
	return answer, nil
}

// The QuotaRefusal a refusal's body holds, or nil: a body whose limit_key is no well formed key, or whose
// fields do not each hold their type, holds none. The shapes it reads are the plain body and x402's terms with
// the refusal's fields beside them (server/controller/x402_quota_controller.go).
func decodeSidecarApiQuotaRefusal(body []byte) *QuotaRefusal {
	fields := struct {
		LimitKey     *string `json:"limit_key"`
		Limit        *int64  `json:"limit"`
		Used         *int64  `json:"used"`
		RetryAfterMs *uint32 `json:"retry_after_ms"`
		Upgrade      *bool   `json:"upgrade"`
	}{}
	if json.Unmarshal(body, &fields) != nil {
		return nil
	}
	if fields.LimitKey == nil || !isSidecarApiCode(*fields.LimitKey) || fields.Limit == nil || fields.Used == nil {
		return nil
	}
	refusal := &QuotaRefusal{
		LimitKey: *fields.LimitKey,
		Limit:    *fields.Limit,
		Used:     *fields.Used,
	}
	if fields.RetryAfterMs != nil {
		refusal.RetryAfterMs = *fields.RetryAfterMs
	}
	if fields.Upgrade != nil {
		refusal.Upgrade = *fields.Upgrade
	}
	return refusal
}
