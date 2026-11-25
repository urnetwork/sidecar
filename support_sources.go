//go:build !ios_extension && !sidecar_http

// What the support client reads from components other areas build (DESIGN-COMPUTE §28.6, §28.10, §28.13), each a seam
// until its owner lands, and each failing closed while none is set:
//
//	SupportPolicySource      the newest verified policy's support line (§5.4): the feedback service's host and the
//	                         subprocessors support:urnetwork names. ATTEST's ComputePolicy keeps the line's raw JSON once
//	                         it takes it, as it keeps search's and services', which ParseSupportPolicyLine reads
//	                         strictly; with none, nothing is posted, and every message waits in the outbox
//	SupportDisclosureSource  support:urnetwork's current version and the version this network's person acknowledged
//	                         (CTRUST's compute.disclosures, §2.8); with none, every message answers disclosure_required
//	SupportTokenSource       FB section 5's token: at most an hour, bound to the sidecar's key (DESIGN §7.8), held by
//	                         the client and never in an agent's environment (R-CTX-9); with none, nothing is posted
//	SupportNetworkSource     the compute block's support (§16.4): egress on, persons, auto_only or off, agents and
//	                         logs; with none, the block's defaults, which only an admin's setting narrows
//	SupportSecretSource      credentials the scan refuses beyond Sidecar.SecretMatcher's (support_form.go)
//
// Each is set on a SupportClient with SetSources, by its host or a test. Safe for concurrent use as their implementations
// are.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// One subprocessor that reads support's entries for URnetwork (§28.10): today the triage model's provider.
type SupportSubprocessor struct {
	Name      string `json:"name"`
	Purpose   string `json:"purpose"`
	Retention string `json:"retention"`
}

// The policy's support line (§5.4): the one host a device posts a message, file or bundle to, over TLS, and every
// subprocessor support:urnetwork names.
type SupportPolicyLine struct {
	Host          string                 `json:"host"`
	Subprocessors []*SupportSubprocessor `json:"subprocessors"`
}

// A host as the line names it: lowercase DNS labels, as attest_policy.go's hosts are.
var supportPolicyHostPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]([a-z0-9-]*[a-z0-9])?$`)

// The support line's raw JSON read strictly: one object, every member known, a host of DNS labels and each
// subprocessor named with its purpose and retention.
func ParseSupportPolicyLine(raw []byte) (*SupportPolicyLine, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	line := &SupportPolicyLine{}
	if err := decoder.Decode(line); err != nil {
		return nil, fmt.Errorf("support policy line: %w", err)
	}
	if decoder.More() {
		return nil, errors.New("support policy line: more than one value")
	}
	if !supportPolicyHostPattern.MatchString(line.Host) {
		return nil, errors.New("support policy line: no host of DNS labels")
	}
	for _, subprocessor := range line.Subprocessors {
		if subprocessor == nil || subprocessor.Name == "" || subprocessor.Purpose == "" || subprocessor.Retention == "" {
			return nil, errors.New("support policy line: a subprocessor without its name, purpose or retention")
		}
	}
	return line, nil
}

// Where the support line comes from: the newest policy the device verified, its release's copy at least, whatever that
// policy's not_after, since support must work when nothing else does (§28.10).
type SupportPolicySource interface {
	SupportLine() (*SupportPolicyLine, error)
}

// support:urnetwork's id (§2.8, §28.13).
const SupportDisclosureId = "support:urnetwork"

// support:urnetwork on this network: its current version in the newest verified policy, and the version the person
// acknowledged, 0 for none. Its grace is 0, so only the current version lets a message go (§28.13).
type SupportDisclosureState struct {
	Current      uint32
	Acknowledged uint32
}

// Where the disclosure's state comes from: CTRUST's acknowledgments.
type SupportDisclosureSource interface {
	SupportDisclosure() (*SupportDisclosureState, error)
}

// FB section 5's token for this sidecar, minted as it nears its end; never handed to an agent.
type SupportTokenSource interface {
	SupportToken(ctx context.Context) (string, error)
}

// The compute block's egress values (§16.4, FB section 5's feedback.egress).
const (
	SupportEgressOn       = "on"
	SupportEgressPersons  = "persons"
	SupportEgressAutoOnly = "auto_only"
	SupportEgressOff      = "off"
)

// The network's support settings: egress, whether agents may write, whether they may attach logs, and whether support
// paused the network's submissions (FB section 11).
type SupportNetworkSettings struct {
	Egress string
	Agents bool
	Logs   bool
	Paused bool
}

// The compute block's defaults: egress on, agents and logs on, nothing paused.
func defaultSupportNetworkSettings() *SupportNetworkSettings {
	return &SupportNetworkSettings{Egress: SupportEgressOn, Agents: true, Logs: true}
}

// Where the network's support settings come from: the compute block, its admins' to narrow.
type SupportNetworkSource interface {
	SupportNetwork() (*SupportNetworkSettings, error)
}

// What a SupportClient reads beyond its Sidecar. A nil field is a source not built yet, which fails closed as the file
// header says.
type SupportSources struct {
	Policy      SupportPolicySource
	Disclosures SupportDisclosureSource
	Tokens      SupportTokenSource
	Network     SupportNetworkSource
	Secrets     SupportSecretSource
}
