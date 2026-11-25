//go:build !ios_extension && !sidecar_http

// ur support report <code> (DESIGN-COMPUTE §28.4): FB section 10.3's enumerated report, unchanged. The auto tier's
// closed schema, which the sidecar fills and in which a caller chooses only the code, so no text of anyone's rides it:
//
//	report  registry, component, code and severity, from the support log's registry; occurrences, FB's buckets
//	        (1, 2-9, 10-99, 100+), and first_seen_day, from this process's ring, which must hold the code
//	client  ur's version, format-checked, the OS and arch; the harness and its version where one runs here
//	sender  the person, or the agent's registered name and where it runs (§28.10's agent_ref)
//
// posted like any message from the outbox under its client_ref, tier auto, with its support:urnetwork version. The
// person's report, at a terminal no run binds and confirmed on /dev/tty, goes on the person's limits. An agent's
// needs FB section 5's feedback.auto grant, a person's per network or per agent with an expiry, which nothing builds
// yet (FB's G3): until it is built an agent's report is refused grant_required, failing closed, and the auto tier's
// own limits (FB section 11: 5 new fingerprints a day per agent, 20 per network) wait with it, as does its sender,
// which FB section 3 as amended keeps opaque on the auto tier, keyed under a network-held secret, never the agent's
// name that its free-text messages carry. Safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"time"
)

// What Report takes.
type SupportReportArgs struct {
	// The person's, or an agent's: a harness's process, an MCP session or the Harness.
	Surface SupportSurface
	Sender  *SupportSender
	// The code as the registry names it, component.code.
	Code string
	// What the report's client fields say of the host; its version is format-checked.
	Host *SupportLogBundleHost
}

// FB section 10.3's report fields.
type SupportReportFields struct {
	Registry     int    `json:"registry"`
	Component    string `json:"component"`
	Code         string `json:"code"`
	Severity     string `json:"severity"`
	Occurrences  string `json:"occurrences"`
	FirstSeenDay string `json:"first_seen_day"`
}

// FB section 10.3's client fields, each enumerated or format-checked.
type SupportReportClient struct {
	Version        string `json:"version"`
	Os             string `json:"os"`
	Arch           string `json:"arch"`
	Harness        string `json:"harness,omitempty"`
	HarnessVersion string `json:"harness_version,omitempty"`
}

// An enumerated report as it leaves the device: FB section 10.3's schema, with the client_ref, the sender and the
// support:urnetwork version every message carries (§28.10).
type SupportReportBody struct {
	V          int                  `json:"v"`
	Product    string               `json:"product"`
	ClientRef  string               `json:"client_ref"`
	Tier       SupportTier          `json:"tier"`
	Report     *SupportReportFields `json:"report"`
	Client     *SupportReportClient `json:"client"`
	Sender     *SupportBodySender   `json:"sender"`
	Disclosure uint32               `json:"disclosure"`
}

// The code the registry names name, false for none.
func supportLogCodeNamed(name string) (SupportLogCode, bool) {
	for _, code := range SupportLogCodes() {
		if code.String() == name {
			return code, true
		}
	}
	return 0, false
}

// One enumerated report: the release's switch, the network's support, the grant, the disclosure, the code and its
// occurrences in the ring, the limits, then the outbox; it answers at once, queued.
func (self *SupportClient) Report(ctx context.Context, args *SupportReportArgs) (*SupportSendResult, error) {
	if args == nil {
		return nil, errors.New("support: no report")
	}
	person := args.Surface == SupportSurfacePerson
	if !person && (args.Sender == nil || args.Sender.AgentName == "") {
		return nil, errors.New("support: an agent's report names its agent")
	}
	if !self.settings.ServiceEnabled {
		return nil, ErrSupportUnavailable
	}
	sendArgs := &SupportSendArgs{Surface: args.Surface, Sender: args.Sender}
	sources := self.currentSources()

	// network: on, persons and auto_only each carry enumerated reports
	network := defaultSupportNetworkSettings()
	if sources.Network != nil {
		read, err := sources.Network.SupportNetwork()
		if err != nil {
			return nil, fmt.Errorf("support: the network's settings: %w", err)
		}
		network = read
	}
	switch {
	case network.Paused:
		return nil, self.refuse(sendArgs, supportRefused(SupportRefusalPaused))
	case network.Egress == SupportEgressOff:
		return nil, self.refuse(sendArgs, supportRefused(SupportRefusalSupportOff))
	}

	// the grant: an agent's report needs feedback.auto, which nothing builds yet
	if !person {
		return nil, self.refuse(sendArgs, supportRefused(SupportRefusalGrantRequired))
	}

	// disclosure, grace 0
	disclosureVersion := uint32(0)
	if sources.Disclosures != nil {
		if disclosure, err := sources.Disclosures.SupportDisclosure(); err == nil && disclosure != nil &&
			0 < disclosure.Current && disclosure.Acknowledged == disclosure.Current {
			disclosureVersion = disclosure.Current
		}
	}
	if disclosureVersion == 0 {
		refusal := supportRefused(SupportRefusalDisclosureRequired)
		refusal.DisclosureId = SupportDisclosureId
		return nil, self.refuse(sendArgs, refusal)
	}

	// the code, which the ring must hold
	code, ok := supportLogCodeNamed(args.Code)
	if !ok {
		return nil, self.refuse(sendArgs, supportRefused(SupportRefusalNotFound))
	}
	count, first := self.log.Occurrences(code)
	if count == 0 {
		return nil, self.refuse(sendArgs, supportRefused(SupportRefusalNotFound))
	}
	component, name, severity, _ := supportLogRegistry.code(code)
	host := args.Host
	if host == nil {
		host = &SupportLogBundleHost{}
	}
	version := ""
	if host.Version != "" {
		version = "invalid"
		if supportLogVersionValid(host.Version, self.settings) {
			version = host.Version
		}
	}

	// limits, then the outbox
	self.sendLock.Lock()
	defer self.sendLock.Unlock()
	state, err := self.loadState()
	if err != nil {
		return nil, err
	}
	if refusal := self.limitRefusal(state, "", false); refusal != nil {
		return nil, self.refuse(sendArgs, refusal)
	}
	clientRef, err := newSupportClientRef()
	if err != nil {
		return nil, err
	}
	countBuckets := supportLogRegistry.countBuckets
	body := &SupportReportBody{
		V:         supportBodyVersion,
		Product:   SupportProductUrnetwork,
		ClientRef: supportClientRefText(clientRef),
		Tier:      SupportTierAuto,
		Report: &SupportReportFields{
			Registry:     supportLogRegistry.version,
			Component:    component,
			Code:         name,
			Severity:     supportLogSeverityNames[severity],
			Occurrences:  supportLogBucketLabel(countBuckets, supportLogBucketIndex(countBuckets, uint64(count))),
			FirstSeenDay: time.Unix(first, 0).UTC().Format(time.DateOnly),
		},
		Client:     &SupportReportClient{Version: version, Os: runtime.GOOS, Arch: runtime.GOARCH},
		Sender:     &SupportBodySender{Person: true},
		Disclosure: disclosureVersion,
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("support report: %w", err)
	}
	item := &supportOutboxItem{
		ClientRef:     body.ClientRef,
		Body:          encoded,
		Tier:          SupportTierAuto,
		Approved:      SupportApprovedNone,
		CreatedMillis: self.clock.Now().UnixMilli(),
		State:         supportOutboxPending,
		Disclosure:    disclosureVersion,
	}
	if err := self.enqueue(item, [][]byte{nil}, nil); err != nil {
		return nil, err
	}
	self.logQueued(sendArgs, item, SupportLogDeciderNone)
	return &SupportSendResult{Outcome: SupportOutcomeQueued, ClientRef: body.ClientRef}, nil
}

// What a person reads of an enumerated report in the conversation and the vault, from its body: its code, severity,
// occurrences and first day; "" for a body that is no report.
func supportReportSummary(encoded []byte) string {
	body := &SupportReportBody{}
	if err := json.Unmarshal(encoded, body); err != nil || body.Report == nil {
		return ""
	}
	report := body.Report
	return fmt.Sprintf("enumerated report %s.%s (%s): %s occurrences since %s", report.Component, report.Code, report.Severity,
		report.Occurrences, report.FirstSeenDay)
}
