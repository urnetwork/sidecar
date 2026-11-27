//go:build !ios_extension && !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The daemon's context-history methods (DESIGN-COMPUTE §24.6, §24.7; CTXH-M11-05), by their wire: what `ur harness
// continue` and `ur harness export` call, and a desktop app in remote mode with them (SidecarHarness.Continue and
// ContinuePlan). ur's cli serves them over each network's Sidecar (cli/cmd_harness_history.go), as it serves
// `ur harness show`'s.
//
//	harness.continue_plan  {run, at?, act?, model?, name?}: what continuing or forking the run would take (T10): the
//	                       node, the model, what carries over and whether the run is live; nothing is started
//	harness.continue       the same params: the person's act alone, confirmed and with no harness process among the
//	                       caller's ancestors (§7.10's origin rule), since it starts a run that reads the old one whole
//	                       and spends; answers the new agent, its name and its run
//	harness.export         {run}: the run as Pi's v3 JSONL (session_export_pi.go), confirmed, the runs of a harness among
//	                       the caller's ancestors tainted before anything is read, the export's disclosure entry landed
//	                       before the lines are answered, its addresses and numbers hashed under record.redact.pii
//
// Nothing here carries a secret, so every reply passes the reply walk.

package sidecar

// The methods' names.
const (
	HarnessDaemonMethodContinuePlan = "harness.continue_plan"
	HarnessDaemonMethodContinue     = "harness.continue"
	HarnessDaemonMethodExport       = "harness.export"
)

// harness.continue_plan's and harness.continue's params: the network, and the spec (SessionContinueSpec).
type HarnessContinueParams struct {
	Network string `json:"network,omitempty"`
	SessionContinueSpec
}

// harness.export's params.
type HarnessExportParams struct {
	Network string `json:"network,omitempty"`
	Run     Id     `json:"run"`
}

// harness.export's reply: the lines, the session header first, and what the export left out or hashed.
type HarnessExportReply struct {
	Lines           []string `json:"lines"`
	NodeCount       int      `json:"node_count"`
	UnheldCount     int      `json:"unheld_count,omitempty"`
	PrunedPartCount int      `json:"pruned_part_count,omitempty"`
	PiiCount        int      `json:"pii_count,omitempty"`
	ReceiptsOnly    bool     `json:"receipts_only,omitempty"`
}

// The reply of an export.
func HarnessExportReplyOf(exported *SessionPiExported) *HarnessExportReply {
	reply := &HarnessExportReply{Lines: []string{}, NodeCount: exported.NodeCount, UnheldCount: exported.UnheldCount,
		PrunedPartCount: exported.PrunedPartCount, PiiCount: exported.PiiCount, ReceiptsOnly: exported.ReceiptsOnly}
	for _, line := range exported.Lines {
		reply.Lines = append(reply.Lines, string(line))
	}
	return reply
}

// Opens the view log of a continued agent, as harness.agent opens a new one's, so `ur harness --agent` and
// harness.events watch it.
func (self *Harness) OpenView(agentId Id) {
	self.viewLog().open(agentId, self.stamper.seqOf(agentId))
}
