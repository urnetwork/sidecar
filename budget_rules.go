//go:build !ios_extension && !sidecar_http

// The budgets that cap a call or a search (DESIGN-COMPUTE §16.4, §16.5; D-CACL-6, IC-6, IC-11; CACL-M12-05), as the
// device reads them before it asks; the broker enforces every one again from the signed projection (IC-6), so the
// device's check is advisory and never skips it. A local model's call touches no budget (CO-9).
//
//	defaults   BudgetSettings': per agent id, the agent's; per tagged subject, the tagged sidecar's; per untagged
//	           device, for calls naming no agent, the device's; per untagged device across all its agents and calls,
//	           its ceiling, counted by the calls' sidecar, since an agent id is the device's own word (D-CACL-6)
//	policy     the compute block's budgets whose subject the caller holds (compute_rows' budgets, by atom), per agent,
//	           per subject, per member or per network, by UTC day and month; one per agent or per subject replaces the
//	           defaults counted per the same subject in its period, a raise or a narrowing: per agent the agent's, per
//	           subject the tagged sidecar's, or an untagged device's own and its ceiling; per member and per network
//	           add budgets the broker alone counts, across devices
//	run        a Harness's or a gateway grant's budget for its run, which its holder passes
//	raises     an approved kind-21 raise lifts the one budget it names, for its period, until its expiry (§7.4, §8.6)
//
// ClampGrant holds a gateway grant's or a Harness agent's budget to the default for its agent unless an approved
// kind-21 raise lifts it (§8.6, IC-11).
//
// Pure functions of their inputs: integers only, never a float for money. Device legs only.

package sidecar

import (
	"encoding/hex"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A budget's period (§16.4), BudgetFields.period's values.
type ComputeBudgetPeriod uint32

const (
	// A UTC day.
	ComputeBudgetPeriodDay ComputeBudgetPeriod = 1
	// A UTC month.
	ComputeBudgetPeriodMonth ComputeBudgetPeriod = 2
	// One run's, a Harness's or a gateway grant's: the device's alone, never the broker's.
	ComputeBudgetPeriodRun ComputeBudgetPeriod = 3
)

// The period's word: day, month or run.
func (self ComputeBudgetPeriod) String() string {
	switch self {
	case ComputeBudgetPeriodDay:
		return "day"
	case ComputeBudgetPeriodMonth:
		return "month"
	case ComputeBudgetPeriodRun:
		return "run"
	}
	return "unknown"
}

// The budgets' names, the broker's (model's ComputeBudget* names) for the defaults.
const (
	// An agent id's, the default's or a policy's per agent.
	ComputeBudgetNameAgent = "agent"
	// A tagged subject's own, the default's or a policy's per subject.
	ComputeBudgetNameTagged = "tagged"
	// An untagged device's, for its calls naming no agent.
	ComputeBudgetNameDevice = "device"
	// An untagged device's ceiling across all its agents and calls.
	ComputeBudgetNameCeiling = "ceiling"
	// An untagged device's own across its calls, a policy's per subject, which stands in for its device budget and
	// its ceiling in that period.
	ComputeBudgetNameSubject = "subject"
	// A member's across their devices, a policy's per member: the broker's alone.
	ComputeBudgetNameMember = "member"
	// The network's, a policy's per network: the broker's alone.
	ComputeBudgetNameNetwork = "network"
	// A Harness's or a gateway grant's run.
	ComputeBudgetNameRun = "run"
)

// One budget that caps a call.
type ComputeBudget struct {
	Name string
	// What it counts under: an agent's, a sidecar's, a member's or a run's id, the zero id for the network's.
	SubjectId Id
	Period    ComputeBudgetPeriod
	// What its subjects may be charged in the period, in nano-USD.
	CapNanoUsd uint64
	// Whether this device's ledger counts it: false for a member's across devices and the network's, which only the
	// broker sees whole.
	DeviceCounts bool
	// Where a kind-21 raise lifted it, the raise's expiry; zero otherwise.
	RaisedUntil time.Time
}

// The budget's key in a ledger: its name, its subject and its period.
func (self *ComputeBudget) Key() string {
	return self.Name + ":" + hex.EncodeToString(self.SubjectId.Bytes()) + ":" + self.Period.String()
}

// A run's budget, which its Harness or gateway grant holds.
type ComputeBudgetRun struct {
	Id         Id
	CapNanoUsd uint64
}

// An approved kind-21 raise in force: the budget it lifts, by name, subject and period, to CapNanoUsd until NotAfter.
type ComputeBudgetRaise struct {
	Name       string
	SubjectId  Id
	Period     ComputeBudgetPeriod
	CapNanoUsd uint64
	NotAfter   time.Time
}

// Who a call or a search is for, as the device knows it.
type ComputeBudgetCall struct {
	// The calls' sidecar: this device, or a tagged sidecar.
	SidecarId Id
	// An untagged device's member; zero for a tagged sidecar.
	MemberId Id
	Tagged   bool
	// The agent the call names, nil for none.
	AgentId *Id
	// A local model's call: no budget (CO-9).
	Local bool
	// The compute block's budget rows whose subject the caller holds (ComputePolicyBudgetsBinding).
	Policy []*protocol.AclComputeBudgetRow
	// The run's budget, nil for none.
	Run *ComputeBudgetRun
	// Approved kind-21 raises, in force or not: those past their expiry lift nothing.
	Raises []*ComputeBudgetRaise
}

// Every budget that caps call at now, as the file header says; none for a local model's.
func ComputeBudgetsFor(call *ComputeBudgetCall, settings *BudgetSettings, now time.Time) []*ComputeBudget {
	if call == nil || call.Local {
		return []*ComputeBudget{}
	}
	if settings == nil {
		settings = DefaultBudgetSettings()
	}
	// which per and period the policy replaces the defaults of
	replaced := map[[2]uint32]bool{}
	for _, row := range call.Policy {
		for _, period := range computeBudgetRowPeriods(row) {
			replaced[[2]uint32{row.GetPer(), uint32(period)}] = true
		}
	}
	budgets := []*ComputeBudget{}
	add := func(name string, subjectId Id, period ComputeBudgetPeriod, capNanoUsd uint64, deviceCounts bool) {
		budgets = append(budgets, &ComputeBudget{Name: name, SubjectId: subjectId, Period: period, CapNanoUsd: capNanoUsd, DeviceCounts: deviceCounts})
	}
	defaults := func(per AclComputeBudgetPer, name string, subjectId Id, day uint64, month uint64) {
		for _, item := range []struct {
			period     ComputeBudgetPeriod
			capNanoUsd uint64
		}{{period: ComputeBudgetPeriodDay, capNanoUsd: day}, {period: ComputeBudgetPeriodMonth, capNanoUsd: month}} {
			if item.capNanoUsd != 0 && !replaced[[2]uint32{uint32(per), uint32(item.period)}] {
				add(name, subjectId, item.period, item.capNanoUsd, true)
			}
		}
	}
	if call.AgentId != nil {
		defaults(AclComputeBudgetPerAgent, ComputeBudgetNameAgent, *call.AgentId, settings.AgentDayNanoUsd, settings.AgentMonthNanoUsd)
	}
	if call.Tagged {
		defaults(AclComputeBudgetPerSubject, ComputeBudgetNameTagged, call.SidecarId, settings.AgentDayNanoUsd, settings.AgentMonthNanoUsd)
	} else {
		if call.AgentId == nil {
			defaults(AclComputeBudgetPerSubject, ComputeBudgetNameDevice, call.SidecarId, settings.DeviceDayNanoUsd, settings.DeviceMonthNanoUsd)
		}
		defaults(AclComputeBudgetPerSubject, ComputeBudgetNameCeiling, call.SidecarId, settings.DeviceCeilingDayNanoUsd, 0)
	}
	for _, row := range call.Policy {
		for _, period := range computeBudgetRowPeriods(row) {
			capNanoUsd := row.GetDayNanoUsd()
			if period == ComputeBudgetPeriodMonth {
				capNanoUsd = row.GetMonthNanoUsd()
			}
			switch AclComputeBudgetPer(row.GetPer()) {
			case AclComputeBudgetPerAgent:
				if call.AgentId != nil {
					add(ComputeBudgetNameAgent, *call.AgentId, period, capNanoUsd, true)
				}
			case AclComputeBudgetPerSubject:
				if call.Tagged {
					add(ComputeBudgetNameTagged, call.SidecarId, period, capNanoUsd, true)
				} else {
					add(ComputeBudgetNameSubject, call.SidecarId, period, capNanoUsd, true)
				}
			case AclComputeBudgetPerMember:
				if call.MemberId != (Id{}) {
					add(ComputeBudgetNameMember, call.MemberId, period, capNanoUsd, false)
				}
			case AclComputeBudgetPerNetwork:
				add(ComputeBudgetNameNetwork, Id{}, period, capNanoUsd, false)
			}
		}
	}
	if call.Run != nil {
		add(ComputeBudgetNameRun, call.Run.Id, ComputeBudgetPeriodRun, call.Run.CapNanoUsd, true)
	}
	for _, budget := range budgets {
		for _, raise := range call.Raises {
			if raise.Name == budget.Name && raise.SubjectId == budget.SubjectId && raise.Period == budget.Period &&
				now.Before(raise.NotAfter) && budget.CapNanoUsd < raise.CapNanoUsd {
				budget.CapNanoUsd, budget.RaisedUntil = raise.CapNanoUsd, raise.NotAfter
			}
		}
	}
	return budgets
}

// The periods a policy budget row caps: day, month or both.
func computeBudgetRowPeriods(row *protocol.AclComputeBudgetRow) []ComputeBudgetPeriod {
	periods := []ComputeBudgetPeriod{}
	if row.GetDayNanoUsd() != 0 {
		periods = append(periods, ComputeBudgetPeriodDay)
	}
	if row.GetMonthNanoUsd() != 0 {
		periods = append(periods, ComputeBudgetPeriodMonth)
	}
	return periods
}

// The compute block's budget rows that bind subject at now: each whose subject atom it holds (AclState's
// SubjectHoldsAtom), none where the rows hold no compute block.
func ComputePolicyBudgetsBinding(state *AclState, subject AclSubject, now time.Time) []*protocol.AclComputeBudgetRow {
	binding := []*protocol.AclComputeBudgetRow{}
	if state == nil {
		return binding
	}
	for _, row := range state.rows.GetComputeRows().GetBudgets() {
		atomId, err := IdFromBytes(row.GetSubject())
		if err == nil && state.SubjectHoldsAtom(subject, atomId, now) {
			binding = append(binding, row)
		}
	}
	return binding
}
