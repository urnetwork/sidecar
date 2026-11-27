// The compute block's compile (DESIGN-COMPUTE §16.4, §16.6; CACL-M12-03): what the broker enforces from the signed
// id-only projection, AclRows.compute_rows (compute-6; api-7's words since metadata_list.yml v68), and what stays on
// the device, AclLocalPolicy.Compute.
//
//	rows       the floors, as ComputeAssurance values, 0 where the block leaves one out, read as the default; the
//	           providers and enclave shapes sorted, empty where left out, read as every one; search's switch, on unless
//	           the block turns it off, and its day cap, 0 where left out, the broker's own; and the budgets by subject
//	           atom, each selector resolved as a rule's src is (self.atom), one row per subject with its per and its
//	           amounts in nano-USD, sorted and without repeats
//	device     modes, fetch, calendar, connect, support, approvals, disclosures and history: the parsed block, which
//	           ComputePolicyView reads with §16.5's defaults
//	source     the document's compute key, or, for a network with no document, the head's block-alone record
//	           (ConfigHeadComputePath), which sets no reach: has_document stays false and the implicit document compiles
//	           as before. A head holding both is refused, so a block never has two sources.
//	feature    a head whose block, or block-alone record, stands while its ServiceSettings does not turn compute_policy
//	           on does not compile, alike in every reader: one built before the block refuses its key as unknown, one
//	           built after refuses it here, so no reader compiles rows another withholds (§16.6's before row). Under
//	           the feature the block changes rows; with no block, compute_rows stays unset and the broker applies §16.5's
//	           defaults.
//
// Budgets §16.5 gives by default compile into no row: the broker applies BudgetSettings' defaults whatever the
// document says (§16.4), though §16.6's table lists budget rules among the implicit document's (CACL-M12-04's report).
//
// On every leg, as acl_compile.go is: a pure function of the head, no clock, no map iteration.

package sidecar

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// The block this compile reads: the document's, or a network with no document's record; nil for none.
func (self *aclCompiler) computeBlock() *AclComputeBlock {
	if self.hasDocument {
		return self.policy.Compute
	}
	return self.computeRecord
}

// Reads the head's block-alone record into the compiler: refused beside a document, and where it does not parse.
func (self *aclCompiler) readComputeRecord() error {
	if self.input.ComputeRecord == nil {
		return nil
	}
	if self.hasDocument {
		return aclCompileRefusal("a block-alone compute record beside a document, which holds its own block")
	}
	block, err := ParseAclComputeRecord(self.input.ComputeRecord)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrAclCompile, ConfigHeadComputePath, err)
	}
	self.computeRecord = block
	return nil
}

// Compiles the block into rows and the local policy, as the file header says.
func (self *aclCompiler) compileComputeBlock(rows *protocol.AclRows) error {
	block := self.computeBlock()
	if block == nil {
		return nil
	}
	if self.input.AuthFeatures&AuthFeatureComputePolicy == 0 {
		return aclCompileRefusal("a compute block while the network's compute_policy feature is off")
	}
	computeRows := &protocol.AclComputeRows{
		AssuranceFloor:        block.AssuranceFloor,
		EnclaveAssuranceFloor: block.EnclaveAssuranceFloor,
		Providers:             aclSortedStrings(block.Providers),
		EnclaveShapes:         aclSortedStrings(block.EnclaveShapes),
		SearchEnabled:         block.Search == nil || block.Search.Enabled == nil || *block.Search.Enabled,
	}
	if block.Search != nil {
		computeRows.SearchDayMax = block.Search.DayMax
	}
	for i, budget := range block.Budgets {
		for _, subject := range budget.Subjects {
			atomId, err := self.atom(subject)
			if err != nil {
				return fmt.Errorf("compute.budgets[%d]: %w", i, err)
			}
			computeRows.Budgets = append(computeRows.Budgets, &protocol.AclComputeBudgetRow{
				Subject:      atomId.Bytes(),
				Per:          uint32(budget.Per),
				DayNanoUsd:   budget.DayNanoUsd,
				MonthNanoUsd: budget.MonthNanoUsd,
			})
		}
	}
	computeRows.Budgets = aclSortComputeBudgets(computeRows.Budgets)
	rows.ComputeRows = computeRows
	self.local.Compute = block
	return nil
}

// A list sorted and without repeats, nil for none.
func aclSortedStrings(list []string) []string {
	if len(list) == 0 {
		return nil
	}
	sorted := slices.Clone(list)
	slices.Sort(sorted)
	return slices.Compact(sorted)
}

// Budget rows in (subject, per, day, month) order, without repeats, so equal blocks give equal bytes.
func aclSortComputeBudgets(budgets []*protocol.AclComputeBudgetRow) []*protocol.AclComputeBudgetRow {
	compare := func(a *protocol.AclComputeBudgetRow, b *protocol.AclComputeBudgetRow) int {
		if c := bytes.Compare(a.GetSubject(), b.GetSubject()); c != 0 {
			return c
		}
		for _, pair := range [][2]uint64{
			{uint64(a.GetPer()), uint64(b.GetPer())}, {a.GetDayNanoUsd(), b.GetDayNanoUsd()},
			{a.GetMonthNanoUsd(), b.GetMonthNanoUsd()},
		} {
			switch {
			case pair[0] < pair[1]:
				return -1
			case pair[1] < pair[0]:
				return 1
			}
		}
		return 0
	}
	sorted := slices.Clone(budgets)
	slices.SortFunc(sorted, compare)
	return slices.CompactFunc(sorted, func(a *protocol.AclComputeBudgetRow, b *protocol.AclComputeBudgetRow) bool {
		return compare(a, b) == 0
	})
}
