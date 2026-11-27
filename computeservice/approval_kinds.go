// §16.6's broker gate for the approval kinds the broker admits only with, 19 and 21 (DESIGN-COMPUTE §14.3, §16.3), as
// the one ComputeApprovalGate the engine reads (auth.go): each kind's area registers its check from its own file, BAL's
// kind 21 in ledger_budget_raise.go and ENC's kind 19 with its enclave routes (M14), and a kind with no check answers
// 503 unavailable, so an approval route whose area has not landed refuses rather than admits.
//
// A kind's whole gate (its stored result's lookup, the spend check at server time and the use's claim) runs in its
// route's handler, in the effect's own transaction, as DESIGN §16.6's gate steps 1 to 4 do, since a use and its effect
// commit together; what a kind registers here is only what refuses before that transaction, a request no handler of
// its may take.

package computeservice

import (
	"errors"
	"fmt"
)

// One kind's check before its handler: nil admits to the handler, a refusal answers.
type computeApprovalKindCheck func(request *ComputeRequest) *ComputeRefusal

// The checks the areas registered, by kind, written only during the package's init.
var computeApprovalKindChecks = map[ComputeApprovalKind]computeApprovalKindCheck{}

// Registers kind's check from its area's file at init. A kind registered twice or a nil check panics.
func registerComputeApprovalKind(kind ComputeApprovalKind, check computeApprovalKindCheck) {
	if check == nil {
		panic(errors.New("a nil compute approval kind check"))
	}
	if _, registered := computeApprovalKindChecks[kind]; registered {
		panic(fmt.Errorf("compute approval kind %d registered twice", kind))
	}
	computeApprovalKindChecks[kind] = check
}

// The gate over the registered kinds.
type computeApprovalKinds struct{}

// See ComputeApprovalGate.
func (self *computeApprovalKinds) Admit(request *ComputeRequest, kind ComputeApprovalKind) *ComputeRefusal {
	check, ok := computeApprovalKindChecks[kind]
	if !ok {
		return NewComputeRefusal(ComputeRefusalUnavailable)
	}
	return check(request)
}

func init() {
	registerComputeApprovalGate(&computeApprovalKinds{})
}
