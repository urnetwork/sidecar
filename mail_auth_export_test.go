//go:build !sidecar_http

// A bridge for MAIL-M7-07's external tests: how many queries wait for a slot, so a test knows every one has asked
// before it frees a slot.

package sidecar

// The queries budget holds waiting for a slot.
func MailAuthBudgetWaitingForTest(budget *MailAuthBudget) int {
	budget.stateLock.Lock()
	defer budget.stateLock.Unlock()
	return len(budget.waiters)
}
