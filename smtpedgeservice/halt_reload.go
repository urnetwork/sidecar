// The edge's reload of halts (§14.8: edges reload every 60 s; D-SMTP-9, §14.9; SMTP-M9-16): each
// HaltReloadInterval the engine reads ActiveHalts and makes its quota's halts exactly that set, in memory and in
// {smq_}, so a halt the intake's ladder set reaches this edge within the interval, a halt lifted on appeal leaves
// it within the interval, and a Redis that lost its flags has them again within the interval. A reload that
// cannot read the store changes nothing: the memory keeps every halt it held, so losing Postgres for a while
// lifts nothing (§14.9).
//
// The engine's run loop calls reload; one reload runs at a time. Nothing here logs a network or a label (I-13).

package smtpedgeservice

import (
	"context"
)

// The engine's reload. Safe for concurrent use only as its run loop uses it, one call at a time.
type smtpHaltReloader struct {
	store SmtpEdgeStore
	// nil when the host gave no Redis: the store is still probed
	quota *SmtpQuota
}

// Reads the active halts and holds exactly them. An error is the store's: nothing changed.
func (self *smtpHaltReloader) reload(ctx context.Context) error {
	halts, err := self.store.ActiveHalts(ctx)
	if err != nil {
		return err
	}
	if self.quota != nil {
		// a write that fails leaves the halt in memory, and the next reload writes it again
		self.quota.ReplaceHalts(ctx, halts)
	}
	return nil
}
