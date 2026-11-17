// RECORD.md section 6.4's caps as settings (QD-702): format values, which a writer holds a body to before it seals
// and every reader holds a stored body to after it opens, so no device sets one on its own; this object holds them
// and its defaults stay here. §16.7's capture settings may cut lower, never higher. The section's older caps are still
// record_body.go's constants, which join this object as QD-706's sweep reaches them; QD-900's prompts are the first
// cap written here. Package-level functions are safe for concurrent use.

package sidecar

// Section 6.4's caps that live in settings.
type RecordBodySettings struct {
	// ContextBody.prompts in one entry, the prompts' bytes together: 2,048 B, §16.10's "first 2 KiB of user prompts",
	// all a run card reads of them (QD-900). Each prompt is non-empty.
	ContextPromptByteCount int
}

// RECORD.md's values, the only source of their defaults. A fresh value each call.
func DefaultRecordBodySettings() *RecordBodySettings {
	return &RecordBodySettings{
		ContextPromptByteCount: 2 * 1024,
	}
}
