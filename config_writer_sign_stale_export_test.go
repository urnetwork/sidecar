//go:build !sidecar_http && !ios_extension

// The bridge the sign-stale writer tests reach the writer's signing barrier through: its name, which a schedule under
// sidecar_testhooks holds. Tests only.

package sidecar

// The barrier a writer passes between its plan and its signing (configWriterBarrierSignTip).
const ConfigWriterBarrierSignTip = configWriterBarrierSignTip
