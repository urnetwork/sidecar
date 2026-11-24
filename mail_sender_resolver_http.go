//go:build sidecar_http && !ios_extension

// MailSendSettings' resolver on the page Worker's leg, which sends no internet mail (§18.10): empty, so the settings
// read alike on every leg.

package sidecar

// Nothing: the page Worker composes no sender, and nothing reads a factory's resolver here.
type MailSenderResolver struct{}
