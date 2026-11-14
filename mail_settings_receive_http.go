//go:build sidecar_http && !ios_extension

// MailSettings' receiver part on the page Worker's leg, which reads mail and never receives it (R-MAIL-13): empty.

package sidecar

// Nothing: the page Worker runs no receiver.
type MailReceiveSettings struct{}

// The empty part.
func defaultMailReceiveSettings() *MailReceiveSettings {
	return &MailReceiveSettings{}
}

// Nothing to adjust: the page Worker runs no receiver.
func ApplyMobileMailSettings(settings *MailSettings) {}
