//go:build !sidecar_http && !ios_extension

// MailSettings' receiver part on the legs a receiver's parts build on (MAIL-M7-17): the receiver, its sessions and
// deposits, and its reception-time checks. The page Worker's leg has none (mail_settings_receive_http.go).

package sidecar

// A receiver's settings.
type MailReceiveSettings struct {
	// Whether this device runs a receiver once policy grants it the listen on smtp/25/mx (§15.5, §15.6): a desktop,
	// NAS or VPS daemon does, which keeps it up while mail is on, and an app does while it is open (MailHostProfile).
	Enabled  bool
	Receiver *MailReceiverSettings
	Session  *MailSessionSettings
	Auth     *MailAuthSettings
}

// The receiver's defaults: on, as a daemon runs.
func defaultMailReceiveSettings() *MailReceiveSettings {
	return &MailReceiveSettings{
		Enabled:  true,
		Receiver: DefaultMailReceiverSettings(),
		Session:  DefaultMailSessionSettings(),
		Auth:     DefaultMailAuthSettings(),
	}
}

// The receiver part of ApplyMobileMailSettings: the receiver stays on, so an app listens while it is open where policy
// grants its listen (§15.6 step 4; owner decision 197), max_streams and the check slots stay as §15.5 fixes them, and
// deposits drop to 2 at once (§15.7).
func applyMobileMailSettings(settings *MailSettings) {
	if settings == nil || settings.Receive == nil {
		return
	}
	settings.Receive.Enabled = true
	if settings.Receive.Session != nil {
		ApplyMobileMailSessionSettings(settings.Receive.Session)
	}
}
