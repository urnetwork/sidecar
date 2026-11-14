// §18.7's vendor submissions (D-SDK-10, WK4; §2.8's ext-8): what the push sender hands APNs and FCM. A
// wake carries a topic class and a version and nothing else, never an id (owner decision 88): the class is
// mail, team, evs or core, §6.8's topic with any id stripped, and the version is the topic's, which for evs
// passes 2^53, so it travels as its canonical decimal digits and never through a float (reading 15).
//
//	APNs  apns-push-type background, apns-priority 5   {"aps":{"content-available":1},"t":"mail","v":42}
//	FCM   data message, Android priority high           {"data":{"t":"mail","v":"42"}}
//
// APNs' v is the digits as a JSON integer, within uint64 and with no exponent; FCM's data values are
// strings, so its v is the same digits quoted. A vendor never logs a token, and its errors name a status
// and a vendor's reason code, never the token or the payload (I-13).

package pushservice

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/urnetwork/sidecar"
)

// The platforms a wake goes to, as tok's <platform> names them.
const (
	WakePlatformApns = sidecar.PushTokenPlatformApns
	WakePlatformFcm  = sidecar.PushTokenPlatformFcm
)

// A vendor's arguments it cannot run on.
var ErrWakeVendorSettings = errors.New("wake vendor: settings or credentials invalid")

// What one wake carries (WK4): a topic class and a version.
type WakePayload struct {
	// mail, team, evs or core.
	TopicClass string
	// The topic's version in ver.
	Version uint64
}

// APNs' body for payload: {"aps":{"content-available":1},"t":<class>,"v":<digits>}, the version written as
// its canonical digits, never through a float.
func ApnsWakeBody(payload *WakePayload) []byte {
	class, _ := json.Marshal(payload.TopicClass)
	body := []byte(`{"aps":{"content-available":1},"t":`)
	body = append(body, class...)
	body = append(body, `,"v":`...)
	body = append(body, FormatVersion(payload.Version)...)
	return append(body, '}')
}

// FCM v1's message for one token: a data message at Android's high priority, its data t and v, v the
// version's digits as a string.
func FcmWakeMessage(token string, payload *WakePayload) []byte {
	type fcmAndroid struct {
		Priority string `json:"priority"`
	}
	type fcmMessage struct {
		Token   string            `json:"token"`
		Data    map[string]string `json:"data"`
		Android fcmAndroid        `json:"android"`
	}
	body, _ := json.Marshal(struct {
		Message fcmMessage `json:"message"`
	}{
		Message: fcmMessage{
			Token:   token,
			Data:    map[string]string{"t": payload.TopicClass, "v": FormatVersion(payload.Version)},
			Android: fcmAndroid{Priority: "high"},
		},
	})
	return body
}

// What a vendor answered one submission.
type WakeVendorOutcome int

const (
	// Accepted for delivery.
	WakeVendorSent WakeVendorOutcome = iota
	// APNs' 410 or FCM's UNREGISTERED: the token is no longer the app's, which tombstones the row read
	// with it (§18.7's step 4).
	WakeVendorUnregistered
	// A 429, a 5xx or no answer: worth trying again, at most WakeSenderSettings.RetryCount times.
	WakeVendorRetry
	// Any other answer: the vendor refused this wake for good, and nothing is retried or tombstoned.
	WakeVendorRefused
)

// The outcome's name, as metrics label results.
func (self WakeVendorOutcome) String() string {
	switch self {
	case WakeVendorSent:
		return "sent"
	case WakeVendorUnregistered:
		return "unregistered"
	case WakeVendorRetry:
		return "retry"
	default:
		return "refused"
	}
}

// One submission's answer.
type WakeVendorResult struct {
	Outcome WakeVendorOutcome
	// The vendor's HTTP status, 0 when none came.
	Status int
	// The vendor's reason code, such as BadDeviceToken or UNREGISTERED: a vendor's word, never a token.
	Reason string
	// A Retry-After the vendor named, 0 for none.
	RetryAfter time.Duration
}

// A push vendor: APNs or FCM, or a test's. Safe for concurrent use.
type WakeVendor interface {
	// WakePlatformApns or WakePlatformFcm, tok's <platform>.
	Platform() string
	// Submits one wake to token. Never logs or returns the token.
	Send(ctx context.Context, token string, payload *WakePayload) *WakeVendorResult
}

// The outcome of an HTTP status no vendor-specific reason overrides: 2xx sent, 429 and 5xx retry, other
// statuses refused.
func wakeVendorOutcomeOf(status int) WakeVendorOutcome {
	switch {
	case 200 <= status && status < 300:
		return WakeVendorSent
	case status == 429 || 500 <= status:
		return WakeVendorRetry
	default:
		return WakeVendorRefused
	}
}
