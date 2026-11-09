// POST /sidecar/push-token (§18.7's step 0; D-SDK-16): a host's wake token for the sidecar's own client.
// Apps post it at every launch, and again after a refresh answers restore_required (§19.10's rows step);
// the server keeps one row per client, whose revision every change raises. An empty token deletes it.
//
// The token is a credential of the app's vendor registration, so it goes in the request body and
// nowhere else: errors name the route alone, and nothing here logs it (I-7, I-13). The rules of what the
// route takes are here, on every leg, so the server, pushservice and the sdk hold one copy.

package sidecar

import (
	"context"
	"fmt"
)

// The vendors a wake token is for, as POST /sidecar/push-token's platform names them.
const (
	// Apple Push Notification service: a device token.
	PushTokenPlatformApns = "apns"
	// Firebase Cloud Messaging: a registration token.
	PushTokenPlatformFcm = "fcm"
)

// The longest token the route takes, a field length of its body: far past an APNs device token's 64 hex
// digits and an FCM registration token's 150 to 200 characters.
const PushTokenMaxByteCount = 4096

// Whether the route takes platform and token as a token to set: platform apns or fcm, and a token of 1
// to PushTokenMaxByteCount printable ASCII characters with no space, which keeps tok's
// <platform>\n<token> parseable. An empty token is a delete, which ValidPushTokenDelete decides.
func ValidPushToken(platform string, token string) bool {
	if platform != PushTokenPlatformApns && platform != PushTokenPlatformFcm {
		return false
	}
	if token == "" || PushTokenMaxByteCount < len(token) {
		return false
	}
	for i := 0; i < len(token); i += 1 {
		if c := token[i]; c <= ' ' || '~' < c {
			return false
		}
	}
	return true
}

// Whether the route takes platform with an empty token as a delete: no platform, or either vendor's.
func ValidPushTokenDelete(platform string) bool {
	return platform == "" || platform == PushTokenPlatformApns || platform == PushTokenPlatformFcm
}

// POST /sidecar/push-token's body.
type SidecarPushTokenArgs struct {
	// apns or fcm; may be empty with an empty token.
	Platform string `json:"platform"`
	// Empty deletes the client's token.
	Token string `json:"token"`
}

// What the body shows when printed: never the token.
func (self SidecarPushTokenArgs) String() string {
	return fmt.Sprintf("SidecarPushTokenArgs{Platform: %q, Token: (%d bytes)}", self.Platform, len(self.Token))
}

// The same as String.
func (self SidecarPushTokenArgs) GoString() string {
	return self.String()
}

// The route as errors name it.
const sidecarPushTokenRoute = "POST /sidecar/push-token"

// POST /sidecar/push-token (§18.7; Client class, on §7.4's strict_exp allowlist), with the jwt as bearer:
// sets the caller's own client's wake token, or deletes it when token is empty. A platform or token the
// route does not take is ErrSidecarApiArgs, and nothing is sent. The server answers 503 with Retry-After
// while its wake switch is off or its migration group is not in the binary; the caller posts again at its
// next launch. Never on a packet path.
func (self *SidecarApi) SetPushToken(ctx context.Context, platform string, token string) error {
	if token == "" {
		if !ValidPushTokenDelete(platform) {
			return fmt.Errorf("sidecar api %s: %w", sidecarPushTokenRoute, ErrSidecarApiArgs)
		}
	} else if !ValidPushToken(platform, token) {
		return fmt.Errorf("sidecar api %s: %w", sidecarPushTokenRoute, ErrSidecarApiArgs)
	}
	return self.sendJson(ctx, &sidecarApiRequest{
		route:     sidecarPushTokenRoute,
		operation: "push_token",
		method:    "POST",
		url:       self.settings.ApiUrl + "/sidecar/push-token",
		bearer:    true,
	}, &SidecarPushTokenArgs{Platform: platform, Token: token}, nil)
}
