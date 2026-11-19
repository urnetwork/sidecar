// CC4's fake APNs and FCM source, and §22.7's wake row (TEST-M8-01; R-TEST-3, D-TEST-5; owner decision 88, WK4):
// "wake payloads carry only a topic class and version". A wake is the one thing sidecar hands a party outside
// URnetwork and the user's devices, Apple's or Google's push service, so what a vendor is sent is captured as a class
// of its own and held to its exact shape:
//
//	capture  AddWakeVendor reads every submission a FakeWakeVendor took at each scan: the body the real vendor would
//	         have been sent, that body's strings as the vendor's JSON reader has them, and the token it went to, so a
//	         canary, a forbidden value or a hooked key in any is a finding of CC4/wake
//	shape    WakeSubmissionErrors holds a submission to WK4 by decoding the vendor's body strictly: APNs' is
//	         {"aps":{"content-available":1},"t":<class>,"v":<digits>} and FCM's a data message of t and v at high
//	         priority to its token, the class one of mail, team, evs and core, the version its canonical digits and
//	         never 0, and no other field anywhere, so a body that gained a run id, a repo id, a sender or a preview
//	         fails whatever it is called
//
// The scan and the shape are two checks on purpose: an id is no canary, so only the shape refuses it, and a canary
// inside an allowed field (a topic class that is user text) is the scan's. privacy_wake_leak.go holds the class's leak
// for §22.7's self-test.

package sidecartest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/pushservice"
)

// What a wake vendor was sent, each submission's body and token (§22.7's CC4: fake APNs/FCM).
var PrivacyClassWake = RegisterPrivacyClass("CC4/wake")

var _ = RegisterPrivacyAssert("wake-payloads", &PrivacyAssertTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestWakePayloadsCarryOnlyATopicClassAndVersion"})
var _ = RegisterPrivacyAssert("wake-payloads", &PrivacyAssertTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestAWakePayloadCarryingAnIdFails"})

// The classes a wake names (§18.7): pushservice.WakeTopicClass answers no other.
var wakeTopicClasses = []string{"mail", "team", "evs", "core"}

// Adds every submission vendor takes to the capture, read at each scan: its body as the vendor's API would have
// received it, and its token.
func (self *PrivacyCapture) AddWakeVendor(vendor *FakeWakeVendor) {
	self.AddSource(func() []*PrivacyItem {
		items := []*PrivacyItem{}
		for index, submission := range vendor.Submissions() {
			name := fmt.Sprintf("wake %s %d", submission.Platform, index)
			items = append(items,
				&PrivacyItem{Class: PrivacyClassWake, Name: name + " body", Body: bytes.Clone(submission.Body)},
				&PrivacyItem{Class: PrivacyClassWake, Name: name + " body strings", Body: wakeBodyStrings(submission.Body)},
				&PrivacyItem{Class: PrivacyClassWake, Name: name + " token", Body: []byte(submission.Token)},
			)
		}
		return items
	})
}

// Every string of the JSON in body, names and values, as the vendor reads them: unescaped, one to a line. A value
// whose bytes JSON escapes (a line break inside it, a quote) is whole only here. Nil for a body that is no JSON, whose
// raw bytes the scan has.
func wakeBodyStrings(body []byte) []byte {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var out bytes.Buffer
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		if text, ok := token.(string); ok {
			out.WriteString(text)
			out.WriteByte('\n')
		}
	}
	return out.Bytes()
}

// Decodes body into value, refusing a field value does not declare and anything after the document.
func wakeStrictDecode(body []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("bytes follow the document")
	}
	return nil
}

// The keys of a JSON object in body, an error for anything else.
func wakeObjectKeys(body []byte) ([]string, error) {
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, err
	}
	keys := []string{}
	for key := range fields {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys, nil
}

// Whether class and version are what WK4 lets a wake carry: a wake class, and a version's canonical digits.
func wakeClassAndVersionErrors(class string, version string) []error {
	errs := []error{}
	if !slices.Contains(wakeTopicClasses, class) {
		errs = append(errs, fmt.Errorf("its topic class %q is none of %v", class, wakeTopicClasses))
	}
	if !pushservice.CanonicalVersion(version) {
		errs = append(errs, fmt.Errorf("its version %q is no canonical version", version))
	}
	return errs
}

// What of WK4 submission breaks, nil for a wake that carries a topic class and a version and nothing else. It reads
// the vendor's body, never the payload a test built it from, so a field added on the way to the vendor fails here.
func WakeSubmissionErrors(submission *FakeWakeSubmission) []error {
	errs := []error{}
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("a wake to %s: "+format, append([]any{submission.Platform}, args...)...))
	}
	var class, version string
	switch submission.Platform {
	case pushservice.WakePlatformApns:
		body := struct {
			Aps *struct {
				ContentAvailable json.RawMessage `json:"content-available"`
			} `json:"aps"`
			TopicClass *string `json:"t"`
			// its raw bytes: a number's digits, which a quoted string or a float's form is not
			Version json.RawMessage `json:"v"`
		}{}
		if err := wakeStrictDecode(submission.Body, &body); err != nil {
			fail("its body is not APNs' wake: %v", err)
			return errs
		}
		if body.Aps == nil || string(body.Aps.ContentAvailable) != "1" || body.TopicClass == nil || len(body.Version) == 0 {
			fail("its body lacks aps.content-available 1, t or v: %s", submission.Body)
			return errs
		}
		class, version = *body.TopicClass, string(body.Version)
	case pushservice.WakePlatformFcm:
		body := struct {
			Message *struct {
				Token   *string           `json:"token"`
				Data    map[string]string `json:"data"`
				Android *struct {
					Priority *string `json:"priority"`
				} `json:"android"`
			} `json:"message"`
		}{}
		if err := wakeStrictDecode(submission.Body, &body); err != nil {
			fail("its body is not FCM's wake: %v", err)
			return errs
		}
		message := body.Message
		if message == nil || message.Token == nil || message.Android == nil || message.Android.Priority == nil || *message.Android.Priority != "high" {
			fail("its body lacks its token or android.priority high: %s", submission.Body)
			return errs
		}
		if *message.Token != submission.Token {
			fail("its body names another token than the one it went to")
		}
		keys := []string{}
		for key := range message.Data {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, []string{"t", "v"}) {
			fail("its data holds %v, not a topic class and a version alone", keys)
			return errs
		}
		class, version = message.Data["t"], message.Data["v"]
	default:
		fail("no vendor's body is known for the platform")
		return errs
	}
	for _, err := range wakeClassAndVersionErrors(class, version) {
		fail("%v", err)
	}
	if class != submission.Payload.TopicClass || version != pushservice.FormatVersion(submission.Payload.Version) {
		fail("its body carries %q at %s, its payload %q at %d", class, version, submission.Payload.TopicClass, submission.Payload.Version)
	}
	// the top level again by its keys, so a duplicate key's second value, which a struct decode would take, is no
	// way around the shape
	if keys, err := wakeObjectKeys(submission.Body); err != nil {
		fail("its body is no object: %v", err)
	} else if submission.Platform == pushservice.WakePlatformApns && !slices.Equal(keys, []string{"aps", "t", "v"}) {
		fail("its body holds %v", keys)
	} else if submission.Platform == pushservice.WakePlatformFcm && !slices.Equal(keys, []string{"message"}) {
		fail("its body holds %v", keys)
	}
	return errs
}

// WakeSubmissionErrors over every submission vendor took, and an error for a vendor that took none, which shows
// nothing.
func WakeVendorErrors(vendor *FakeWakeVendor) []error {
	submissions := vendor.Submissions()
	if len(submissions) == 0 {
		return []error{fmt.Errorf("the %s vendor took no wake, so its payloads show nothing", vendor.Platform())}
	}
	errs := []error{}
	for _, submission := range submissions {
		errs = append(errs, WakeSubmissionErrors(submission)...)
	}
	return errs
}
