//go:build linux

// logind's resume (resume_linux.go): only PrepareForSleep(false) on logind's path is a resume; the signal before a
// sleep, another member or path, and a body of another shape are not.

package main

import (
	"testing"

	"github.com/godbus/dbus/v5"
)

// The signals the watch may be handed, and which of them is a resume.
func TestLogindResumedReadsOnlyPrepareForSleepFalse(t *testing.T) {
	sleep := urLogindManager + "." + urLogindSleepMember
	cases := []struct {
		name    string
		signal  *dbus.Signal
		resumed bool
	}{
		{name: "resumed", signal: &dbus.Signal{Path: urLogindPath, Name: sleep, Body: []any{false}}, resumed: true},
		{name: "going to sleep", signal: &dbus.Signal{Path: urLogindPath, Name: sleep, Body: []any{true}}},
		{name: "another member", signal: &dbus.Signal{Path: urLogindPath, Name: urLogindManager + ".PrepareForShutdown", Body: []any{false}}},
		{name: "another path", signal: &dbus.Signal{Path: dbus.ObjectPath("/org/freedesktop/login1/session/self"), Name: sleep, Body: []any{false}}},
		{name: "the bus's own", signal: &dbus.Signal{Path: dbus.ObjectPath("/org/freedesktop/DBus"), Name: "org.freedesktop.DBus.NameAcquired", Body: []any{":1.9"}}},
		{name: "no body", signal: &dbus.Signal{Path: urLogindPath, Name: sleep}},
		{name: "a body of another type", signal: &dbus.Signal{Path: urLogindPath, Name: sleep, Body: []any{"false"}}},
		{name: "two values", signal: &dbus.Signal{Path: urLogindPath, Name: sleep, Body: []any{false, false}}},
		{name: "none", signal: nil},
	}
	for _, testCase := range cases {
		if resumed := urLogindResumed(testCase.signal); resumed != testCase.resumed {
			t.Errorf("%s: resumed %v", testCase.name, resumed)
		}
	}
}
