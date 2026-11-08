package sidecartest

import (
	"testing"
	"time"
)

// Whether channel has closed, without waiting: every edge here happens before this reads it.
func closed(channel <-chan struct{}) bool {
	select {
	case <-channel:
		return true
	default:
		return false
	}
}

func TestFakeClockCheckStartsSure(t *testing.T) {
	check := NewFakeClockCheck(nil)
	if offset, known := check.Offset(); offset != 0 || !known {
		t.Errorf("offset %v known %t", offset, known)
	}
	if !check.Sure() {
		t.Error("a new fake is not sure")
	}
	if closed(check.UnsureChannel()) {
		t.Error("a sure clock's channel is closed")
	}
}

func TestFakeClockCheckSureIncludesItsBound(t *testing.T) {
	check := NewFakeClockCheck(nil)
	unsure := check.UnsureChannel()
	check.SetOffset(50 * time.Millisecond)
	if !check.Sure() {
		t.Error("50 ms is not sure")
	}
	if closed(unsure) {
		t.Error("the channel closed within the bound")
	}
	check.SetOffset(50*time.Millisecond + 1)
	if check.Sure() {
		t.Error("past 50 ms is sure")
	}
	if !closed(unsure) {
		t.Error("the channel stayed open past the bound")
	}
	if offset, known := check.Offset(); offset != 50*time.Millisecond+1 || !known {
		t.Errorf("offset %v known %t", offset, known)
	}
}

// A clock an hour fast is not within 50 ms, though -1 h is less than 50 ms.
func TestFakeClockCheckOffsetIsAMagnitude(t *testing.T) {
	check := NewFakeClockCheck(nil)
	check.SetOffset(-time.Hour)
	if check.Sure() {
		t.Error("a clock an hour fast is sure")
	}
	if offset, known := check.Offset(); offset != time.Hour || !known {
		t.Errorf("offset %v known %t", offset, known)
	}
	check.SetOffset(-50 * time.Millisecond)
	if !check.Sure() {
		t.Error("a clock 50 ms fast is not sure")
	}
}

func TestFakeClockCheckUnknownIsUnsure(t *testing.T) {
	check := NewFakeClockCheck(nil)
	unsure := check.UnsureChannel()
	check.SetUnknown()
	if offset, known := check.Offset(); offset != 0 || known {
		t.Errorf("offset %v known %t", offset, known)
	}
	if check.Sure() {
		t.Error("unknown is sure")
	}
	if !closed(unsure) {
		t.Error("the channel stayed open")
	}
}

func TestFakeClockCheckChannelIsClosedWhileUnsure(t *testing.T) {
	check := NewFakeClockCheck(nil)
	check.SetUnknown()
	if !closed(check.UnsureChannel()) {
		t.Error("a channel taken while unsure is open")
	}
	// staying unsure closes nothing twice
	check.SetOffset(time.Second)
	check.SetUnknown()
	if !closed(check.UnsureChannel()) {
		t.Error("a channel taken while still unsure is open")
	}
}

func TestFakeClockCheckEachSureStretchHasItsOwnChannel(t *testing.T) {
	check := NewFakeClockCheck(nil)
	first := check.UnsureChannel()
	check.SetUnknown()
	check.SetOffset(10 * time.Millisecond)
	second := check.UnsureChannel()
	if !closed(first) {
		t.Error("the first stretch's channel reopened")
	}
	if closed(second) {
		t.Error("the second stretch's channel is closed")
	}
	// moving within the bound ends no stretch
	check.SetOffset(20 * time.Millisecond)
	if check.UnsureChannel() != second || closed(second) {
		t.Error("a move within the bound replaced the channel")
	}
}

func TestFakeHostHandsOutItsClockCheck(t *testing.T) {
	host, _, _ := newHostFixture(t)
	host.ClockCheck.SetUnknown()
	if host.ServiceHost().ClockCheck.Sure() {
		t.Error("the host's check is not the fake a test moves")
	}
}

func TestFakeHostTakesTheClockCheckBound(t *testing.T) {
	settings := DefaultFakeHostSettings()
	settings.ClockCheck.SureOffset = time.Millisecond
	host := NewFakeHost(t.Context(), nil, nil, nil, settings)
	t.Cleanup(host.Redis.Close)
	host.ClockCheck.SetOffset(2 * time.Millisecond)
	if host.ClockCheck.Sure() {
		t.Error("the settings did not reach the fake")
	}
}
