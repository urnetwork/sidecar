//go:build !sidecar_http

package sidecar

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestDefaultSmtpSenderSettingsMatchDesign(t *testing.T) {
	settings := DefaultSidecarSettings().Connect.SmtpSender
	want := &SmtpSenderSettings{
		RetryFirstTimeout:          30 * time.Minute,
		RetryMaxTimeout:            4 * time.Hour,
		RetryGiveUpTimeout:         5 * 24 * time.Hour,
		RetryUnitsPerMessagePerDay: 2,
		ProverConcurrency:          1,
		PinTimeout:                 90 * 24 * time.Hour,
		OutboxProgressInterval:     5 * time.Minute,
		OutboxTakeoverTimeout:      10 * time.Minute,
		DkimRotateTimeout:          90 * 24 * time.Hour,
		DkimRetiredKeepTimeout:     7 * 24 * time.Hour,
	}
	if !reflect.DeepEqual(settings, want) {
		t.Errorf("%+v", settings)
	}
}

// D-SMTP-18: a host with no prover is a valid host, one that queues to the outbox and never sends, and
// every default is one.
func TestDefaultSettingsHaveNoProver(t *testing.T) {
	settings := validSidecarSettings()
	if settings.Connect.SmtpProver != nil {
		t.Error("a default prover")
	}
	if err := settings.validate(); err != nil {
		t.Error(err)
	}
}

func TestDefaultSmtpSenderSettingsShareNothing(t *testing.T) {
	first := DefaultSidecarSettings().Connect.SmtpSender
	first.ProverConcurrency = 3
	if DefaultSidecarSettings().Connect.SmtpSender.ProverConcurrency != 1 || DefaultSmtpSenderSettings() == DefaultSmtpSenderSettings() {
		t.Error("an adjustment reached the next default")
	}
}

// The rule of settings.go's header, which the walk in settings_validate_test.go leaves to this file,
// since it skips the connect settings.
func TestEverySmtpSenderNumberMustBePositive(t *testing.T) {
	fields := reflect.TypeFor[SmtpSenderSettings]()
	for i := range fields.NumField() {
		for _, value := range []int64{0, -1} {
			settings := validSidecarSettings()
			field := reflect.ValueOf(settings.Connect.SmtpSender).Elem().Field(i)
			field.SetInt(value)
			if err := settings.validate(); !errors.Is(err, errInvalidSettings) {
				t.Errorf("%s at %d: %v", fields.Field(i).Name, value, err)
			}
		}
	}
}

func TestSmtpSenderSettingsRefuseSchedulesOutOfOrder(t *testing.T) {
	for _, adjust := range []func(settings *SmtpSenderSettings){
		func(settings *SmtpSenderSettings) { settings.RetryMaxTimeout = settings.RetryFirstTimeout - 1 },
		func(settings *SmtpSenderSettings) { settings.RetryGiveUpTimeout = settings.RetryMaxTimeout - 1 },
		func(settings *SmtpSenderSettings) { settings.OutboxTakeoverTimeout = settings.OutboxProgressInterval },
	} {
		settings := validSidecarSettings()
		adjust(settings.Connect.SmtpSender)
		if err := settings.validate(); !errors.Is(err, errInvalidSettings) {
			t.Errorf("%+v: %v", settings.Connect.SmtpSender, err)
		}
	}
	settings := validSidecarSettings()
	settings.Connect.SmtpSender = nil
	if err := settings.validate(); !errors.Is(err, errInvalidSettings) {
		t.Errorf("nil: %v", err)
	}
}
