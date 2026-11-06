package sidecar

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

// DefaultSidecarSettings with every url a host sets, so what a test changes is all that is wrong.
func validSidecarSettings() *SidecarSettings {
	settings := DefaultSidecarSettings()
	settings.ApiUrl = "https://api.example"
	settings.PlatformUrl = "wss://connect.example"
	settings.AuthUrl = "https://auth.example"
	settings.EvsUrl = "https://evs.example"
	settings.GkmUrl = "https://gkm.example"
	settings.SocketsUrl = "https://sockets.example"
	settings.DnsUrl = "https://dns.example"
	return settings
}

func TestValidSettingsPass(t *testing.T) {
	if err := validSidecarSettings().validate(); err != nil {
		t.Fatal(err)
	}
}

func TestNoSettingsAreRefused(t *testing.T) {
	var settings *SidecarSettings
	if err := settings.validate(); !errors.Is(err, errInvalidSettings) {
		t.Errorf("err %v", err)
	}
}

// A host that sets nothing gets a refusal naming what it forgot, on every leg, where the page Worker's
// own transport would have sent the token to the page's host.
func TestDefaultSettingsRefuseUntilAHostSetsItsUrls(t *testing.T) {
	err := DefaultSidecarSettings().validate()
	if !errors.Is(err, errInvalidSettings) || !strings.Contains(err.Error(), "ApiUrl") {
		t.Errorf("err %v", err)
	}
}

// Each url on its own, so one service left out of the list cannot hide behind the others.
func TestEveryRequestUrlIsRequired(t *testing.T) {
	for _, c := range []struct {
		name  string
		clear func(settings *SidecarSettings)
	}{
		{name: "ApiUrl", clear: func(settings *SidecarSettings) { settings.ApiUrl = "" }},
		{name: "AuthUrl", clear: func(settings *SidecarSettings) { settings.AuthUrl = "" }},
		{name: "EvsUrl", clear: func(settings *SidecarSettings) { settings.EvsUrl = "" }},
		{name: "GkmUrl", clear: func(settings *SidecarSettings) { settings.GkmUrl = "" }},
		{name: "SocketsUrl", clear: func(settings *SidecarSettings) { settings.SocketsUrl = "" }},
		{name: "DnsUrl", clear: func(settings *SidecarSettings) { settings.DnsUrl = "" }},
	} {
		settings := validSidecarSettings()
		c.clear(settings)
		if err := settings.validate(); !errors.Is(err, errInvalidSettings) || !strings.Contains(err.Error(), c.name) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// What fetch would resolve against the page, or what would not reach the service once a route's path
// is appended. Each is held by the check every url passes through.
func TestServiceUrlRefusesWhatIsNotAbsolute(t *testing.T) {
	for _, serviceUrl := range []string{
		"",
		"/",
		"/synthetic-path",
		"synthetic-path",
		// a host with no scheme is a relative path to fetch
		"api.example",
		"api.example:8080",
		// scheme-relative: fetch keeps the page's scheme and goes to this host
		"//api.example",
		// no host at all
		"https://",
		"https:///path",
		"https://:443",
		"https:api.example",
		// schemes a token must not follow
		"ftp://api.example",
		"file:///etc/hosts",
		"javascript:alert(1)",
		"data:text/plain,x",
		// another service's scheme
		"wss://api.example",
		// credentials of its own
		"https://user:pass@api.example",
		// a route's path would not land on the service
		"https://api.example/",
		"https://api.example?a=1",
		"https://api.example#a",
		"https://api.example/?a=1",
		// fetch would trim what net/url keeps
		" https://api.example",
		"https://api.example ",
		"https://api.example/a b",
		"https://api.example\n",
	} {
		err := checkServiceUrl("ApiUrl", serviceUrl, "http", "https")
		if !errors.Is(err, errInvalidSettings) {
			t.Errorf("%q: %v", serviceUrl, err)
			continue
		}
		if serviceUrl != "" && strings.Contains(err.Error(), serviceUrl) {
			t.Errorf("error %q repeats its input", err)
		}
	}
}

func TestServiceUrlTakesAnAbsoluteUrl(t *testing.T) {
	for _, serviceUrl := range []string{
		"https://api.example",
		"http://api.example",
		"https://api.example:8443",
		"https://api.example/v1",
		"http://127.0.0.1:50080",
		"http://[2001:db8::1]:50080",
	} {
		if err := checkServiceUrl("ApiUrl", serviceUrl, "http", "https"); err != nil {
			t.Errorf("%q: %v", serviceUrl, err)
		}
	}
}

func TestInstanceHoldsToItsForm(t *testing.T) {
	for _, c := range []struct {
		instance string
		want     bool
	}{
		{instance: "default", want: true},
		{instance: "a", want: true},
		{instance: "0-a", want: true},
		{instance: strings.Repeat("a", 32), want: true},
		{instance: "", want: false},
		{instance: strings.Repeat("a", 33), want: false},
		{instance: "-a", want: false},
		{instance: "A", want: false},
		{instance: "a_b", want: false},
		{instance: "a.b", want: false},
		{instance: "../a", want: false},
		{instance: "a/b", want: false},
	} {
		settings := validSidecarSettings()
		settings.Instance = c.instance
		err := settings.validate()
		if c.want && err != nil {
			t.Errorf("%q: %v", c.instance, err)
		}
		if !c.want && !errors.Is(err, errInvalidSettings) {
			t.Errorf("%q: %v", c.instance, err)
		}
	}
}

func TestAStructLeftNilIsRefused(t *testing.T) {
	settings := validSidecarSettings()
	settings.KeychainSettings = nil
	if err := settings.validate(); !errors.Is(err, errInvalidSettings) || !strings.Contains(err.Error(), "KeychainSettings") {
		t.Errorf("err %v", err)
	}

	settings = validSidecarSettings()
	settings.Connect = nil
	if err := settings.validate(); !errors.Is(err, errInvalidSettings) {
		t.Errorf("err %v", err)
	}
}

func TestSearchModesHoldToTheirLists(t *testing.T) {
	settings := validSidecarSettings()
	settings.Search.AllPolicy = "wifi_charging"
	settings.Search.RemoteMode = "own"
	if err := settings.validate(); err != nil {
		t.Error(err)
	}

	settings = validSidecarSettings()
	settings.Search.AllPolicy = ""
	if err := settings.validate(); !errors.Is(err, errInvalidSettings) {
		t.Errorf("AllPolicy: %v", err)
	}
	settings = validSidecarSettings()
	settings.Search.RemoteMode = "ON"
	if err := settings.validate(); !errors.Is(err, errInvalidSettings) {
		t.Errorf("RemoteMode: %v", err)
	}
}

// Every number in every settings struct, by walking them, so a field added later is held here with
// no new row. fn gets the field's path, its settable value and its settings:"zero" tag.
func forEachSettingsNumber(path string, value reflect.Value, zeroAllowed bool, fn func(path string, number reflect.Value, zeroAllowed bool)) {
	switch value.Kind() {
	case reflect.Pointer:
		if !value.IsNil() {
			forEachSettingsNumber(path, value.Elem(), zeroAllowed, fn)
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i += 1 {
			field := value.Type().Field(i)
			if field.Type == reflect.TypeFor[*SidecarConnectSettings]() {
				continue
			}
			forEachSettingsNumber(path+"."+field.Name, value.Field(i), field.Tag.Get("settings") == "zero", fn)
		}
	case reflect.Array:
		for i := 0; i < value.Len(); i += 1 {
			forEachSettingsNumber(path, value.Index(i), zeroAllowed, fn)
		}
	case reflect.Int, reflect.Int64, reflect.Float64:
		fn(path, value, zeroAllowed)
	}
}

// What a walk of one fresh settings value reaches, so each case can change its own.
func settingsNumberPaths() []string {
	paths := []string{}
	settings := validSidecarSettings()
	forEachSettingsNumber("settings", reflect.ValueOf(settings), false, func(path string, number reflect.Value, zeroAllowed bool) {
		paths = append(paths, path)
	})
	return paths
}

// Sets the n-th number of a fresh value and validates it.
func validateWithNumber(n int, set func(number reflect.Value)) (string, bool, error) {
	settings := validSidecarSettings()
	numberPath := ""
	numberZeroAllowed := false
	i := 0
	forEachSettingsNumber("settings", reflect.ValueOf(settings), false, func(path string, number reflect.Value, zeroAllowed bool) {
		if i == n {
			set(number)
			numberPath = path
			numberZeroAllowed = zeroAllowed
		}
		i += 1
	})
	return numberPath, numberZeroAllowed, settings.validate()
}

// The rule itself: zero never reads as unlimited or off, for any field, and those that give it a
// meaning are the three a person reading settings.go can see.
func TestEveryNumberMustBePositive(t *testing.T) {
	zeroFieldNames := []string{}
	for i := range settingsNumberPaths() {
		path, zeroAllowed, err := validateWithNumber(i, func(number reflect.Value) {
			if number.Kind() == reflect.Float64 {
				number.SetFloat(0)
			} else {
				number.SetInt(0)
			}
		})
		if zeroAllowed {
			zeroFieldNames = append(zeroFieldNames, path)
			if err != nil {
				t.Errorf("%s zero: %v", path, err)
			}
		} else if !errors.Is(err, errInvalidSettings) {
			t.Errorf("%s zero: %v", path, err)
		}

		path, _, err = validateWithNumber(i, func(number reflect.Value) {
			if number.Kind() == reflect.Float64 {
				number.SetFloat(-1)
			} else {
				number.SetInt(-1)
			}
		})
		if !errors.Is(err, errInvalidSettings) {
			t.Errorf("%s negative: %v", path, err)
		}
	}

	want := []string{
		"settings.KeychainSettings.AutoLockTimeout",
		"settings.LocalSettings.IdleExitTimeout",
		"settings.Search.CacheByteCount",
	}
	if !reflect.DeepEqual(zeroFieldNames, want) {
		t.Errorf("zero means something in %q, want %q", zeroFieldNames, want)
	}
}

// The walk reaches what it should, or the rule above would pass by holding nothing: a nested rate, the
// array of timeouts, and a float.
func TestSettingsWalkReachesNestedNumbers(t *testing.T) {
	paths := strings.Join(settingsNumberPaths(), " ")
	for _, path := range []string{
		"settings.Mcp.SessionWriteRate.Burst",
		"settings.Search.RemoteTimeout",
		"settings.ProtocolSettings.StreamMaxPeerCreditFraction",
		"settings.KeychainSettings.PassMemoryByteCount",
		"settings.StreamChunkByteCount",
	} {
		if !strings.Contains(paths, path) {
			t.Errorf("no %s in %s", path, paths)
		}
	}
}

func TestNotANumberIsRefused(t *testing.T) {
	settings := validSidecarSettings()
	settings.TokenRefreshSettings.RefreshWindowStart = math.NaN()
	if err := settings.validate(); !errors.Is(err, errInvalidSettings) {
		t.Errorf("err %v", err)
	}
}

// Unmetered and metered are two settings in one field, so the walk holds each.
func TestEachRemoteTimeoutIsHeld(t *testing.T) {
	settings := validSidecarSettings()
	settings.Search.RemoteTimeout = [2]time.Duration{1 * time.Second, 0}
	if err := settings.validate(); !errors.Is(err, errInvalidSettings) || !strings.Contains(err.Error(), "RemoteTimeout[1]") {
		t.Errorf("err %v", err)
	}
}
