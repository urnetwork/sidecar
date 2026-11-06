// What NewSidecar refuses before it starts anything, on every leg, so that no later code has to ask
// what a zero or an empty url means. A failure wraps errInvalidSettings and names the field, never its
// value, since a url may hold anything (I-13).
//
// Every number in a settings struct must be positive: a zero never reads as unlimited or off, because
// nothing gets that far. A field tagged settings:"zero" gives zero a meaning, which its comment states,
// and a negative value there is refused all the same.

package sidecar

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"
)

var errInvalidSettings = errors.New("invalid sidecar settings")

// Whether the settings can run a Sidecar. Each leg's validateLeg adds what only that leg uses.
//
// An empty service url stops here with a clear error, and not at a dial, which in the page Worker
// would go to the page's own host (api_transport.go). So NewSidecar runs this on every leg, and
// legs_test.go fails a NewSidecar that does not.
func (self *SidecarSettings) validate() error {
	if self == nil {
		return fmt.Errorf("%w: no settings", errInvalidSettings)
	}
	for _, serviceUrl := range []struct {
		name  string
		value string
	}{
		{name: "ApiUrl", value: self.ApiUrl},
		{name: "AuthUrl", value: self.AuthUrl},
		{name: "EvsUrl", value: self.EvsUrl},
		{name: "GkmUrl", value: self.GkmUrl},
		{name: "SocketsUrl", value: self.SocketsUrl},
		{name: "DnsUrl", value: self.DnsUrl},
	} {
		if err := checkServiceUrl(serviceUrl.name, serviceUrl.value, "http", "https"); err != nil {
			return err
		}
	}
	// §5.9's form. An instance names a directory, so this also keeps a path out of it.
	instanceFits := func() bool {
		if self.Instance == "" || 32 < len(self.Instance) || self.Instance[0] == '-' {
			return false
		}
		for i := 0; i < len(self.Instance); i += 1 {
			if c := self.Instance[i]; !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
				return false
			}
		}
		return true
	}
	if !instanceFits() {
		return fmt.Errorf("%w: Instance is not [a-z0-9][a-z0-9-]{0,31}", errInvalidSettings)
	}
	if self.Connect == nil {
		return fmt.Errorf("%w: Connect is nil", errInvalidSettings)
	}
	if err := self.validateLeg(); err != nil {
		return err
	}
	if err := checkSettingsNumbers("SidecarSettings", reflect.ValueOf(self).Elem(), false); err != nil {
		return err
	}
	if !slices.Contains([]string{"background", "wifi_charging", "on_demand", "never"}, self.Search.AllPolicy) {
		return fmt.Errorf("%w: Search.AllPolicy is not one of §18.4's modes", errInvalidSettings)
	}
	if !slices.Contains([]string{"on", "own", "off"}, self.Search.RemoteMode) {
		return fmt.Errorf("%w: Search.RemoteMode is not on, own or off", errInvalidSettings)
	}
	return nil
}

// The form every service url takes: absolute on one of schemes, and ready for a route's path to be
// appended, so with no trailing slash, query or fragment.
func checkServiceUrl(name string, serviceUrl string, schemes ...string) error {
	parsed, err := url.Parse(serviceUrl)
	if err != nil || !isAbsoluteServiceUrl(parsed, schemes...) ||
		strings.ContainsAny(serviceUrl, "?# ") || strings.HasSuffix(serviceUrl, "/") {
		return fmt.Errorf("%w: %s is not an absolute url with no trailing slash, query or fragment", errInvalidSettings, name)
	}
	return nil
}

// Walks a settings value, refusing a nil settings struct and a number that is not positive. name
// says where the walk is, for the error. zeroAllowed is the settings:"zero" tag of the field holding
// value. Strings, bools and the logger are not numbers and stay out of it, and validateLeg reads
// connect's own settings, which keep connect's rules.
func checkSettingsNumbers(name string, value reflect.Value, zeroAllowed bool) error {
	refused := func() error {
		return fmt.Errorf("%w: %s", errInvalidSettings, name)
	}
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			return refused()
		}
		return checkSettingsNumbers(name, value.Elem(), zeroAllowed)
	case reflect.Struct:
		for i := 0; i < value.NumField(); i += 1 {
			field := value.Type().Field(i)
			if field.Type == reflect.TypeFor[*SidecarConnectSettings]() {
				continue
			}
			err := checkSettingsNumbers(name+"."+field.Name, value.Field(i), field.Tag.Get("settings") == "zero")
			if err != nil {
				return err
			}
		}
	case reflect.Array:
		for i := 0; i < value.Len(); i += 1 {
			if err := checkSettingsNumbers(fmt.Sprintf("%s[%d]", name, i), value.Index(i), zeroAllowed); err != nil {
				return err
			}
		}
	case reflect.Int, reflect.Int64:
		if number := value.Int(); number < 0 || number == 0 && !zeroAllowed {
			return refused()
		}
	case reflect.Float64:
		// a NaN compares false both ways, so it is asked for by name
		if number := value.Float(); !(0 <= number) || number == 0 && !zeroAllowed {
			return refused()
		}
	}
	return nil
}
