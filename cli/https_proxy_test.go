package main

// HTTPS_PROXY as ur reads it: the forms it takes, the ones it refuses without repeating a password, NO_PROXY, and the
// daemon's settings it fills. Every host is a .example name.

import (
	"strings"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// An environment of values.
func testEnvironment(values map[string]string) func(name string) string {
	return func(name string) string {
		return values[name]
	}
}

// Each form a proxy is named in, and what ur dials through.
func TestHttpsProxyReadsTheEnvironment(t *testing.T) {
	cases := []struct {
		environment map[string]string
		protocol    connect.ProxyProtocol
		address     string
		user        string
		password    string
	}{
		{environment: map[string]string{"HTTPS_PROXY": "http://proxy.proxytest.example:3128"}, protocol: connect.ProxyProtocolHttpConnect, address: "proxy.proxytest.example:3128"},
		{environment: map[string]string{"HTTPS_PROXY": "proxy.proxytest.example:3128"}, protocol: connect.ProxyProtocolHttpConnect, address: "proxy.proxytest.example:3128"},
		{environment: map[string]string{"HTTPS_PROXY": "http://proxy.proxytest.example"}, protocol: connect.ProxyProtocolHttpConnect, address: "proxy.proxytest.example:80"},
		{environment: map[string]string{"https_proxy": "http://proxy.proxytest.example:8080"}, protocol: connect.ProxyProtocolHttpConnect, address: "proxy.proxytest.example:8080"},
		{environment: map[string]string{"HTTPS_PROXY": "http://upper.proxytest.example:1", "https_proxy": "http://lower.proxytest.example:2"}, protocol: connect.ProxyProtocolHttpConnect, address: "upper.proxytest.example:1"},
		{environment: map[string]string{"HTTPS_PROXY": "socks5://proxy.proxytest.example:1081"}, protocol: connect.ProxyProtocolSocks5, address: "proxy.proxytest.example:1081"},
		{environment: map[string]string{"HTTPS_PROXY": "socks5h://proxy.proxytest.example"}, protocol: connect.ProxyProtocolSocks5, address: "proxy.proxytest.example:1080"},
		{environment: map[string]string{"HTTPS_PROXY": "http://[2001:db8::1]:3128"}, protocol: connect.ProxyProtocolHttpConnect, address: "[2001:db8::1]:3128"},
		{environment: map[string]string{"HTTPS_PROXY": "http://synthetic-user:pa%40ss@proxy.proxytest.example:3128"}, protocol: connect.ProxyProtocolHttpConnect, address: "proxy.proxytest.example:3128", user: "synthetic-user", password: "pa@ss"},
	}
	for _, c := range cases {
		proxySettings, err := urHttpsProxy(testEnvironment(c.environment), "api.proxytest.example")
		if err != nil || proxySettings == nil {
			t.Errorf("%v: %v, %v", c.environment, proxySettings, err)
			continue
		}
		if proxySettings.Protocol != c.protocol || proxySettings.Address != c.address || proxySettings.Network != "tcp" {
			t.Errorf("%v: %+v", c.environment, proxySettings)
		}
		if c.user == "" {
			if proxySettings.Auth != nil {
				t.Errorf("%v: credentials %+v", c.environment, proxySettings.Auth)
			}
		} else if proxySettings.Auth == nil || proxySettings.Auth.User != c.user || proxySettings.Auth.Password != c.password {
			t.Errorf("%v: credentials %+v", c.environment, proxySettings.Auth)
		}
	}
	if proxySettings, err := urHttpsProxy(testEnvironment(nil), "api.proxytest.example"); proxySettings != nil || err != nil {
		t.Errorf("no proxy set: %+v, %v", proxySettings, err)
	}
}

// What ur cannot dial through refuses, and the refusal never repeats the value, which may hold a password.
func TestHttpsProxyRefusesWhatItCannotUse(t *testing.T) {
	for _, value := range []string{
		"https://synthetic-user:synthetic-password@proxy.proxytest.example:3128",
		"ftp://synthetic-user:synthetic-password@proxy.proxytest.example",
		"http://synthetic-user:synthetic-password@:3128",
		"http://%zz",
	} {
		proxySettings, err := urHttpsProxy(testEnvironment(map[string]string{"HTTPS_PROXY": value}), "api.proxytest.example")
		if err == nil {
			t.Errorf("%q: %+v", value, proxySettings)
			continue
		}
		if strings.Contains(err.Error(), "synthetic-password") || strings.Contains(err.Error(), "proxy.proxytest.example") {
			t.Errorf("%q's refusal repeats it: %v", value, err)
		}
	}
}

// NO_PROXY turns the proxy off for a host it covers, and only for one.
func TestNoProxyCoversItsHosts(t *testing.T) {
	cases := []struct {
		noProxy string
		covered bool
	}{
		{noProxy: "*", covered: true},
		{noProxy: "proxytest.example", covered: true},
		{noProxy: ".proxytest.example", covered: true},
		{noProxy: "localhost, api.proxytest.example:443", covered: true},
		{noProxy: "API.PROXYTEST.EXAMPLE", covered: true},
		{noProxy: "other.example", covered: false},
		{noProxy: "test.example", covered: false},
		{noProxy: "198.51.100.0/24,localhost", covered: false},
		{noProxy: "", covered: false},
	}
	for _, c := range cases {
		if covered := urNoProxyCovers(c.noProxy, "api.proxytest.example"); covered != c.covered {
			t.Errorf("%q covers: %v", c.noProxy, covered)
		}
		proxySettings, err := urHttpsProxy(testEnvironment(map[string]string{
			"HTTPS_PROXY": "http://proxy.proxytest.example:3128",
			"no_proxy":    c.noProxy,
		}), "api.proxytest.example")
		if err != nil || (proxySettings == nil) != c.covered {
			t.Errorf("%q: %+v, %v", c.noProxy, proxySettings, err)
		}
	}
}

// The daemon's client strategy takes the proxy, which every generation's client and SidecarApi dial through; no
// proxy leaves connect's direct dial; a refused one leaves the settings as they were.
func TestDaemonSettingsTakeTheProxy(t *testing.T) {
	newSettings := func() *sidecar.SidecarSettings {
		settings := sidecar.DefaultSidecarSettings()
		settings.ApiUrl = "https://api.proxytest.example"
		return settings
	}
	settings := newSettings()
	if err := applyUrHttpsProxy(testEnvironment(map[string]string{"HTTPS_PROXY": "http://proxy.proxytest.example:3128"}), settings); err != nil {
		t.Fatal(err)
	}
	proxySettings := settings.Connect.ClientStrategySettings.ConnectSettings.ProxySettings
	if proxySettings == nil || proxySettings.Protocol != connect.ProxyProtocolHttpConnect || proxySettings.Address != "proxy.proxytest.example:3128" {
		t.Errorf("proxy %+v", proxySettings)
	}

	settings = newSettings()
	if err := applyUrHttpsProxy(testEnvironment(nil), settings); err != nil || settings.Connect.ClientStrategySettings.ConnectSettings.ProxySettings != nil {
		t.Errorf("no HTTPS_PROXY: %+v, %v", settings.Connect.ClientStrategySettings.ConnectSettings.ProxySettings, err)
	}

	settings = newSettings()
	err := applyUrHttpsProxy(testEnvironment(map[string]string{"HTTPS_PROXY": "https://proxy.proxytest.example"}), settings)
	if err == nil || settings.Connect.ClientStrategySettings.ConnectSettings.ProxySettings != nil {
		t.Errorf("a refused proxy: %+v, %v", settings.Connect.ClientStrategySettings.ConnectSettings.ProxySettings, err)
	}
}
