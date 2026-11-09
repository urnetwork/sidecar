// The proxy ur's dials go through (§18.9's rung 2, C8): ur reads HTTPS_PROXY here, at the host, and hands connect a
// ProxySettings, so connect itself never reads the environment. Every stream dial of the daemon's client strategy
// then crosses it: the platform transport's wss, api, the token exchange and SidecarApi alike. UDP 443 (H3) never
// goes through it.
//
// HTTPS_PROXY, else https_proxy, names it: http://[user:password@]host[:port] for a CONNECT proxy, port 80 when
// none is given, as Go's own proxy rules read it, and socks5:// or socks5h:// for a SOCKS5 one, port 1080. A value
// with no scheme is http. An https:// proxy, which would need tls to the proxy itself, is refused, as is anything
// that does not parse: a proxy ur cannot use never becomes a direct dial. NO_PROXY, else no_proxy, turns it off for
// a host it covers: * covers every host, and a name covers itself and the names under it. Every host ur reaches
// shares the api host's domain, so the api host decides for all of them.

package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/urnetwork/connect"
	"golang.org/x/net/proxy"

	"github.com/urnetwork/sidecar"
)

// A proxy setting ur will not dial through. Its text names the variable, never its value, which may hold a
// password.
var errUrHttpsProxy = errors.New("HTTPS_PROXY is not a proxy ur can use")

// The proxy host's dials take, or nil for none.
func urHttpsProxy(getenv func(name string) string, host string) (*connect.ProxySettings, error) {
	value := getenv("HTTPS_PROXY")
	if value == "" {
		value = getenv("https_proxy")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	noProxy := getenv("NO_PROXY")
	if noProxy == "" {
		noProxy = getenv("no_proxy")
	}
	if urNoProxyCovers(noProxy, host) {
		return nil, nil
	}
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" {
		return nil, fmt.Errorf("%w: it names no proxy host", errUrHttpsProxy)
	}
	proxySettings := &connect.ProxySettings{Network: "tcp"}
	defaultPort := ""
	switch strings.ToLower(parsed.Scheme) {
	case "http":
		proxySettings.Protocol = connect.ProxyProtocolHttpConnect
		defaultPort = "80"
	case "socks5", "socks5h":
		proxySettings.Protocol = connect.ProxyProtocolSocks5
		defaultPort = "1080"
	case "https":
		return nil, fmt.Errorf("%w: an https:// proxy needs tls to the proxy, which ur does not speak; give its http:// form", errUrHttpsProxy)
	default:
		return nil, fmt.Errorf("%w: its scheme is not http, socks5 or socks5h", errUrHttpsProxy)
	}
	port := parsed.Port()
	if port == "" {
		port = defaultPort
	}
	proxySettings.Address = net.JoinHostPort(parsed.Hostname(), port)
	if parsed.User != nil {
		password, _ := parsed.User.Password()
		proxySettings.Auth = &proxy.Auth{User: parsed.User.Username(), Password: password}
	}
	return proxySettings, nil
}

// Whether noProxy, a NO_PROXY value, covers host: * covers every host, and each other entry, comma or space
// separated, covers its own name and every name under it, a leading dot or a port aside. Address and CIDR
// entries never match a name.
func urNoProxyCovers(noProxy string, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, entry := range strings.FieldsFunc(noProxy, func(r rune) bool { return r == ',' || r == ' ' }) {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "*" {
			return true
		}
		if entryHost, _, err := net.SplitHostPort(entry); err == nil {
			entry = entryHost
		}
		entry = strings.TrimSuffix(strings.TrimPrefix(entry, "."), ".")
		if entry == "" {
			continue
		}
		if host == entry || strings.HasSuffix(host, "."+entry) {
			return true
		}
	}
	return false
}

// Points every stream dial of the daemon's client strategy through the proxy HTTPS_PROXY names for settings' api host,
// if any. A value ur cannot use refuses, leaving settings as they were, so the caller runs no Sidecar.
func applyUrHttpsProxy(getenv func(name string) string, settings *sidecar.SidecarSettings) error {
	apiUrl, err := url.Parse(settings.ApiUrl)
	if err != nil {
		return err
	}
	proxySettings, err := urHttpsProxy(getenv, apiUrl.Hostname())
	if err != nil || proxySettings == nil {
		return err
	}
	settings.Connect.ClientStrategySettings.ConnectSettings.ProxySettings = proxySettings
	return nil
}
