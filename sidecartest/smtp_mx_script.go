//go:build !sidecar_http

// ScriptedMx: an MX behind Go's own crypto/tls server, at a chosen version and suite, running
// smtp_mx.go's machine before and after STARTTLS by an MxScript. It covers §14.5's scripted cases (no
// CHUNKING, pre-TLS-only CHUNKING, no PIPELINING, a refused MAIL or RCPT, mixed recipients, no 354, a
// 421 banner, a 451 under TLS) and serves any number of connections, each to its end. What crypto/tls
// cannot do on demand, a late NewSessionTicket, a KeyUpdate or padded records, is RecordMx's. Safe for
// concurrent use.

package sidecartest

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"net"
)

// TLS for a ScriptedMx.
type ScriptedMxSettings struct {
	// The versions served: tls.VersionTLS12 to tls.VersionTLS13 by default.
	MinVersion uint16
	MaxVersion uint16
	// 1.2's suites. 1.3's are crypto/tls's own to choose among.
	CipherSuites []uint16
	// An RSA key in place of ECDSA P-256, for 1.2's ECDHE-RSA suite.
	RsaKey bool
	// Used as given when set, else one is made for the host.
	Certificate *tls.Certificate
}

func DefaultScriptedMxSettings() *ScriptedMxSettings {
	return &ScriptedMxSettings{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
}

type ScriptedMx struct {
	mxRecord
	host        string
	script      *MxScript
	settings    *ScriptedMxSettings
	certificate tls.Certificate
}

var _ MxServer = (*ScriptedMx)(nil)

// An MX for host. A nil script is DefaultMxScript's and nil settings DefaultScriptedMxSettings'.
func NewScriptedMx(host string, script *MxScript, settings *ScriptedMxSettings) (*ScriptedMx, error) {
	if script == nil {
		script = DefaultMxScript()
	}
	if settings == nil {
		settings = DefaultScriptedMxSettings()
	}
	mx := &ScriptedMx{host: host, script: script, settings: settings}
	if settings.Certificate != nil {
		mx.certificate = *settings.Certificate
	} else {
		certificate, err := NewMxCertificate(host, settings.RsaKey)
		if err != nil {
			return nil, err
		}
		mx.certificate = certificate
	}
	return mx, nil
}

// The MX's leaf, for a TLSA record or a test's VerifyPeer.
func (self *ScriptedMx) Certificate() *x509.Certificate {
	return self.certificate.Leaf
}

// Serves conn to its end: the banner, the pre-TLS dialog, then after STARTTLS the handshake and the
// dialog inside TLS. Closes conn.
func (self *ScriptedMx) ServeMx(conn net.Conn) {
	defer conn.Close()
	self.addConnection()
	banner := self.script.Banner
	if banner == "" {
		banner = "220 " + self.host + " ESMTP"
	}
	if _, err := conn.Write([]byte(banner + "\r\n")); err != nil || banner[0] != '2' {
		return
	}
	plain := &mxSmtpSession{host: self.host, script: self.script, record: &self.mxRecord, reader: bufio.NewReader(conn), writer: conn}
	startTls, err := plain.serve()
	if err != nil || !startTls {
		return
	}
	server := tls.Server(conn, &tls.Config{
		Certificates:           []tls.Certificate{self.certificate},
		MinVersion:             self.settings.MinVersion,
		MaxVersion:             self.settings.MaxVersion,
		CipherSuites:           self.settings.CipherSuites,
		SessionTicketsDisabled: true,
	})
	if err := server.Handshake(); err != nil {
		return
	}
	secure := &mxSmtpSession{host: self.host, script: self.script, record: &self.mxRecord, reader: bufio.NewReader(server), writer: server, secure: true}
	secure.serve()
}
