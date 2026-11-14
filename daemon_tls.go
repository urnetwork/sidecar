//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The daemon's control methods for §13.10's publish (TLS-M5-23): tls.publish, tls.unpublish and tls.status, what
// `ur bridge public-tls` and its --stop and --status send. Each acts on the call's network through its Sidecar's
// PublishTls, UnpublishTls and TlsPublishes, so the gate, the probe and the front are the same ones a tool's call
// passes (I-8).
//
// tls.publish answers the publish, or the approval its request waits on: `ur approve <id>` on an approval-capable
// device, then the same call again. A reply holds names, an expiry and a file's path, and never a key, a token or a
// certificate's bytes (I-7).

package sidecar

import (
	"context"
	"encoding/hex"
	"errors"
	"time"
)

// The methods.
const (
	// ur bridge public-tls <host>:[<local ip>:]<local port>.
	DaemonMethodTlsPublish = "tls.publish"
	// ur bridge public-tls --stop <host>.
	DaemonMethodTlsUnpublish = "tls.unpublish"
	// ur bridge public-tls --status.
	DaemonMethodTlsStatus = "tls.status"
)

// tls.publish's params: §13.10's argument and flags.
type DaemonTlsPublishParams struct {
	// The call's network, empty for .ur's or the only one (§5.8).
	Network string `json:"network,omitempty"`
	Host    string `json:"host"`
	// 0 takes 443.
	Port int `json:"port,omitempty"`
	// [<local ip>:]<local port>.
	Target string `json:"target"`
	// Empty takes members.
	Audience      string   `json:"audience,omitempty"`
	Tcp           bool     `json:"tcp,omitempty"`
	Alpn          []string `json:"alpn,omitempty"`
	ProxyProtocol bool     `json:"proxy_protocol,omitempty"`
	// --expires, in milliseconds from now. 0 takes the rule's default.
	ExpiresMs int64 `json:"expires_ms,omitempty"`
}

// One publish as ur bridge public-tls prints it (§13.10 step 4).
type DaemonTlsPublishStatus struct {
	Name        string   `json:"name"`
	Url         string   `json:"url"`
	ServerNames []string `json:"server_names"`
	// The grant's id in hex, empty under a standing grant.
	GrantId string `json:"grant_id,omitempty"`
	// When the grant ends, in milliseconds since the epoch. 0 for a standing name.
	ExpiresMs int64  `json:"expires_ms,omitempty"`
	Audience  string `json:"audience"`
	AppMode   string `json:"app_mode"`
	// "passthrough: key on this device".
	Passthrough string `json:"passthrough"`
	// A raw link's client key and certificate: the file's path, never its bytes.
	ClientCertificateFile string `json:"client_certificate_file,omitempty"`
	// The target answered the probe.
	Serving bool `json:"serving"`
}

// tls.publish's reply: the publish, or the approval it waits on.
type DaemonTlsPublishReply struct {
	Publish *DaemonTlsPublishStatus `json:"publish,omitempty"`
	// §5.4's gate is waiting on a person: ur approve <id> on an approval-capable device (§16.6), then the publish
	// again.
	ApprovalId *Id `json:"approval_id,omitempty"`
}

// tls.unpublish's params.
type DaemonTlsUnpublishParams struct {
	Network string `json:"network,omitempty"`
	Host    string `json:"host"`
	Port    int    `json:"port,omitempty"`
}

// tls.unpublish's reply.
type DaemonTlsUnpublishReply struct {
	// False when this device published no such name.
	Unpublished bool `json:"unpublished"`
}

// tls.status's params.
type DaemonTlsStatusParams struct {
	Network string `json:"network,omitempty"`
}

// tls.status's reply: this device's publishes on the network, its certificates and its CT watch.
type DaemonTlsStatusReply struct {
	Publishes []*DaemonTlsPublishStatus `json:"publishes"`
	// The certificates this device holds: ids, states and validity, public values only.
	Certificates []*DaemonTlsCertificateStatus `json:"certificates"`
	// "CT watch degraded" (D-TLS-8).
	CtWatchDegraded bool `json:"ct_watch_degraded"`
}

// One certificate this device holds.
type DaemonTlsCertificateStatus struct {
	CertId Id `json:"cert_id"`
	// Empty for the network's own certificate.
	CustomHost string `json:"custom_host,omitempty"`
	State      string `json:"state"`
	// In milliseconds since the epoch.
	NotAfterMs int64 `json:"not_after_ms"`
	// It answers handshakes now.
	Presented bool `json:"presented"`
}

// A publish as the daemon answers it.
func newDaemonTlsPublishStatus(result *TlsPublishResult) *DaemonTlsPublishStatus {
	status := &DaemonTlsPublishStatus{
		Name:                  result.Name,
		Url:                   result.Url,
		ServerNames:           result.ServerNames,
		GrantId:               hex.EncodeToString(result.GrantId),
		Audience:              result.Audience,
		AppMode:               result.AppMode,
		Passthrough:           result.Passthrough,
		ClientCertificateFile: result.ClientCertificateFile,
		Serving:               result.Serving,
	}
	if !result.Expires.IsZero() {
		status.ExpiresMs = result.Expires.UnixMilli()
	}
	return status
}

// The origin a call's own-resource filing runs from: a person's confirmation where the ur that sent it had one.
func daemonTlsOrigin(call *DaemonCall) SidecarActOrigin {
	if call.Confirmed {
		return SidecarActConfirmed
	}
	return SidecarActUnconfirmed
}

// The daemon's tls methods, which the daemon's composition registers with RegisterMethod.
func DaemonTlsMethods() []*DaemonMethod {
	return []*DaemonMethod{
		{
			Name:    DaemonMethodTlsPublish,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonTlsPublishParams{}
				if err := decodeDaemonSocketParams(call, params); err != nil {
					return nil, err
				}
				settings := &TlsPublishSettings{
					Host:          params.Host,
					Port:          params.Port,
					Target:        params.Target,
					Audience:      params.Audience,
					Tcp:           params.Tcp,
					Alpn:          params.Alpn,
					ProxyProtocol: params.ProxyProtocol,
					Expires:       time.Duration(params.ExpiresMs) * time.Millisecond,
				}
				result, err := call.Sidecar.PublishTls(ctx, settings)
				var pending *ApprovalPendingError
				if errors.As(err, &pending) {
					approvalId := pending.ApprovalId
					return &DaemonTlsPublishReply{ApprovalId: &approvalId}, nil
				}
				if err != nil {
					return nil, err
				}
				return &DaemonTlsPublishReply{Publish: newDaemonTlsPublishStatus(result)}, nil
			},
		},
		{
			Name:    DaemonMethodTlsUnpublish,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonTlsUnpublishParams{}
				if err := decodeDaemonSocketParams(call, params); err != nil {
					return nil, err
				}
				err := call.Sidecar.UnpublishTls(ctx, params.Host, params.Port, daemonTlsOrigin(call))
				if errors.Is(err, ErrTlsPublishAbsent) {
					return &DaemonTlsUnpublishReply{}, nil
				}
				if err != nil {
					return nil, err
				}
				return &DaemonTlsUnpublishReply{Unpublished: true}, nil
			},
		},
		{
			Name:    DaemonMethodTlsStatus,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonTlsStatusParams{}
				if err := decodeDaemonSocketParams(call, params); err != nil {
					return nil, err
				}
				reply := &DaemonTlsStatusReply{
					Publishes:       []*DaemonTlsPublishStatus{},
					Certificates:    []*DaemonTlsCertificateStatus{},
					CtWatchDegraded: call.Sidecar.Status().CtWatchDegraded,
				}
				for _, publish := range call.Sidecar.TlsPublishes() {
					reply.Publishes = append(reply.Publishes, newDaemonTlsPublishStatus(publish))
				}
				for _, certificate := range call.Sidecar.TlsCertificates() {
					reply.Certificates = append(reply.Certificates, &DaemonTlsCertificateStatus{
						CertId:     certificate.CertId,
						CustomHost: certificate.CustomHost,
						State:      string(certificate.State),
						NotAfterMs: certificate.NotAfter.UnixMilli(),
						Presented:  certificate.Presented,
					})
				}
				return reply, nil
			},
		},
	}
}

// Registers the tls methods on this daemon.
func (self *Daemon) RegisterTlsMethods() error {
	for _, method := range DaemonTlsMethods() {
		if err := self.RegisterMethod(method); err != nil {
			return err
		}
	}
	return nil
}
