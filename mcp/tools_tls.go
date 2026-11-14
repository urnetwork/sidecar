//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's tls tools (TLS-M5-23; §13.10, D-TLS-5, D-TLS-13, D-MCP-17, I-7, I-8): tls_publish at O and tls_unpublish at
// W, each acting through the call's network as `ur bridge public-tls` does (sidecar.Sidecar's PublishTls and
// UnpublishTls), so a tool's publish passes the same checks, the same §5.4 gate and the same target probe.
//
//   - tls_publish(host, port?, local_port, audience?, expires?, app_mode?, alpn?) publishes 127.0.0.1:<local_port> on
//     <host> of this network. The action is the daemon's own: its CanonicalAction of kind publish is built from the
//     checked arguments, never from the agent's words, and the call's run is what a decision binds. With no active
//     approved grant the result is approval_pending with the approval's id, and the same call after a person approves
//     publishes. In a tainted run the gate takes harness evidence only where the rule names it (owner decision 142),
//     which is the gate's to judge, not this tool's.
//   - tls_unpublish(host, port?) ends this device's publish of the name and revokes the grant its approval activated,
//     the subject's own filing.
//
// A tool publishes only a port on 127.0.0.1: another local address is a person's to name in their own terminal. No
// result holds a key, a token or a certificate's bytes (I-7): a raw link's client key is a file whose path the result
// names.

package mcp

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/urnetwork/sidecar"
)

// What the tls tools act through: *sidecar.Sidecar, or a test's. Safe for concurrent use.
type mcpTlsPublisher interface {
	PublishTls(ctx context.Context, settings *sidecar.TlsPublishSettings) (*sidecar.TlsPublishResult, error)
	UnpublishTls(ctx context.Context, host string, port int, origin sidecar.SidecarActOrigin) error
}

// The tools' refusals, each constant.
var (
	errMcpTlsArguments = NewMcpError(McpCodeInvalidArguments,
		"tls_publish takes a host label or @, a port of 443, 8443, 8883 or 5671, a local_port from 1 to 65535, an audience of members, members-device, link or public, an app_mode of http or raw, and raw only with public or link", false)
	errMcpTlsExpires     = NewMcpError(McpCodeInvalidArguments, "expires is an RFC 3339 time", false)
	errMcpTlsHostTaken   = NewMcpError(McpCodeRefused, "that host is a client's name or the system's: choose another", false)
	errMcpTlsUnavailable = NewMcpError(McpCodeUnavailable, "this daemon cannot publish for tools now: run ur status in your own terminal", false)
	errMcpTlsHeld        = NewMcpError(McpCodeRefused, "no grant covers this publish, and no approval of it could be spent", false)
	errMcpTlsTarget      = NewMcpError(McpCodeRefused, "that local port is not one a publish may reach", false)
	errMcpTlsPublished   = NewMcpError(McpCodeFailedPrecondition, "this daemon already publishes that name: tls_unpublish it first", false)
)

// tls_publish's arguments.
type mcpTlsPublishIn struct {
	// a label, or @ for the network's own name
	Host string `json:"host"`
	// 443, 8443, 8883 or 5671; 443 when absent
	Port int `json:"port,omitempty"`
	// the port on 127.0.0.1 to publish
	LocalPort int `json:"local_port"`
	// members, members-device, link or public; members when absent
	Audience string `json:"audience,omitempty"`
	// RFC 3339; the rule's default when absent
	Expires string `json:"expires,omitempty"`
	// http or raw; http when absent
	AppMode string `json:"app_mode,omitempty"`
	// the ALPN ids served
	Alpn []string `json:"alpn,omitempty"`
}

// tls_publish's data.
type mcpTlsPublishOut struct {
	// published, or approval_pending with approval_id.
	Status     string `json:"status"`
	ApprovalId string `json:"approval_id,omitempty"`
	Url        string `json:"url,omitempty"`
	// The grant's id, hex, where the approval activated one.
	GrantId string `json:"grant_id,omitempty"`
	// A raw link's client key and certificate: the file's path.
	CertFile string `json:"cert_file,omitempty"`
	// RFC 3339; absent for a standing name.
	Expires  string `json:"expires,omitempty"`
	Audience string `json:"audience,omitempty"`
	// "passthrough: key on this device".
	Passthrough string `json:"passthrough,omitempty"`
	// The local port answered the probe.
	Serving bool `json:"serving"`
}

// tls_unpublish's arguments.
type mcpTlsUnpublishIn struct {
	Host string `json:"host"`
	// 443 when absent
	Port int `json:"port,omitempty"`
}

// tls_unpublish's data: unpublished, or not_published when there was nothing to end.
type mcpTlsUnpublishOut struct {
	Status string `json:"status"`
}

func init() {
	registerMcpTools(func(catalog *McpCatalog, server *McpServer) {
		addTlsTools(catalog, server.clock.Now)
	})
}

// A publish's error as a tool answers it: by its constant text, never a name or a path (I-13).
func mcpTlsError(err error) error {
	switch {
	case errors.Is(err, sidecar.ErrTlsPublishInvalid):
		return errMcpTlsArguments
	case errors.Is(err, sidecar.ErrTlsPublishHostTaken):
		return errMcpTlsHostTaken
	case errors.Is(err, sidecar.ErrTlsProbeRefused):
		return errMcpTlsTarget
	case errors.Is(err, sidecar.ErrTlsPublishPublished):
		return errMcpTlsPublished
	case errors.Is(err, sidecar.ErrTlsPublishUnavailable), errors.Is(err, sidecar.ErrTlsComponentAbsent),
		errors.Is(err, sidecar.ErrTlsCertsOffline), errors.Is(err, sidecar.ErrTlsCertsUnconfigured):
		return errMcpTlsUnavailable
	case errors.Is(err, sidecar.ErrSidecarGateDenied), errors.Is(err, sidecar.ErrAclGrantFile):
		return errMcpTlsHeld
	}
	return errMcpFailed
}

// Registers the two tls tools on catalog. now reads the time an expires is measured from.
func addTlsTools(catalog *McpCatalog, now func() time.Time) {
	AddTool(catalog, &McpToolSpec[mcpTlsPublishIn]{
		Name:        "tls_publish",
		Tier:        McpTierOutward,
		Description: "Publishes a port on 127.0.0.1 at a host name of this network over TLS that ends on this device; outward, so it waits for a person's approval unless a grant covers it.",
		Access:      func(call *McpCall, in *mcpTlsPublishIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpTlsPublishIn, result *McpResult) (*mcpTlsPublishOut, error) {
		if in.LocalPort < 1 || 65535 < in.LocalPort {
			return nil, errMcpTlsArguments
		}
		settings := &sidecar.TlsPublishSettings{
			Host:      in.Host,
			Port:      in.Port,
			Target:    "127.0.0.1:" + strconv.Itoa(in.LocalPort),
			Audience:  in.Audience,
			Alpn:      in.Alpn,
			AskedRisk: sidecar.SidecarRiskNormal,
		}
		switch in.AppMode {
		case "", sidecar.TlsPublishAppModeHttp:
		case sidecar.TlsPublishAppModeRaw:
			settings.Tcp = true
		default:
			return nil, errMcpTlsArguments
		}
		if in.Expires != "" {
			expires, err := time.Parse(time.RFC3339, in.Expires)
			if err != nil {
				return nil, errMcpTlsExpires
			}
			settings.Expires = expires.Sub(now())
			if settings.Expires <= 0 {
				return nil, errMcpTlsExpires
			}
		}
		publisher, ok := call.Network.(mcpTlsPublisher)
		if !ok {
			return nil, errMcpTlsUnavailable
		}
		// the decision binds this call's run
		runId := call.RunId
		settings.RunId = &runId
		result.SetSource("tls:publish")
		published, err := publisher.PublishTls(ctx, settings)
		var pending *sidecar.ApprovalPendingError
		if errors.As(err, &pending) {
			return &mcpTlsPublishOut{Status: "approval_pending", ApprovalId: pending.ApprovalId.String()}, nil
		}
		if err != nil {
			return nil, mcpTlsError(err)
		}
		out := &mcpTlsPublishOut{
			Status:      "published",
			Url:         published.Url,
			GrantId:     hex.EncodeToString(published.GrantId),
			CertFile:    published.ClientCertificateFile,
			Audience:    published.Audience,
			Passthrough: published.Passthrough,
			Serving:     published.Serving,
		}
		if !published.Expires.IsZero() {
			out.Expires = published.Expires.UTC().Format(time.RFC3339)
		}
		return out, nil
	})

	AddTool(catalog, &McpToolSpec[mcpTlsUnpublishIn]{
		Name:        "tls_unpublish",
		Tier:        McpTierWrite,
		Description: "Ends this device's publish of a host name and revokes the grant its approval activated.",
		Access:      func(call *McpCall, in *mcpTlsUnpublishIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpTlsUnpublishIn, result *McpResult) (*mcpTlsUnpublishOut, error) {
		publisher, ok := call.Network.(mcpTlsPublisher)
		if !ok {
			return nil, errMcpTlsUnavailable
		}
		result.SetSource("tls:unpublish")
		err := publisher.UnpublishTls(ctx, in.Host, in.Port, sidecar.SidecarActMcp)
		if errors.Is(err, sidecar.ErrTlsPublishAbsent) {
			return &mcpTlsUnpublishOut{Status: "not_published"}, nil
		}
		if err != nil {
			return nil, mcpTlsError(err)
		}
		return &mcpTlsUnpublishOut{Status: "unpublished"}, nil
	})
}
