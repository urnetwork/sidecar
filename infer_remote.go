//go:build !ios_extension && !sidecar_http

// The remote paths' seam (DESIGN-COMPUTE §6.6): the TEE path (INFER-M15-01) and the direct path (INFER-M12-03) each
// register for their catalog kind from their own files, at init, through registerInferRemotePath, so no later task
// edits the router's files and the router's own files never name a path or a provider. The remote catalog
// (INFER-M12-01) registers the same way, through registerInferRemoteCatalog. A Sidecar's router constructs each
// registration once, as its compute component constructs; a kind no registration serves answers model_refused naming
// the kind, and a constructor's error leaves its kind refusing on that Sidecar.
//
// A path is called only after the router's checks passed and only with the call they passed; it answers by emitting
// the events of InferEmit and returning nil at the call's end or the call's error, which the router turns into the
// stream's one terminal event. It never changes the model, its provider or its label: a failure is its caller's to
// handle (R-INFER-3), though within one remote model a path may move to another instance that passes §5 (§6.4).
//
// The registrations are written only during the package's init, so read without a lock after it.

package sidecar

import (
	"context"
	"fmt"
	"slices"
)

// How an engine or a path hands the router its events. It never blocks: the router holds what its reader has not
// taken. An engine or a path calls it from any goroutine, never after its call has returned, and never with error or
// end, which are the router's; an event of a kind it may not emit, or with fields beyond its kind's, is dropped or
// stripped (inferEventEmitted).
type InferEmit func(event *InferEvent)

// One call the router resolved and checked, as an engine or a path receives it.
type InferCall struct {
	// The request as its caller gave it: read, never changed.
	Request *InferRequest
	// The model's catalog entry, a copy.
	Entry *InferCatalogEntry
	// The effort the call runs at, one the entry lists: the name's own, or an alias's mapped to the nearest listed
	// (§6.3). A path maps it onto its provider's own parameter by its adapter's table (§6.4), never to an effort the
	// model does not list.
	Effort InferEffort
	// The canonical name the call runs under, its effort included, which the record and the badge name.
	Name string
	// The newest verified compute policy the checks read, which a remote path uses as they did; nil for a local call.
	Policy *ComputePolicy
}

// A remote path: §6.6's TEE path or direct path.
type InferRemotePath interface {
	// Runs one call the router checked: emits its events, the attestation before its first token on the TEE path, and
	// returns nil at its end or why it failed, an *InferError where it can say which. Returns promptly once ctx ends.
	Infer(ctx context.Context, call *InferCall, emit InferEmit) error
}

// What builds a remote path for one Sidecar: the path's own constructor, which reads the Sidecar's settings, broker
// client and gate at use, never while it constructs.
type InferRemotePathConstructor func(sidecar *Sidecar, settings *InferSettings) (InferRemotePath, error)

// One kind's registration.
type inferRemotePathRegistration struct {
	kind      InferCatalogKind
	construct InferRemotePathConstructor
}

// Every remote path's registration, in the order the files' init functions made them.
var inferRemotePathRegistrations = []*inferRemotePathRegistration{}

// Registers the remote path for kind, tee or direct, from an init function in the path's own file. Another kind, a nil
// constructor or a kind registered twice is a build error, which panics as registerComputeComponent does.
func registerInferRemotePath(kind InferCatalogKind, construct InferRemotePathConstructor) {
	registered := slices.ContainsFunc(inferRemotePathRegistrations, func(registration *inferRemotePathRegistration) bool {
		return registration.kind == kind
	})
	if (kind != InferCatalogKindTee && kind != InferCatalogKindDirect) || construct == nil || registered {
		panic(fmt.Sprintf("remote inference path %q registered twice, for no remote kind or without a constructor", kind))
	}
	inferRemotePathRegistrations = append(inferRemotePathRegistrations, &inferRemotePathRegistration{
		kind:      kind,
		construct: construct,
	})
}

// The remote catalog's entries, joined with the newest verified policy (§6.3, INFER-M12-01).
type InferRemoteCatalog interface {
	// The remote entries and search endpoints this device may list now: each whole, none local. An error lists no
	// remote entry, and the catalog says why.
	Entries(ctx context.Context) ([]*InferCatalogEntry, error)
}

// What builds the remote catalog for one Sidecar.
type InferRemoteCatalogConstructor func(sidecar *Sidecar, settings *InferSettings) (InferRemoteCatalog, error)

// The remote catalog's registration, nil until one registers.
var inferRemoteCatalogRegistration InferRemoteCatalogConstructor

// Registers the remote catalog, from an init function in its own file. A second registration, or a nil constructor,
// is a build error, which panics.
func registerInferRemoteCatalog(construct InferRemoteCatalogConstructor) {
	if construct == nil || inferRemoteCatalogRegistration != nil {
		panic("remote inference catalog registered twice or without a constructor")
	}
	inferRemoteCatalogRegistration = construct
}

// What the registered paths came to on one Sidecar: each kind's path, or why there is none.
type inferRemotePaths struct {
	paths map[InferCatalogKind]InferRemotePath
	// why a registered kind has no path here
	errs map[InferCatalogKind]error
}

// Constructs each registration for sidecar. A constructor's error is its kind's for good on this Sidecar, and the
// others construct regardless.
func newInferRemotePaths(sidecar *Sidecar, settings *InferSettings, registrations []*inferRemotePathRegistration) *inferRemotePaths {
	remotePaths := &inferRemotePaths{
		paths: map[InferCatalogKind]InferRemotePath{},
		errs:  map[InferCatalogKind]error{},
	}
	for _, registration := range registrations {
		path, err := registration.construct(sidecar, settings)
		switch {
		case err != nil:
			remotePaths.errs[registration.kind] = err
		case path == nil:
			remotePaths.errs[registration.kind] = errComputeComponentNil
		default:
			remotePaths.paths[registration.kind] = path
		}
	}
	return remotePaths
}

// The path for kind, or model_refused naming the kind and why it has none.
func (self *inferRemotePaths) path(kind InferCatalogKind) (InferRemotePath, *InferError) {
	if path, ok := self.paths[kind]; ok {
		return path, nil
	}
	if err, ok := self.errs[kind]; ok {
		return nil, newInferError(InferErrorModelRefused, "the %s path did not construct here: %s", kind, err)
	}
	return nil, newInferError(InferErrorModelRefused, "this build has no %s path", kind)
}
