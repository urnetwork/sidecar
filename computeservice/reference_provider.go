// The reference provider (DESIGN-COMPUTE §11.3, D-ENC-2, CO-21): the enclave stack's provider before any Bittensor
// provider passes its gate, Google Cloud's confidential VMs with Intel TDX and an AMD SEV-SNP host URnetwork runs, for
// development, CI and staging alone. It meets EPC-1 to EPC-6 but not EPC-7, so no user is ever offered it: a registry
// builds it only in a development, CI or staging env, an engine whose settings would enable it in production refuses
// to start (provider_settings.go), the production catalog lists none of its shapes and the production policy none of
// its profiles, so a user's device refuses its evidence.
//
// This file is its adapter's shell, PROV's: it offers no inference, takes no payment, and forwards every VM call and
// its catalog of shapes to ComputeEnclaveSide, ENC's VM side (ENC-M14-20's TDX half and ENC-M14-21's SEV-SNP half,
// registered from ENC's computeservice/provider_enclave_reference.go through registerComputeEnclaveSide). With no side
// registered, every call answers ErrComputeNotOffered and its catalog holds no shape.
//
// The side's registration is written only during the package's init, so read without a lock after it. The adapter is
// safe for concurrent use as its side is.

package computeservice

import (
	"context"
	"fmt"
	"slices"
)

// The reference provider's VM side, ENC's (§11.3, §11.7): its shapes and prices, and each VM call of §4.6. Safe for
// concurrent use.
type ComputeEnclaveSide interface {
	// The shapes it offers now and their prices: its Catalog, with no model.
	Catalog(ctx context.Context) (*ComputeProviderCatalog, error)
	CreateVm(ctx context.Context, spec *ComputeVmSpec) (*ComputeVm, error)
	VmEvidence(ctx context.Context, vmId string, nonce []byte) (*ComputeEvidence, error)
	VmStatus(ctx context.Context, vmId string) (*ComputeVm, error)
	DeleteVm(ctx context.Context, vmId string) error
}

// Builds the reference provider's VM side for one registry, from the same args an adapter takes: its credentials are
// the reference provider's section of compute-providers.yml.
type ComputeEnclaveSideConstructor func(args *ComputeProviderArgs) (ComputeEnclaveSide, error)

// ENC's side, nil until registered.
var computeEnclaveSideRegistration ComputeEnclaveSideConstructor

// Registers the reference provider's VM side, from an init function in ENC's own file. A second registration, or a nil
// constructor, is a build error, which panics.
func registerComputeEnclaveSide(construct ComputeEnclaveSideConstructor) {
	if construct == nil || computeEnclaveSideRegistration != nil {
		panic("the reference provider's enclave side registered twice or without a constructor")
	}
	computeEnclaveSideRegistration = construct
}

// The reference provider's registration, from its own file as every adapter's.
func init() {
	registerComputeProvider(ComputeProviderIdReference, constructReferenceProvider)
}

// The registry's constructor: refused outside development, CI and staging, whatever the settings say, then the
// provider over ENC's side where one is registered.
func constructReferenceProvider(args *ComputeProviderArgs) (ComputeProvider, error) {
	return constructReferenceProviderWith(args, computeEnclaveSideRegistration)
}

// constructReferenceProvider with side's constructor, nil for none.
func constructReferenceProviderWith(args *ComputeProviderArgs, side ComputeEnclaveSideConstructor) (ComputeProvider, error) {
	kind := args.Settings.EnvironmentKind(args.Settings.Environment)
	if !slices.Contains(computeReferenceDeploymentKinds, kind) {
		return nil, fmt.Errorf("the reference provider serves development, CI and staging alone, and %q is %s (D-ENC-2, CO-21)", args.Settings.Environment, kind)
	}
	if side == nil {
		return NewReferenceProvider(nil), nil
	}
	enclave, err := side(args)
	if err != nil {
		return nil, err
	}
	return NewReferenceProvider(enclave), nil
}

// The reference provider over enclave, ENC's VM side; nil offers no VM call and no shape.
func NewReferenceProvider(enclave ComputeEnclaveSide) ComputeProvider {
	return &referenceProvider{
		ComputeProviderBase: ComputeProviderBase{ProviderId: ComputeProviderIdReference},
		enclave:             enclave,
	}
}

// The reference provider: inference not offered (embedded), its VM calls forwarded.
type referenceProvider struct {
	ComputeProviderBase
	enclave ComputeEnclaveSide
}

// The side's shapes, as this provider's; no shape without a side.
func (self *referenceProvider) Catalog(ctx context.Context) (*ComputeProviderCatalog, error) {
	if self.enclave == nil {
		return &ComputeProviderCatalog{Provider: ComputeProviderIdReference}, nil
	}
	catalog, err := self.enclave.Catalog(ctx)
	if err != nil {
		return nil, err
	}
	if catalog == nil {
		return nil, fmt.Errorf("the reference provider's enclave side answered no catalog")
	}
	if 0 < len(catalog.Models) {
		return nil, fmt.Errorf("the reference provider's enclave side answered models, and it serves no inference")
	}
	shapes := slices.Clone(catalog.Shapes)
	return &ComputeProviderCatalog{
		Provider:     ComputeProviderIdReference,
		GammaNanoUsd: catalog.GammaNanoUsd,
		Shapes:       shapes,
	}, nil
}

// The side's, or not offered.
func (self *referenceProvider) CreateVm(ctx context.Context, spec *ComputeVmSpec) (*ComputeVm, error) {
	if self.enclave == nil {
		return nil, ErrComputeNotOffered
	}
	return self.enclave.CreateVm(ctx, spec)
}

// The side's, or not offered.
func (self *referenceProvider) VmEvidence(ctx context.Context, vmId string, nonce []byte) (*ComputeEvidence, error) {
	if self.enclave == nil {
		return nil, ErrComputeNotOffered
	}
	return self.enclave.VmEvidence(ctx, vmId, nonce)
}

// The side's, or not offered.
func (self *referenceProvider) VmStatus(ctx context.Context, vmId string) (*ComputeVm, error) {
	if self.enclave == nil {
		return nil, ErrComputeNotOffered
	}
	return self.enclave.VmStatus(ctx, vmId)
}

// The side's, or not offered.
func (self *referenceProvider) DeleteVm(ctx context.Context, vmId string) error {
	if self.enclave == nil {
		return ErrComputeNotOffered
	}
	return self.enclave.DeleteVm(ctx, vmId)
}
