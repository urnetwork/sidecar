//go:build !ios_extension && !sidecar_http

// Inference's settings, DESIGN-COMPUTE §6's, which INFER's tasks fill. Every limit, size, count, time, interval,
// threshold, retry or budget the component reads is a field here, its default set only in DefaultInferSettings,
// protocol and format limits included; only identifiers stay constants (QD-702). The struct is created empty by the
// compute skeleton (CARCH-M11-01, CONTRACTS C-38), so no later task edits settings.go: SidecarSettings holds it, and
// DefaultSidecarSettings sets it from DefaultInferSettings.
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go).

package sidecar

// DESIGN-COMPUTE §6, inference: the catalog, the router, the local engine and the remote path.
type InferSettings struct {
	// §6.3's names. The longest canonical name, alias or search id a parse reads, in bytes: 96, the bound §7.5's
	// models_list and §9.13's labels put on a name, and twice the longest any provider's catalog gave on 2026-11-23. A
	// longer one is refused before any other work, so the parser is bounded, and a model part whose names would pass
	// it makes no name. A format limit both ends read: the broker's catalog and the policy's names must fit it.
	// Non-positive refuses every name.
	NameMaxByteCount int
	// The longest id a provider gives a model that InferNormalizeModelId reads, in bytes: 256, room for a Hugging
	// Face organization and repository with a revision. A longer id is refused, never cut. Non-positive refuses all.
	ProviderModelIdMaxByteCount int
	// The most ids one InferNormalizeModelId call reads: 4096, some sixty times the largest provider catalog of
	// 2026-11-23 (67 models), so a hostile catalog bounds the work. Non-positive refuses every call with an id.
	ProviderModelIdMaxCount int
	// A model's tool budget (§7.4), the tokens a request's tool schemas and the skill may take, is its context window
	// divided by this: 4, a quarter of the window, as §6.3 and §7.4 set it. Non-positive gives no model a tool budget.
	ToolBudgetWindowDivisor int64

	// §6.5's release manifest. The largest infer_manifest.json a parse reads, in bytes: 4 MiB, room for hundreds of
	// models' entries where a release carries a handful. A larger one is refused before it is decoded.
	ManifestMaxByteCount int
	// The largest file a manifest may list, in bytes: 64 GiB, four times §6.5's largest default (about 16 GB), so a
	// typo cannot list an unbounded download; the manifest's own size of each file bounds what a pull fetches
	// (INFER-M11-06). Non-positive refuses every file.
	ManifestFileMaxByteCount int64

	// §6.5's defaults by memory, best first: InferCatalog.Recommended takes the first whose device classes hold the
	// device's, whose memory floor the device meets, unified where asked, and whose model this device may use. Each
	// floor is the design's: phones with 6 GiB or more get the E2B Gemma 4, laptops with 16 GiB the E4B, desktops with
	// 32 GiB the 12B, and desktops with 48 GiB of unified memory the 26B A4B. Each default also serves the larger
	// classes, so a laptop or desktop below the next floor still gets the largest default its memory fits. Empty
	// recommends nothing.
	LocalDefaults []*InferLocalDefault

	// §6.4's stream. The events a call's channel holds ahead of its reader: 64, a few seconds of a fast local model's
	// deltas at the Harness's 30 renders a second, past which the router holds them, folding text, reasoning and
	// argument deltas, so a slow reader never blocks the engine. Non-positive holds one.
	EventBufferCount int
	// The most a call's held events may come to, in bytes, before the router stops the call, answering canceled: 16
	// MiB, many times the longest answer a model's maximum output gives, so only a reader that stopped reading reaches
	// it, and a stopped reader holds no engine. Non-positive stops a call whose reader falls behind at all.
	EventPendingMaxByteCount int
}

// One of §6.5's defaults by memory: the local model a device of its classes gets with at least its memory.
type InferLocalDefault struct {
	// The canonical name recommended, local-<model>-<effort>.
	Name string
	// The device classes it is for.
	DeviceClasses []InferDeviceClass
	// The least memory the device must have, in bytes.
	MinMemoryByteCount int64
	// Whether the memory must be unified, shared by CPU and GPU.
	UnifiedMemory bool
}

// The component's defaults, the only place one is set.
func DefaultInferSettings() *InferSettings {
	return &InferSettings{
		NameMaxByteCount:            96,
		ProviderModelIdMaxByteCount: 256,
		ProviderModelIdMaxCount:     4096,
		ToolBudgetWindowDivisor:     4,
		ManifestMaxByteCount:        4 * 1024 * 1024,
		ManifestFileMaxByteCount:    64 * 1024 * 1024 * 1024,
		EventBufferCount:            64,
		EventPendingMaxByteCount:    16 * 1024 * 1024,
		LocalDefaults: []*InferLocalDefault{
			{
				Name:               "local-gemma-4-26b-a4b-off",
				DeviceClasses:      []InferDeviceClass{InferDeviceClassDesktop},
				MinMemoryByteCount: 48 * 1024 * 1024 * 1024,
				UnifiedMemory:      true,
			},
			{
				Name:               "local-gemma-4-12b-off",
				DeviceClasses:      []InferDeviceClass{InferDeviceClassDesktop},
				MinMemoryByteCount: 32 * 1024 * 1024 * 1024,
			},
			{
				Name:               "local-gemma-4-e4b-off",
				DeviceClasses:      []InferDeviceClass{InferDeviceClassLaptop, InferDeviceClassDesktop},
				MinMemoryByteCount: 16 * 1024 * 1024 * 1024,
			},
			{
				Name:               "local-gemma-4-e2b-off",
				DeviceClasses:      []InferDeviceClass{InferDeviceClassPhone, InferDeviceClassLaptop, InferDeviceClassDesktop},
				MinMemoryByteCount: 6 * 1024 * 1024 * 1024,
			},
		},
	}
}
