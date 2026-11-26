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

import (
	"time"
)

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

	// §6.5's engine helper, ur-engine. The longest request line the daemon sends the helper and the helper reads, in
	// bytes: 64 MiB, a whole conversation with its images, which the gateway bounds at 32 MiB of body (§8.7) and base64
	// grows by a third. A protocol limit both ends read from these settings. Non-positive refuses every request.
	EngineRequestMaxByteCount int
	// The longest answer line the helper writes and the daemon reads, in bytes: 1 MiB, far past any delta or a tool
	// call's arguments as the engine parses them. A line past it ends the helper. Non-positive refuses every answer.
	EngineAnswerMaxByteCount int
	// The helpers the daemon runs at once, one a loaded model: 2, so a second model loads beside a first without
	// unloading it, and a third stops the least recently used idle one. Non-positive starts none.
	EngineProcessMaxCount int
	// The most engines of one model a helper holds, each running one call at a time: 2, §6.5's "up to two on a desktop
	// with the memory for both", a second only where the device's memory holds the model's minimum twice over. Below 2
	// holds one.
	EngineInstanceMaxCount int
	// How long a helper may take to load its model: 5 minutes, a 16 GB model read from a slow disk. Past it the helper is
	// ended and the call answers engine_failed. Non-positive ends every load at once.
	EngineLoadTimeout time.Duration
	// How long a canceled call's helper may take to stop it before the helper is ended, which frees its engine: 10
	// seconds, many times a stream's cancel. Non-positive ends the helper at once.
	EngineCancelTimeout time.Duration
	// How long a helper asked to exit, its input closed, may take before it is killed: 5 seconds. Non-positive kills it
	// at once.
	EngineStopTimeout time.Duration
	// §6.5's confinement on Linux (INFER-M11-05; infer_engine_confine_linux.go): the system's paths the helper may read
	// beneath once Landlock holds it, beside its engine and model directories, each passed over where it is not there:
	// the loader's libraries and cache, the GPU's loaders and their tables, and the processor, memory and device facts
	// the engine and its GPU drivers read. Nothing beneath any is writable. Other OSes read none of it.
	EngineConfineSystemReadPaths []string
	// The device nodes the helper may open to read and write, with ioctl where the kernel's Landlock handles it, each
	// passed over where it is not there: the GPU's render nodes and NVIDIA's and AMD's compute nodes, and the null,
	// zero and random devices libraries open. A device node holds no file, so nothing on disk becomes writable.
	EngineConfineDevicePaths []string
	// The bytes of a helper's stderr the daemon keeps for its log when the helper ends: 64 KiB. Non-positive keeps none.
	EngineStderrMaxByteCount int

	// §6.5's engine files on a desktop (INFER-M11-06's InferPull): the C library, its GPU plugins and Dawn, each whole
	// from LiteRT-LM's release at the manifest's https url. How long one file's download may take: 30 minutes, an
	// 85 MB library on a link under half a megabit a second. Past it the pull stops with download_unavailable.
	EngineDownloadTimeout time.Duration
	// The redirects one engine file's request may follow: 3, room for a release asset's redirect to its storage host.
	// Each must be https, to the url's own host or one under EngineDownloadRedirectHostSuffixes.
	EngineDownloadRedirectMaxCount int
	// The hosts an engine file's request may be redirected to besides the url's own, each a domain matching itself and
	// every name under it: GitHub's and its release assets' storage, as LiteRT-LM's release serves them on 2026-11-25.
	EngineDownloadRedirectHostSuffixes []string

	// §6.5's app host (INFER-M11-06's inferHostEngine). The models the app's engine holds loaded at once: 1, a phone's
	// memory holding one model, so a second model's call unloads the first once it is idle.
	HostLoadedModelMaxCount int

	// §6.5's phones in the background (INFER-M11-06's InferRouter.Background). How long a call in flight may run on
	// once an iOS app leaves the foreground, where the app names no grant of its own: 30 seconds, a background task's
	// time. Past it the call is cancelled; a local call on the GPU is cancelled at once, since iOS gives a background
	// app no GPU. Also the grant where the device is not known, the shorter of the two.
	BackgroundIosGrant time.Duration
	// The same on Android: 3 minutes, a short foreground service's time.
	BackgroundAndroidGrant time.Duration

	// §6.5's model downloads (CO-49): the chunk index's format (compute-plan-model-index-format, QD-1408), whose bounds
	// are format limits both ends read, the release tooling and the api's mirror (CSRV-M11-01, CSRV-M11-02) as every
	// device and the browser's engine Worker (INFER-M13-02) does. The chunk size InferModelIndexBuild writes an index
	// with, in bytes: 16 MiB, §6.5's, the last chunk shorter. Non-positive builds no index.
	ModelChunkByteCount int64
	// The least chunk size an index may name, in bytes: 1 MiB, a sixteenth of ModelChunkByteCount, so an index stays
	// within ModelIndexMaxByteCount for any file a manifest may list at a size the release could still choose. An index
	// naming less is refused, and InferModelIndexBuild builds none.
	ModelChunkMinByteCount int64
	// The most chunk size an index may name, in bytes: 64 MiB, four times ModelChunkByteCount, the most one chunk the
	// download holds in memory before its check, ModelChunkFetchConcurrency times over. An index naming more is refused,
	// and InferModelIndexBuild builds none.
	ModelChunkMaxByteCount int64
	// The largest index a parse reads, in bytes: 1 MiB. An index takes about 67 bytes a chunk, so a 64 GiB file's at
	// 16 MiB chunks (4096 chunks, about 270 KiB) fits nearly four times over. A larger one is refused before it is hashed,
	// and InferModelIndexBuild builds none. Non-positive refuses every index.
	ModelIndexMaxByteCount int

	// §6.5's download (INFER-M11-11), every Go host's. The chunks fetched at once: 4, §6.5's "up to four at a time".
	// Below 1 fetches one at a time.
	ModelChunkFetchConcurrency int
	// How many more times a chunk that fails its check, or the index that fails its pin, is fetched before the download
	// stops with download_corrupt naming it: 2, §6.5's "fetched again, twice". Negative counts as 0.
	ModelChunkRetryCount int
	// The timeouts and 5xx answers in a row, a connection dropped mid-answer among them, after which the api counts as
	// unreachable and the chunks come from the hub (D-INFER-12): 3, so one slow answer or a restart of one api host does
	// not move a download. A connection refused, no route or no name counts as unreachable at once. Below 1 counts the
	// api unreachable at its first.
	ModelApiUnreachableCount int
	// How long the index's fetch may take, its answer read whole: 30 seconds, an index being at most a megabyte.
	// Past it the fetch counts as unanswered. Non-positive leaves only the caller's context.
	ModelIndexTimeout time.Duration
	// How long one chunk's fetch may take, its answer read whole: 5 minutes, a 16 MiB chunk on a link under half a
	// megabit a second, the api's own write deadline for one (CSRV-M11-01). As ModelIndexTimeout past it or when
	// non-positive.
	ModelChunkTimeout time.Duration
	// The room a download needs beyond what it has left to write, as a fraction of the file's size: 0.1, so a fresh
	// download starts only with the file's size free and a tenth more (§6.5), as the browser's probe asks. Negative
	// counts as 0.
	ModelFreeSpaceMarginFraction float64
	// How long a download waits before it asks a source again after a timeout, a 5xx or a dropped connection: 2
	// seconds. Non-positive asks again at once.
	ModelFetchRetryInterval time.Duration
	// The longest Retry-After a 429 is waited out for: 1 minute, the api's per-address window (CSRV-M11-01). A longer
	// one is waited this long; a 429 with none waits ModelFetchRetryInterval.
	ModelRetryAfterMaxDuration time.Duration
	// The 429s in a row one chunk or the index may take before the download stops with download_unavailable: 10, ten
	// windows of the api's limit with no progress. Negative counts as 0.
	ModelRateLimitedMaxCount int

	// §6.5's fallback (D-INFER-12): where the api cannot be reached, the daemon and the apps take the same chunks from
	// the manifest's Hugging Face URL at its pinned commit, by Range requests, checked against the same index; the
	// browser never does (its download is JS, INFER-M13-02). Whether this host falls back: true, every Go host's.
	ModelHubFallback bool
	// While the chunks come from the hub, how often the api is asked again whether it answers, before a chunk, so the
	// download goes back to it at the next chunk once it does: 30 seconds. Non-positive asks before every chunk.
	ModelApiProbeInterval time.Duration
	// The failed requests in a row at the hub, timeouts, 5xx answers and dropped or refused connections alike, before
	// the download stops with download_unavailable: 3. Below 1 stops at the first.
	ModelHubFailureMaxCount int
	// The redirects one hub request may follow: 3, room for a renamed repository's and the hub's redirect to its CDN.
	// Each must be https, to the manifest URL's own host or to one under ModelHubRedirectHostSuffixes. Negative counts
	// as 0.
	ModelHubRedirectMaxCount int
	// The hosts a hub request may be redirected to besides the manifest URL's own: each a domain, matching itself and
	// every name under it, Hugging Face's own and its CDN's as of 2026-11-25 (huggingface.co, and hf.co, which serves
	// its large files). Every other redirect is refused. Empty allows the manifest URL's own host alone.
	ModelHubRedirectHostSuffixes []string

	// ur.io's browser view of the catalog (INFER-M13-01; §6.5's In the browser block, Q-INFER-9). The least
	// navigator.deviceMemory, in GiB as the browser reports it, at which local-gemma-4-e4b-off is offered beside the
	// E2B default: 16. Where the browser reports none, as Safari, the E4B is listed for the person to choose, with the
	// memory it needs. Non-positive offers it wherever the probe passes.
	BrowserLargeModelMemoryGiB float64
	// The least decode rate a browser's first-load test turn must reach, in tokens a second, below which local models
	// are marked unavailable in that browser until its version or the engine's changes: 8. Non-positive marks none
	// unavailable for its rate.
	BrowserMinDecodeTokensPerSecond float64

	// §6.6's member cache secret (INFER-M12-02; infer_cache_secret.go). How long a secret this device holds serves
	// before cache.json is read again: 5 minutes. That read is the sync at which a device that holds the secret seals a
	// copy to each newly listed device and answers asks, and at which the first device to see that one which held a
	// copy left the readers draws a new secret, so a revocation's new secret reaches the member's devices within a sync
	// of their next remote calls. Non-positive reads at every call.
	CacheSecretSyncInterval time.Duration
	// The most of the member's own secret repos one sync opens to find the one whose cache.json stands: 64, past the
	// 16 connections, 8 calendar links and the ACME key's repo a member holds at most beside the cache's own. Repos
	// past it, in id order, are not opened. Non-positive opens none, and the device salts with a secret of its own.
	CacheSecretRepoScanMaxCount int
	// The largest cache.json a read takes, in bytes: 1 MiB, about 600 devices' sealed copies. A larger one is read as
	// no file of the format, which a device that may draw replaces. Non-positive takes none.
	CacheFileMaxByteCount int
	// The most copies, and the most asks, one cache.json holds: 512 each, past any member's devices and their agents'
	// enclaves. A file past either is read as one larger than CacheFileMaxByteCount is.
	CacheFileMaxEntryCount int
	// How many times a sync whose write lost to another device's, the write being conditional on the version it read
	// (EXACT_HEAD), reads cache.json again and decides again: 3. Past it the sync keeps what it read, and the next
	// tries again. Negative counts as 0.
	CacheSecretWriteRetryCount int
	// How long an agents' enclave's remote call waits for a copy of the member's secret sealed to it, which a sponsor's
	// device seals at its next sync after the enclave's ask: 2 minutes, past a sync's interval and a slow EVS round.
	// Past it the call is refused, the secret pending. Non-positive does not wait.
	CacheSecretEnclaveWaitTimeout time.Duration
	// How often a waiting enclave reads cache.json again for its copy: 10 seconds. Non-positive reads again at once.
	CacheSecretEnclaveWaitInterval time.Duration
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
		EngineRequestMaxByteCount:   64 * 1024 * 1024,
		EngineAnswerMaxByteCount:    1024 * 1024,
		EngineProcessMaxCount:       2,
		EngineInstanceMaxCount:      2,
		EngineLoadTimeout:           5 * time.Minute,
		EngineCancelTimeout:         10 * time.Second,
		EngineStopTimeout:           5 * time.Second,
		EngineConfineSystemReadPaths: []string{
			"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib",
			"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
			"/usr/share/vulkan", "/etc/vulkan", "/usr/share/glvnd", "/usr/share/drirc.d", "/etc/drirc", "/usr/share/libdrm",
			"/proc/cpuinfo", "/proc/meminfo", "/proc/driver/nvidia",
			"/sys/devices", "/sys/bus/pci", "/sys/class/drm", "/sys/dev/char",
		},
		EngineConfineDevicePaths: []string{
			"/dev/dri", "/dev/kfd", "/dev/nvidiactl", "/dev/nvidia-uvm", "/dev/nvidia-uvm-tools",
			"/dev/nvidia0", "/dev/nvidia1", "/dev/nvidia2", "/dev/nvidia3",
			"/dev/null", "/dev/zero", "/dev/urandom",
		},
		EngineStderrMaxByteCount:           64 * 1024,
		EngineDownloadTimeout:              30 * time.Minute,
		EngineDownloadRedirectMaxCount:     3,
		EngineDownloadRedirectHostSuffixes: []string{"github.com", "githubusercontent.com"},
		HostLoadedModelMaxCount:            1,
		BackgroundIosGrant:                 30 * time.Second,
		BackgroundAndroidGrant:             3 * time.Minute,
		ModelChunkByteCount:                16 * 1024 * 1024,
		ModelChunkMinByteCount:             1024 * 1024,
		ModelChunkMaxByteCount:             64 * 1024 * 1024,
		ModelIndexMaxByteCount:             1024 * 1024,
		ModelChunkFetchConcurrency:         4,
		ModelChunkRetryCount:               2,
		ModelApiUnreachableCount:           3,
		ModelIndexTimeout:                  30 * time.Second,
		ModelChunkTimeout:                  5 * time.Minute,
		// a tenth
		ModelFreeSpaceMarginFraction:    0.1,
		ModelFetchRetryInterval:         2 * time.Second,
		ModelRetryAfterMaxDuration:      time.Minute,
		ModelRateLimitedMaxCount:        10,
		ModelHubFallback:                true,
		ModelApiProbeInterval:           30 * time.Second,
		ModelHubFailureMaxCount:         3,
		ModelHubRedirectMaxCount:        3,
		ModelHubRedirectHostSuffixes:    []string{"huggingface.co", "hf.co"},
		BrowserLargeModelMemoryGiB:      16,
		BrowserMinDecodeTokensPerSecond: 8,
		CacheSecretSyncInterval:         5 * time.Minute,
		CacheSecretRepoScanMaxCount:     64,
		CacheFileMaxByteCount:           1024 * 1024,
		CacheFileMaxEntryCount:          512,
		CacheSecretWriteRetryCount:      3,
		CacheSecretEnclaveWaitTimeout:   2 * time.Minute,
		CacheSecretEnclaveWaitInterval:  10 * time.Second,
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
