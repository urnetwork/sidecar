//go:build !ios_extension && !sidecar_http

// The app's local engine seam (DESIGN-COMPUTE §6.5, §3.3, §15.3; INFER-M11-06): what an app that embeds LiteRT-LM
// implements for the core, SidecarLocalInferenceHost, exactly as §6.5 writes it, strings and int64 alone, and the
// safety classifier's host as §15.3 writes it, which SAFE's code uses (§27.5). They live here, where §3.3 puts the sdk
// host seam, so the core never imports the sdk; gomobile binds only the sdk's own types, so the sdk declares twins of
// both (sdk/sidecar_compute_host.go) and adapts its inference twin to this interface
// (sdk/sidecar_compute_host_inference.go; CONTRACTS C-39). The engine runs in the app's process alone, never in its VPN
// component (owner decision 197).
//
// The JSON the host takes and gives is the contract with the apps:
//
//	Capabilities()  {"platform": "ios/arm64", "class": "phone", "memory_byte_count": ..., "unified_memory": true,
//	                "accelerators": ["gpu", "npu"], "gpu": "Adreno 750"}: InferDeviceCapabilities' members, and the
//	                GPU's name, which says whether its activations must run FP32
//	Load            the whole model file's path, never a part (InferModelFile), and {"backend": "cpu"|"gpu",
//	                "max_token_count": n, "activations": "fp32"}: FP32 on iOS's GPUs and Adreno's, whose FP16
//	                activations corrupt digits past 2-4K tokens (#3913, #4001), and the engine's own choice elsewhere
//	Generate        {"conversation", "messages", "tools", "tool_choice", "schema", "max_output", "sampling",
//	                "effort"}: the desktop helper's generate params without the handle (infer_engine_protocol.go), the
//	                conversation the core's opaque key for an agent's, never a run's or an agent's id; the events come
//	                to the listener as InferEvent JSON, ending in exactly one end or error
//	Cancel          stops the generation in flight, which then ends with an error event
//
// Sidecar.SetLocalInferenceHost makes a host the router's local engine (infer_host_engine.go), and Sidecar.InferPull
// pulls the models it loads into the app's state directory (infer_pull.go). Nothing here sends a request to a server
// for inference (IC-5): a local call stays in the app's process.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
)

// The app's local inference engine (§6.5): LiteRT-LM embedded in the app, on iOS, macOS and Android, which the router
// calls for local models. Its methods are called from any goroutine, never under a lock of the core's, and must be
// safe for concurrent use.
type SidecarLocalInferenceHost interface {
	// JSON: the platform, its RAM and accelerators.
	Capabilities() string
	// Loads the model whose whole file is at modelPath with settingsJson's engine settings, answering a handle.
	Load(modelPath string, settingsJson string) (int64, error)
	// Runs requestJson on handle's model, its events to listener, ending in exactly one end or error event, until it
	// ends, Cancel or Unload.
	Generate(handle int64, requestJson string, listener SidecarLocalInferenceListener) error
	// Stops handle's generation in flight.
	Cancel(handle int64)
	// Frees handle's model.
	Unload(handle int64)
}

// A local generation's events.
type SidecarLocalInferenceListener interface {
	// One InferEvent, as JSON.
	OnEvent(eventJson string)
}

// The app's safety classifier (§27.5, §15.3): a reduced ONNX Runtime embedded in the app, which scores what a run read
// for injected instructions. Declared here for SAFE, whose code implements its use (SAFE-M13-04).
type SidecarSafetyClassifierHost interface {
	// Loads the classifier at modelPath, answering a handle.
	Load(modelPath string) (int64, error)
	// Scores idsJson's token id windows on handle's model: two logits a window, as JSON.
	Classify(handle int64, idsJson string) (string, error)
	Unload(handle int64)
}

// The directories the local half keeps its files in: the models, by their SHA-256 (InferModelDownload), and on a
// desktop the engine's libraries, by their manifest names; an app's inside its <state>, beside §5.9's tree, a desktop
// instance's inside its own folder of InferDesktopLocalDirectory. Format values: every build of an instance reads the
// same tree.
const (
	inferModelDirectoryName  = "models"
	inferEngineDirectoryName = "engine"
)

// The folder beside a desktop's instance state directories that holds each instance's engine and model files and
// nothing else (question infer-m11-05-macos-instance-directories, option 1): no instance can be named so, since an
// instance's name is [a-z0-9][a-z0-9-]{0,31}. The macOS helper's sandbox names it once, as one read-only exception
// (build/all/ur/macos/ur-engine.entitlements), so every instance's helper reads its files and none reads an instance's
// state; Landlock and the AppContainer grant an instance's two directories alone. A format value.
const inferDesktopLocalDirectoryName = "_local"

// The folder a desktop instance whose state is state (<ur>/<instance>, SidecarStateDirectory's) keeps its engine and
// model files in: <ur>/_local/<instance>, outside its state, which the helper must not read.
func InferDesktopLocalDirectory(state string) string {
	state = filepath.Clean(state)
	return filepath.Join(filepath.Dir(state), inferDesktopLocalDirectoryName, filepath.Base(state))
}

// The directory of local the model files are kept in: <local>/models, an app's <state>/models, a desktop instance's
// <ur>/_local/<instance>/models.
func InferModelDirectory(local string) string {
	return filepath.Join(local, inferModelDirectoryName)
}

// The directory of local a desktop's engine files are kept in: <ur>/_local/<instance>/engine.
func InferEngineDirectory(local string) string {
	return filepath.Join(local, inferEngineDirectoryName)
}

// No directory to keep model files in: this Sidecar's state is not on a disk, as the page Worker's and a test's
// memory store are not.
var ErrInferNoModelDirectory = errors.New("this sidecar keeps no files on a disk, so it pulls and loads no local model")

// The instance's state directory on its disk, where the local half keeps its files.
func (self *Sidecar) inferStateDirectory() (string, error) {
	if self.instance == nil {
		return "", ErrInferNoModelDirectory
	}
	backend, ok := self.instance.backend.(*osStoreBackend)
	if !ok {
		return "", ErrInferNoModelDirectory
	}
	return backend.directory, nil
}

// The name the local half's component registers under: the app's host engine and the pull over the state directory.
const computeInferLocalComponentName = "infer_local"

// Registers the local half's component, which every Sidecar on a compute leg then constructs.
func init() {
	registerComputeComponent(computeInferLocalComponentName, newSidecarInferLocal, func(component *sidecarInferLocal) {
		component.close()
	})
}

// A Sidecar's local half on an app's host: the host's engine while one is set, and the pull over <state>/models, made
// at its first use. Safe for concurrent use.
type sidecarInferLocal struct {
	sidecar *Sidecar

	stateLock sync.Mutex
	engine    *inferHostEngine
	pull      *InferPull
	closed    bool
}

// The component for sidecar; it reads the state directory and the api at use.
func newSidecarInferLocal(sidecar *Sidecar) (*sidecarInferLocal, error) {
	return &sidecarInferLocal{sidecar: sidecar}, nil
}

// Ends the host engine's models, at the Sidecar's end.
func (self *sidecarInferLocal) close() {
	engine := func() *inferHostEngine {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		engine := self.engine
		self.engine = nil
		return engine
	}()
	if engine != nil {
		engine.close()
	}
}

// The pull over the state directory's models, made at the first call: an app's, which has no engine directory, since
// its engine is in its bundle. Its device is the router's local engine's.
func (self *sidecarInferLocal) inferPull() (*InferPull, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, ErrSidecarClosed
	}
	if self.pull != nil {
		return self.pull, nil
	}
	state, err := self.sidecar.inferStateDirectory()
	if err != nil {
		return nil, err
	}
	if self.sidecar.sidecarApi == nil {
		return nil, errors.New("this sidecar has no api client to pull models through")
	}
	settings := self.sidecar.settings.Infer
	if settings == nil {
		settings = DefaultInferSettings()
	}
	pull, err := NewInferPull(&InferPullArgs{
		ApiUrl:         self.sidecar.settings.ApiUrl,
		Transport:      self.sidecar.sidecarApi.Transport(),
		ModelDirectory: InferModelDirectory(state),
		Device:         self.sidecar.inferLocalDevice,
		Settings:       settings,
		Clock:          self.sidecar.clock,
		Log:            self.sidecar.log,
	})
	if err != nil {
		return nil, err
	}
	self.pull = pull
	return pull, nil
}

// The device the router's local engine reports, for a pull's choice of file: an app's host's, or the daemon's.
func (self *Sidecar) inferLocalDevice(ctx context.Context) (*InferDeviceCapabilities, error) {
	infer, err := sidecarComputeComponent[sidecarInfer](self, computeInferComponentName)
	if err != nil {
		return nil, err
	}
	engine := infer.router.engine()
	if engine == nil {
		return nil, errors.New("no local engine runs on this host")
	}
	return engine.Capabilities(ctx)
}

// This Sidecar's pull over its state directory's models (§6.5, CO-49): what an app's Models().Pull and Remove take,
// and what the app's host engine finds a model's whole file through. ErrInferNoModelDirectory where its state is not
// on a disk. ur's daemon keeps one pull of its own for the instance, beside its engine process, and never takes this.
func (self *Sidecar) InferPull() (*InferPull, error) {
	local, err := sidecarComputeComponent[sidecarInferLocal](self, computeInferLocalComponentName)
	if err != nil {
		return nil, err
	}
	return local.inferPull()
}

// Makes the app's host this Sidecar's local engine (§6.5): the router's local calls then run on it, each model's whole
// file found through InferPull, and the catalog's local view is judged for its device. nil takes the host away, which
// leaves the catalog with no local entry. The host set before is let go: its models unloaded once its calls end. The
// sdk's SetLocalInferenceHost calls this through its adapter (C-39).
func (self *Sidecar) SetLocalInferenceHost(host SidecarLocalInferenceHost) error {
	local, err := sidecarComputeComponent[sidecarInferLocal](self, computeInferLocalComponentName)
	if err != nil {
		return err
	}
	var engine *inferHostEngine
	if host != nil {
		pull, err := local.inferPull()
		if err != nil {
			return fmt.Errorf("the app's local engine: %w", err)
		}
		settings := self.settings.Infer
		if settings == nil {
			settings = DefaultInferSettings()
		}
		engine = newInferHostEngine(&inferHostEngineArgs{Host: host, Models: pull, Settings: settings, Clock: self.clock, Log: self.log})
	}
	replaced, err := func() (*inferHostEngine, error) {
		local.stateLock.Lock()
		defer local.stateLock.Unlock()
		if local.closed {
			return nil, ErrSidecarClosed
		}
		replaced := local.engine
		local.engine = engine
		return replaced, nil
	}()
	if err != nil {
		if engine != nil {
			engine.close()
		}
		return err
	}
	var routerEngine InferLocalEngine
	if engine != nil {
		routerEngine = engine
	}
	setErr := self.SetInferLocalEngine(routerEngine)
	if replaced != nil {
		replaced.close()
	}
	return setErr
}
