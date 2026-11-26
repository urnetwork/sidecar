//go:build !ios_extension && !sidecar_http

// Pulling a local model (DESIGN-COMPUTE §6.5, CO-49, R-INFER-10, D-INFER-12, IC-5; INFER-M11-06): InferPull, what
// `ur models pull`, an app's Models().Pull and their removals take, over one directory's InferModelDownload, the one
// downloader of every Go host (INFER-M11-11; CONTRACTS C-44).
//
//   - A pull takes a local model by its canonical name or alias, as this device's local view resolves it: a model the
//     device lacks the memory, a build or an accelerator for is refused with the catalog's reason, never pulled.
//   - The model's file is the one the engine would load on this device (inferLocalModelFile: the GPU build where the
//     device and the model have one), taken from the api in chunks each checked against the index the signed manifest
//     pins, resumed at the first chunk missing, Hugging Face's pinned commit the fallback by ranges; it is opened only
//     once whole (InferModelFile.OpenWhole), which WholePath is how an engine finds it.
//   - On a desktop the engine's files come first, whole, from the manifest's https URLs (LiteRT-LM's release): its C
//     library, its GPU plugins where the model runs on the GPU, and Dawn where the version needs it; each is written to
//     a part, its size held to the manifest's and its SHA-256 checked before it is moved into place, a mismatch
//     deleted and refused, and the helper checks it again before it loads it (§6.5's desktop row). A file already in
//     place is checked, and one off its pin deleted and fetched again.
//   - Progress is the model's chunks done, and an engine file's bytes, one call at a time, in order.
//   - Remove deletes a model's every state: its part, its list of chunks done, its whole file and its kept index.
//
// A pull starts only when its caller asks, at the person's first pick, never at install (§6.12), and goes from the
// device itself with no credential: no token, cookie or member id reaches the api, a cache, the hub or the engine's
// release, so the api sees a file and an address and no member. Nothing here is an inference's request (IC-5). Safe for
// concurrent use: one file's fetch and removal run one at a time.

package sidecar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// What a pull's phase is.
type InferPullPhase string

const (
	// An engine file, whole, from LiteRT-LM's release: desktops alone.
	InferPullPhaseEngine InferPullPhase = "engine"
	// The model's file, in chunks.
	InferPullPhaseModel InferPullPhase = "model"
)

// How far a pull is, as `ur models pull` and the bot tab show it (§15.4): the file in hand, by chunks done for the
// model and bytes for an engine file, and the files of the pull.
type InferPullProgress struct {
	// The canonical name pulled.
	Name  string         `json:"name"`
	Phase InferPullPhase `json:"phase"`
	// The file in hand: its name in the manifest and its SHA-256.
	File   string `json:"file"`
	Sha256 string `json:"sha256"`
	// Its chunks: the model's from its index, an engine file one.
	ChunkCount     int `json:"chunk_count"`
	DoneChunkCount int `json:"done_chunk_count"`
	// Its size, and the bytes done, in bytes.
	ByteCount     int64 `json:"byte_count"`
	DoneByteCount int64 `json:"done_byte_count"`
	// Where its bytes come from now: the api or the hub for the model, the engine's release for an engine file.
	Source string `json:"source"`
	// The file's place among the pull's, from 1.
	FileIndex int `json:"file_index"`
	FileCount int `json:"file_count"`
}

// Where an engine file's bytes come from.
const inferPullSourceRelease = "release"

// What a model file of this device's is: whole, a part a download began, or nothing.
type InferPullFileState string

const (
	InferPullFileWhole  InferPullFileState = "whole"
	InferPullFilePart   InferPullFileState = "part"
	InferPullFileAbsent InferPullFileState = "absent"
)

// What a pull needs from its host.
type InferPullArgs struct {
	// The api's base url, https://<host>: the host list's (SidecarSettings.ApiUrl).
	ApiUrl string
	// What every request goes through: the host's egress-bound transport, never net/http's default.
	Transport http.RoundTripper
	// Where the model files are kept, absolute: <state>/models.
	ModelDirectory string
	// Where the engine's files are kept, absolute: <state>/engine on a desktop; empty on an app, whose engine is in its
	// bundle, which then pulls no engine file.
	EngineDirectory string
	// The release manifest; nil for this build's.
	Manifest *InferManifest
	// This device, as its local engine reports it. Required.
	Device func(ctx context.Context) (*InferDeviceCapabilities, error)
	// Nil for the defaults.
	Settings *InferSettings
	// Nil for real time.
	Clock Clock
	// Nil logs to connect's default logger.
	Log Logger
	// The bytes free to this process on a directory's volume; nil reads the OS's.
	FreeByteCount func(directory string) (int64, error)
}

// Pulls local models and removes them (see the file comment).
type InferPull struct {
	download        *InferModelDownload
	engineDirectory string
	manifest        *InferManifest
	device          func(ctx context.Context) (*InferDeviceCapabilities, error)
	settings        *InferSettings
	clock           Clock
	log             Logger
	freeByteCount   func(directory string) (int64, error)
	// the engine's release's client: no jar, no credential, its redirects held to https and the release's hosts
	engineClient *http.Client

	stateLock sync.Mutex
	// one lock an engine file, by its name
	engineLocks map[string]*sync.Mutex
}

// A pull on args, refused unless its api url, transport and directories are fit.
func NewInferPull(args *InferPullArgs) (*InferPull, error) {
	if args == nil || args.Device == nil {
		return nil, errors.New("model pull: no device")
	}
	if args.EngineDirectory != "" && !filepath.IsAbs(args.EngineDirectory) {
		return nil, errors.New("model pull: the engine directory is not absolute")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultInferSettings()
	}
	freeByteCount := args.FreeByteCount
	if freeByteCount == nil {
		freeByteCount = inferDownloadFreeByteCount
	}
	download, err := NewInferModelDownload(&InferModelDownloadArgs{
		ApiUrl:        args.ApiUrl,
		Transport:     args.Transport,
		Directory:     args.ModelDirectory,
		Settings:      settings,
		Clock:         args.Clock,
		Log:           args.Log,
		FreeByteCount: freeByteCount,
	})
	if err != nil {
		return nil, err
	}
	manifest := args.Manifest
	if manifest == nil {
		manifest, err = InferReleaseManifest(settings)
		if err != nil {
			return nil, err
		}
	}
	self := &InferPull{
		download:        download,
		engineDirectory: args.EngineDirectory,
		manifest:        manifest,
		device:          args.Device,
		settings:        settings,
		clock:           clockOrReal(args.Clock),
		log:             loggerOrDefault(args.Log),
		freeByteCount:   freeByteCount,
		engineLocks:     map[string]*sync.Mutex{},
	}
	self.engineClient = &http.Client{
		Transport:     args.Transport,
		CheckRedirect: self.checkEngineRedirect,
	}
	return self, nil
}

// An engine file's redirect: https alone, to the url's own host or one under EngineDownloadRedirectHostSuffixes, at
// most EngineDownloadRedirectMaxCount, with no Referer.
func (self *InferPull) checkEngineRedirect(request *http.Request, via []*http.Request) error {
	if max(self.settings.EngineDownloadRedirectMaxCount, 0) < len(via) {
		return errors.New("the engine's release redirected too often")
	}
	if request.URL.Scheme != "https" {
		return errors.New("the engine's release redirected off https")
	}
	host := strings.ToLower(request.URL.Hostname())
	allowed := host == strings.ToLower(via[0].URL.Hostname()) || slices.ContainsFunc(self.settings.EngineDownloadRedirectHostSuffixes, func(suffix string) bool {
		suffix = strings.ToLower(suffix)
		return host == suffix || strings.HasSuffix(host, "."+suffix)
	})
	if !allowed {
		return errors.New("the engine's release redirected to a host it does not name")
	}
	request.Header.Del("Referer")
	return nil
}

// The model file of entry the engine would load on device, and its backend: the GPU build where the device has a GPU
// and the model runs on one, else the one every accelerator loads (§6.5); model_refused where none serves.
func inferLocalModelFile(entry *InferCatalogEntry, device *InferDeviceCapabilities) (*InferManifestModelFile, InferAccelerator, error) {
	local := entry.Local
	if local == nil {
		return nil, "", newInferError(InferErrorModelRefused, "no local model")
	}
	backend := InferAcceleratorCpu
	if slices.Contains(device.Accelerators, InferAcceleratorGpu) && slices.Contains(local.Accelerators, InferAcceleratorGpu) {
		backend = InferAcceleratorGpu
	}
	// the build for the backend's accelerator, else the one every accelerator loads
	var modelFile *InferManifestModelFile
	for _, file := range local.Files {
		if file.Accelerator == backend || (file.Accelerator == "" && modelFile == nil) {
			modelFile = file
		}
	}
	if modelFile == nil {
		return nil, "", newInferError(InferErrorModelRefused, "no build of %s runs on this device's %s", entry.Provider+"-"+entry.Model, backend)
	}
	return modelFile, backend, nil
}

// The local entry name names on this device, refused with the local view's reason where the device may not run it,
// and the device.
func (self *InferPull) resolve(ctx context.Context, name string) (*InferCatalogResolution, *InferDeviceCapabilities, error) {
	device, err := self.device(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("model pull: this device's capabilities do not read: %w", err)
	}
	catalog, err := NewInferLocalCatalog(self.manifest, device, self.settings)
	if err != nil {
		return nil, nil, err
	}
	resolution, err := catalog.Resolve(name, "")
	if err != nil {
		if reason := catalog.LocalUnavailable(); reason != "" && errors.Is(err, ErrInferModelUnknown) {
			return nil, nil, fmt.Errorf("%w: no local model here: %s", err, reason)
		}
		return nil, nil, err
	}
	if resolution.Entry.Kind != InferCatalogKindLocal {
		return nil, nil, fmt.Errorf("%w: %s is no local model", ErrInferModelUnknown, name)
	}
	return resolution, device, nil
}

// The engine files a pull takes for backend on device: none on an app's host, else the platform's libraries, Dawn
// where pinned, and the GPU plugins where the model runs on the GPU.
func (self *InferPull) engineFiles(device *InferDeviceCapabilities, backend InferAccelerator) ([]*InferManifestFile, error) {
	if self.engineDirectory == "" {
		return nil, nil
	}
	engine := self.manifest.Engine(device.Platform)
	if engine == nil || len(engine.Libraries) == 0 {
		return nil, newInferError(InferErrorModelRefused, "this build pins no engine for %s", device.Platform)
	}
	files := slices.Clone(engine.Libraries)
	if engine.Dawn != nil {
		files = append(files, engine.Dawn)
	}
	if backend == InferAcceleratorGpu {
		files = append(files, engine.GpuPlugins...)
	}
	return files, nil
}

// Pulls name's local model, and on a desktop its engine's files, reporting progress to listener where it is not nil,
// one call at a time, in order; it should return promptly. An error is ctx's, the catalog's refusal, an
// *InferDownloadError (download_corrupt naming its chunk, download_unavailable, download_no_space), or a local file's;
// what was done is kept for the next try.
func (self *InferPull) Pull(ctx context.Context, name string, listener func(*InferPullProgress)) error {
	resolution, device, err := self.resolve(ctx, name)
	if err != nil {
		return err
	}
	modelFile, backend, err := inferLocalModelFile(resolution.Entry, device)
	if err != nil {
		return err
	}
	engineFiles, err := self.engineFiles(device, backend)
	if err != nil {
		return err
	}
	fileCount := len(engineFiles) + 1
	report := func(progress *InferPullProgress) {
		if listener != nil {
			progress.Name = resolution.Name
			progress.FileCount = fileCount
			listener(progress)
		}
	}
	for i, file := range engineFiles {
		if err := self.pullEngineFile(ctx, file, func(done int64, whole bool) {
			progress := &InferPullProgress{
				Phase:         InferPullPhaseEngine,
				File:          file.Name,
				Sha256:        file.Sha256,
				ChunkCount:    1,
				ByteCount:     file.ByteCount,
				DoneByteCount: done,
				Source:        inferPullSourceRelease,
				FileIndex:     i + 1,
			}
			if whole {
				progress.DoneChunkCount = 1
			}
			report(progress)
		}); err != nil {
			return err
		}
	}
	_, err = self.download.Fetch(ctx, modelFile, func(progress *InferModelDownloadProgress) {
		report(&InferPullProgress{
			Phase:          InferPullPhaseModel,
			File:           modelFile.Name,
			Sha256:         progress.Sha256,
			ChunkCount:     progress.ChunkCount,
			DoneChunkCount: progress.DoneChunkCount,
			ByteCount:      progress.ByteCount,
			DoneByteCount:  progress.DoneByteCount,
			Source:         string(progress.Source),
			FileIndex:      fileCount,
		})
	})
	return err
}

// Deletes every state of name's model on this device, each of its files of any build: whole, part, the chunks done
// and the kept index. The engine's files stay, since every model shares them. A model not pulled removes nothing.
func (self *InferPull) Remove(ctx context.Context, name string) error {
	parsed, err := InferParseModelName(name, self.settings)
	if err != nil {
		return err
	}
	model := self.manifest.Model(parsed.Model)
	if parsed.Provider != computeLocalProvider || model == nil {
		return fmt.Errorf("%w: %s is no local model this build lists", ErrInferModelUnknown, parsed.String())
	}
	for _, file := range model.Files {
		modelFile, err := self.download.File(file)
		if err != nil {
			return err
		}
		if err := modelFile.Remove(ctx); err != nil {
			return err
		}
	}
	return nil
}

// See InferModelFiles: the whole file's path, opened whole once to check it.
func (self *InferPull) WholePath(ctx context.Context, file *InferManifestModelFile) (string, error) {
	modelFile, err := self.download.File(file)
	if err != nil {
		return "", err
	}
	opened, err := modelFile.OpenWhole(ctx)
	if err != nil {
		return "", err
	}
	opened.Close()
	return modelFile.Path(), nil
}

// How far file is on this device, read without waiting or checking a chunk: whole where its whole mark matches it,
// part where a download of it began, else absent. A listing's reading; only WholePath is a loader's.
func (self *InferPull) FileState(file *InferManifestModelFile) InferPullFileState {
	modelFile, err := self.download.File(file)
	if err != nil {
		return InferPullFileAbsent
	}
	if info, err := os.Stat(modelFile.paths.whole); err == nil {
		if mark := modelFile.readMark(); mark != nil && mark.matches(modelFile.file, info) {
			return InferPullFileWhole
		}
		return InferPullFilePart
	}
	if _, err := os.Stat(modelFile.paths.part); err == nil {
		return InferPullFilePart
	}
	return InferPullFileAbsent
}

// How far name's model is on this device: its file for this device's backend, as FileState reads it, and the file.
func (self *InferPull) State(ctx context.Context, name string) (InferPullFileState, *InferManifestModelFile, error) {
	resolution, device, err := self.resolve(ctx, name)
	if err != nil {
		return InferPullFileAbsent, nil, err
	}
	modelFile, _, err := inferLocalModelFile(resolution.Entry, device)
	if err != nil {
		return InferPullFileAbsent, nil, err
	}
	return self.FileState(modelFile), modelFile, nil
}

// The lock of one engine file, made at first use.
func (self *InferPull) engineLock(name string) *sync.Mutex {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	lock, ok := self.engineLocks[name]
	if !ok {
		lock = &sync.Mutex{}
		self.engineLocks[name] = lock
	}
	return lock
}

// An engine file's error, naming the file.
func inferEngineFileError(code InferDownloadErrorCode, file *InferManifestFile, format string, a ...any) *InferDownloadError {
	return &InferDownloadError{Code: code, Sha256: file.Sha256, Chunk: -1, Message: fmt.Sprintf(format, a...)}
}

// Whether the file at path is file, by its size and SHA-256; an error only where it is there and does not read.
func inferEngineFileMatches(path string, file *InferManifestFile) (bool, error) {
	opened, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer opened.Close()
	info, err := opened.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != file.ByteCount {
		return false, err
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, opened); err != nil {
		return false, err
	}
	return hex.EncodeToString(digest.Sum(nil)) == file.Sha256, nil
}

// A writer that counts and hashes what passes, reporting the count.
type inferPullCounter struct {
	digest hash.Hash
	count  int64
	report func(count int64)
}

func (self *inferPullCounter) Write(data []byte) (int, error) {
	self.digest.Write(data)
	self.count += int64(len(data))
	self.report(self.count)
	return len(data), nil
}

// Takes one engine file whole into the engine directory: kept where it is there on its pin, else fetched to a part,
// its size and SHA-256 checked before it is moved into place, a mismatch deleted and refused. report hears the bytes
// done and, once, that it is whole.
func (self *InferPull) pullEngineFile(ctx context.Context, file *InferManifestFile, report func(done int64, whole bool)) error {
	lock := self.engineLock(file.Name)
	lock.Lock()
	defer lock.Unlock()
	if err := os.MkdirAll(self.engineDirectory, 0o700); err != nil {
		return fmt.Errorf("model pull: %w", err)
	}
	path := filepath.Join(self.engineDirectory, file.Name)
	matches, err := inferEngineFileMatches(path, file)
	if err != nil {
		return fmt.Errorf("model pull: an engine file does not read: %w", err)
	}
	if matches {
		report(file.ByteCount, true)
		return nil
	}
	// a file off its pin is deleted before anything is fetched over it
	if err := inferRemoveIfExists(path); err != nil {
		return err
	}
	free, err := self.freeByteCount(self.engineDirectory)
	needed := file.ByteCount + int64(float64(file.ByteCount)*max(self.settings.ModelFreeSpaceMarginFraction, 0))
	if err != nil || free < needed {
		return inferEngineFileError(InferDownloadErrorNoSpace, file, "the engine's volume lacks %d bytes free", needed)
	}
	part := path + inferModelPartSuffix
	if err := inferRemoveIfExists(part); err != nil {
		return err
	}
	fetchCtx := ctx
	if 0 < self.settings.EngineDownloadTimeout {
		var cancel context.CancelFunc
		fetchCtx, cancel = context.WithTimeout(ctx, self.settings.EngineDownloadTimeout)
		defer cancel()
	}
	target, err := url.Parse(file.Url)
	if err != nil || target.Scheme != "https" {
		return inferEngineFileError(InferDownloadErrorUnavailable, file, "its url is not https")
	}
	request, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, target.String(), nil)
	if err != nil {
		return err
	}
	response, err := self.engineClient.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return inferEngineFileError(InferDownloadErrorUnavailable, file, "the engine's release did not answer")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return inferEngineFileError(InferDownloadErrorUnavailable, file, "the engine's release answered %d", response.StatusCode)
	}
	if 0 <= response.ContentLength && response.ContentLength != file.ByteCount {
		return inferEngineFileError(InferDownloadErrorCorrupt, file, "the engine's release offered %d bytes, not the manifest's %d", response.ContentLength, file.ByteCount)
	}
	written, err := os.OpenFile(part, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	removePart := func() {
		written.Close()
		os.Remove(part)
	}
	counter := &inferPullCounter{digest: sha256.New(), report: func(count int64) { report(count, false) }}
	// one byte past the manifest's size tells a longer answer from a whole one, which is refused, never cut
	copied, err := io.Copy(io.MultiWriter(written, counter), io.LimitReader(response.Body, file.ByteCount+1))
	if err != nil {
		removePart()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return inferEngineFileError(InferDownloadErrorUnavailable, file, "the engine's release stopped answering")
	}
	if copied != file.ByteCount || hex.EncodeToString(counter.digest.Sum(nil)) != file.Sha256 {
		removePart()
		return inferEngineFileError(InferDownloadErrorCorrupt, file, "it was not the manifest's file, so it was deleted")
	}
	if err := written.Sync(); err != nil {
		removePart()
		return err
	}
	if err := written.Close(); err != nil {
		os.Remove(part)
		return err
	}
	testHookBarrier("infer.pull.engine.rename.before", file.Name)
	if err := os.Rename(part, path); err != nil {
		os.Remove(part)
		return err
	}
	if err := inferSyncDirectory(self.engineDirectory); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	report(file.ByteCount, true)
	return nil
}

// The transport this Sidecar's api calls go through, bound to its egress: what a host's InferPull downloads with,
// sending no credential of its own (CO-49). ur's daemon hands it to the pull it keeps for the instance.
func (self *Sidecar) InferDownloadTransport() http.RoundTripper {
	if self.sidecarApi == nil {
		return nil
	}
	return self.sidecarApi.Transport()
}

// The api's url this Sidecar's settings name, the host list's.
func (self *Sidecar) InferApiUrl() string {
	return self.settings.ApiUrl
}
