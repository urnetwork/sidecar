//go:build ur_engine && !ios_extension && !sidecar_http

// ONNX Runtime's C API through purego (DESIGN-COMPUTE §27.5's desktop row; SAFE-M13-03): the binding the classify
// methods run on in the ur-engine helper (infer_engine_classify.go), and their registration in its method registry.
// Only the ur_engine build tag builds this file, which the helper's executable sets, so ur and the sdk link no binding
// and no ONNX Runtime symbol. There is no cgo: purego opens the library, by the path the helper checked against its
// pin, and calls it.
//
// What it holds to:
//
//   - The library's OrtGetApiBase answers the OrtApiBase struct, whose GetApi takes the OrtApi version the release
//     pins and answers the function table, or nothing from a library older than that version, which is refused.
//   - The table's entries are read at their positions in the C API header, onnxruntime_c_api.h, whose struct only ever
//     grows at its end, so a position never moves between versions; each entry the methods use must be there before
//     any is called, so a short table is refused whole at load.
//   - Strings the API takes are copied to NUL-terminated buffers kept alive through the call; the model's path is
//     ORTCHAR_T, UTF-16 on Windows (infer_engine_classify_ort_windows.go). The runtime's memory, a tensor's data, is
//     read and written only through the table's own pointers.
//
// The positions and signatures are the C API's as its header gives them; a hand run on each desktop, with the
// release's runtime and model, confirms them (External): until then a mismatch fails the load, or crashes the helper,
// never the daemon, and the daemon answers unavailable, which asks.

package sidecar

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
)

// OrtApi's positions of the functions the classify methods call, in onnxruntime_c_api.h's order.
const (
	ortApiGetErrorCode                   = 1
	ortApiGetErrorMessage                = 2
	ortApiCreateEnv                      = 3
	ortApiDisableTelemetryEvents         = 6
	ortApiCreateSession                  = 7
	ortApiRun                            = 9
	ortApiCreateSessionOptions           = 10
	ortApiSetIntraOpNumThreads           = 24
	ortApiSessionGetInputCount           = 30
	ortApiSessionGetOutputCount          = 31
	ortApiCreateTensorAsOrtValue         = 48
	ortApiGetTensorMutableData           = 51
	ortApiGetTensorElementType           = 60
	ortApiGetDimensionsCount             = 61
	ortApiGetDimensions                  = 62
	ortApiGetTensorTypeAndShape          = 65
	ortApiGetAllocatorWithDefaultOptions = 78
	ortApiReleaseEnv                     = 92
	ortApiReleaseStatus                  = 93
	ortApiReleaseSession                 = 95
	ortApiReleaseValue                   = 96
	ortApiReleaseTensorTypeAndShapeInfo  = 99
	ortApiReleaseSessionOptions          = 100
	// the entries read: through ReleaseSessionOptions
	ortApiReadCount = 101
)

// The library's one exported symbol the binding reads.
const ortGetApiBaseSymbol = "OrtGetApiBase"

// Registers the classify methods in the helper's registry, over the binding.
func init() {
	classify := newInferEngineClassify(ortOpenLibrary, DefaultSafetySettings())
	for name, method := range classify.methods() {
		registerInferEngineMethod(name, method)
	}
}

// The runtime's memory at address, as a pointer Go reads through. The address is the runtime's, never Go's, so the
// collector neither moves nor frees what it points at.
func ortPointer(address uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&address))
}

// Opens the runtime's library at path, its pin checked by the caller: its OrtApiBase's two functions, and the table's
// binding.
func ortOpenLibrary(path string) (*ortLibrary, error) {
	library, err := ortOpen(path)
	if err != nil {
		return nil, err
	}
	symbol, err := ortSymbol(library, ortGetApiBaseSymbol)
	if err != nil || symbol == 0 {
		return nil, fmt.Errorf("the library exports no %s", ortGetApiBaseSymbol)
	}
	var getApiBase func() uintptr
	purego.RegisterFunc(&getApiBase, symbol)
	base := getApiBase()
	if base == 0 {
		return nil, fmt.Errorf("%s answered nothing", ortGetApiBaseSymbol)
	}
	entries := unsafe.Slice((*uintptr)(ortPointer(base)), 2)
	if entries[0] == 0 || entries[1] == 0 {
		return nil, errors.New("the library's OrtApiBase is not whole")
	}
	opened := &ortLibrary{bind: ortBindApi}
	purego.RegisterFunc(&opened.getApi, entries[0])
	purego.RegisterFunc(&opened.versionString, entries[1])
	return opened, nil
}

// Copies of values as C strings, and the pointers to them, which the caller keeps alive through its call.
func ortCStrings(values []string) ([]*byte, [][]byte) {
	buffers := make([][]byte, len(values))
	pointers := make([]*byte, len(values))
	for i, value := range values {
		buffers[i] = append([]byte(value), 0)
		pointers[i] = &buffers[i][0]
	}
	return pointers, buffers
}

// The table at address as an ortApi, refused whole where an entry the methods use is missing.
func ortBindApi(address uintptr) (*ortApi, error) {
	table := unsafe.Slice((*uintptr)(ortPointer(address)), ortApiReadCount)
	register := func(function any, index int) error {
		if table[index] == 0 {
			return fmt.Errorf("the runtime's table holds nothing at %d", index)
		}
		purego.RegisterFunc(function, table[index])
		return nil
	}
	api := &ortApi{
		int64s: func(data uintptr, count int) []int64 {
			return unsafe.Slice((*int64)(ortPointer(data)), count)
		},
		float32s: func(data uintptr, count int) []float32 {
			return unsafe.Slice((*float32)(ortPointer(data)), count)
		},
	}
	var createTensor func(allocator uintptr, shape *int64, shapeLength uintptr, elementType int32, value *uintptr) uintptr
	var getDimensions func(info uintptr, dimensions *int64, count uintptr) uintptr
	var run func(session uintptr, runOptions uintptr, inputNames **byte, inputs *uintptr, inputCount uintptr,
		outputNames **byte, outputCount uintptr, outputs *uintptr) uintptr
	err := errors.Join(
		register(&api.getErrorCode, ortApiGetErrorCode),
		register(&api.getErrorMessage, ortApiGetErrorMessage),
		register(&api.releaseStatus, ortApiReleaseStatus),
		register(&api.createEnv, ortApiCreateEnv),
		register(&api.disableTelemetryEvents, ortApiDisableTelemetryEvents),
		register(&api.releaseEnv, ortApiReleaseEnv),
		register(&api.createSessionOptions, ortApiCreateSessionOptions),
		register(&api.setIntraOpNumThreads, ortApiSetIntraOpNumThreads),
		register(&api.releaseSessionOptions, ortApiReleaseSessionOptions),
		register(&api.sessionGetInputCount, ortApiSessionGetInputCount),
		register(&api.sessionGetOutputCount, ortApiSessionGetOutputCount),
		register(&api.releaseSession, ortApiReleaseSession),
		register(&api.getAllocatorWithDefaultOptions, ortApiGetAllocatorWithDefaultOptions),
		register(&api.getTensorMutableData, ortApiGetTensorMutableData),
		register(&api.getTensorTypeAndShape, ortApiGetTensorTypeAndShape),
		register(&api.getTensorElementType, ortApiGetTensorElementType),
		register(&api.getDimensionsCount, ortApiGetDimensionsCount),
		register(&api.releaseTensorTypeAndShapeInfo, ortApiReleaseTensorTypeAndShapeInfo),
		register(&api.releaseValue, ortApiReleaseValue),
		register(&createTensor, ortApiCreateTensorAsOrtValue),
		register(&getDimensions, ortApiGetDimensions),
		register(&run, ortApiRun),
	)
	if err != nil {
		return nil, err
	}
	api.createSession = ortRegisterCreateSession(table[ortApiCreateSession])
	if table[ortApiCreateSession] == 0 {
		return nil, fmt.Errorf("the runtime's table holds nothing at %d", ortApiCreateSession)
	}
	api.createTensorAsOrtValue = func(allocator uintptr, shape []int64, elementType int32, value *uintptr) uintptr {
		status := createTensor(allocator, &shape[0], uintptr(len(shape)), elementType, value)
		runtime.KeepAlive(shape)
		return status
	}
	api.getDimensions = func(info uintptr, dimensions []int64) uintptr {
		status := getDimensions(info, &dimensions[0], uintptr(len(dimensions)))
		runtime.KeepAlive(dimensions)
		return status
	}
	api.run = func(session uintptr, inputNames []string, inputs []uintptr, outputNames []string, outputs []uintptr) uintptr {
		inputPointers, inputBuffers := ortCStrings(inputNames)
		outputPointers, outputBuffers := ortCStrings(outputNames)
		status := run(session, 0, &inputPointers[0], &inputs[0], uintptr(len(inputs)), &outputPointers[0], uintptr(len(outputs)), &outputs[0])
		runtime.KeepAlive(inputPointers)
		runtime.KeepAlive(inputBuffers)
		runtime.KeepAlive(outputPointers)
		runtime.KeepAlive(outputBuffers)
		runtime.KeepAlive(inputs)
		runtime.KeepAlive(outputs)
		return status
	}
	return api, nil
}
