//go:build darwin && !ios && !sdk_mobile_bind

// mDNSResponder's DNS-SD API (dns_sd.h) for §17.7.1's gatherer and advertising proxy on macOS (owner decision 778),
// reached through purego with CGO_ENABLED=0, as §5.10's keychain is: libSystem's client stub, loaded once by path.
//
//	connection  one DNSServiceCreateConnection per owner, every operation sharing its socket
//	            (kDNSServiceFlagsShareConnection), so a gatherer or a proxy holds one socket to mDNSResponder whatever
//	            it browses or registers
//	calls       serialized on the connection, since the stub is not safe for concurrent use of one; each writes its
//	            request and waits for mDNSResponder's immediate answer, a local round trip
//	replies     one goroutine per connection polls the socket and calls DNSServiceProcessResult, which calls the
//	            operation's callback on that goroutine; a callback hands what it got to its operation's handler, which
//	            must neither block nor call the connection, which the reader holds through the call
//	callbacks   one C callback per reply kind, made once, since purego's are never freed; an operation's context is an
//	            integer key into one table, never a Go pointer, and a reply whose key has gone is dropped
//	failure     a reply the stub refuses, mDNSResponder's restart among them, ends the connection: its done channel
//	            closes, and its owner builds another
//
// Names, types and TXT are the network's or the LAN's words and reach no log (I-13).

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// libSystem, which carries the DNS-SD client stub (libsystem_dnssd), fixed by the system.
const darwinLibSystemPath = "/usr/lib/libSystem.B.dylib"

// dns_sd.h's identifiers this file uses.
const (
	darwinDnsSdFlagsMoreComing      = 0x1
	darwinDnsSdFlagsAdd             = 0x2
	darwinDnsSdFlagsNoAutoRename    = 0x8
	darwinDnsSdFlagsShared          = 0x10
	darwinDnsSdFlagsUnique          = 0x20
	darwinDnsSdFlagsShareConnection = 0x4000

	darwinDnsSdInterfaceIndexAny       = 0
	darwinDnsSdInterfaceIndexLocalOnly = 0xFFFFFFFF

	darwinDnsSdProtocolIpv4 = 0x01
	darwinDnsSdProtocolIpv6 = 0x02

	darwinDnsSdClassIn  = 1
	darwinDnsSdTypeA    = 1
	darwinDnsSdTypeAaaa = 28

	darwinDnsSdErrNoError           = 0
	darwinDnsSdErrBadParam          = -65540
	darwinDnsSdErrNameConflict      = -65548
	darwinDnsSdErrServiceNotRunning = -65563
	darwinDnsSdErrDefunctConnection = -65569
)

// A DNS-SD error code as an error.
type darwinDnsSdError int32

func (self darwinDnsSdError) Error() string {
	switch self {
	case darwinDnsSdErrNameConflict:
		return "dns-sd: the name is taken"
	case darwinDnsSdErrServiceNotRunning:
		return "dns-sd: mDNSResponder is not running"
	case darwinDnsSdErrDefunctConnection:
		return "dns-sd: the connection to mDNSResponder ended"
	}
	return fmt.Sprintf("dns-sd: error %d", int32(self))
}

// The error of a code, nil for none.
func darwinDnsSdErrorOf(code int32) error {
	if code == darwinDnsSdErrNoError {
		return nil
	}
	return darwinDnsSdError(code)
}

// The connection has ended.
var errDarwinDnsSdClosed = errors.New("dns-sd: the connection has ended")

// The client stub's functions, loaded once. A buffer goes as a pointer to its first byte, never a slice: purego lays a
// slice that falls past the registers out on Apple's packed stack whole, its length and capacity with it.
type darwinDnsSdApi struct {
	createConnection func(sdRef *uintptr) int32
	refSockFd        func(sdRef uintptr) int32
	processResult    func(sdRef uintptr) int32
	refDeallocate    func(sdRef uintptr)
	register         func(sdRef *uintptr, flags uint32, interfaceIndex uint32, name string, regtype string, domain string,
		host string, port uint16, txtLen uint16, txtRecord *byte, callBack uintptr, context uintptr) int32
	registerRecord func(sdRef uintptr, recordRef *uintptr, flags uint32, interfaceIndex uint32, fullname string,
		rrtype uint16, rrclass uint16, rdlen uint16, rdata *byte, ttl uint32, callBack uintptr, context uintptr) int32
	removeRecord func(sdRef uintptr, recordRef uintptr, flags uint32) int32
	browse       func(sdRef *uintptr, flags uint32, interfaceIndex uint32, regtype string, domain string, callBack uintptr,
		context uintptr) int32
	resolve func(sdRef *uintptr, flags uint32, interfaceIndex uint32, name string, regtype string, domain string,
		callBack uintptr, context uintptr) int32
	getAddrInfo func(sdRef *uintptr, flags uint32, interfaceIndex uint32, protocol uint32, hostname string,
		callBack uintptr, context uintptr) int32

	// the C callbacks, one per reply kind
	browseReply         uintptr
	resolveReply        uintptr
	addressReply        uintptr
	registerReply       uintptr
	registerRecordReply uintptr
}

var loadDarwinDnsSdApi = sync.OnceValues(func() (*darwinDnsSdApi, error) {
	library, err := purego.Dlopen(darwinLibSystemPath, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, err
	}
	self := &darwinDnsSdApi{}
	functions := []struct {
		target any
		name   string
	}{
		{&self.createConnection, "DNSServiceCreateConnection"},
		{&self.refSockFd, "DNSServiceRefSockFD"},
		{&self.processResult, "DNSServiceProcessResult"},
		{&self.refDeallocate, "DNSServiceRefDeallocate"},
		{&self.register, "DNSServiceRegister"},
		{&self.registerRecord, "DNSServiceRegisterRecord"},
		{&self.removeRecord, "DNSServiceRemoveRecord"},
		{&self.browse, "DNSServiceBrowse"},
		{&self.resolve, "DNSServiceResolve"},
		{&self.getAddrInfo, "DNSServiceGetAddrInfo"},
	}
	for _, function := range functions {
		symbol, err := purego.Dlsym(library, function.name)
		if err != nil {
			return nil, fmt.Errorf("dns-sd: %s: %w", function.name, err)
		}
		purego.RegisterFunc(function.target, symbol)
	}
	self.browseReply = purego.NewCallback(darwinDnsSdBrowseCallback)
	self.resolveReply = purego.NewCallback(darwinDnsSdResolveCallback)
	self.addressReply = purego.NewCallback(darwinDnsSdAddressCallback)
	self.registerReply = purego.NewCallback(darwinDnsSdRegisterCallback)
	self.registerRecordReply = purego.NewCallback(darwinDnsSdRegisterRecordCallback)
	return self, nil
})

// A browse's reply: an instance of a type found on an interface (Add) or gone from it.
type darwinDnsSdBrowseReply struct {
	Flags          uint32
	InterfaceIndex uint32
	Err            error
	Name           string
	Service        string
	Domain         string
}

// A resolve's reply: an instance's target, port and TXT rdata.
type darwinDnsSdResolveReply struct {
	Flags          uint32
	InterfaceIndex uint32
	Err            error
	FullName       string
	Host           string
	Port           uint16
	Txt            []byte
}

// An address lookup's reply: one of a host's addresses found (Add) or gone, with its record's TTL in seconds.
type darwinDnsSdAddressReply struct {
	Flags          uint32
	InterfaceIndex uint32
	Err            error
	Host           string
	Address        netip.Addr
	Ttl            uint32
}

// A registration's reply: the name it registered under, or why it did not.
type darwinDnsSdRegisterReply struct {
	Flags   uint32
	Err     error
	Name    string
	Service string
	Domain  string
}

// What one operation hears: the function of its kind.
type darwinDnsSdHandler struct {
	browse   func(reply *darwinDnsSdBrowseReply)
	resolve  func(reply *darwinDnsSdResolveReply)
	address  func(reply *darwinDnsSdAddressReply)
	register func(reply *darwinDnsSdRegisterReply)
	// a record registration's error, nil once it stands
	record func(err error)
}

// The table every operation's context keys into: the C side holds the key alone.
var darwinDnsSdHandlers = struct {
	stateLock sync.Mutex
	nextKey   uintptr
	handlers  map[uintptr]*darwinDnsSdHandler
}{handlers: map[uintptr]*darwinDnsSdHandler{}}

// Holds handler under a new key.
func darwinDnsSdAddHandler(handler *darwinDnsSdHandler) uintptr {
	darwinDnsSdHandlers.stateLock.Lock()
	defer darwinDnsSdHandlers.stateLock.Unlock()
	darwinDnsSdHandlers.nextKey += 1
	key := darwinDnsSdHandlers.nextKey
	darwinDnsSdHandlers.handlers[key] = handler
	return key
}

// Drops a key's handler, so a reply still on its way is dropped.
func darwinDnsSdRemoveHandler(key uintptr) {
	darwinDnsSdHandlers.stateLock.Lock()
	defer darwinDnsSdHandlers.stateLock.Unlock()
	delete(darwinDnsSdHandlers.handlers, key)
}

// The handler of key, nil for none.
func darwinDnsSdHandlerOf(key uintptr) *darwinDnsSdHandler {
	darwinDnsSdHandlers.stateLock.Lock()
	defer darwinDnsSdHandlers.stateLock.Unlock()
	return darwinDnsSdHandlers.handlers[key]
}

// The longest C string a reply's field is read to: a full DNS name in its escaped presentation form, 1,009 bytes
// (dns_sd.h's kDNSServiceMaxDomainName), with room to spare. A protocol bound, so a constant.
const darwinDnsSdStringMaxByteCount = 1024

// A C string the stub passed, copied, cut at darwinDnsSdStringMaxByteCount; "" for none.
func darwinDnsSdString(pointer *byte) string {
	if pointer == nil {
		return ""
	}
	out := []byte{}
	for i := 0; i < darwinDnsSdStringMaxByteCount; i += 1 {
		c := *(*byte)(unsafe.Add(unsafe.Pointer(pointer), i))
		if c == 0 {
			break
		}
		out = append(out, c)
	}
	return string(out)
}

// count bytes the stub passed at pointer, copied.
func darwinDnsSdBytes(pointer *byte, count int) []byte {
	if pointer == nil || count <= 0 {
		return []byte{}
	}
	return append([]byte{}, unsafe.Slice(pointer, count)...)
}

// A buffer's first byte, nil for an empty one, which the stub reads as none.
func darwinDnsSdFirst(buffer []byte) *byte {
	if len(buffer) == 0 {
		return nil
	}
	return &buffer[0]
}

// The address of a struct sockaddr the stub passed: sockaddr_in's or sockaddr_in6's, invalid for another family.
func darwinDnsSdSockaddr(pointer *byte) netip.Addr {
	if pointer == nil {
		return netip.Addr{}
	}
	header := unsafe.Slice(pointer, 2)
	switch header[1] {
	case unix.AF_INET:
		raw := unsafe.Slice(pointer, unix.SizeofSockaddrInet4)
		return netip.AddrFrom4([4]byte(raw[4:8]))
	case unix.AF_INET6:
		raw := unsafe.Slice(pointer, unix.SizeofSockaddrInet6)
		return netip.AddrFrom16([16]byte(raw[8:24]))
	}
	return netip.Addr{}
}

// DNSServiceBrowseReply.
func darwinDnsSdBrowseCallback(sdRef uintptr, flags uint32, interfaceIndex uint32, errorCode int32, serviceName *byte,
	regtype *byte, replyDomain *byte, context uintptr) {
	handler := darwinDnsSdHandlerOf(context)
	if handler == nil || handler.browse == nil {
		return
	}
	handler.browse(&darwinDnsSdBrowseReply{
		Flags:          flags,
		InterfaceIndex: interfaceIndex,
		Err:            darwinDnsSdErrorOf(errorCode),
		Name:           darwinDnsSdString(serviceName),
		Service:        darwinDnsSdString(regtype),
		Domain:         darwinDnsSdString(replyDomain),
	})
}

// DNSServiceResolveReply. port comes in network byte order.
func darwinDnsSdResolveCallback(sdRef uintptr, flags uint32, interfaceIndex uint32, errorCode int32, fullname *byte,
	hosttarget *byte, port uint16, txtLen uint16, txtRecord *byte, context uintptr) {
	handler := darwinDnsSdHandlerOf(context)
	if handler == nil || handler.resolve == nil {
		return
	}
	var portBytes [2]byte
	binary.NativeEndian.PutUint16(portBytes[:], port)
	handler.resolve(&darwinDnsSdResolveReply{
		Flags:          flags,
		InterfaceIndex: interfaceIndex,
		Err:            darwinDnsSdErrorOf(errorCode),
		FullName:       darwinDnsSdString(fullname),
		Host:           darwinDnsSdString(hosttarget),
		Port:           binary.BigEndian.Uint16(portBytes[:]),
		Txt:            darwinDnsSdBytes(txtRecord, int(txtLen)),
	})
}

// DNSServiceGetAddrInfoReply.
func darwinDnsSdAddressCallback(sdRef uintptr, flags uint32, interfaceIndex uint32, errorCode int32, hostname *byte,
	address *byte, ttl uint32, context uintptr) {
	handler := darwinDnsSdHandlerOf(context)
	if handler == nil || handler.address == nil {
		return
	}
	handler.address(&darwinDnsSdAddressReply{
		Flags:          flags,
		InterfaceIndex: interfaceIndex,
		Err:            darwinDnsSdErrorOf(errorCode),
		Host:           darwinDnsSdString(hostname),
		Address:        darwinDnsSdSockaddr(address),
		Ttl:            ttl,
	})
}

// DNSServiceRegisterReply.
func darwinDnsSdRegisterCallback(sdRef uintptr, flags uint32, errorCode int32, name *byte, regtype *byte, domain *byte,
	context uintptr) {
	handler := darwinDnsSdHandlerOf(context)
	if handler == nil || handler.register == nil {
		return
	}
	handler.register(&darwinDnsSdRegisterReply{
		Flags:   flags,
		Err:     darwinDnsSdErrorOf(errorCode),
		Name:    darwinDnsSdString(name),
		Service: darwinDnsSdString(regtype),
		Domain:  darwinDnsSdString(domain),
	})
}

// DNSServiceRegisterRecordReply.
func darwinDnsSdRegisterRecordCallback(sdRef uintptr, recordRef uintptr, flags uint32, errorCode int32, context uintptr) {
	handler := darwinDnsSdHandlerOf(context)
	if handler == nil || handler.record == nil {
		return
	}
	handler.record(darwinDnsSdErrorOf(errorCode))
}

// One connection to mDNSResponder (the file's comment).
type darwinDnsSdConnection struct {
	api  *darwinDnsSdApi
	main uintptr
	fd   int
	// the pipe that wakes the reader's poll at close
	wakeRead  int
	wakeWrite int
	// closed once the reader has returned; err says why
	done chan struct{}
	err  atomic.Pointer[error]

	// serializes every call on the connection, the reader's DNSServiceProcessResult among them
	callLock sync.Mutex
	closed   bool
	// the keys of the operations it holds
	keys map[uintptr]bool
}

// One operation on a connection: a browse, a resolve, an address lookup or a service registration, which
// darwinDnsSdConnection.Cancel ends.
type darwinDnsSdOperation struct {
	ref uintptr
	key uintptr
}

// One record registered on a connection, which RemoveRecord ends. A record's rdata changes by a new record in its place:
// mDNSResponder's lookups on LocalOnly do not hear DNSServiceUpdateRecord.
type darwinDnsSdRecord struct {
	ref uintptr
	key uintptr
}

// A connection to mDNSResponder, its reader running until Close or a failure.
func newDarwinDnsSdConnection() (*darwinDnsSdConnection, error) {
	api, err := loadDarwinDnsSdApi()
	if err != nil {
		return nil, err
	}
	var main uintptr
	if err := darwinDnsSdErrorOf(api.createConnection(&main)); err != nil {
		return nil, err
	}
	pipe := make([]int, 2)
	syscall.ForkLock.RLock()
	err = unix.Pipe(pipe)
	if err == nil {
		unix.CloseOnExec(pipe[0])
		unix.CloseOnExec(pipe[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		api.refDeallocate(main)
		return nil, err
	}
	self := &darwinDnsSdConnection{
		api:       api,
		main:      main,
		fd:        int(api.refSockFd(main)),
		wakeRead:  pipe[0],
		wakeWrite: pipe[1],
		done:      make(chan struct{}),
		keys:      map[uintptr]bool{},
	}
	go self.read()
	return self, nil
}

// Closed once the connection has ended, by Close or a failure.
func (self *darwinDnsSdConnection) Done() <-chan struct{} {
	return self.done
}

// Why the connection ended, nil while it stands or after Close alone.
func (self *darwinDnsSdConnection) Err() error {
	if err := self.err.Load(); err != nil {
		return *err
	}
	return nil
}

// Polls the socket and processes each reply until Close or a failure. It closes the wake pipe as it returns, once the
// connection is closed, so nothing writes to it after.
func (self *darwinDnsSdConnection) read() {
	defer close(self.done)
	defer func() {
		unix.Close(self.wakeRead)
		unix.Close(self.wakeWrite)
	}()
	descriptors := []unix.PollFd{
		{Fd: int32(self.fd), Events: unix.POLLIN},
		{Fd: int32(self.wakeRead), Events: unix.POLLIN},
	}
	for {
		descriptors[0].Revents, descriptors[1].Revents = 0, 0
		if _, err := unix.Poll(descriptors, -1); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			self.fail(err)
			return
		}
		if descriptors[1].Revents != 0 {
			return
		}
		if descriptors[0].Revents == 0 {
			continue
		}
		err := func() error {
			self.callLock.Lock()
			defer self.callLock.Unlock()
			if self.closed {
				return errDarwinDnsSdClosed
			}
			return darwinDnsSdErrorOf(self.api.processResult(self.main))
		}()
		if errors.Is(err, errDarwinDnsSdClosed) {
			return
		}
		if err != nil {
			self.fail(err)
			return
		}
	}
}

// Ends the connection on the reader's failure: what it held is gone with mDNSResponder's end of it.
func (self *darwinDnsSdConnection) fail(err error) {
	self.err.Store(&err)
	self.callLock.Lock()
	defer self.callLock.Unlock()
	if self.closed {
		return
	}
	self.closed = true
	self.releaseWithLock()
}

// Ends the connection and everything on it, once its reader has returned, so no reply runs after. Safe to call more
// than once.
func (self *darwinDnsSdConnection) Close() {
	release := func() bool {
		self.callLock.Lock()
		defer self.callLock.Unlock()
		if self.closed {
			return false
		}
		self.closed = true
		unix.Write(self.wakeWrite, []byte{0})
		return true
	}()
	<-self.done
	if release {
		self.callLock.Lock()
		defer self.callLock.Unlock()
		self.releaseWithLock()
	}
}

// Deallocates the main ref, which ends every operation and record on it, and drops their handlers. Called with
// callLock held, once.
func (self *darwinDnsSdConnection) releaseWithLock() {
	self.api.refDeallocate(self.main)
	for key := range self.keys {
		darwinDnsSdRemoveHandler(key)
	}
	clear(self.keys)
}

// Runs start, which makes one operation sharing the connection, under a new key for handler. Called by the operations
// below.
func (self *darwinDnsSdConnection) start(handler *darwinDnsSdHandler, start func(ref *uintptr, key uintptr) int32) (*darwinDnsSdOperation, error) {
	self.callLock.Lock()
	defer self.callLock.Unlock()
	if self.closed {
		return nil, errDarwinDnsSdClosed
	}
	key := darwinDnsSdAddHandler(handler)
	// a shared operation's ref begins as a copy of the main one (kDNSServiceFlagsShareConnection)
	ref := self.main
	if err := darwinDnsSdErrorOf(start(&ref, key)); err != nil {
		darwinDnsSdRemoveHandler(key)
		return nil, err
	}
	self.keys[key] = true
	return &darwinDnsSdOperation{ref: ref, key: key}, nil
}

// Browses for instances of service in domain on the interface at index, each found or gone to handle.
func (self *darwinDnsSdConnection) Browse(index uint32, service string, domain string, handle func(reply *darwinDnsSdBrowseReply)) (*darwinDnsSdOperation, error) {
	return self.start(&darwinDnsSdHandler{browse: handle}, func(ref *uintptr, key uintptr) int32 {
		return self.api.browse(ref, darwinDnsSdFlagsShareConnection, index, service, domain, self.api.browseReply, key)
	})
}

// Resolves an instance to its target, port and TXT on the interface at index, following each change, to handle.
func (self *darwinDnsSdConnection) Resolve(index uint32, name string, service string, domain string, handle func(reply *darwinDnsSdResolveReply)) (*darwinDnsSdOperation, error) {
	return self.start(&darwinDnsSdHandler{resolve: handle}, func(ref *uintptr, key uintptr) int32 {
		return self.api.resolve(ref, darwinDnsSdFlagsShareConnection, index, name, service, domain, self.api.resolveReply, key)
	})
}

// Looks up a host's addresses of protocol (darwinDnsSdProtocolIpv4, darwinDnsSdProtocolIpv6) on the interface at index,
// each found or gone to handle.
func (self *darwinDnsSdConnection) GetAddrInfo(index uint32, protocol uint32, host string, handle func(reply *darwinDnsSdAddressReply)) (*darwinDnsSdOperation, error) {
	return self.start(&darwinDnsSdHandler{address: handle}, func(ref *uintptr, key uintptr) int32 {
		return self.api.getAddrInfo(ref, darwinDnsSdFlagsShareConnection, index, protocol, host, self.api.addressReply, key)
	})
}

// Registers a service on the interface at index with flags beside the shared connection's: name of service, with its
// subtypes, in domain, at host and port, with txt (none is one empty string, RFC 6763 §6.1). Its outcome goes to
// handle.
func (self *darwinDnsSdConnection) Register(flags uint32, index uint32, name string, service string, domain string, host string,
	port uint16, txt []byte, handle func(reply *darwinDnsSdRegisterReply)) (*darwinDnsSdOperation, error) {
	if 0xFFFF < len(txt) {
		return nil, darwinDnsSdError(darwinDnsSdErrBadParam)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], port)
	networkPort := binary.NativeEndian.Uint16(portBytes[:])
	defer runtime.KeepAlive(txt)
	return self.start(&darwinDnsSdHandler{register: handle}, func(ref *uintptr, key uintptr) int32 {
		return self.api.register(ref, flags|darwinDnsSdFlagsShareConnection, index, name, service, domain, host,
			networkPort, uint16(len(txt)), darwinDnsSdFirst(txt), self.api.registerReply, key)
	})
}

// Ends an operation: a browse, a resolve or a lookup stops, a registration is withdrawn. No reply of it follows.
func (self *darwinDnsSdConnection) Cancel(operation *darwinDnsSdOperation) {
	if operation == nil {
		return
	}
	self.callLock.Lock()
	defer self.callLock.Unlock()
	if self.closed || !self.keys[operation.key] {
		return
	}
	self.api.refDeallocate(operation.ref)
	delete(self.keys, operation.key)
	darwinDnsSdRemoveHandler(operation.key)
}

// Registers one record of rrtype with rdata on the interface at index, of the connection itself
// (DNSServiceRegisterRecord), with flags (darwinDnsSdFlagsShared or darwinDnsSdFlagsUnique); ttl 0 is the record type's
// default (RFC 6762 §10). Its outcome goes to handle.
func (self *darwinDnsSdConnection) RegisterRecord(flags uint32, index uint32, fullName string, rrtype uint16, rdata []byte,
	ttl uint32, handle func(err error)) (*darwinDnsSdRecord, error) {
	if len(rdata) == 0 || 0xFFFF < len(rdata) {
		return nil, darwinDnsSdError(darwinDnsSdErrBadParam)
	}
	self.callLock.Lock()
	defer self.callLock.Unlock()
	if self.closed {
		return nil, errDarwinDnsSdClosed
	}
	key := darwinDnsSdAddHandler(&darwinDnsSdHandler{record: handle})
	var ref uintptr
	defer runtime.KeepAlive(rdata)
	if err := darwinDnsSdErrorOf(self.api.registerRecord(self.main, &ref, flags, index, fullName, rrtype, darwinDnsSdClassIn,
		uint16(len(rdata)), darwinDnsSdFirst(rdata), ttl, self.api.registerRecordReply, key)); err != nil {
		darwinDnsSdRemoveHandler(key)
		return nil, err
	}
	self.keys[key] = true
	return &darwinDnsSdRecord{ref: ref, key: key}, nil
}

// Withdraws a registered record.
func (self *darwinDnsSdConnection) RemoveRecord(record *darwinDnsSdRecord) {
	if record == nil {
		return
	}
	self.callLock.Lock()
	defer self.callLock.Unlock()
	if self.closed || !self.keys[record.key] {
		return
	}
	self.api.removeRecord(self.main, record.ref, 0)
	delete(self.keys, record.key)
	darwinDnsSdRemoveHandler(record.key)
}
