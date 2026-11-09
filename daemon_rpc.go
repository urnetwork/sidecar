//go:build !js && !ios && !android && !sdk_mobile_bind

// The control and hook modes' newline-delimited JSON-RPC 2.0 (§5.8): one request a line, one response a line, every
// method an area registers as a DaemonMethod, so no area edits this file. The mode selects a protocol, never a
// privilege (D-CORE-9): a method marked Confirm runs only from control, and only when the request says the ur that
// sent it confirmed on /dev/tty or in an app's UI (DaemonCall.Confirmed), never from mcp or hook. Any same-uid
// process can forge that flag, the residual owner decision 47 discloses; a presence check closes it for the acts it
// covers (§5.6).
//
// Replies never carry a token, a key, the pass or a recovery code (I-7): a method's result is walked before it is
// encoded, and one holding a value of a secret type (daemonSecretValue, or one of daemonSecretTypes) is refused with
// an internal error in its place, so a method that returns the wrong struct fails loudly rather than leaking.

package sidecar

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

// A control method an area registers (§5.8): what it is called, whether it acts on one network and whether it needs
// a person's confirmation.
type DaemonMethod struct {
	// The JSON-RPC method name.
	Name string
	// The call acts on one network: its network argument, else .ur's, else the only network the daemon hosts
	// (§5.8). One that resolves to none is refused FAILED_PRECONDITION before the handler runs, and the handler gets
	// the network and its Sidecar.
	Network bool
	// Signs or approves what only a person may (D-CORE-13): runs only from control, with Confirmed set.
	Confirm bool
	// Runs the call. Its result is JSON-encoded as the response's result, after the secret walk; its error's text
	// is the response's message.
	Handler func(ctx context.Context, call *DaemonCall) (any, error)
}

// One call of a DaemonMethod.
type DaemonCall struct {
	// The session's hello.
	Hello *DaemonHello
	// The request's params, as sent.
	Params json.RawMessage
	// The network argument as sent, for a Network method.
	Network string
	// A Network method's network, resolved by §5.8's rule, and the Sidecar hosting it.
	NetworkId Id
	Sidecar   *Sidecar
	// The agent the session acts as: its hello's, else its project's .ur default; nil for none (daemon_agent.go).
	Agent *SidecarAgent
	// The ur that sent the call confirmed it on /dev/tty or in an app's UI (D-CORE-13). Only control mode sets it;
	// any same-uid process can forge it (owner decision 47).
	Confirmed bool
}

// A value no reply may carry: the root's types holding a token, a key, a seed or a pass carry this method, so the
// reply walk refuses them wherever they sit.
type daemonSecretValue interface {
	daemonSecret()
}

// A secret no reply carries.
func (self *AuthKey) daemonSecret() {}

// A secret no reply carries.
func (self *AuthKeyBundle) daemonSecret() {}

// A secret no reply carries.
func (self *SidecarServiceToken) daemonSecret() {}

// A secret no reply carries.
func (self *SidecarEnrollResult) daemonSecret() {}

// A secret no reply carries.
func (self *SidecarEnrollCredential) daemonSecret() {}

// A secret no reply carries.
func (self *SidecarAuthClientResult) daemonSecret() {}

// A secret no reply carries.
func (self *sidecarIdentityKeys) daemonSecret() {}

// A secret no reply carries.
func (self *sidecarIdentityRecord) daemonSecret() {}

// A secret no reply carries.
func (self *SidecarApi) daemonSecret() {}

// A secret no reply carries.
func (self *keychain) daemonSecret() {}

// Secret types the root does not own, so they cannot carry the method.
var daemonSecretTypes = map[reflect.Type]bool{
	reflect.TypeFor[ed25519.PrivateKey](): true,
}

// The secret marker's interface, for the walk.
var daemonSecretValueType = reflect.TypeFor[daemonSecretValue]()

// The bound on how deep the walk follows a value, past which it refuses: a reply nests a few levels, and a cycle
// would otherwise never end.
const daemonReplyMaxDepth = 32

// Refuses a reply that holds a secret anywhere it can reach: a value of a type marked daemonSecretValue, as itself or
// behind a pointer, or one of daemonSecretTypes. Unexported fields are walked too, since encoding/json skips them
// but a MarshalJSON need not.
func checkDaemonReply(value any) error {
	visited := map[uintptr]bool{}
	var walk func(value reflect.Value, depth int) error
	walk = func(value reflect.Value, depth int) error {
		if !value.IsValid() {
			return nil
		}
		if daemonReplyMaxDepth < depth {
			return errors.New("the reply nests too deep")
		}
		valueType := value.Type()
		if daemonSecretTypes[valueType] || valueType.Implements(daemonSecretValueType) ||
			reflect.PointerTo(valueType).Implements(daemonSecretValueType) {
			return fmt.Errorf("the reply holds a %s", valueType)
		}
		switch value.Kind() {
		case reflect.Pointer, reflect.Interface:
			if value.IsNil() {
				return nil
			}
			if value.Kind() == reflect.Pointer {
				if visited[value.Pointer()] {
					return nil
				}
				visited[value.Pointer()] = true
			}
			return walk(value.Elem(), depth+1)
		case reflect.Struct:
			for i := 0; i < value.NumField(); i += 1 {
				if err := walk(value.Field(i), depth+1); err != nil {
					return err
				}
			}
		case reflect.Slice, reflect.Array:
			if value.Kind() == reflect.Slice && value.Type().Elem().Kind() == reflect.Uint8 {
				return nil
			}
			for i := 0; i < value.Len(); i += 1 {
				if err := walk(value.Index(i), depth+1); err != nil {
					return err
				}
			}
		case reflect.Map:
			iterator := value.MapRange()
			for iterator.Next() {
				if err := walk(iterator.Key(), depth+1); err != nil {
					return err
				}
				if err := walk(iterator.Value(), depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(reflect.ValueOf(value), 0)
}

// The network argument a Network method's params carry: a JSON object's "network" string, or "".
func daemonCallNetwork(params json.RawMessage) string {
	var withNetwork struct {
		Network string `json:"network"`
	}
	if len(params) == 0 || json.Unmarshal(params, &withNetwork) != nil {
		return ""
	}
	return withNetwork.Network
}

// The response to one request line of a session, or nil for a notification, which has no id and gets no answer. run
// runs the method's handler under the request bound, which the session gives.
func (self *Daemon) dispatch(line []byte, session *daemonSession, run func(handler func(ctx context.Context) (any, error)) (any, error, bool)) *daemonRpcResponse {
	hello := session.hello
	request := &daemonRpcRequest{}
	if err := json.Unmarshal(line, request); err != nil {
		return &daemonRpcResponse{JsonRpc: "2.0", Id: json.RawMessage("null"), Error: &DaemonRpcError{Code: daemonRpcParseError, Message: "parse error"}}
	}
	id := request.Id
	answer := func(code int, message string) *daemonRpcResponse {
		if id == nil {
			return nil
		}
		return &daemonRpcResponse{JsonRpc: "2.0", Id: id, Error: &DaemonRpcError{Code: code, Message: message}}
	}
	if request.JsonRpc != "2.0" || request.Method == "" {
		if id == nil {
			id = json.RawMessage("null")
		}
		return answer(daemonRpcInvalidRequest, "invalid request")
	}
	method, ok := self.method(request.Method)
	if !ok {
		return answer(daemonRpcMethodNotFound, "method not found")
	}
	confirmed := hello.Mode == DaemonModeControl && request.UrConfirmed
	if method.Confirm && !confirmed {
		return answer(DaemonRpcConfirmationRequired, "this call needs a person's confirmation on /dev/tty or in an app")
	}
	call := &DaemonCall{Hello: hello, Params: request.Params, Confirmed: confirmed}
	if method.Network {
		call.Network = daemonCallNetwork(request.Params)
		networkId, err := self.resolveSessionNetwork(session, call.Network)
		if err != nil {
			return answer(daemonNetworkErrorCode(err), err.Error())
		}
		sidecar, ok := self.SidecarForNetwork(networkId)
		if !ok {
			return answer(DaemonRpcFailedPrecondition, (&DaemonNetworkError{Reason: "unknown", Networks: self.hostedNetworkNames()}).Error())
		}
		call.NetworkId = networkId
		call.Sidecar = sidecar
	}
	agent, err := self.sessionAgent(session)
	if err != nil {
		return answer(daemonRpcInvalidParams, err.Error())
	}
	call.Agent = agent
	result, err, timedOut := run(func(ctx context.Context) (any, error) {
		return method.Handler(ctx, call)
	})
	if timedOut {
		return answer(DaemonRpcTimeout, "the call timed out")
	}
	if err != nil {
		return answer(DaemonRpcFailed, err.Error())
	}
	if err := checkDaemonReply(result); err != nil {
		self.log.Errorf("[daemon]method %s answered a secret, which no reply carries", request.Method)
		return answer(daemonRpcInternalError, "internal error")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return answer(daemonRpcInternalError, "internal error")
	}
	if id == nil {
		return nil
	}
	return &daemonRpcResponse{JsonRpc: "2.0", Id: id, Result: encoded}
}
