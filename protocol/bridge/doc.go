// Every wire type the keyless device role parses, declared here and nowhere else: signed.proto,
// auth.proto and bridge.proto (§4.4). No .proto exists yet.
//
// Imports only std and protobuf, so the iOS extension links this without the root or protocol
// (D-SDK-20).
package bridge
