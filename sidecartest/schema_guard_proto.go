// The guard's walk over proto fields (plan-TEST-small-readings reading 5). A proto field in §22.7's
// sense is one reachable from a message a <svc>service or server decodes, so the walk starts at the
// map's roots and follows message fields, and never enters bytes: a message behind sealed bytes is
// the design's sealed client data, and marking it visible would bury the signal. Every registered
// message of protocol/ must still land in a class, reached or sealed, so a message nobody classified
// fails too: nothing in the descriptors passes unseen.

package sidecartest

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	// each registers its files, which is what the walk reads
	_ "github.com/urnetwork/sidecar/protocol"
	_ "github.com/urnetwork/sidecar/protocol/bridge"
)

// This module's proto package, which every file of protocol/ and protocol/bridge declares (§4.9).
// Anything else registered, such as connect's bringyour, is not this guard's.
const schemaGuardProtoPackage = "urnetwork.sidecar"

// What a .proto's header says when it means no server reads the file.
const schemaGuardSealedClaim = "no server reads a field"

// A message's name in the map: its full name without its package.
func schemaGuardMessageName(message protoreflect.MessageDescriptor) string {
	return strings.TrimPrefix(string(message.FullName()), string(message.ParentFile().Package())+".")
}

// A field's key in the map.
func schemaGuardFieldKey(field protoreflect.FieldDescriptor) string {
	return schemaGuardMessageName(field.ContainingMessage()) + "." + string(field.Name())
}

// The message a field holds, a map's value included, or nil.
func schemaGuardFieldMessage(field protoreflect.FieldDescriptor) protoreflect.MessageDescriptor {
	if field.IsMap() {
		return field.MapValue().Message()
	}
	return field.Message()
}

// Every message declared in descriptors, nested ones included, by name in the map.
func schemaGuardDeclaredMessages(descriptors protoreflect.MessageDescriptors, messages map[string]protoreflect.MessageDescriptor) {
	for index := 0; index < descriptors.Len(); index += 1 {
		message := descriptors.Get(index)
		if message.IsMapEntry() {
			continue
		}
		messages[schemaGuardMessageName(message)] = message
		schemaGuardDeclaredMessages(message.Messages(), messages)
	}
}

// Each registered file of this module, by path.
func schemaGuardProtoFiles(files *protoregistry.Files) map[string]protoreflect.FileDescriptor {
	protoFiles := map[string]protoreflect.FileDescriptor{}
	files.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		if file.Package() == schemaGuardProtoPackage {
			protoFiles[file.Path()] = file
		}
		return true
	})
	return protoFiles
}

// One walk's results: what the roots reach, and what no root may.
type schemaGuardProtoWalk struct {
	// by name, the first root that reached each
	reachedMessageRoots map[string]string
	// by key, the first root that reached each
	reachedFieldRoots map[string]string
	// by name
	sealedMessages map[string]bool
}

// Walks from each root, skipping what the map says stays unset on what a server reads.
func (self *SchemaGuard) walkRoots(messages map[string]protoreflect.MessageDescriptor) (*schemaGuardProtoWalk, []string) {
	walk := &schemaGuardProtoWalk{
		reachedMessageRoots: map[string]string{},
		reachedFieldRoots:   map[string]string{},
		sealedMessages:      map[string]bool{},
	}
	findings := []string{}
	var visit func(message protoreflect.MessageDescriptor, rootName string)
	visit = func(message protoreflect.MessageDescriptor, rootName string) {
		messageName := schemaGuardMessageName(message)
		if _, seen := walk.reachedMessageRoots[messageName]; seen {
			return
		}
		walk.reachedMessageRoots[messageName] = rootName
		fields := message.Fields()
		for index := 0; index < fields.Len(); index += 1 {
			field := fields.Get(index)
			key := schemaGuardFieldKey(field)
			walk.reachedFieldRoots[key] = rootName
			if _, unset := self.fieldMap.Unset[key]; unset {
				continue
			}
			if inner := schemaGuardFieldMessage(field); inner != nil {
				visit(inner, rootName)
			}
		}
	}
	for _, rootName := range slices.Sorted(maps.Keys(self.fieldMap.Roots)) {
		message, found := messages[rootName]
		if !found {
			findings = append(findings, fmt.Sprintf("root %s is no registered message", rootName))
			continue
		}
		visit(message, rootName)
	}
	return walk, findings
}

// Marks a message and all it holds sealed, stopping at what a root reaches.
func (self *schemaGuardProtoWalk) seal(message protoreflect.MessageDescriptor) {
	messageName := schemaGuardMessageName(message)
	if self.sealedMessages[messageName] {
		return
	}
	self.sealedMessages[messageName] = true
	fields := message.Fields()
	for index := 0; index < fields.Len(); index += 1 {
		if inner := schemaGuardFieldMessage(fields.Get(index)); inner != nil {
			self.seal(inner)
		}
	}
}

// The field a Message.field key names, or nil.
func schemaGuardFindField(messages map[string]protoreflect.MessageDescriptor, key string) protoreflect.FieldDescriptor {
	messageName, fieldName, found := schemaGuardCutField(key)
	if !found {
		return nil
	}
	message, found := messages[messageName]
	if !found {
		return nil
	}
	return message.Fields().ByName(protoreflect.Name(fieldName))
}

// A field's type as a .proto writes it, with the message or enum by its own name.
func schemaGuardFieldType(field protoreflect.FieldDescriptor) string {
	name := field.Kind().String()
	switch field.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		name = string(field.Message().Name())
	case protoreflect.EnumKind:
		name = string(field.Enum().Name())
	}
	if field.IsList() {
		return "repeated " + name
	}
	return name
}

// Each area line whose number or type its descriptor contradicts.
func (self *SchemaGuard) areaFieldFindings(messages map[string]protoreflect.MessageDescriptor) []string {
	findings := []string{}
	for key, line := range self.areaFields {
		field := schemaGuardFindField(messages, key)
		if field == nil {
			continue
		}
		if line.Number != 0 && int32(field.Number()) != line.Number {
			findings = append(findings, fmt.Sprintf("proto field %s is number %d, and its line says %d", key, field.Number(), line.Number))
		}
		if line.Type != "" && schemaGuardFieldType(field) != line.Type {
			findings = append(findings, fmt.Sprintf("proto field %s is %s, and its line says %s", key, schemaGuardFieldType(field), line.Type))
		}
	}
	return findings
}

// What the seals say, each of which must be true of the descriptors.
func (self *SchemaGuard) sealFindings(walk *schemaGuardProtoWalk, messages map[string]protoreflect.MessageDescriptor, protoFiles map[string]protoreflect.FileDescriptor) []string {
	findings := []string{}
	for key, targetName := range self.fieldMap.Seals {
		field := schemaGuardFindField(messages, key)
		if field == nil {
			findings = append(findings, fmt.Sprintf("seal on %s names no field", key))
			continue
		}
		if field.Kind() != protoreflect.BytesKind {
			findings = append(findings, fmt.Sprintf("seal on %s: a seal is on bytes, and this is %s", key, field.Kind()))
		}
		target, found := messages[targetName]
		if !found {
			findings = append(findings, fmt.Sprintf("seal on %s opens to %s, which is no registered message", key, targetName))
			continue
		}
		walk.seal(target)
	}
	for messageName := range self.fieldMap.SealedMessages {
		message, found := messages[messageName]
		if !found {
			findings = append(findings, fmt.Sprintf("sealed message %s is no registered message", messageName))
			continue
		}
		if rootName, reached := walk.reachedMessageRoots[messageName]; reached {
			findings = append(findings, fmt.Sprintf("message %s is called sealed, and root %s reaches it", messageName, rootName))
		}
		walk.seal(message)
	}
	for path := range self.fieldMap.SealedFiles {
		file, found := protoFiles[path]
		if !found {
			findings = append(findings, fmt.Sprintf("sealed file %s is not registered", path))
			continue
		}
		fileMessages := map[string]protoreflect.MessageDescriptor{}
		schemaGuardDeclaredMessages(file.Messages(), fileMessages)
		for _, message := range fileMessages {
			walk.seal(message)
		}
	}
	return findings
}

// Whether a file's header, everything above its syntax statement, says no server reads the file. The
// sentence may wrap. A tree with no source for a descriptor, as a planted one may have, says nothing.
func (self *SchemaGuard) headerClaimsSealed(path string) (bool, error) {
	source, err := os.ReadFile(filepath.Join(self.sources.RootDirectory, filepath.FromSlash(path)))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	header, _, _ := strings.Cut(string(source), "\nsyntax = ")
	words := strings.Join(strings.Fields(strings.ReplaceAll(header, "//", " ")), " ")
	return strings.Contains(words, schemaGuardSealedClaim), nil
}

// Each message a root reaches in a file whose header says no server reads it. A header is a sentence,
// and the walk does not take its word for anything, or the next walk by hand will: record.proto's once
// sent one past the three messages every gate parses.
func (self *SchemaGuard) headerFindings(walk *schemaGuardProtoWalk, protoFiles map[string]protoreflect.FileDescriptor) []string {
	findings := []string{}
	for path, file := range protoFiles {
		claimed, err := self.headerClaimsSealed(path)
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		if !claimed {
			continue
		}
		fileMessages := map[string]protoreflect.MessageDescriptor{}
		schemaGuardDeclaredMessages(file.Messages(), fileMessages)
		for messageName := range fileMessages {
			if rootName, reached := walk.reachedMessageRoots[messageName]; reached {
				findings = append(findings, fmt.Sprintf(
					"%s says %s, and root %s reaches its message %s: correct the header", path, schemaGuardSealedClaim, rootName, messageName,
				))
			}
		}
	}
	return findings
}

// Each reached field with no row, each mapped field nothing reaches, each message in no class, and
// each enum mapped only in part. A row for a field is what the brief makes a precondition, so a finding
// says where the row comes from.
func (self *SchemaGuard) protoFindings() []string {
	protoFiles := schemaGuardProtoFiles(self.sources.Files)
	messages := map[string]protoreflect.MessageDescriptor{}
	for _, file := range protoFiles {
		schemaGuardDeclaredMessages(file.Messages(), messages)
	}
	walk, findings := self.walkRoots(messages)
	findings = append(findings, self.sealFindings(walk, messages, protoFiles)...)
	findings = append(findings, self.headerFindings(walk, protoFiles)...)
	findings = append(findings, self.areaFieldFindings(messages)...)

	for key, rootName := range walk.reachedFieldRoots {
		_, mapped := self.fieldMap.Fields[key]
		_, open := self.fieldMap.Open[key]
		_, unset := self.fieldMap.Unset[key]
		count := 0
		for _, present := range []bool{mapped, open, unset} {
			if present {
				count += 1
			}
		}
		switch {
		case count == 0:
			findings = append(findings, fmt.Sprintf("proto field %s, reachable from %s, maps to no row: give it one in %s, and if §2.8 has none raise a question (I-18)", key, rootName, schemaGuardFieldsPath))
		case 1 < count:
			findings = append(findings, fmt.Sprintf("proto field %s sits in more than one of fields, open and unset", key))
		}
	}
	stale := func(section string, keys []string) {
		for _, key := range keys {
			if _, reached := walk.reachedFieldRoots[key]; !reached {
				findings = append(findings, fmt.Sprintf("%s entry %s is a field no root reaches", section, key))
			}
		}
	}
	stale("fields", slices.Collect(maps.Keys(self.fieldMap.Fields)))
	stale("open", slices.Collect(maps.Keys(self.fieldMap.Open)))
	stale("unset", slices.Collect(maps.Keys(self.fieldMap.Unset)))

	for messageName := range messages {
		if _, reached := walk.reachedMessageRoots[messageName]; !reached && !walk.sealedMessages[messageName] {
			findings = append(findings, fmt.Sprintf("message %s is in no class: name it a root if a server decodes it, else say what seals it", messageName))
		}
	}
	return append(findings, self.enumFindings(protoFiles)...)
}

// Every enum declared in descriptors, nested in a message or not, by name in the map.
func schemaGuardDeclaredEnums(file protoreflect.FileDescriptor, enums map[string]protoreflect.EnumDescriptor) {
	add := func(descriptors protoreflect.EnumDescriptors) {
		for index := 0; index < descriptors.Len(); index += 1 {
			enum := descriptors.Get(index)
			enums[strings.TrimPrefix(string(enum.FullName()), string(file.Package())+".")] = enum
		}
	}
	add(file.Enums())
	messages := map[string]protoreflect.MessageDescriptor{}
	schemaGuardDeclaredMessages(file.Messages(), messages)
	for _, message := range messages {
		add(message.Enums())
	}
}

// Each enum_values entry that is no value, and each value of a mapped enum left out, which is how a new
// flag bit fails: EvsPush.flags is a uint32, so no field names the enum its bits come from.
func (self *SchemaGuard) enumFindings(protoFiles map[string]protoreflect.FileDescriptor) []string {
	enums := map[string]protoreflect.EnumDescriptor{}
	for _, file := range protoFiles {
		schemaGuardDeclaredEnums(file, enums)
	}
	findings := []string{}
	mappedEnums := map[string]bool{}
	for key := range self.fieldMap.EnumValues {
		enumName, valueName, found := schemaGuardCutField(key)
		if !found {
			findings = append(findings, fmt.Sprintf("enum value %s is not Enum.VALUE", key))
			continue
		}
		enum, found := enums[enumName]
		if !found || enum.Values().ByName(protoreflect.Name(valueName)) == nil {
			findings = append(findings, fmt.Sprintf("enum value %s is no registered value", key))
			continue
		}
		mappedEnums[enumName] = true
	}
	for enumName := range mappedEnums {
		values := enums[enumName].Values()
		for index := 0; index < values.Len(); index += 1 {
			key := enumName + "." + string(values.Get(index).Name())
			if _, mapped := self.fieldMap.EnumValues[key]; !mapped {
				findings = append(findings, fmt.Sprintf("enum value %s maps to no row, and its enum is mapped", key))
			}
		}
	}
	return findings
}
