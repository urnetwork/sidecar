//go:build !ios_extension && !sidecar_http

// SentencePiece's model file, read by sidecar's own code (DESIGN-COMPUTE §27.5's Tokens; SAFE-M13-01): the release
// pins the classifier's vocabulary, Prompt Guard 2's spm.model, a SentencePiece ModelProto, and the daemon and the sdk
// turn text into the model's token ids with this reader and safety_tokenizer.go's encoder, so no host holds text logic.
//
// What it reads of the ModelProto (sentencepiece_model.proto), through protowire:
//
//   - the pieces: each one's bytes, its score (a log probability) and its type: normal, unknown, control,
//     user-defined, unused or byte;
//   - the trainer's spec: the model type, which must be unigram, byte fallback, and whitespace as a suffix, which this
//     reader does not run and refuses;
//   - the normalizer's spec: its precompiled character map, a darts-clone double-array trie over each rule's key with
//     the replacements after it, and its three switches, the dummy prefix, extra whitespace's removal and whitespace's
//     escape to U+2581.
//
// It refuses a file that does not parse whole (a field cut short), one past the settings' bounds, a model type other
// than unigram, a piece type it does not know, an empty piece, a piece twice in its namespace, a piece that is not
// UTF-8 or whose score is not a finite number, no unknown piece or two, byte pieces without byte fallback or byte
// fallback without all 256, no [CLS] or [SEP], and a character map that is not whole. A refusal matches both
// ErrSafetyVocabularyInvalid and ErrSafetyUnavailable, so every verdict asks until a vocabulary loads.
//
// Its normalizer is SentencePiece's Normalizer::Normalize as the library runs it: user-defined pieces pass unchanged,
// otherwise the longest rule of the character map that matches, among the first 32 a search finds, as the library's
// fixed result buffer has it, else the character itself, an invalid byte becoming U+FFFD; leading, trailing and
// repeated spaces dropped where the spec says so, the dummy prefix added, and every space escaped to U+2581. A rule
// pointing past the replacements is a character map that is not whole: the text is refused, never guessed. Two bounds
// the library does not keep, which no real map comes near: a rule is looked for at most CharsmapRuleMaxByteCount bytes
// in, and a text normalizing past NormalizeGrowthMaxFactor times its size is refused; each refusal asks.
//
// A parsed vocabulary is read only, so safe for concurrent use.

package sidecar

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
)

// A vocabulary this reader does not run, or a file that is not one. Every refusal also matches ErrSafetyUnavailable.
var ErrSafetyVocabularyInvalid = errors.New("safety vocabulary refused")

// A vocabulary refusal, naming the first fault.
func safetyVocabularyFault(format string, a ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrSafetyUnavailable, ErrSafetyVocabularyInvalid, fmt.Sprintf(format, a...))
}

// sentencepiece_model.proto's field numbers this reader takes.
const (
	safetySpModelPieces         protowire.Number = 1
	safetySpModelTrainerSpec    protowire.Number = 2
	safetySpModelNormalizerSpec protowire.Number = 3

	safetySpPiecePiece protowire.Number = 1
	safetySpPieceScore protowire.Number = 2
	safetySpPieceType  protowire.Number = 3

	safetySpTrainerModelType               protowire.Number = 3
	safetySpTrainerTreatWhitespaceAsSuffix protowire.Number = 24
	safetySpTrainerByteFallback            protowire.Number = 35

	safetySpNormalizerPrecompiledCharsmap    protowire.Number = 2
	safetySpNormalizerAddDummyPrefix         protowire.Number = 3
	safetySpNormalizerRemoveExtraWhitespaces protowire.Number = 4
	safetySpNormalizerEscapeWhitespaces      protowire.Number = 5
)

// TrainerSpec.ModelType's unigram, the one model this reader runs.
const safetySpModelTypeUnigram = 1

// SentencePiece.Type's values.
type safetyPieceType int32

const (
	safetyPieceNormal      safetyPieceType = 1
	safetyPieceUnknown     safetyPieceType = 2
	safetyPieceControl     safetyPieceType = 3
	safetyPieceUserDefined safetyPieceType = 4
	safetyPieceUnused      safetyPieceType = 5
	safetyPieceByte        safetyPieceType = 6
)

// The special tokens' pieces, as DeBERTa-v2's tokenizer names them: the model reads [CLS], the text, then [SEP].
const (
	safetyClsPiece = "[CLS]"
	safetySepPiece = "[SEP]"
)

// SentencePiece's whitespace symbol, U+2581, which the normalizer writes for each space.
const safetySpaceSymbol = "\u2581"

// The replacement character an invalid byte becomes, consuming that one byte.
const safetyReplacementCharacter = "\ufffd"

// The results a character map's prefix search keeps, as the library's fixed buffer does: of more matches, only the
// first, shortest, 32 count.
const safetyCharsmapResultCount = 32

// FLT_MIN, which the library starts its highest score at, so a user-defined piece's score reads it whatever the
// pieces' scores are.
var safetyFloatMinNormal = math.Float32frombits(0x00800000)

// One piece of the vocabulary.
type safetyPiece struct {
	text  string
	score float32
	kind  safetyPieceType
}

// A SentencePiece model the classifier's tokenizer runs (see the file comment), parsed by LoadSafetyVocabulary.
type SafetyVocabulary struct {
	// by id
	pieces []safetyPiece
	// the ids of the normal and user-defined pieces, which the encoder matches, by their bytes
	matchIds []int32
	// the ids of the user-defined pieces, which the normalizer passes unchanged, by their bytes
	userDefinedIds []int32
	// the longest bytes of each
	matchMaxByteCount       int
	userDefinedMaxByteCount int
	unkId                   int32
	clsId                   int32
	sepId                   int32
	byteFallback            bool
	// byte b's piece's id, with byte fallback
	byteIds [256]int32
	// the lowest normal piece's score, which an unknown character's is 10 below, and the highest, at least FLT_MIN
	minScore float32
	maxScore float32

	charsmap               *safetyCharsmap
	addDummyPrefix         bool
	removeExtraWhitespaces bool
	escapeWhitespaces      bool
	// how far a rule of the character map is looked for
	charsmapRuleMaxByteCount int
	// how many times its input's bytes the normalized text may grow to
	normalizeGrowthMaxFactor int
}

// The pieces the vocabulary holds.
func (self *SafetyVocabulary) PieceCount() int {
	return len(self.pieces)
}

// The ids the model reads before and after a window's text: [CLS]'s and [SEP]'s.
func (self *SafetyVocabulary) Specials() (cls int64, sep int64) {
	return int64(self.clsId), int64(self.sepId)
}

// The vocabulary in data, a SentencePiece ModelProto, refused as the file comment says.
func LoadSafetyVocabulary(data []byte, settings *SafetySettings) (*SafetyVocabulary, error) {
	if settings.VocabularyMaxByteCount < len(data) {
		return nil, safetyVocabularyFault("longer than %d bytes", settings.VocabularyMaxByteCount)
	}
	// the pieces' text is cut from one copy of the file, so 250,000 pieces cost no 250,000 allocations
	whole := string(data)
	textOf := func(field []byte) string {
		offset := cap(data) - cap(field)
		return whole[offset : offset+len(field)]
	}
	vocabulary := &SafetyVocabulary{
		addDummyPrefix:           true,
		removeExtraWhitespaces:   true,
		escapeWhitespaces:        true,
		charsmapRuleMaxByteCount: settings.CharsmapRuleMaxByteCount,
		normalizeGrowthMaxFactor: settings.NormalizeGrowthMaxFactor,
	}
	modelType := uint64(safetySpModelTypeUnigram)
	whitespaceAsSuffix := false
	var charsmap []byte
	err := safetyProtoFields(data, func(number protowire.Number, wireType protowire.Type, value []byte) error {
		switch number {
		case safetySpModelPieces:
			body, err := safetyProtoBytes(wireType, value)
			if err != nil {
				return err
			}
			if settings.VocabularyMaxPieceCount <= len(vocabulary.pieces) {
				return safetyVocabularyFault("more than %d pieces", settings.VocabularyMaxPieceCount)
			}
			piece := safetyPiece{kind: safetyPieceNormal}
			err = safetyProtoFields(body, func(number protowire.Number, wireType protowire.Type, value []byte) error {
				switch number {
				case safetySpPiecePiece:
					text, err := safetyProtoBytes(wireType, value)
					if err != nil {
						return err
					}
					piece.text = textOf(text)
				case safetySpPieceScore:
					if wireType != protowire.Fixed32Type {
						return safetyVocabularyFault("a score that is no float")
					}
					bits, _ := protowire.ConsumeFixed32(value)
					piece.score = math.Float32frombits(bits)
				case safetySpPieceType:
					kind, err := safetyProtoVarint(wireType, value)
					if err != nil {
						return err
					}
					piece.kind = safetyPieceType(int32(kind))
				}
				return nil
			})
			if err != nil {
				return err
			}
			vocabulary.pieces = append(vocabulary.pieces, piece)
		case safetySpModelTrainerSpec:
			body, err := safetyProtoBytes(wireType, value)
			if err != nil {
				return err
			}
			return safetyProtoFields(body, func(number protowire.Number, wireType protowire.Type, value []byte) error {
				var err error
				switch number {
				case safetySpTrainerModelType:
					modelType, err = safetyProtoVarint(wireType, value)
				case safetySpTrainerTreatWhitespaceAsSuffix:
					var flag uint64
					flag, err = safetyProtoVarint(wireType, value)
					whitespaceAsSuffix = flag != 0
				case safetySpTrainerByteFallback:
					var flag uint64
					flag, err = safetyProtoVarint(wireType, value)
					vocabulary.byteFallback = flag != 0
				}
				return err
			})
		case safetySpModelNormalizerSpec:
			body, err := safetyProtoBytes(wireType, value)
			if err != nil {
				return err
			}
			return safetyProtoFields(body, func(number protowire.Number, wireType protowire.Type, value []byte) error {
				var err error
				var flag uint64
				switch number {
				case safetySpNormalizerPrecompiledCharsmap:
					charsmap, err = safetyProtoBytes(wireType, value)
				case safetySpNormalizerAddDummyPrefix:
					flag, err = safetyProtoVarint(wireType, value)
					vocabulary.addDummyPrefix = flag != 0
				case safetySpNormalizerRemoveExtraWhitespaces:
					flag, err = safetyProtoVarint(wireType, value)
					vocabulary.removeExtraWhitespaces = flag != 0
				case safetySpNormalizerEscapeWhitespaces:
					flag, err = safetyProtoVarint(wireType, value)
					vocabulary.escapeWhitespaces = flag != 0
				}
				return err
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if modelType != safetySpModelTypeUnigram {
		return nil, safetyVocabularyFault("model type %d, not unigram", modelType)
	}
	if whitespaceAsSuffix {
		return nil, safetyVocabularyFault("whitespace as a suffix, which this reader does not run")
	}
	if 0 < len(charsmap) {
		vocabulary.charsmap, err = parseSafetyCharsmap(charsmap)
		if err != nil {
			return nil, err
		}
	}
	if err := vocabulary.index(settings); err != nil {
		return nil, err
	}
	return vocabulary, nil
}

// Checks every piece and builds the indexes the normalizer and the encoder search (see the file comment).
func (self *SafetyVocabulary) index(settings *SafetySettings) error {
	self.unkId, self.clsId, self.sepId = -1, -1, -1
	// SentencePiece's two namespaces: the normal, user-defined and unused pieces, which text can match, and the rest
	normalIds := map[string]int32{}
	reservedIds := map[string]int32{}
	byteFound := [256]bool{}
	self.minScore = math.MaxFloat32
	self.maxScore = safetyFloatMinNormal
	for i, piece := range self.pieces {
		id := int32(i)
		if piece.text == "" {
			return safetyVocabularyFault("piece %d is empty", i)
		}
		if settings.VocabularyPieceMaxByteCount < len(piece.text) {
			return safetyVocabularyFault("piece %d is longer than %d bytes", i, settings.VocabularyPieceMaxByteCount)
		}
		if !utf8.ValidString(piece.text) {
			return safetyVocabularyFault("piece %d is not UTF-8", i)
		}
		if score := float64(piece.score); math.IsNaN(score) || math.IsInf(score, 0) {
			return safetyVocabularyFault("piece %d's score is not a finite number", i)
		}
		namespace := reservedIds
		switch piece.kind {
		case safetyPieceNormal, safetyPieceUserDefined, safetyPieceUnused:
			namespace = normalIds
		case safetyPieceUnknown, safetyPieceControl, safetyPieceByte:
		default:
			return safetyVocabularyFault("piece %d has the type %d", i, piece.kind)
		}
		if _, ok := namespace[piece.text]; ok {
			return safetyVocabularyFault("piece %d is defined twice", i)
		}
		namespace[piece.text] = id
		switch piece.kind {
		case safetyPieceNormal:
			self.minScore = min(self.minScore, piece.score)
			self.maxScore = max(self.maxScore, piece.score)
			self.matchIds = append(self.matchIds, id)
		case safetyPieceUserDefined:
			self.matchIds = append(self.matchIds, id)
			self.userDefinedIds = append(self.userDefinedIds, id)
		case safetyPieceUnknown:
			if 0 <= self.unkId {
				return safetyVocabularyFault("two unknown pieces")
			}
			self.unkId = id
		case safetyPieceByte:
			if !self.byteFallback {
				return safetyVocabularyFault("a byte piece without byte fallback")
			}
			value, ok := safetyBytePieceValue(piece.text)
			if !ok {
				return safetyVocabularyFault("piece %d is no byte's", i)
			}
			byteFound[value] = true
			self.byteIds[value] = id
		}
	}
	if self.unkId < 0 {
		return safetyVocabularyFault("no unknown piece")
	}
	if self.byteFallback && slices.Contains(byteFound[:], false) {
		return safetyVocabularyFault("byte fallback without all 256 byte pieces")
	}
	// the library's PieceToId: the reserved namespace first
	special := func(text string) int32 {
		if id, ok := reservedIds[text]; ok {
			return id
		}
		if id, ok := normalIds[text]; ok {
			return id
		}
		return -1
	}
	self.clsId, self.sepId = special(safetyClsPiece), special(safetySepPiece)
	if self.clsId < 0 || self.sepId < 0 {
		return safetyVocabularyFault("no %s or %s piece", safetyClsPiece, safetySepPiece)
	}
	byText := func(a int32, b int32) int {
		return strings.Compare(self.pieces[a].text, self.pieces[b].text)
	}
	slices.SortFunc(self.matchIds, byText)
	slices.SortFunc(self.userDefinedIds, byText)
	for _, id := range self.matchIds {
		self.matchMaxByteCount = max(self.matchMaxByteCount, len(self.pieces[id].text))
	}
	for _, id := range self.userDefinedIds {
		self.userDefinedMaxByteCount = max(self.userDefinedMaxByteCount, len(self.pieces[id].text))
	}
	return nil
}

// The byte a byte piece names, <0x00> to <0xFF> with uppercase digits, as the library writes them.
func safetyBytePieceValue(text string) (byte, bool) {
	const digits = "0123456789ABCDEF"
	if len(text) != 6 || !strings.HasPrefix(text, "<0x") || text[5] != '>' {
		return 0, false
	}
	high, low := strings.IndexByte(digits, text[3]), strings.IndexByte(digits, text[4])
	if high < 0 || low < 0 {
		return 0, false
	}
	return byte(high<<4 | low), true
}

// Calls match for each piece of sorted, ids ordered by their bytes, that is a prefix of text, shortest first, looking
// at most maxByteCount bytes in, until match answers false. The pieces that share the text's first n bytes are one
// range of sorted, which each next byte narrows, so a position costs a few binary searches a byte.
func (self *SafetyVocabulary) prefixes(sorted []int32, text []byte, maxByteCount int, match func(id int32, length int) bool) {
	lo, hi := 0, len(sorted)
	for depth := 0; depth < len(text) && depth < maxByteCount && lo < hi; depth += 1 {
		// a piece of exactly depth bytes sorts first in the range, and matched a step ago
		if len(self.pieces[sorted[lo]].text) == depth {
			lo += 1
		}
		key := text[depth]
		start := lo
		lo = start + safetySearch(hi-start, func(i int) bool {
			return key <= self.pieces[sorted[start+i]].text[depth]
		})
		hi = lo + safetySearch(hi-lo, func(i int) bool {
			return key < self.pieces[sorted[lo+i]].text[depth]
		})
		if lo < hi && len(self.pieces[sorted[lo]].text) == depth+1 {
			if !match(sorted[lo], depth+1) {
				return
			}
		}
	}
}

// The smallest i in [0, n) at which holds is true, n where none; holds false then true over the range.
func safetySearch(n int, holds func(i int) bool) int {
	lo, hi := 0, n
	for lo < hi {
		middle := int(uint(lo+hi) >> 1)
		if holds(middle) {
			hi = middle
		} else {
			lo = middle + 1
		}
	}
	return lo
}

// The id of the matched piece whose bytes are text, -1 for none.
func (self *SafetyVocabulary) matchId(text []byte) int32 {
	found := int32(-1)
	self.prefixes(self.matchIds, text, len(text), func(id int32, length int) bool {
		if length == len(text) {
			found = id
			return false
		}
		return true
	})
	return found
}

// A precompiled character map (normalizer.cc's DecodePrecompiledCharsMap): darts-clone's double array over the rules'
// keys, and the replacements, each ending in a NUL.
type safetyCharsmap struct {
	units        []uint32
	replacements []byte
}

// The character map in blob: a little-endian uint32 of the trie's bytes, the trie, then the replacements.
func parseSafetyCharsmap(blob []byte) (*safetyCharsmap, error) {
	if len(blob) <= 4 {
		return nil, safetyVocabularyFault("a character map too short to hold its trie")
	}
	trieByteCount := binary.LittleEndian.Uint32(blob)
	rest := blob[4:]
	if uint64(len(rest)) < uint64(trieByteCount) || trieByteCount%4 != 0 || trieByteCount == 0 {
		return nil, safetyVocabularyFault("a character map whose trie is not whole")
	}
	units := make([]uint32, trieByteCount/4)
	for i := range units {
		units[i] = binary.LittleEndian.Uint32(rest[4*i:])
	}
	return &safetyCharsmap{units: units, replacements: rest[trieByteCount:]}, nil
}

// Whether a darts-clone unit's node ends a key, its value at its base.
func safetyDartsHasLeaf(unit uint32) bool {
	return (unit>>8)&1 == 1
}

// A value unit's value, its low 31 bits.
func safetyDartsValue(unit uint32) uint32 {
	return unit & (1<<31 - 1)
}

// A unit's label: its low byte, and its high bit, which a value unit sets so no byte matches it.
func safetyDartsLabel(unit uint32) uint32 {
	return unit & (1<<31 | 0xFF)
}

// The offset a unit gives its children's base, in its high bits, shifted 8 more where its bit 9 says so.
func safetyDartsOffset(unit uint32) uint32 {
	return (unit >> 10) << ((unit & (1 << 9)) >> 6)
}

// The longest rule whose key is a prefix of text, among the first safetyCharsmapResultCount a search finds and looking
// at most maxByteCount bytes in: its replacement and its key's length, or found false. A rule pointing past the
// replacements, or to one with no NUL, is an error.
func (self *safetyCharsmap) longestMatch(text []byte, maxByteCount int) (replacement []byte, length int, found bool, err error) {
	if len(self.units) == 0 {
		return nil, 0, false, nil
	}
	units := self.units
	position := uint64(safetyDartsOffset(units[0]))
	resultCount := 0
	value := uint32(0)
	for i := 0; i < len(text) && i < maxByteCount; i += 1 {
		position ^= uint64(text[i])
		if uint64(len(units)) <= position {
			break
		}
		unit := units[position]
		if safetyDartsLabel(unit) != uint32(text[i]) {
			break
		}
		position ^= uint64(safetyDartsOffset(unit))
		if safetyDartsHasLeaf(unit) {
			if uint64(len(units)) <= position {
				break
			}
			if resultCount < safetyCharsmapResultCount {
				value, length = safetyDartsValue(units[position]), i+1
			}
			resultCount += 1
		}
	}
	if length == 0 {
		return nil, 0, false, nil
	}
	if uint64(len(self.replacements)) <= uint64(value) {
		return nil, 0, false, safetyVocabularyFault("a character map rule past its replacements")
	}
	end := slices.Index(self.replacements[value:], 0)
	if end < 0 {
		return nil, 0, false, safetyVocabularyFault("a character map replacement with no end")
	}
	return self.replacements[value : int(value)+end], length, true, nil
}

// The library's OneCharLen: a UTF-8 sequence's length by its first byte, 1 for a byte no sequence starts with.
func safetyOneCharLen(first byte) int {
	return int("\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x02\x02\x03\x04"[first>>4])
}

// What the normalizer makes of input's first characters: their normalized bytes and how many input bytes they were.
func (self *SafetyVocabulary) normalizePrefix(input []byte) ([]byte, int, error) {
	// user-defined pieces pass as they are
	userDefinedLength := 0
	self.prefixes(self.userDefinedIds, input, self.userDefinedMaxByteCount, func(id int32, length int) bool {
		userDefinedLength = length
		return true
	})
	if 0 < userDefinedLength {
		return input[:userDefinedLength], userDefinedLength, nil
	}
	if self.charsmap != nil {
		replacement, length, found, err := self.charsmap.longestMatch(input, self.charsmapRuleMaxByteCount)
		if err != nil {
			return nil, 0, err
		}
		if found {
			return replacement, length, nil
		}
	}
	if character, size := utf8.DecodeRune(input); character == utf8.RuneError && size <= 1 {
		return []byte(safetyReplacementCharacter), 1, nil
	} else {
		return input[:size], size, nil
	}
}

// SentencePiece's Normalizer::Normalize (see the file comment): input as the encoder reads it.
func (self *SafetyVocabulary) normalize(input []byte) ([]byte, error) {
	if self.removeExtraWhitespaces {
		for 0 < len(input) {
			normalized, consumed, err := self.normalizePrefix(input)
			if err != nil {
				return nil, err
			}
			if string(normalized) != " " {
				break
			}
			input = input[consumed:]
		}
	}
	if len(input) == 0 {
		return nil, nil
	}
	space := []byte(" ")
	if self.escapeWhitespaces {
		space = []byte(safetySpaceSymbol)
	}
	// a character map's replacements bound the growth only as far as the file does, so the text is held to a multiple
	// of itself and refused past it, never grown without end
	maxByteCount := self.normalizeGrowthMaxFactor*len(input) + len(space)
	output := make([]byte, 0, len(input)+len(input)/2+len(space))
	if self.addDummyPrefix {
		output = append(output, space...)
	}
	previousSpace := self.removeExtraWhitespaces
	for 0 < len(input) {
		normalized, consumed, err := self.normalizePrefix(input)
		if err != nil {
			return nil, err
		}
		if previousSpace {
			for 0 < len(normalized) && normalized[0] == ' ' {
				normalized = normalized[1:]
			}
		}
		if 0 < len(normalized) {
			for _, b := range normalized {
				if b == ' ' {
					output = append(output, space...)
				} else {
					output = append(output, b)
				}
			}
			if maxByteCount < len(output) {
				return nil, safetyUnavailable("a text that normalizes past %d times its size", self.normalizeGrowthMaxFactor)
			}
			previousSpace = normalized[len(normalized)-1] == ' '
		}
		input = input[consumed:]
		if !self.removeExtraWhitespaces {
			previousSpace = false
		}
	}
	if self.removeExtraWhitespaces {
		for 0 < len(output) && bytes.HasSuffix(output, space) {
			output = output[:len(output)-len(space)]
		}
	}
	return output, nil
}

// Calls field for each field of message in order, refusing a message that does not parse whole.
func safetyProtoFields(message []byte, field func(number protowire.Number, wireType protowire.Type, value []byte) error) error {
	for 0 < len(message) {
		number, wireType, tagLength := protowire.ConsumeTag(message)
		if tagLength < 0 {
			return safetyVocabularyFault("a field cut short")
		}
		message = message[tagLength:]
		valueLength := protowire.ConsumeFieldValue(number, wireType, message)
		if valueLength < 0 {
			return safetyVocabularyFault("a field cut short")
		}
		if err := field(number, wireType, message[:valueLength]); err != nil {
			return err
		}
		message = message[valueLength:]
	}
	return nil
}

// A length-delimited field's body.
func safetyProtoBytes(wireType protowire.Type, value []byte) ([]byte, error) {
	if wireType != protowire.BytesType {
		return nil, safetyVocabularyFault("a field of the wrong wire type")
	}
	body, _ := protowire.ConsumeBytes(value)
	return body, nil
}

// A varint field's value.
func safetyProtoVarint(wireType protowire.Type, value []byte) (uint64, error) {
	if wireType != protowire.VarintType {
		return 0, safetyVocabularyFault("a field of the wrong wire type")
	}
	number, _ := protowire.ConsumeVarint(value)
	return number, nil
}
