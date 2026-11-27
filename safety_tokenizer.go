//go:build !ios_extension && !sidecar_http

// The classifier's tokenizer (DESIGN-COMPUTE §27.5's Tokens, §27.6's windows; SAFE-M13-01): text to the model's token
// ids with the release's SentencePiece vocabulary (safety_sentencepiece.go), then to the windows the model reads. The
// daemon and the sdk run it, so a runtime, the engine helper's or an app's, is given ids and holds no text logic.
//
// Encode is SentencePiece's unigram encoding as the library runs it (unigram_model.cc's optimized Encode, then
// SentencePieceProcessor's pieces to ids), which DeBERTa-v2's tokenizer, Prompt Guard 2's, calls:
//
//   - the text normalized (SafetyVocabulary.normalize: the character map, the dummy prefix, spaces to U+2581);
//   - a Viterbi pass over it, one character at a time: every normal or user-defined piece that starts at the character
//     scores its log probability, a user-defined one its length times the highest score less 0.1 so it is always
//     taken, and a character no single piece covers is an unknown of the lowest score less 10; the best path ending at
//     each byte is kept, a tie going to the path that reached it first, and path scores are kept in single precision
//     while each candidate sums in double, as the library's types have it;
//   - the best path read back from the end; a run of unknown pieces is one unknown id, as the library merges it,
//     except with byte fallback, where each unknown piece's bytes become their byte pieces' ids.
//
// The work is linear in the text: at each character the lattice looks at most the longest piece's bytes ahead, and
// the text is capped at SafetySettings.InputMaxByteCount, a longer one refused, unscored, which asks. The ids equal
// the reference tokenizer's only where the bench says so, over its whole corpus with the real vocabulary (§18,
// External); a literal "[CLS]" in a text is text here, as it is to SentencePiece, where Hugging Face's tokenizers would
// split it out as the special token: the bench's comparison says whether that difference stands.
//
// SafetyWindows cuts ids into windows of at most WindowTokenCount ids, [CLS] first and [SEP] last, each starting
// WindowOverlapTokenCount ids before the one before it ended, so any run of up to 65 ids is whole in one window
// (question compute-plan-safe-window-specials, QD-1373: the 512 include the two specials). An empty text is one window
// of the two specials alone, which the model scores as the reference pipeline would.
//
// Safe for concurrent use: nothing here changes after it is made.

package sidecar

import (
	"slices"
)

// The library's kUnkPenalty: an unknown character scores this much under the lowest piece.
const safetyUnkPenalty float32 = 10

// What turns text into the model's windows (see the file comment).
type SafetyTokenizer struct {
	vocabulary *SafetyVocabulary
	settings   *SafetySettings
}

// The tokenizer over vocabulary, refused where the settings leave no window room for text past the overlap.
func NewSafetyTokenizer(vocabulary *SafetyVocabulary, settings *SafetySettings) (*SafetyTokenizer, error) {
	if vocabulary == nil {
		return nil, safetyUnavailable("no vocabulary")
	}
	if err := safetyCheckWindowSettings(settings); err != nil {
		return nil, err
	}
	return &SafetyTokenizer{vocabulary: vocabulary, settings: settings}, nil
}

// Nil when a window holds the two specials and more text than the overlap, so each window advances.
func safetyCheckWindowSettings(settings *SafetySettings) error {
	if settings.WindowTokenCount-2 <= settings.WindowOverlapTokenCount || settings.WindowOverlapTokenCount < 0 {
		return safetyUnavailable("windows of %d tokens cannot overlap by %d", settings.WindowTokenCount, settings.WindowOverlapTokenCount)
	}
	return nil
}

// The vocabulary the tokenizer runs.
func (self *SafetyTokenizer) Vocabulary() *SafetyVocabulary {
	return self.vocabulary
}

// text's token ids, without the specials: refused, matching ErrSafetyUnavailable, past InputMaxByteCount or where the
// vocabulary's character map is not whole.
func (self *SafetyTokenizer) Encode(text string) ([]int64, error) {
	if self.settings.InputMaxByteCount < len(text) {
		return nil, safetyUnavailable("a text of %d bytes, past %d", len(text), self.settings.InputMaxByteCount)
	}
	normalized, err := self.vocabulary.normalize([]byte(text))
	if err != nil {
		return nil, err
	}
	return self.vocabulary.encode(normalized)
}

// text's windows: Encode's ids cut by SafetyWindows.
func (self *SafetyTokenizer) Windows(text string) ([][]int64, error) {
	ids, err := self.Encode(text)
	if err != nil {
		return nil, err
	}
	cls, sep := self.vocabulary.Specials()
	return SafetyWindows(ids, cls, sep, self.settings)
}

// The windows the model reads for ids (see the file comment): cls, at most WindowTokenCount - 2 ids, sep; each window's
// ids starting WindowOverlapTokenCount before the last one's end; one window of cls and sep for no ids.
func SafetyWindows(ids []int64, cls int64, sep int64, settings *SafetySettings) ([][]int64, error) {
	if err := safetyCheckWindowSettings(settings); err != nil {
		return nil, err
	}
	textCount := settings.WindowTokenCount - 2
	stride := textCount - settings.WindowOverlapTokenCount
	window := func(text []int64) []int64 {
		return slices.Concat([]int64{cls}, text, []int64{sep})
	}
	if len(ids) == 0 {
		return [][]int64{window(nil)}, nil
	}
	windows := [][]int64{}
	for start := 0; ; start += stride {
		end := min(start+textCount, len(ids))
		windows = append(windows, window(ids[start:end]))
		if end == len(ids) {
			return windows, nil
		}
	}
}

// The ids of normalized text (see the file comment): the Viterbi pass, the path read back, then the unknowns.
func (self *SafetyVocabulary) encode(normalized []byte) ([]int64, error) {
	size := len(normalized)
	if size == 0 {
		return []int64{}, nil
	}
	// the best path ending at each byte: its score and where its last piece starts; which piece it is, is read again
	// from those bytes when the path is read back, so a byte of text costs 8 bytes here
	type bestPath struct {
		score    float32
		startsAt int32
	}
	best := make([]bestPath, size+1)
	for i := range best {
		best[i].startsAt = -1
	}
	unkScore := self.minScore - safetyUnkPenalty
	for startsAt := 0; startsAt < size; {
		scoreTillHere := best[startsAt].score
		characterLength := min(safetyOneCharLen(normalized[startsAt]), size-startsAt)
		single := false
		self.prefixes(self.matchIds, normalized[startsAt:], self.matchMaxByteCount, func(id int32, length int) bool {
			piece := &self.pieces[id]
			// the library's conditional is a double: a float score widened, or a user-defined bonus
			score := float64(piece.score)
			if piece.kind == safetyPieceUserDefined {
				score = float64(float32(length)*self.maxScore) - 0.1
			}
			candidate := score + float64(scoreTillHere)
			target := &best[startsAt+length]
			if target.startsAt < 0 || float64(target.score) < candidate {
				target.score = float32(candidate)
				target.startsAt = int32(startsAt)
			}
			if length == characterLength {
				single = true
			}
			return true
		})
		if !single {
			target := &best[startsAt+characterLength]
			candidate := unkScore + scoreTillHere
			if target.startsAt < 0 || target.score < candidate {
				target.score = candidate
				target.startsAt = int32(startsAt)
			}
		}
		startsAt += characterLength
	}
	// the path, read back from the end
	type span struct {
		start int
		end   int
	}
	spans := []span{}
	for end := size; 0 < end; {
		start := int(best[end].startsAt)
		if start < 0 || end <= start {
			return nil, safetyUnavailable("a text the encoder found no path through")
		}
		spans = append(spans, span{start: start, end: end})
		end = start
	}
	slices.Reverse(spans)
	ids := make([]int64, 0, len(spans))
	previousUnknown := false
	for _, span := range spans {
		piece := normalized[span.start:span.end]
		id := self.matchId(piece)
		unknown := id < 0
		switch {
		case unknown && self.byteFallback:
			for _, b := range piece {
				ids = append(ids, int64(self.byteIds[b]))
			}
		case unknown && previousUnknown:
			// one unknown id for the run, as the library merges it
		case unknown:
			ids = append(ids, int64(self.unkId))
		default:
			ids = append(ids, int64(id))
		}
		previousUnknown = unknown
	}
	return ids, nil
}
