// Git's pack delta, on every leg: a `diff` record's body is one against the file's previous version
// (D-EVS-3, R-EVS-7; §11.6, §11.7; gitformat-pack's deltified representation). A delta is two sizes
// and then instructions, each copying a range of the base or inserting bytes it carries. A reader
// runs them after decrypting, so what a writer's bytes may do ends here: apply checks every size and
// bound and refuses instead of panicking, and a final oid check (§11.7) answers for the content.
//
// Both directions stream (R-EVS-14, §11.15): neither holds a whole file, so a base over 1 MiB can sit
// in the sealed local store behind an EvsGitDeltaSource. The encoder's memory is what its settings
// say, and apply's is two chunks. Which files get a delta and whether one is worth keeping stay the
// caller's: the checkpoint rules, and a mobile client never diffing over 1 MiB, are EvsWritePlan's
// (§11.7). A caller stops an oversized delta by returning an error from its Write, which ends the
// encode.
//
// The encoder holds no table of constants, unlike git's Rabin window: it hashes a block by
// multiplication, in plain Go on every leg, and its one table is the per-call index of the base. It
// is deterministic, so equal inputs and settings give equal bytes on every leg.
//
// A delta here is equal to go-git's in what it means, not in its bytes: mlsinterop's git_oracle_test.go
// has go-git apply these and this apply go-git's. Apply also takes the deltas under stock git's 4 B
// minimum, because one that empties a file needs no more, and no delta here reaches stock git as a
// delta: export writes whole objects.

package sidecar

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math/bits"
)

const (
	// The high bit of an instruction: a copy, its low seven saying which operand bytes follow.
	evsGitDeltaCopyFlag = 0x80
	// A copy's offset field holds four bytes and its size field three, each present only where set.
	evsGitDeltaOffsetFieldCount = 4
	evsGitDeltaSizeFieldCount   = 3
	// What a copy's size of zero means, and the longest copy this encoder writes, as git's does.
	evsGitDeltaCopySizeDefault = 64 * 1024
	// The most bytes one insert carries: an instruction's seven low bits.
	evsGitDeltaMaxInsertSize = 127
	// A copy's offset field cannot reach past this, so the encoder stops short of it.
	evsGitDeltaMaxBaseReach = 4 * 1024 * 1024 * 1024
	// The most bytes of seven bits a size may take: 63 bits, an int64.
	evsGitDeltaMaxSizeByteCount = 9
	// The bytes the encoder hashes as one block, which is also the shortest match it copies: git's
	// window (diff-delta.c), and go-git's. A copy of fewer would barely beat inserting them.
	evsGitDeltaBlockSize = 16
	// The least a window or chunk may be: a chunk holds a whole insert, and half a window holds one
	// and a block.
	evsGitDeltaMinBufferSize = 256
	// The block hash's multiplier: odd, so no byte's effect is lost, and every bit is set about half
	// the time, which also makes it the finishing mix. 2^64 over the golden ratio, as Fibonacci
	// hashing uses it.
	evsGitDeltaHashFactor uint64 = 0x9e3779b97f4a7c15
)

// A delta's sizes are wrong, an instruction is out of bounds or cut short, or it holds the reserved
// instruction. Wrapped with the fault, never with content.
var ErrEvsGitDeltaInvalid = errors.New("git delta invalid")

// A result would pass the bound the caller set.
var ErrEvsGitDeltaTooLarge = errors.New("git delta result too large")

// Random access to bytes of a known size: bytes.Reader, io.SectionReader, or a sealed spill. Its size
// and bytes hold still for the call.
type EvsGitDeltaSource interface {
	io.ReaderAt
	Size() int64
}

// What the delta codec may use. Every number must be positive, and a change alters the delta bytes
// it writes and not what they mean. Sizes fit §11.15's 4 MiB iOS working set with room for the
// record and network layers beside them. A caller's settings block carries one of these from
// DefaultEvsGitDeltaSettings.
type EvsGitDeltaSettings struct {
	// Base blocks the encoder indexes, at 10 B each: 65,536, every 16 B block of a 1 MiB base, the
	// largest a phone diffs, in 640 KiB. A longer base is sampled evenly to fit, so a common run
	// shorter than the sampling step can go unfound and is inserted instead.
	IndexBlockCount int
	// Index entries examined at one position of the target: 16. This bounds the work per byte on
	// data that repeats, where every block has the same few candidates.
	CandidateCount int
	// A match this long ends the search at its position: 4 KiB, git's.
	GoodMatchByteCount int
	// Target bytes held at once: 128 KiB. A match grows backward over at most half of this.
	WindowByteCount int
	// Bytes of the base read at once, and bytes of a delta read and result written at once: 16 KiB. A
	// multiple of the 16 B block, so no block spans two reads.
	ChunkByteCount int
}

// The one source of the delta codec's numbers.
func DefaultEvsGitDeltaSettings() *EvsGitDeltaSettings {
	return &EvsGitDeltaSettings{
		IndexBlockCount:    64 * 1024,
		CandidateCount:     16,
		GoodMatchByteCount: 4 * 1024,
		WindowByteCount:    128 * 1024,
		ChunkByteCount:     16 * 1024,
	}
}

// Refuses what the code below could not run on, nil included.
func (self *EvsGitDeltaSettings) validate() error {
	switch {
	case self == nil:
		return fmt.Errorf("%w: no git delta settings", errInvalidSettings)
	case self.IndexBlockCount <= 0, self.CandidateCount <= 0, self.GoodMatchByteCount <= 0:
		return fmt.Errorf("%w: a git delta count is not positive", errInvalidSettings)
	case self.WindowByteCount < evsGitDeltaMinBufferSize, self.ChunkByteCount < evsGitDeltaMinBufferSize:
		return fmt.Errorf("%w: a git delta buffer is under %d B", errInvalidSettings, evsGitDeltaMinBufferSize)
	case self.ChunkByteCount%evsGitDeltaBlockSize != 0:
		return fmt.Errorf("%w: a git delta chunk is not a multiple of the block", errInvalidSettings)
	}
	return nil
}

// Reads a source's bytes into buffer, all of them or an error. A source shorter than it says is a
// fault in the caller's store, not in a delta.
func evsGitDeltaReadFull(source io.ReaderAt, buffer []byte, offset int64) error {
	readSize, err := source.ReadAt(buffer, offset)
	if readSize == len(buffer) {
		return nil
	}
	if err == nil || err == io.EOF {
		return fmt.Errorf("git delta source stops short of its size: %w", io.ErrUnexpectedEOF)
	}
	return err
}

// Reads one of a delta's two sizes: seven bits a byte, low bits first. A reader's own error comes back
// as it is, so a sealed stream's failure is not read as a bad delta.
func evsGitDeltaReadSize(delta io.ByteReader) (int64, error) {
	size := int64(0)
	for shift, count := 0, 0; ; shift, count = shift+7, count+1 {
		if evsGitDeltaMaxSizeByteCount <= count {
			return 0, fmt.Errorf("%w: a size is past 63 bits", ErrEvsGitDeltaInvalid)
		}
		sizeByte, err := delta.ReadByte()
		if err == io.EOF {
			return 0, fmt.Errorf("%w: a size is cut short", ErrEvsGitDeltaInvalid)
		}
		if err != nil {
			return 0, err
		}
		size |= int64(sizeByte&0x7f) << shift
		if sizeByte&0x80 == 0 {
			return size, nil
		}
	}
}

// Appends one of a delta's two sizes.
func evsGitDeltaAppendSize(encoded []byte, size int64) []byte {
	for 0x7f < size {
		encoded = append(encoded, byte(size&0x7f)|0x80)
		size >>= 7
	}
	return append(encoded, byte(size))
}

// Runs delta against base, writing the result as it goes, and answers the result's size. A result
// past maxResultSize is ErrEvsGitDeltaTooLarge before any of it is written: the size is the delta's
// claim, which a 7 B copy can multiply a million times over, and nothing is allocated on it. Every
// other fault in the delta is ErrEvsGitDeltaInvalid, and an error from a reader or writer comes back
// as it is. After any error the bytes already written mean nothing, and the caller drops them.
func EvsGitDeltaApply(base EvsGitDeltaSource, delta io.Reader, maxResultSize int64, result io.Writer, settings *EvsGitDeltaSettings) (int64, error) {
	if err := settings.validate(); err != nil {
		return 0, err
	}
	reader := bufio.NewReaderSize(delta, settings.ChunkByteCount)
	baseSize, err := evsGitDeltaReadSize(reader)
	if err != nil {
		return 0, err
	}
	if baseSize != base.Size() {
		return 0, fmt.Errorf("%w: its base size is not the base's", ErrEvsGitDeltaInvalid)
	}
	resultSize, err := evsGitDeltaReadSize(reader)
	if err != nil {
		return 0, err
	}
	if maxResultSize < resultSize {
		return 0, ErrEvsGitDeltaTooLarge
	}

	chunk := make([]byte, settings.ChunkByteCount)
	remainingSize := resultSize
	// the next operand byte, where running out is the delta's fault
	readOperand := func() (int64, error) {
		operand, err := reader.ReadByte()
		if err == io.EOF {
			return 0, fmt.Errorf("%w: a copy is cut short", ErrEvsGitDeltaInvalid)
		}
		return int64(operand), err
	}
	for {
		instruction, err := reader.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
		switch {
		case instruction&evsGitDeltaCopyFlag != 0:
			copyOffset, copySize := int64(0), int64(0)
			for field := 0; field < evsGitDeltaOffsetFieldCount; field += 1 {
				if instruction&(1<<field) != 0 {
					operand, err := readOperand()
					if err != nil {
						return 0, err
					}
					copyOffset |= operand << (8 * field)
				}
			}
			for field := 0; field < evsGitDeltaSizeFieldCount; field += 1 {
				if instruction&(1<<(evsGitDeltaOffsetFieldCount+field)) != 0 {
					operand, err := readOperand()
					if err != nil {
						return 0, err
					}
					copySize |= operand << (8 * field)
				}
			}
			if copySize == 0 {
				copySize = evsGitDeltaCopySizeDefault
			}
			if baseSize < copyOffset || baseSize-copyOffset < copySize || remainingSize < copySize {
				return 0, fmt.Errorf("%w: a copy is out of bounds", ErrEvsGitDeltaInvalid)
			}
			for copied := int64(0); copied < copySize; {
				piece := chunk[:min(int64(len(chunk)), copySize-copied)]
				if err := evsGitDeltaReadFull(base, piece, copyOffset+copied); err != nil {
					return 0, err
				}
				if _, err := result.Write(piece); err != nil {
					return 0, err
				}
				copied += int64(len(piece))
			}
			remainingSize -= copySize
		case instruction != 0:
			insertSize := int64(instruction)
			if remainingSize < insertSize {
				return 0, fmt.Errorf("%w: an insert is out of bounds", ErrEvsGitDeltaInvalid)
			}
			piece := chunk[:insertSize]
			if _, err := io.ReadFull(reader, piece); err != nil {
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					return 0, fmt.Errorf("%w: an insert is cut short", ErrEvsGitDeltaInvalid)
				}
				return 0, err
			}
			if _, err := result.Write(piece); err != nil {
				return 0, err
			}
			remainingSize -= insertSize
		default:
			return 0, fmt.Errorf("%w: the reserved instruction", ErrEvsGitDeltaInvalid)
		}
	}
	if remainingSize != 0 {
		return 0, fmt.Errorf("%w: it stops short of its result size", ErrEvsGitDeltaInvalid)
	}
	return resultSize, nil
}

// One aligned chunk of a base at a time, so scanning for matches near each other reads the base once.
type evsGitDeltaChunkCache struct {
	source EvsGitDeltaSource
	chunk  []byte
	// where chunk starts in the source, and -1 before the first load
	chunkOffset int64
	loadedSize  int
}

// The source's bytes from offset to the end of offset's chunk, borrowed until the next call. Never
// empty for an offset inside the source.
func (self *evsGitDeltaChunkCache) from(offset int64) ([]byte, error) {
	chunkSize := int64(len(self.chunk))
	chunkOffset := offset - offset%chunkSize
	if chunkOffset != self.chunkOffset {
		self.chunkOffset = -1
		loadedSize := int(min(chunkSize, self.source.Size()-chunkOffset))
		if err := evsGitDeltaReadFull(self.source, self.chunk[:loadedSize], chunkOffset); err != nil {
			return nil, err
		}
		self.chunkOffset = chunkOffset
		self.loadedSize = loadedSize
	}
	return self.chunk[offset-chunkOffset : self.loadedSize], nil
}

// A block's hash: a polynomial in the factor, mod 2^64.
func evsGitDeltaHashBlock(block []byte) uint64 {
	blockHash := uint64(0)
	for _, blockByte := range block {
		blockHash = blockHash*evsGitDeltaHashFactor + uint64(blockByte)
	}
	return blockHash
}

// The factor to the block size, which rolling a hash one byte along takes out of the oldest byte.
var evsGitDeltaHashFactorPower = func() uint64 {
	power := uint64(1)
	for count := 0; count < evsGitDeltaBlockSize; count += 1 {
		power *= evsGitDeltaHashFactor
	}
	return power
}()

// An index of the base's blocks: a chained hash table in three flat slices, so its size is its
// settings' whatever the base holds. Entry i is the block at offset i times stride.
type evsGitDeltaIndex struct {
	// bucket to its first entry plus one, 0 for none; a table of a power of two
	heads []uint32
	// entry to the next in its bucket plus one, 0 for none, in rising offset
	nexts []uint32
	// more of each entry's hash, so a colliding entry costs no read of the base
	checks []uint16
	// 64 less the table's bits, so a mixed hash shifted by this is its bucket
	bucketShift int
	// bytes from one entry's block to the next
	stride int64
}

// A hash's bucket and its check. A block hash's top bits miss the block's last byte, so they are
// mixed before the table reads them.
func (self *evsGitDeltaIndex) locate(blockHash uint64) (uint64, uint16) {
	mixedHash := (blockHash ^ blockHash>>32) * evsGitDeltaHashFactor
	return mixedHash >> self.bucketShift, uint16(mixedHash >> 8)
}

// Indexes the first reach bytes of base. Blocks go in from the end, so a bucket reads in rising offset
// and the earliest place leaves the longest run after it, and a run of equal blocks keeps only its
// first, or a file of zeros would fill a bucket with candidates that all run out early.
func newEvsGitDeltaIndex(base *evsGitDeltaChunkCache, reach int64, settings *EvsGitDeltaSettings) (*evsGitDeltaIndex, error) {
	index := &evsGitDeltaIndex{}
	blockTotal := reach / evsGitDeltaBlockSize
	if blockTotal == 0 {
		return index, nil
	}
	maxBlockCount := int64(settings.IndexBlockCount)
	index.stride = evsGitDeltaBlockSize * ((blockTotal + maxBlockCount - 1) / maxBlockCount)
	entryCount := (reach-evsGitDeltaBlockSize)/index.stride + 1
	tableBits := bits.Len64(uint64(entryCount - 1))
	index.heads = make([]uint32, 1<<tableBits)
	index.nexts = make([]uint32, entryCount)
	index.checks = make([]uint16, entryCount)
	index.bucketShift = 64 - tableBits

	laterHash := uint64(0)
	for entry := entryCount - 1; 0 <= entry; entry -= 1 {
		block, err := base.from(entry * index.stride)
		if err != nil {
			return nil, err
		}
		blockHash := evsGitDeltaHashBlock(block[:evsGitDeltaBlockSize])
		bucket, check := index.locate(blockHash)
		index.checks[entry] = check
		if entry != entryCount-1 && blockHash == laterHash {
			// takes the later block's place, which the bucket's head still is
			index.nexts[entry] = index.nexts[entry+1]
		} else {
			index.nexts[entry] = index.heads[bucket]
		}
		index.heads[bucket] = uint32(entry) + 1
		laterHash = blockHash
	}
	return index, nil
}

// One encode's state. The target passes through window: bytes before insertStart are written out,
// insertStart to position wait to become an insert or the tail of a match, and position to loadedSize
// are yet to be scanned.
type evsGitDeltaEncoder struct {
	settings *EvsGitDeltaSettings
	base     *evsGitDeltaChunkCache
	// where copies stop: the base's size, or what a copy's offset can reach
	baseReach int64
	index     *evsGitDeltaIndex
	target    EvsGitDeltaSource
	// where window[0] sits in the target
	windowOffset int64
	window       []byte
	insertStart  int
	position     int
	loadedSize   int
	output       *bufio.Writer
}

// Writes window[insertStart:insertEnd] as inserts.
func (self *evsGitDeltaEncoder) writeInserts(insertEnd int) error {
	for self.insertStart < insertEnd {
		insertSize := min(insertEnd-self.insertStart, evsGitDeltaMaxInsertSize)
		if err := self.output.WriteByte(byte(insertSize)); err != nil {
			return err
		}
		if _, err := self.output.Write(self.window[self.insertStart : self.insertStart+insertSize]); err != nil {
			return err
		}
		self.insertStart += insertSize
	}
	return nil
}

// Writes copies of size bytes from offset. A field of zero stays out, and a copy of the longest size
// holds no size field at all, since that is what zero reads as.
func (self *evsGitDeltaEncoder) writeCopies(offset int64, size int) error {
	for 0 < size {
		copySize := min(size, evsGitDeltaCopySizeDefault)
		instruction := [1 + evsGitDeltaOffsetFieldCount + evsGitDeltaSizeFieldCount]byte{evsGitDeltaCopyFlag}
		instructionSize := 1
		for field := 0; field < evsGitDeltaOffsetFieldCount; field += 1 {
			if operand := byte(offset >> (8 * field)); operand != 0 {
				instruction[0] |= 1 << field
				instruction[instructionSize] = operand
				instructionSize += 1
			}
		}
		for field := 0; field < evsGitDeltaSizeFieldCount; field += 1 {
			if operand := byte(copySize % evsGitDeltaCopySizeDefault >> (8 * field)); operand != 0 {
				instruction[0] |= 1 << (evsGitDeltaOffsetFieldCount + field)
				instruction[instructionSize] = operand
				instructionSize += 1
			}
		}
		if _, err := self.output.Write(instruction[:instructionSize]); err != nil {
			return err
		}
		offset += int64(copySize)
		size -= copySize
	}
	return nil
}

// Makes room and reads on, answering false once the whole target is loaded. Pending bytes past half
// the window go out as inserts first, in full ones, so the rest can still join a match.
func (self *evsGitDeltaEncoder) loadMore() (bool, error) {
	targetSize := self.target.Size()
	unloadedSize := targetSize - self.windowOffset - int64(self.loadedSize)
	if unloadedSize == 0 {
		return false, nil
	}
	if excessSize := self.position - self.insertStart - len(self.window)/2; 0 < excessSize {
		excessSize += evsGitDeltaMaxInsertSize - 1
		excessSize -= excessSize % evsGitDeltaMaxInsertSize
		if err := self.writeInserts(self.insertStart + excessSize); err != nil {
			return false, err
		}
	}
	keptSize := copy(self.window, self.window[self.insertStart:self.loadedSize])
	self.windowOffset += int64(self.insertStart)
	self.position -= self.insertStart
	self.insertStart = 0
	self.loadedSize = keptSize
	readSize := int(min(int64(len(self.window)-keptSize), unloadedSize))
	if err := evsGitDeltaReadFull(self.target, self.window[keptSize:keptSize+readSize], self.windowOffset+int64(keptSize)); err != nil {
		return false, err
	}
	self.loadedSize += readSize
	return true, nil
}

// How many bytes of the base from offset equal the loaded target from position.
func (self *evsGitDeltaEncoder) matchSize(offset int64) (int, error) {
	maxSize := int(min(int64(self.loadedSize-self.position), self.baseReach-offset))
	matchedSize := 0
	for matchedSize < maxSize {
		chunk, err := self.base.from(offset + int64(matchedSize))
		if err != nil {
			return 0, err
		}
		comparedSize := min(len(chunk), maxSize-matchedSize)
		loaded := self.window[self.position+matchedSize:]
		for index := 0; index < comparedSize; index += 1 {
			if chunk[index] != loaded[index] {
				return matchedSize + index, nil
			}
		}
		matchedSize += comparedSize
	}
	return matchedSize, nil
}

// The longest match at position among the candidates blockHash's bucket holds, the earliest of equals,
// and 0 if none reaches a block.
func (self *evsGitDeltaEncoder) findMatch(blockHash uint64) (int64, int, error) {
	if len(self.index.heads) == 0 {
		return 0, 0, nil
	}
	bucket, check := self.index.locate(blockHash)
	matchOffset, matchedSize := int64(0), 0
	entry := self.index.heads[bucket]
	for examined := 0; entry != 0 && examined < self.settings.CandidateCount; examined += 1 {
		if self.index.checks[entry-1] == check {
			offset := int64(entry-1) * self.index.stride
			size, err := self.matchSize(offset)
			if err != nil {
				return 0, 0, err
			}
			if matchedSize < size {
				matchOffset, matchedSize = offset, size
			}
			if self.settings.GoodMatchByteCount <= matchedSize {
				break
			}
		}
		entry = self.index.nexts[entry-1]
	}
	if matchedSize < evsGitDeltaBlockSize {
		return 0, 0, nil
	}
	return matchOffset, matchedSize, nil
}

// Grows a match backward over the pending bytes, which is how the bytes between one sampled block and
// the next join a copy, and answers the match's new start and size.
func (self *evsGitDeltaEncoder) growBack(offset int64, size int) (int64, int, error) {
	for self.insertStart < self.position && 0 < offset {
		chunk, err := self.base.from(offset - 1)
		if err != nil {
			return 0, 0, err
		}
		if chunk[0] != self.window[self.position-1] {
			break
		}
		offset -= 1
		size += 1
		self.position -= 1
	}
	return offset, size, nil
}

// Scans the target from its first byte to its last, a block at a time, rolling the hash along.
func (self *evsGitDeltaEncoder) run() error {
	rolling := false
	blockHash := uint64(0)
	for {
		if self.loadedSize-self.position < evsGitDeltaBlockSize {
			loaded, err := self.loadMore()
			if err != nil {
				return err
			}
			if !loaded {
				break
			}
			continue
		}
		if !rolling {
			blockHash = evsGitDeltaHashBlock(self.window[self.position : self.position+evsGitDeltaBlockSize])
			rolling = true
		}
		offset, size, err := self.findMatch(blockHash)
		if err != nil {
			return err
		}
		if size == 0 {
			if self.position+evsGitDeltaBlockSize < self.loadedSize {
				// one byte along: the block's first byte out, the next one in
				blockHash = blockHash*evsGitDeltaHashFactor + uint64(self.window[self.position+evsGitDeltaBlockSize]) -
					uint64(self.window[self.position])*evsGitDeltaHashFactorPower
			} else {
				rolling = false
			}
			self.position += 1
			continue
		}
		offset, size, err = self.growBack(offset, size)
		if err != nil {
			return err
		}
		if err := self.writeInserts(self.position); err != nil {
			return err
		}
		if err := self.writeCopies(offset, size); err != nil {
			return err
		}
		self.position += size
		self.insertStart = self.position
		rolling = false
	}
	if err := self.writeInserts(self.loadedSize); err != nil {
		return err
	}
	return self.output.Flush()
}

// Writes the delta that turns base into target, for any two sources, either of them empty. An error
// from a source or from delta's Write ends it. apply(base, encode(base, target)) is target, and
// mlsinterop holds go-git and stock git to that as well, once both are non-empty.
func EvsGitDeltaEncode(base EvsGitDeltaSource, target EvsGitDeltaSource, delta io.Writer, settings *EvsGitDeltaSettings) error {
	if err := settings.validate(); err != nil {
		return err
	}
	baseSize, targetSize := base.Size(), target.Size()
	if baseSize < 0 || targetSize < 0 {
		return errors.New("a git delta source's size is negative")
	}
	baseCache := &evsGitDeltaChunkCache{
		source:      base,
		chunk:       make([]byte, settings.ChunkByteCount),
		chunkOffset: -1,
	}
	baseReach := min(baseSize, evsGitDeltaMaxBaseReach)
	index, err := newEvsGitDeltaIndex(baseCache, baseReach, settings)
	if err != nil {
		return err
	}
	encoder := &evsGitDeltaEncoder{
		settings:  settings,
		base:      baseCache,
		baseReach: baseReach,
		index:     index,
		target:    target,
		window:    make([]byte, settings.WindowByteCount),
		output:    bufio.NewWriterSize(delta, settings.ChunkByteCount),
	}
	header := evsGitDeltaAppendSize(nil, baseSize)
	header = evsGitDeltaAppendSize(header, targetSize)
	if _, err := encoder.output.Write(header); err != nil {
		return err
	}
	return encoder.run()
}
