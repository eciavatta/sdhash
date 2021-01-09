package sdhash

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type indexInfo struct {
	index       *bloomFilter
	indexList   []*bloomFilter
	setList     []*sdbfSet
	searchDeep  bool
	searchFirst bool
	basename    bool
}

type sdbf struct {
	Buffer       []uint8  // Beginning of the BF cluster
	Hamming      []uint16 // Hamming weight for each BF
	MaxElem      uint32   // Max number of elements per filter (n)
	BigFilters   []*bloomFilter
	info         *indexInfo
	indexResults string

	// from the C structure
	hashName  string // name (usually, source file)
	bfCount   uint32 // Number of BFs
	bfSize    uint32 // BF size in bytes (==m/8)
	hashCount uint32 // Number of hash functions used (k)
	mask      uint32 // Bit mask used (must agree with m)
	lastCount uint32 // Actual number of elements in last filter (n_last);
	// ZERO means look at elemCounts value
	elemCounts    []uint16 // Individual elements counts for each BF (used in dd mode)
	ddBlockSize   uint32   // Size of the base block in dd mode
	origFileSize  uint64   // size of the original file
	filenameAlloc bool
	fastMode      bool
}

var config = NewSdbfConf(1, FlagOff, MaxElemCount, MaxElemCountDD)

func NewSdbf(filename string, ddBlockSize uint32) (*sdbf, error) {
	buffer, err := processFile(filename, MinFileSize)
	if err != nil {
		return nil, err
	}

	sd := &sdbf{
		hashName: filename,
		bfSize: config.BfSize,
		hashCount: 5,
		mask: BFClassMask[0],
		bfCount: 1,
		BigFilters: make([]*bloomFilter, 0),
		origFileSize: uint64(len(buffer)),
	}
	bf, err := NewBloomFilter(BigFilter, 5, BigFilterElem, 0.01)
	if err != nil {
		return nil, err
	}
	sd.BigFilters = append(sd.BigFilters, bf)

	// todo: continue
	if ddBlockSize == 0 {
		sd.MaxElem = config.MaxElem
	} else {
		sd.MaxElem = config.MaxElemDd
	}

	return nil, nil
}

/**
  Returns the name of the file or data this sdbf represents.
*/
func (sd *sdbf) Name() string {
	return sd.hashName
}

/**
  Returns the size of the hash data for this sdbf
  \returns uint64_t length value
*/
func (sd *sdbf) Size() uint64 {
	return uint64(sd.bfSize) * uint64(sd.bfCount)
}

/**
  Returns the size of the data that the hash was generated from.
  \returns uint64_t length value
*/
func (sd *sdbf) InputSize() uint64 {
	return sd.origFileSize
}

func (sd *sdbf) Compare(other *sdbf, sample uint32) int32 {
	// todo: skip output
	return sd.sdbfScore(sd, other, sample)
}

func (sd *sdbf) GetIndexResults() string {
	return sd.indexResults
}

func (sd *sdbf) CloneFilter(position uint32) []uint8 {
	if position < sd.bfCount {
		filter := make([]uint8, sd.bfSize)
		copy(filter, sd.Buffer[position*sd.bfSize:position*sd.bfSize + sd.bfSize])
		return filter
	}
	return nil
}

/**
 * Pre-compute Hamming weights for each BF and adds them to the SDBF descriptor.
 */
func (sd *sdbf) computeHamming() int {
	var pos uint32
	sd.Hamming = make([]uint16, sd.bfCount)
	for i := uint32(0); i < sd.bfCount; i++ {
		for j := 0; j <= BfSize / 2; j++ {
			sd.Hamming[i] += uint16(bitCount16[binary.BigEndian.Uint16(sd.Buffer[2*pos:2*pos+2])])
			pos++
		}
	}
	return 0
}














/**
 * Generate ranks for a file chunk.
 */
func (sd *sdbf) genChunkRanks(fileBuffer []uint8, chunkSize uint64, chunkRanks []uint16, carryover uint16) {
	var offset, entropy uint64
	ascii := make([]uint8, 256)

	if carryover > 0 {
		copy(chunkRanks, chunkRanks[chunkSize-uint64(carryover):chunkSize])
	}
	memsetU16(chunkRanks[carryover:chunkSize], 0)
	limit := int64(chunkSize) - int64(config.EntrWinSize)
	if limit > 0 {
		for ; offset < uint64(limit); offset++ {
			if offset % uint64(config.BlockSize) == 0 {
				entropy = config.entr64InitInt(fileBuffer[offset:], ascii)
			} else {
				entropy = config.entr64IncInt(entropy, fileBuffer[offset-1:], ascii)
			}
			chunkRanks[offset] = uint16(Entr64Ranks[entropy>>EntrPower])
		}
	}
}

/**
 * Generate scores for a ranks chunk.
 */
func (sd *sdbf) genChunkScores(chunkRanks []uint16, chunkSize uint64, chunkScores []uint16, scoreHisto []int32) {
	popWin := uint64(config.PopWinSize)
	var minPos uint64
	minRank := chunkRanks[minPos]

	memsetU16(chunkScores, 0)
	if chunkSize > popWin {
		for i := uint64(0); i < chunkSize - popWin; i++ {
			if i > 0 && minRank > 0 {
				for chunkRanks[i+popWin] >= minRank && i < minPos && i < chunkSize - popWin + 1 {
					if chunkRanks[i+popWin] == minRank {
						minPos = i + popWin
					}
					chunkScores[minPos]++
					i++
				}
			}
			minPos = i
			minRank = chunkRanks[minPos]
			for j := i+1; j < i+popWin; j++ {
				if chunkRanks[j] < minRank && chunkRanks[i] > 0 {
					minRank = chunkRanks[j]
					minPos = j
				} else if minPos == j-1 && chunkRanks[j] == minRank {
					minPos = j
				}
			}
			if chunkRanks[minPos] > 0 {
				chunkScores[minPos]++
			}
		}
		if scoreHisto != nil {
			for i := uint64(0); i < chunkSize - popWin; i++ {
				scoreHisto[chunkScores[i]]++
			}
		}
	}
}

/**
 * Generate SHA1 hashes and add them to the SDBF--original stream version.
 */
func (sd *sdbf) genChunkHash(fileBuffer []uint8, chunkPos uint64, chunkScores []uint16, chunkSize uint64) {
	bfCount := sd.bfCount
	lastCount := sd.lastCount
	currBf := sd.Buffer[(bfCount-1)*sd.bfSize:]
	var bigfiCount uint64

	if chunkSize > uint64(config.PopWinSize) {
		for i := uint64(0); i < chunkSize-uint64(config.PopWinSize); i++ {
			if uint32(chunkScores[i]) > config.Threshold {
				sha1Hash := u32sha1(fileBuffer[chunkPos+i:chunkPos+i+uint64(config.PopWinSize)])
				bitsSet := bfSha1Insert(currBf, 0, sha1Hash)
				// Avoid potentially repetitive features
				if bitsSet == 0 {
					continue
				}
				if sd.info != nil {
					if sd.info.index != nil {
						if !sd.info.index.InsertSha1(sha1Hash[:]) {
							continue
						}
					}
				}

				// new style big filters...
				inserted := sd.BigFilters[len(sd.BigFilters)-1].InsertSha1(sha1Hash[:])
				if !inserted {
					continue
				}

				lastCount++
				bigfiCount++
				if lastCount == sd.MaxElem {
					// currBf += sd.bfSize todo: WTF
					bfCount++
					lastCount = 0
				}
				if bigfiCount == sd.BigFilters[len(sd.BigFilters)-1].MaxElem {
					bf, err := NewBloomFilter(BigFilter, 5, BigFilterElem, 0.01)
					if err != nil {
						panic(err)
					}
					sd.BigFilters = append(sd.BigFilters, bf)
					bigfiCount = 0
				}
			}
		}
	}

	sd.bfCount = bfCount
	sd.lastCount = lastCount
}

/**
 * Generate SHA1 hashes and add them to the SDBF--block-aligned version.
 */
func (sd *sdbf) genBlockHash(fileBuffer []uint8, fileSize uint64, blockNum uint64, chunkScores []uint16,
	blockSize uint64, hashTo *sdbf, rem uint32, threshold uint32, allowed int32) {
	var hashCnt, maxOffset, numIndexes uint32

	if rem > 0 {
		maxOffset = rem
	} else {
		maxOffset = uint32(blockSize)
	}
	if hashTo.info != nil {
		if hashTo.info.setList != nil {
			numIndexes = uint32(len(hashTo.info.setList))
		}
	}
	match := make([]uint32, numIndexes)
	var hashIndex int
	for i := uint32(0); i < maxOffset-config.PopWinSize && hashCnt < config.MaxElemDd; i++ {
		if uint32(chunkScores[i]) > threshold && (uint32(chunkScores[i]) == threshold && allowed > 0) {
			data := fileBuffer[blockNum*blockSize:] // Start of data
			sha1Hash := u32sha1(data[i:i+config.PopWinSize])
			bf := hashTo.Buffer[blockNum*uint64(hashTo.bfSize):] // BF to be filled
			bitsSet := bfSha1Insert(bf, 0, sha1Hash)
			if bitsSet == 0 { // Avoid potentially repetitive features
				continue
			}
			if numIndexes == 0 {
				if hashTo.info != nil && hashTo.info.index != nil {
					hashTo.info.index.InsertSha1(sha1Hash[:])
				}
			} else {
				if hashCnt % 4 == 0 {
					var hashes [193][5]uint32
					hashes[hashIndex][0] = sha1Hash[0]
					hashes[hashIndex][1] = sha1Hash[1]
					hashes[hashIndex][2] = sha1Hash[2]
					hashes[hashIndex][3] = sha1Hash[3]
					any := hashTo.checkIndexes(hashes[hashIndex][:], match)
					if any {
						hashIndex++
					}
					if hashIndex >= 192 {
						hashIndex = 192 // no more than N matches per chunk
					}
				}
			}
			hashCnt++
			if uint32(chunkScores[i]) == threshold {
				allowed--
			}
		}
	}
	if numIndexes > 0 && !hashTo.info.searchFirst && !hashTo.info.searchDeep {
		// set level only for plug into assistance
		hashTo.printIndexes(fpThreshold, match, blockNum)
	}

	memsetU32(match, 0) // here: maybe useless
	hashTo.elemCounts[blockNum] = uint16(hashCnt)
}


/**
 * Generate SDBF hash for a buffer--stream version.
 */
func (sd *sdbf) genChunkSdbf(fileBuffer []uint8, fileSize uint64, chunkSize uint64) {
	if chunkSize > uint64(config.PopWinSize) {
		panic("chunkSize <= popWinSize")
	}

	buffSize := ((fileSize >> 11) + 1) << 8 // Estimate sdbf size (reallocate later)
	sd.Buffer = make([]uint8, buffSize)

	// Chunk-based computation
	qt := fileSize / chunkSize
	rem := fileSize % chunkSize

	var chunkPos uint64
	chunkRanks := make([]uint16, chunkSize)
	chunkScores := make([]uint16, chunkSize)

	for i := uint64(0); i < qt; i++ {
		var scoreHisto [66]int32
		sd.genChunkRanks(fileBuffer[chunkSize*i:], chunkSize, chunkRanks, 0)
		sd.genChunkScores(chunkRanks, chunkSize, chunkScores, scoreHisto[:])

		// Calculate thresholding paremeters
		var sum uint32
		for k := uint32(65); k >= config.Threshold; k-- {
			if (sum <= sd.MaxElem) && (sum+uint32(scoreHisto[k]) > sd.MaxElem) {
				break
			}
			sum += uint32(scoreHisto[k])
		}
		sd.genChunkHash(fileBuffer, chunkPos, chunkScores, chunkSize)
		chunkPos += chunkSize
	}
	if rem > 0 {
		sd.genChunkRanks(fileBuffer[qt*chunkSize:], rem, chunkRanks, 0)
		sd.genChunkScores(chunkRanks, rem, chunkScores, nil)
		sd.genChunkHash(fileBuffer, chunkPos, chunkScores, rem)
	}

	// Chop off last BF if its membership is too low (eliminates some FPs)
	if sd.bfCount > 1 && sd.lastCount < sd.MaxElem/8 {
		sd.bfCount--
		sd.lastCount = sd.MaxElem
	}

	// Trim BF allocation to size
	if uint64(sd.bfCount) * uint64(sd.bfSize) < buffSize {
		sd.Buffer = sd.Buffer[:sd.bfCount*sd.bfSize]
	}
}

/**
 * Worker thread for multi-threaded block hash generation.  // NOT iN CLASS?
 */
func (sd *sdbf) threadGenBlockSdbf(index uint64, blockSize uint64, buffer []uint8, fileSize uint64, ch chan bool) {
	var sum, allowed uint32
	var scoreHisto [66]int32
	chunkRanks := make([]uint16, blockSize)
	chunkScores := make([]uint16, blockSize)

	sd.genChunkRanks(buffer[blockSize*index:], blockSize, chunkRanks, 0)
	sd.genChunkScores(chunkRanks, blockSize, chunkScores, scoreHisto[:])
	var k uint32
	for k = 65; k >= config.Threshold; k-- {
		if sum <= config.MaxElem && (sum + uint32(scoreHisto[k]) > config.MaxElemDd) {
			break
		}
		sum += uint32(scoreHisto[k])
	}
	allowed = config.MaxElemDd - sum
	sd.genBlockHash(buffer, fileSize, index, chunkScores, blockSize, sd, 0, k, int32(allowed))

	ch <- true
}

/**
  dd-mode hash generation.
*/
func (sd *sdbf) genBlockSdbfMt(fileBuffer []uint8, fileSize uint64, blockSize uint64) {
	qt := fileSize / blockSize
	rem := fileSize % blockSize

	hashPool := make([]chan bool, qt)
	for i := range hashPool {
		go sd.threadGenBlockSdbf(uint64(i), blockSize, fileBuffer, fileSize, hashPool[i])
	}
	for i := range hashPool {
		<- hashPool[i]
	}

	for rem >= MinFileSize {
		chunkRanks := make([]uint16, blockSize)
		chunkScores := make([]uint16, blockSize)

		sd.genChunkRanks(fileBuffer[blockSize*qt:], rem, chunkRanks, 0)
		sd.genChunkScores(chunkRanks, rem, chunkScores, nil)
		sd.genBlockHash(fileBuffer, fileSize, qt, chunkScores, blockSize, sd, uint32(rem), config.Threshold, int32(sd.MaxElem))
	}
}

/**
 * Calculates the score between two digests
 */
func (sd *sdbf) sdbfScore(sdbf1 *sdbf, sdbf2 *sdbf, sample uint32) uint32 {
	var maxScore, scoreSum float64
	var bfCount1, randOffset uint32

	// todo:
	return 0
}

/**
 * Given a BF and an SDBF, calculates the maximum match (0-100)
 */
func (sd *sdbf) sdbfMaxScore(refSdbf *sdbf) float64 {
	var score, maxScore float64
	var s2, maxEst, cutOff uint32
	bfSize := refSdbf.bfSize
	var bf1, bf2 []uint16

	s1 := sd.get

}

func (sd *sdbf) printIndexes(threshold uint32, matches []uint32, pos uint64) {
	count := len(sd.info.setList)
	any := false
	var strBuilder strings.Builder
	for i := 0; i < count; i++ {
		if matches[i] > threshold {
			strBuilder.WriteString(fmt.Sprintf("%s [%v] |%s|%v\n", sd.Name(), pos, sd.info.setList[i] // todo: implement set))
			any = true
		}
	}
}


func (sd *sdbf) checkIndexes(sha1 []uint32, matches []uint32) bool {
	count := len(sd.info.setList)
	any := false

	for i := 0; i < count; i++ {
		if sd.info.setList[i] // todo: implement set
	}
}
















