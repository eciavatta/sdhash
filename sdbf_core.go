package sdhash

import (
	"math"
	"math/rand"
	"strings"
)

// generateChunkRanks generate ranks for a file chunk.
func (sd *sdbf) generateChunkRanks(fileBuffer []uint8, chunkRanks []uint16) {
	var entropy uint64
	ascii := make([]uint8, 256)

	limit := len(fileBuffer) - EntropyWinSize
	for offset := 0; limit > 0 && offset < limit; offset++ {
		if offset%BlockSize == 0 { // Initial/sync entropy calculation
			entropy = entropy64InitInt(fileBuffer[offset:], ascii)
		} else { // Incremental entropy update (much faster)
			entropy = entropy64IncInt(entropy, fileBuffer[offset-1:], ascii)
		}
		chunkRanks[offset] = uint16(entropy64Ranks[entropy>>entropyPower])
	}
}

// generateChunkScores generate scores for a ranks chunk.
func (sd *sdbf) generateChunkScores(chunkRanks []uint16, chunkSize uint64, chunkScores []uint16, scoreHistogram []int32) {
	popWin := uint64(PopWinSize)
	var minPos uint64
	minRank := chunkRanks[minPos]

	for i := uint64(0); chunkSize > popWin && i < chunkSize-popWin; i++ {
		if i > 0 && minRank > 0 {
			for chunkRanks[i+popWin] >= minRank && i < minPos && i < chunkSize-popWin+1 {
				if chunkRanks[i+popWin] == minRank {
					minPos = i + popWin
				}
				chunkScores[minPos]++
				i++
			}
		}
		minPos = i
		minRank = chunkRanks[minPos]
		for j := i + 1; j < i+popWin; j++ {
			if chunkRanks[j] < minRank && chunkRanks[j] > 0 {
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
	if scoreHistogram != nil {
		for i := uint64(0); i < chunkSize-popWin; i++ {
			scoreHistogram[chunkScores[i]]++
		}
	}
}

// generateChunkHash generate SHA1 hashes and add them to the Sdbf in stream mode.
func (sd *sdbf) generateChunkHash(fileBuffer []uint8, chunkPos uint64, chunkScores []uint16, chunkSize uint64) {
	bfCount := sd.bfCount
	lastCount := sd.lastCount
	currBf := sd.buffer[(bfCount-1)*sd.bfSize:]
	var bigFiltersCount uint64

	if chunkSize > uint64(PopWinSize) {
		for i := uint64(0); i < chunkSize-uint64(PopWinSize); i++ {
			if uint32(chunkScores[i]) > Threshold {
				sha1Hash := u32sha1(fileBuffer[chunkPos+i : chunkPos+i+uint64(PopWinSize)])
				bitsSet := bfSha1Insert(currBf, sha1Hash)
				// Avoid potentially repetitive features
				if bitsSet == 0 {
					continue
				}
				if sd.index != nil {
					if !sd.index.insertSha1(sha1Hash[:]) {
						continue
					}
				}

				// seems to be useless, used only to skip some cycles
				inserted := sd.bigFilters[len(sd.bigFilters)-1].insertSha1(sha1Hash[:])
				if !inserted {
					continue
				}

				lastCount++
				bigFiltersCount++
				if lastCount == sd.maxElem {
					currBf = currBf[sd.bfSize:]
					bfCount++
					lastCount = 0
				}
				if bigFiltersCount == sd.bigFilters[len(sd.bigFilters)-1].MaxElem() {
					bf, err := newBloomFilter(bigFilter, 5, bigFilterElem)
					if err != nil {
						panic(err)
					}
					sd.bigFilters = append(sd.bigFilters, bf)
					bigFiltersCount = 0
				}
			}
		}
	}

	sd.bfCount = bfCount
	sd.lastCount = lastCount
}

// generateBlockHash generate SHA1 hashes and add them to the Sdbf in block-aligned mode.
func (sd *sdbf) generateBlockHash(fileBuffer []uint8, blockNum uint64, chunkScores []uint16, rem uint32,
	threshold uint32, allowed int32) {
	var hashCnt, maxOffset, numIndexMatches uint32

	if rem > 0 {
		maxOffset = rem
	} else {
		maxOffset = sd.ddBlockSize
	}
	if sd.searchIndexes != nil {
		numIndexMatches = uint32(len(sd.searchIndexes))
	}
	match := make([]uint32, numIndexMatches)
	for i := uint32(0); i < maxOffset-PopWinSize && hashCnt < MaxElemDd; i++ {
		if uint32(chunkScores[i]) > threshold || (uint32(chunkScores[i]) == threshold && allowed > 0) {
			sha1Hash := u32sha1(fileBuffer[i : i+PopWinSize])
			bf := sd.buffer[blockNum*uint64(sd.bfSize) : (blockNum+1)*uint64(sd.bfSize)] // buffer to be filled
			bitsSet := bfSha1Insert(bf, sha1Hash)
			if bitsSet == 0 { // Avoid potentially repetitive features
				continue
			}
			if sd.index != nil {
				sd.indexMutex.Lock()
				sd.index.insertSha1(sha1Hash[:])
				sd.indexMutex.Unlock()
			}

			if sd.searchIndexes != nil {
				if hashCnt%4 == 0 { // why??
					sd.checkIndexes(sha1Hash[:], match)
				}
			}
			hashCnt++
			if uint32(chunkScores[i]) == threshold {
				allowed--
			}
		}
	}

	if sd.searchIndexesResults != nil {
		sd.searchIndexesResults[blockNum] = match
	}

	sd.elemCounts[blockNum] = uint16(hashCnt)
}

// generateChunkSdbf generate Sdbf hash for a buffer in the stream mode.
func (sd *sdbf) generateChunkSdbf(fileBuffer []uint8, chunkSize uint64) {
	if chunkSize <= uint64(PopWinSize) {
		panic("chunkSize <= popWinSize")
	}

	fileSize := uint64(len(fileBuffer))
	buffSize := ((fileSize >> 11) + 1) << 8 // Estimate sdbf size (reallocate later)
	sd.buffer = make([]uint8, buffSize)

	// Chunk-based computation
	qt := fileSize / chunkSize
	rem := fileSize % chunkSize

	var chunkPos uint64
	chunkRanks := make([]uint16, chunkSize)
	chunkScores := make([]uint16, chunkSize)

	for i := uint64(0); i < qt; i++ {
		sd.generateChunkRanks(fileBuffer[chunkSize*i:chunkSize*(i+1)], chunkRanks)
		sd.generateChunkScores(chunkRanks, chunkSize, chunkScores, nil)
		sd.generateChunkHash(fileBuffer, chunkPos, chunkScores, chunkSize)
		chunkPos += chunkSize
	}
	if rem > 0 {
		sd.generateChunkRanks(fileBuffer[qt*chunkSize:], chunkRanks)
		sd.generateChunkScores(chunkRanks, rem, chunkScores, nil)
		sd.generateChunkHash(fileBuffer, chunkPos, chunkScores, rem)
	}

	// Chop off last buffer if its membership is too low (eliminates some FPs)
	if sd.bfCount > 1 && sd.lastCount < sd.maxElem/8 {
		sd.bfCount--
		sd.lastCount = sd.maxElem
	}

	// Trim buffer allocation to size
	if uint64(sd.bfCount)*uint64(sd.bfSize) < buffSize {
		sd.buffer = sd.buffer[:sd.bfCount*sd.bfSize]
	}
}

// generateSingleBlockSdbf is the worker for multi goroutine block hash generation.
func (sd *sdbf) generateSingleBlockSdbf(fileBuffer []uint8, blockNum uint64, ch chan bool) {
	blockSize := uint64(sd.ddBlockSize)
	var sum, allowed uint32
	var scoreHistogram [66]int32
	chunkRanks := make([]uint16, blockSize)
	chunkScores := make([]uint16, blockSize)

	sd.generateChunkRanks(fileBuffer, chunkRanks)
	sd.generateChunkScores(chunkRanks, blockSize, chunkScores, scoreHistogram[:])
	var k uint32
	for k = 65; k >= Threshold; k-- {
		if sum <= MaxElemDd && (sum+uint32(scoreHistogram[k]) > MaxElemDd) {
			break
		}
		sum += uint32(scoreHistogram[k])
	}
	allowed = MaxElemDd - sum
	sd.generateBlockHash(fileBuffer, blockNum, chunkScores, 0, k, int32(allowed))

	ch <- true
}

// Sdbf hash for a buffer in dd-mode.
func (sd *sdbf) generateBlockSdbf(fileBuffer []uint8, ) {
	blockSize := uint64(sd.ddBlockSize)
	qt := uint64(len(fileBuffer)) / blockSize
	rem := uint64(len(fileBuffer)) % blockSize

	if sd.searchIndexes != nil {
		blockCount := qt
		if rem >= MinFileSize {
			blockCount++
		}
		sd.searchIndexesResults = make([][]uint32, blockCount)
	}

	ch := make(chan bool, qt)
	for i := uint64(0); i < qt; i++ {
		go sd.generateSingleBlockSdbf(fileBuffer[blockSize*i:blockSize*(i+1)], i, ch)
	}
	for i := uint64(0); i < qt; i++ {
		<-ch
	}

	if rem >= MinFileSize {
		chunkRanks := make([]uint16, blockSize)
		chunkScores := make([]uint16, blockSize)

		remBuffer := fileBuffer[blockSize*qt : blockSize*qt+rem]
		sd.generateChunkRanks(remBuffer, chunkRanks)
		sd.generateChunkScores(chunkRanks, rem, chunkScores, nil)
		sd.generateBlockHash(remBuffer, qt, chunkScores, uint32(rem), Threshold, int32(sd.maxElem))
	}
}

// sdbfScore calculates the score between two Sdbf.
func (sd *sdbf) sdbfScore(sdbf1 *sdbf, sdbf2 *sdbf, sample uint32) int {
	var maxScore float64
	var scoreSum float64 = -1
	var bfCount1 uint32

	if sdbf1.hamming == nil {
		sdbf1.computeHamming()
	}
	if sdbf2.hamming == nil {
		sdbf2.computeHamming()
	}

	if sample > 0 && sdbf1.bfCount > sample { // if sampling, set sample count here
		bfCount1 = sample
	} else {
		bfCount1 = sdbf1.bfCount
	}

	if bfCount1 > sdbf2.bfCount || (bfCount1 == sdbf2.bfCount &&
		(sdbf1.getElemCount(uint64(bfCount1)-1) > sdbf2.getElemCount(uint64(sdbf2.bfCount)-1) &&
			strings.Compare(sdbf1.hashName, sdbf2.hashName) > 0)) {
		sdbf1, sdbf2 = sdbf2, sdbf1
		bfCount1 = sdbf1.bfCount
	}

	var spartsect uint32
	for i := uint32(0); i < bfCount1; i++ {
		var randOffset uint32 = 1
		if sample > 0 && bfCount1 > sample {
			randOffset = rand.Uint32() % (sdbf1.bfCount / sample)
		}
		maxScore = sd.sdbfMaxScore(sdbf1, i*randOffset, sdbf2)
		if scoreSum < 0 {
			scoreSum = maxScore
		} else {
			scoreSum += maxScore
		}
		if sdbf1.getElemCount(uint64(i)) < minElemCount {
			spartsect++
		}
	}

	denominator := bfCount1
	if bfCount1 > 1 { // improving the average
		denominator -= spartsect
	}
	if denominator == 0 {
		scoreSum--
	}

	if scoreSum < 0 {
		return -1
	}

	return int(math.Round(100.0 * scoreSum / float64(denominator)))
}

// sdbfMaxScore calculates the maximum match (0-100) of a single block.
func (sd *sdbf) sdbfMaxScore(refSdbf *sdbf, refIndex uint32, targetSdbf *sdbf) float64 {
	var score float64
	var maxScore float64 = -1
	bfSize := refSdbf.bfSize

	s1 := refSdbf.getElemCount(uint64(refIndex))
	if s1 < minElemCount {
		return 0
	}
	bf1 := refSdbf.buffer[refIndex*bfSize:]
	e1Cnt := refSdbf.hamming[refIndex]
	for i := uint32(0); i < targetSdbf.bfCount; i++ {
		bf2 := targetSdbf.buffer[i*bfSize:]
		s2 := targetSdbf.getElemCount(uint64(i))
		if refSdbf.bfCount >= 1 && s2 < minElemCount {
			continue
		}
		e2Cnt := targetSdbf.hamming[i]
		// Max/min number of matching bits & zero cut off
		var maxEst uint16
		if e1Cnt < e2Cnt {
			maxEst = e1Cnt
		} else {
			maxEst = e2Cnt
		}
		var cutOff uint32
		if !refSdbf.fastMode {
			mn := 4096 / (s1 + s2)
			cutOff = cutoffs256[mn]
		} else {
			mn := 1024 / (s1 + s2)
			cutOff = cutoffs64[mn]
		}
		// Find matching bits
		match := bfBitCountCut256(bf1, bf2, 0, 0)
		if match <= cutOff {
			score = 0
		} else {
			score = float64(match-cutOff) / float64(uint32(maxEst)-cutOff)
		}
		if score > maxScore {
			maxScore = score
		}
	}

	return maxScore
}

// checkIndexes checks if some of the search blooms filters match.
func (sd *sdbf) checkIndexes(sha1 []uint32, matches []uint32) bool {
	any := false

	for i := 0; i < len(sd.searchIndexes); i++ {
		if sd.searchIndexes[i].querySha1(sha1) {
			matches[i]++
			any = true
		}
	}

	return any
}
