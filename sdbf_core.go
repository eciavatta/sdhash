package sdhash

import (
	"math"
	"math/rand"
	"strings"
)

/**
 * Generate ranks for a file chunk.
 */
func (sd *Sdbf) genChunkRanks(fileBuffer []uint8, chunkRanks []uint16) {
	var entropy uint64
	ascii := make([]uint8, 256)

	limit := len(fileBuffer) - EntrWinSize
	for offset := 0; limit > 0 && offset < limit; offset++ {
		if offset % BlockSize == 0 { // Initial/sync entropy calculation
			entropy = entr64InitInt(fileBuffer[offset:], ascii)
		} else { // Incremental entropy update (much faster)
			entropy = entr64IncInt(entropy, fileBuffer[offset-1:], ascii)
		}
		chunkRanks[offset] = uint16(entr64Ranks[entropy>>entrPower])
	}
}

/**
 * Generate scores for a ranks chunk.
 */
func (sd *Sdbf) genChunkScores(chunkRanks []uint16, chunkSize uint64, chunkScores []uint16, scoreHisto []int32) {
	popWin := uint64(PopWinSize)
	var minPos uint64
	minRank := chunkRanks[minPos]

	for i := uint64(0); chunkSize > popWin && i < chunkSize - popWin; i++ {
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
	if scoreHisto != nil {
		for i := uint64(0); i < chunkSize - popWin; i++ {
			scoreHisto[chunkScores[i]]++
		}
	}
}

/**
 * Generate SHA1 hashes and add them to the SDBF--original stream version.
 */
func (sd *Sdbf) genChunkHash(fileBuffer []uint8, chunkPos uint64, chunkScores []uint16, chunkSize uint64) {
	bfCount := sd.bfCount
	lastCount := sd.lastCount
	currBf := sd.buffer[(bfCount-1)*sd.bfSize:]
	var bigfiCount uint64

	if chunkSize > uint64(PopWinSize) {
		for i := uint64(0); i < chunkSize-uint64(PopWinSize); i++ {
			if uint32(chunkScores[i]) > Threshold {
				sha1Hash := u32sha1(fileBuffer[chunkPos+i:chunkPos+i+uint64(PopWinSize)])
				bitsSet := bfSha1Insert(currBf, sha1Hash)
				// Avoid potentially repetitive features
				if bitsSet == 0 {
					continue
				}
				if sd.index != nil {
					if !sd.index.InsertSha1(sha1Hash[:]) {
						continue
					}
				}

				// new style big filters...
				inserted := sd.bigFilters[len(sd.bigFilters)-1].InsertSha1(sha1Hash[:])
				if !inserted {
					continue
				}

				lastCount++
				bigfiCount++
				if lastCount == sd.maxElem {
					currBf = currBf[sd.bfSize:]
					bfCount++
					lastCount = 0
				}
				if bigfiCount == sd.bigFilters[len(sd.bigFilters)-1].MaxElem {
					bf, err := NewBloomFilter(bigFilter, 5, bigFilterElem, 0.01)
					if err != nil {
						panic(err)
					}
					sd.bigFilters = append(sd.bigFilters, bf)
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
func (sd *Sdbf) genBlockHash(fileBuffer []uint8, blockNum uint64, chunkScores []uint16,
	blockSize uint64, rem uint32, threshold uint32, allowed int32) {
	var hashCnt, maxOffset, numIndexMatches uint32

	if rem > 0 {
		maxOffset = rem
	} else {
		maxOffset = uint32(blockSize)
	}
	if sd.searchIndexes != nil {
		numIndexMatches = uint32(len(sd.searchIndexes))
	}
	match := make([]uint32, numIndexMatches)
	for i := uint32(0); i < maxOffset-PopWinSize && hashCnt < MaxElemDd; i++ {
		if uint32(chunkScores[i]) > threshold || (uint32(chunkScores[i]) == threshold && allowed > 0) {
			data := fileBuffer[blockNum*blockSize:] // Start of data
			sha1Hash := u32sha1(data[i:i+PopWinSize])
			bf := sd.buffer[blockNum*uint64(sd.bfSize):] // BF to be filled
			bitsSet := bfSha1Insert(bf, sha1Hash)
			if bitsSet == 0 { // Avoid potentially repetitive features
				continue
			}
			if sd.index != nil {
				sd.index.InsertSha1(sha1Hash[:])
			}

			if sd.searchIndexes != nil {
				if hashCnt % 4 == 0 { // why??
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

/**
 * Generate SDBF hash for a buffer--stream version.
 */
func (sd *Sdbf) genChunkSdbf(fileBuffer []uint8, chunkSize uint64) {
	if chunkSize <= uint64(PopWinSize) {
		panic("chunkSize <= popWinSize")
	}

	fileSize := uint64(len(fileBuffer))
	buffSize := ((fileSize >> 11) + 1) << 8 // Estimate Sdbf size (reallocate later)
	sd.buffer = make([]uint8, buffSize)

	// Chunk-based computation
	qt := fileSize / chunkSize
	rem := fileSize % chunkSize

	var chunkPos uint64
	chunkRanks := make([]uint16, chunkSize)
	chunkScores := make([]uint16, chunkSize)

	for i := uint64(0); i < qt; i++ {
		var scoreHisto [66]int32
		sd.genChunkRanks(fileBuffer[chunkSize*i:chunkSize*(i+1)], chunkRanks)
		sd.genChunkScores(chunkRanks, chunkSize, chunkScores, scoreHisto[:])

		// Calculate thresholding parameters
		var sum uint32
		for k := uint32(65); k >= Threshold; k-- {
			if (sum <= sd.maxElem) && (sum+uint32(scoreHisto[k]) > sd.maxElem) {
				break
			}
			sum += uint32(scoreHisto[k])
		}
		sd.genChunkHash(fileBuffer, chunkPos, chunkScores, chunkSize)
		chunkPos += chunkSize
	}
	if rem > 0 {
		sd.genChunkRanks(fileBuffer[qt*chunkSize:], chunkRanks)
		sd.genChunkScores(chunkRanks, rem, chunkScores, nil)
		sd.genChunkHash(fileBuffer, chunkPos, chunkScores, rem)
	}

	// Chop off last BF if its membership is too low (eliminates some FPs)
	if sd.bfCount > 1 && sd.lastCount < sd.maxElem/8 {
		sd.bfCount--
		sd.lastCount = sd.maxElem
	}

	// Trim BF allocation to size
	if uint64(sd.bfCount) * uint64(sd.bfSize) < buffSize {
		sd.buffer = sd.buffer[:sd.bfCount*sd.bfSize]
	}
}

/**
 * Worker thread for multi-threaded block hash generation.  // NOT iN CLASS?
 */
func (sd *Sdbf) threadGenBlockSdbf(index uint64, blockSize uint64, buffer []uint8, ch chan bool) {
	var sum, allowed uint32
	var scoreHisto [66]int32
	chunkRanks := make([]uint16, blockSize)
	chunkScores := make([]uint16, blockSize)

	sd.genChunkRanks(buffer[blockSize*index:blockSize*(index+1)], chunkRanks)
	sd.genChunkScores(chunkRanks, blockSize, chunkScores, scoreHisto[:])
	var k uint32
	for k = 65; k >= Threshold; k-- {
		if sum <= MaxElemDd && (sum + uint32(scoreHisto[k]) > MaxElemDd) {
			break
		}
		sum += uint32(scoreHisto[k])
	}
	allowed = MaxElemDd - sum
	sd.genBlockHash(buffer, index, chunkScores, blockSize, 0, k, int32(allowed))

	ch <- true
}

/**
  dd-mode hash generation.
*/
func (sd *Sdbf) genBlockSdbfMt(fileBuffer []uint8, blockSize uint64) {
	qt := uint64(len(fileBuffer)) / blockSize
	rem :=  uint64(len(fileBuffer)) % blockSize

	if sd.searchIndexes != nil {
		blockCount := qt
		if rem >= minFileSize {
			blockCount++
		}
		sd.searchIndexesResults = make([][]uint32, blockCount)
	}

	ch := make(chan bool, qt)
	for i := uint64(0); i < qt; i++ {
		go sd.threadGenBlockSdbf(i, blockSize, fileBuffer, ch)
	}
	for i := uint64(0); i < qt; i++ {
		<- ch
	}

	if rem >= minFileSize {
		chunkRanks := make([]uint16, blockSize)
		chunkScores := make([]uint16, blockSize)

		sd.genChunkRanks(fileBuffer[blockSize*qt:blockSize*qt + rem], chunkRanks)
		sd.genChunkScores(chunkRanks, rem, chunkScores, nil)
		sd.genBlockHash(fileBuffer, qt, chunkScores, blockSize, uint32(rem), Threshold, int32(sd.maxElem))
	}
}

/**
 * Calculates the score between two digests
 */
func (sd *Sdbf) sdbfScore(sdbf1 *Sdbf, sdbf2 *Sdbf, sample uint32) int {
	var maxScore, scoreSum float64 = -1, -1
	var bfCount1 uint32

	if sdbf1.Hamming == nil {
		sdbf1.computeHamming()
	}
	if sdbf2.Hamming == nil {
		sdbf2.computeHamming()
	}

	// if sampling, set sample count here.
	if sample > 0 && sdbf1.bfCount > sample {
		bfCount1 = sample
	} else {
		bfCount1 = sdbf1.bfCount
	}

	if bfCount1 > sdbf2.bfCount || (bfCount1 == sdbf2.bfCount &&
		(sdbf1.GetElemCount(uint64(bfCount1)-1) > sdbf2.GetElemCount(uint64(sdbf2.bfCount)-1) &&
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
		maxScore = sd.sdbfMaxScore(sdbf1, i * randOffset, sdbf2)
		if scoreSum < 0 {
			scoreSum = maxScore
		} else {
			scoreSum += maxScore
		}
		if sdbf1.GetElemCount(uint64(i)) < minElemCount {
			spartsect++
		}
	}
	denom := bfCount1
	// improving the average.
	if bfCount1 > 1 {
		denom -= spartsect
	}
	if denom == 0 {
		scoreSum--
	}

	if scoreSum < 0 {
		return -1
	} else {
		return int(math.Round(100.0 * scoreSum / float64(denom)))
	}
}

/**
 * Given a BF and an SDBF, calculates the maximum match (0-100)
 */
func (sd *Sdbf) sdbfMaxScore(refSdbf *Sdbf, refIndex uint32, targetSdbf *Sdbf) float64 {
	var score, maxScore float64 = -1, -1
	bfSize := refSdbf.bfSize

	s1 := refSdbf.GetElemCount(uint64(refIndex))
	if s1 < minElemCount {
		return 0
	}
	bf1 := refSdbf.buffer[refIndex*bfSize:]
	e1Cnt := refSdbf.Hamming[refIndex]
	for i := uint32(0); i < targetSdbf.bfCount; i++ {
		bf2 := targetSdbf.buffer[i*bfSize:]
		s2 := targetSdbf.GetElemCount(uint64(i))
		if refSdbf.bfCount >= 1 && s2 < minElemCount {
			continue
		}
		e2Cnt := targetSdbf.Hamming[i]
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
			score = float64(match - cutOff) / float64(uint32(maxEst) - cutOff)
		}
		if score > maxScore {
			maxScore = score
		}
	}

	return maxScore
}

func (sd *Sdbf) checkIndexes(sha1 []uint32, matches []uint32) bool {
	any := false

	for i := 0; i < len(sd.searchIndexes); i++ {
		if sd.searchIndexes[i].QuerySha1(sha1) {
			matches[i]++
			any = true
		}
	}

	return any
}
