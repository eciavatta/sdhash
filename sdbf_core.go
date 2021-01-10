package sdhash

import (
	"fmt"
	"math"
	"math/rand"
	"strings"
)

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
			if offset % uint64(config.BlockSize) == 0 { // Initial/sync entropy calculation
				entropy = config.entr64InitInt(fileBuffer[offset:], ascii)
			} else { // Incremental entropy update (much faster)
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
					currBf = currBf[sd.bfSize:]
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
		if uint32(chunkScores[i]) > threshold || (uint32(chunkScores[i]) == threshold && allowed > 0) {
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
	if chunkSize <= uint64(config.PopWinSize) {
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

		// Calculate thresholding parameters
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

	sd.genChunkRanks(buffer[blockSize*index:blockSize*(index+1)], blockSize, chunkRanks, 0)
	sd.genChunkScores(chunkRanks, blockSize, chunkScores, scoreHisto[:])
	var k uint32
	for k = 65; k >= config.Threshold; k-- {
		if sum <= config.MaxElemDd && (sum + uint32(scoreHisto[k]) > config.MaxElemDd) {
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

	ch := make(chan bool, qt)
	for i := uint64(0); i < qt; i++ {
		go sd.threadGenBlockSdbf(i, blockSize, fileBuffer, fileSize, ch)
	}
	for i := uint64(0); i < qt; i++ {
		<- ch
	}

	if rem >= MinFileSize {
		chunkRanks := make([]uint16, blockSize)
		chunkScores := make([]uint16, blockSize)

		sd.genChunkRanks(fileBuffer[blockSize*qt:blockSize*qt + rem], rem, chunkRanks, 0)
		sd.genChunkScores(chunkRanks, rem, chunkScores, nil)
		sd.genBlockHash(fileBuffer, fileSize, qt, chunkScores, blockSize, sd, uint32(rem), config.Threshold, int32(sd.MaxElem))
	}
}

/**
 * Calculates the score between two digests
 */
func (sd *sdbf) sdbfScore(sdbf1 *sdbf, sdbf2 *sdbf, sample uint32) int {
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
		(GetElemCount(sdbf1, uint64(bfCount1)-1) > GetElemCount(sdbf2, uint64(sdbf2.bfCount)-1) &&
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
		if GetElemCount(sdbf1, uint64(i)) < MinElemCount {
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
func (sd *sdbf) sdbfMaxScore(refSdbf *sdbf, refIndex uint32, targetSdbf *sdbf) float64 {
	var score, maxScore float64 = -1, -1
	bfSize := refSdbf.bfSize

	s1 := GetElemCount(refSdbf, uint64(refIndex))
	if s1 < MinElemCount {
		return 0
	}
	bf1 := refSdbf.Buffer[refIndex*bfSize:]
	e1Cnt := refSdbf.Hamming[refIndex]
	for i := uint32(0); i < targetSdbf.bfCount; i++ {
		bf2 := targetSdbf.Buffer[i*bfSize:]
		s2 := GetElemCount(targetSdbf, uint64(i))
		if refSdbf.bfCount >= 1 && s2 < MinElemCount {
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
			cutOff = Cutoffs256[mn]
		} else {
			mn := 1024 / (s1 + s2)
			cutOff = Cutoffs64[mn]
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

func (sd *sdbf) printIndexes(threshold uint32, matches []uint32, pos uint64) {
	count := len(sd.info.setList)
	any := false
	var strBuilder strings.Builder
	for i := 0; i < count; i++ {
		if matches[i] > threshold {
			strBuilder.WriteString(fmt.Sprintf("%s [%v] |%s|%v\n", sd.Name(), pos, sd.info.setList[i].Name(), matches[i]))
			any = true
		}
	}
	if any {
		sd.indexResults += strBuilder.String()
	}
}

func (sd *sdbf) checkIndexes(sha1 []uint32, matches []uint32) bool {
	count := len(sd.info.setList)
	any := false

	for i := 0; i < count; i++ {
		if sd.info.setList[i].Index.QuerySha1(sha1) {
			matches[i]++
			any = true
		}
	}

	return any
}
