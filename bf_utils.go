package sdhash

import (
	"github.com/tmthrgd/go-popcount"
)

/**
 * Insert a SHA1 hash into a Bloom filter
 */
func bfSha1Insert(bf []uint8, bfClass uint8, sha1Hash [5]uint32) uint32 {
	var insertCnt uint32
	bitMask := BFClassMask[bfClass]
	for i := range sha1Hash {
		insert := sha1Hash[i] & bitMask
		k := insert >> 3
		if bf[k] & Bits[insert & 0x7] == 0 {
			insertCnt++
		}
		bf[k] |= Bits[insert & 0x7]
	}
	return insertCnt
}

/**
 * Computer the number of common bits (dot product) b/w two filters--conditional optimized version for 256-byte BFs.
 * The conditional looks first at the dot product of the first 32/64/128 bytes; if it is less than the threshold,
 * it returns 0; otherwise, proceeds with the rest of the computation.
 */
func bfBitCountCut256(bFilter1, bFilter2 []uint8, cutOff uint32, slack uint32) uint32 {
	var size int
	if len(bFilter1) > len(bFilter2) {
		size = len(bFilter2)
	} else {
		size = len(bFilter1)
	}
	common := make([]uint8, size)

	return uint32(popcount.CountBytes(common))
}
