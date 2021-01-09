package sdhash

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