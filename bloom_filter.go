package sdhash

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/pierrec/lz4"
	"io/ioutil"
	"math"
	bits2 "math/bits"
	"os"
	"strconv"
	"strings"
)

var bitMasks32 = []uint32{
	0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF,
	0x01FF, 0x03FF, 0x07FF, 0x0FFF, 0x1FFF, 0x3FFF, 0x7FFF, 0xFFFF,
	0x01FFFF, 0x03FFFF, 0x07FFFF, 0x0FFFFF, 0x1FFFFF, 0x3FFFFF, 0x7FFFFF, 0xFFFFFF,
	0x01FFFFFF, 0x03FFFFFF, 0x07FFFFFF, 0x0FFFFFFF, 0x1FFFFFFF, 0x3FFFFFFF, 0x7FFFFFFF, 0xFFFFFFFF,
}
var cutoffs = []uint32{
	86511, 86511, 86511, 86511, 67010, 52623, 42139, 34377, 28532, 24026, 20499, 17687, 15407, 13535, 11982,
	10685, 9589, 8652, 7846, 7149, 6541, 6008, 5537, 5121, 4745, 4413, 4115, 3850,
	3606, 3388, 3185, 3001, 2834, 2681, 2538, 2407, 2287, 2176, 2072, 1977, 1888, 1802,
	1724, 1651, 1583, 1519, 1458, 1402, 1348, 1298, 1248, 1204, 1161, 1120, 1083, 1047,
	1013, 981, 949, 921, 892, 866, 839, 815, 791, 768, 747, 726, 706, 688, 669, 652,
	635, 619, 603, 589, 575, 561, 546, 533, 521, 510, 498, 487, 476, 467, 456, 447,
	438, 429, 420, 411, 403, 395, 387, 380, 373, 365, 358, 351, 345, 338, 332, 326,
	320, 314, 309, 303, 298, 293, 288, 284, 279, 275, 271, 266, 262, 258, 254, 250,
	246, 242, 238, 235, 231, 228, 225, 221, 218,
}

type BloomFilter struct {
	BF          []uint8 // Beginning of the BF
	Hamming     uint16  // weight of this bf
	Hamminglg   uint32  // weight of this bf
	BitMask     uint64  // Bit mask
	MaxElem     uint64  // Max number of elements
	HashCount   uint16  // Number of hash functions used (k)
	bfElemCount uint64  // Actual number of elements inserted
	compSize    uint64  // size of compressed bf to be read
	setname     string  // name associated with bloom filter
}

func NewBloomFilter(size uint64, hashCount uint16, maxElem uint64) (*BloomFilter, error) {
	bf := &BloomFilter{
		HashCount: hashCount,
		MaxElem:   maxElem,
	}

	// Make sure size is a power of 2 and at least 64
	if size >= 64 && (size&(size-1)) == 0 {
		var logSize uint16
		for tmp := size; tmp > 0; tmp, logSize = tmp>>1, logSize+1 {
		}
		bf.BitMask = uint64(bitMasks32[logSize+1])
	} else {
		return nil, errors.New("invalid size")
	}

	bf.BF = make([]uint8, size)

	return bf, nil
}

func NewSimpleBloomFilter() *BloomFilter {
	if bf, err := NewBloomFilter(64*mB, 5, 0); err != nil {
		panic(err)
	} else {
		return bf
	}
}

func NewBloomFilterFromIndexFile(indexFileName string) (*BloomFilter, error) {
	buffer, err := ioutil.ReadFile(indexFileName)
	if err != nil {
		return nil, err
	}

	bf := &BloomFilter{}

	r := bufio.NewReader(bytes.NewReader(buffer))
	var bfSize uint64
	if _, err := r.ReadBytes(':'); err != nil { // discard headerbit
		return nil, errors.New("failed to read headerbit")
	}
	if bfSizeStr, err := r.ReadString(':'); err != nil {
		return nil, errors.New("failed to read bfSize")
	} else {
		if bfSize, err = strconv.ParseUint(bfSizeStr[:len(bfSizeStr)-1], 10, 64); err != nil {
			return nil, errors.New("failed to parse bfSize")
		}
	}
	if bfElemCountStr, err := r.ReadString(':'); err != nil {
		return nil, errors.New("failed to read bfElemCount")
	} else {
		if bfElemCount, err := strconv.ParseUint(bfElemCountStr[:len(bfElemCountStr)-1], 10, 64); err != nil {
			return nil, errors.New("failed to parse bfElemCount")
		} else {
			bf.bfElemCount = bfElemCount
		}
	}
	if hashCountStr, err := r.ReadString(':'); err != nil {
		return nil, errors.New("failed to read hashCount")
	} else {
		if hashCount, err := strconv.ParseUint(hashCountStr[:len(hashCountStr)-1], 10, 16); err != nil {
			return nil, errors.New("failed to parse hashCount")
		} else {
			bf.HashCount = uint16(hashCount)
		}
	}
	if bitMaskStr, err := r.ReadString(':'); err != nil {
		return nil, errors.New("failed to read bitMask")
	} else {
		if bitMask, err := strconv.ParseUint(bitMaskStr[:len(bitMaskStr)-1], 10, 64); err != nil {
			return nil, errors.New("failed to parse bitMask")
		} else {
			bf.BitMask = bitMask
		}
	}
	if compSizeStr, err := r.ReadString(':'); err != nil {
		return nil, errors.New("failed to read compSize")
	} else {
		if compSize, err := strconv.ParseUint(compSizeStr[:len(compSizeStr)-1], 10, 64); err != nil {
			return nil, errors.New("failed to parse compSize")
		} else {
			bf.compSize = compSize
		}
	}
	if bf.setname, err = r.ReadString('\n'); err != nil {
		return nil, errors.New("failed to read setname")
	}
	bf.setname = bf.setname[:len(bf.setname)-1] // remove ending newline

	bfComp := buffer[uint64(len(buffer))-bf.compSize:]
	bf.BF = make([]uint8, bfSize)
	if n, err := lz4.UncompressBlock(bfComp, bf.BF); err != nil || uint64(n) != bfSize {
		return nil, err
	}

	return bf, err
}

func NewBloomFilterFromExistingData(data []uint8, bfElemCount int, hamming uint16) *BloomFilter {
	var logSize uint16
	for tmp := len(data); tmp > 0; tmp, logSize = tmp>>1, logSize+1 {
	}
	bf := &BloomFilter{
		BitMask:     uint64(bitMasks32[logSize+1]),
		HashCount:   5,
		bfElemCount: uint64(bfElemCount),
		Hamming:     hamming,
		BF:          make([]uint8, 0, len(data)),
	}

	copy(bf.BF, data)

	return bf
}

func (bf *BloomFilter) ElemCount() uint64 {
	return bf.bfElemCount
}

func (bf *BloomFilter) EstFpRate() float64 {
	return -1.0
}

func (bf *BloomFilter) BitsPerElem() float64 {
	return float64(len(bf.BF)<<3) / float64(bf.bfElemCount)
}

func (bf *BloomFilter) WriteOut(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}

	buf := make([]uint8, 160*mB)
	if n, err := lz4.CompressBlock(bf.BF, buf, nil); err != nil {
		return err
	} else {
		bf.compSize = uint64(n)
	}

	if _, err := f.WriteString(fmt.Sprintf("sdbf-idx:%v:%v:%v:%v:%v:%s\n", len(bf.BF), bf.bfElemCount,
		bf.HashCount, bf.BitMask, bf.compSize, bf.setname)); err != nil {
		return err
	}

	if n, err := f.Write(buf[:bf.compSize]); err != nil {
		return err
	} else if uint64(n) != bf.compSize {
		return errors.New("failed to compress bloom filter")
	}
	if err := f.Close(); err != nil {
		return err
	}

	return nil
}

func (bf *BloomFilter) Fold(times uint32) {
	bfSize := len(bf.BF)
	for i := uint32(0); i < times; i++ {
		for j := 0; j < bfSize/2; j++ {
			bf.BF[j] |= bf.BF[j+(bfSize/2)]
		}
		bfSize >>= 2
		if bfSize == 32 {
			break
		}
	}
	var logSize uint16
	for tmp := bfSize; tmp > 0; tmp, logSize = tmp>>1, logSize+1 {
	}
	bf.BitMask = uint64(bitMasks32[logSize+1])

	bf.BF = bf.BF[:bfSize]
}

func (bf *BloomFilter) Add(other *BloomFilter) error {
	if len(bf.BF) != len(other.BF) {
		return errors.New("bloom filters must have the same size")
	}

	for j := 0; j < len(bf.BF); j++ {
		bf.BF[j] += other.BF[j]
	}

	return nil
}

func (bf *BloomFilter) InsertSha1(sha1 []uint32) bool {
	return bf.queryAndSet(sha1, true)
}

func (bf *BloomFilter) QuerySha1(sha1 []uint32) bool {
	return bf.queryAndSet(sha1, false)
}

func (bf *BloomFilter) Compare(other *BloomFilter, scale float64) int {
	if len(bf.BF) != len(other.BF) {
		return -1
	}
	var res uint32
	for i := 0; i < len(bf.BF); i++ {
		res += uint32(bits2.OnesCount8(bf.BF[i] & other.BF[i]))
	}

	var maxEst uint32
	if bf.Hamminglg < other.Hamminglg {
		maxEst = bf.Hamminglg
	} else {
		maxEst = other.Hamminglg
	}

	if bf.bfElemCount < 32 || other.bfElemCount < 32 {
		return 0
	}
	mn := (16 * len(bf.BF)) / int(bf.bfElemCount+other.bfElemCount)
	cutOff := cutoffs[mn]

	if mn > 128 {
		cutOff = cutoffs[128] - uint32(mn-128) // setting the cutoff to cutoff -n
	}
	if cutOff < 0 {
		return 0
	}

	if res > cutOff {
		return int(math.Round(100 * (float64(res-cutOff) / float64(maxEst-cutOff))))
	} else {
		return 0
	}
}

func (bf *BloomFilter) ToString() string {
	return base64.StdEncoding.EncodeToString(bf.BF)
}

func (bf *BloomFilter) ComputeHamming() {
	bf.Hamming = 0
	bf.Hamminglg = 0
	for j := 0; j < len(bf.BF); j++ {
		bf.Hamminglg += uint32(bits2.OnesCount8(bf.BF[j]))
	}
}

func NewBloomFilterFromString(filter string, folds int) (*BloomFilter, error) {
	bf := &BloomFilter{}
	var err error
	r := bufio.NewReader(strings.NewReader(filter))
	var bfSize uint64
	if _, err := r.ReadBytes(byte(':')); err != nil { // discard headerbit
		return nil, errors.New("failed to read headerbit")
	}
	if bfSizeStr, err := r.ReadString(byte(':')); err != nil {
		return nil, errors.New("failed to read bfSize")
	} else {
		if bfSize, err = strconv.ParseUint(bfSizeStr, 10, 64); err != nil {
			return nil, errors.New("failed to parse bfSize")
		}
	}
	if bfElemCountStr, err := r.ReadString(byte(':')); err != nil {
		return nil, errors.New("failed to read bfElemCount")
	} else {
		if bfElemCount, err := strconv.ParseUint(bfElemCountStr, 10, 64); err != nil {
			return nil, errors.New("failed to parse bfElemCount")
		} else {
			bf.bfElemCount = bfElemCount
		}
	}
	if hashCountStr, err := r.ReadString(byte(':')); err != nil {
		return nil, errors.New("failed to read hashCount")
	} else {
		if hashCount, err := strconv.ParseUint(hashCountStr, 10, 16); err != nil {
			return nil, errors.New("failed to parse hashCount")
		} else {
			bf.HashCount = uint16(hashCount)
		}
	}
	if bitMaskStr, err := r.ReadString(byte(':')); err != nil {
		return nil, errors.New("failed to read bitMask")
	} else {
		if bitMask, err := strconv.ParseUint(bitMaskStr, 10, 64); err != nil {
			return nil, errors.New("failed to parse bitMask")
		} else {
			bf.BitMask = bitMask
		}
	}
	if compSizeStr, err := r.ReadString(byte(':')); err != nil {
		return nil, errors.New("failed to read compSize")
	} else {
		if compSize, err := strconv.ParseUint(compSizeStr, 10, 64); err != nil {
			return nil, errors.New("failed to parse compSize")
		} else {
			bf.compSize = compSize
		}
	}
	if bf.setname, err = r.ReadString(byte(':')); err != nil {
		return nil, errors.New("failed to read setname")
	}
	var rawBf string
	if rawBf, err = r.ReadString(byte('\n')); err != nil {
		return nil, errors.New("failed to read raw bf")
	}

	if decodedBf, err := base64.StdEncoding.DecodeString(rawBf); err != nil || bfSize != uint64(len(decodedBf)) {
		return nil, errors.New("failed to decode raw bf")
	} else {
		bf.BF = decodedBf
	}

	bf.Fold(uint32(folds))
	bf.ComputeHamming()

	return bf, err
}

func (bf *BloomFilter) queryAndSet(sha1 []uint32, modeSet bool) bool {
	var pos, k uint32
	var bitCount uint16
	for i := uint16(0); i < bf.HashCount; i++ {
		pos = sha1[i] & uint32(bf.BitMask)
		k = pos >> 3
		if (bf.BF[k] & bits[pos&0x7]) != 0 { // Bit is set
			bitCount++
		} else {
			if modeSet {
				bf.BF[k] |= bits[pos&0x7]
			} else {
				return false
			}
		}
	}
	if modeSet {
		if bitCount < bf.HashCount {
			bf.bfElemCount++
			return true
		} else {
			return false
		}
	} else {
		return bitCount == bf.HashCount
	}
}
