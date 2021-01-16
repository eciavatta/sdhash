package sdhash

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/pierrec/lz4"
	"io"
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

type BloomFilter interface {
	ElemCount() uint64
	MaxElem() uint64
	BitsPerElem() float64
	WriteToFile(filename string) error
	Compare(other BloomFilter) int
	String() string

	insertSha1(sha1 []uint32) bool
	querySha1(sha1 []uint32) bool
}

type bloomFilter struct {
	buffer      []uint8 // Beginning of the bloom filter
	hamming     uint32  // weight of this bf
	bitMask     uint64  // bit mask
	maxElem     uint64  // max number of elements
	hashCount   uint16  // number of hash functions used (k)
	bfElemCount uint64  // actual number of elements inserted
	compSize    uint64  // size of compressed bf to be read
	name        string  // name associated with bloom filter
}

func NewBloomFilter(size uint64, hashCount uint16, maxElem uint64) (BloomFilter, error) {
	bf := &bloomFilter{
		hashCount: hashCount,
		maxElem:   maxElem,
	}

	// Make sure size is a power of 2 and at least 64
	if size >= 64 && (size&(size-1)) == 0 {
		var logSize uint16
		for tmp := size; tmp > 0; tmp, logSize = tmp>>1, logSize+1 {
		}
		bf.bitMask = uint64(bitMasks32[logSize+1])
	} else {
		return nil, errors.New("invalid size")
	}

	bf.buffer = make([]uint8, size)

	return bf, nil
}

func NewSimpleBloomFilter() BloomFilter {
	if bf, err := NewBloomFilter(64*mB, 5, 0); err != nil {
		panic(err)
	} else {
		return bf
	}
}

func NewBloomFilterFromIndexFile(indexFileName string) (BloomFilter, error) {
	buffer, err := ioutil.ReadFile(indexFileName)
	if err != nil {
		return nil, err
	}
	bf := &bloomFilter{}
	var bfSize uint64
	if bfSize, err = bf.deserialize(bytes.NewReader(buffer)); err != nil {
		return nil, err
	}

	bfComp := buffer[uint64(len(buffer))-bf.compSize:]
	bf.buffer = make([]uint8, bfSize)
	if n, err := lz4.UncompressBlock(bfComp, bf.buffer); err != nil || uint64(n) != bfSize {
		return nil, err
	}
	bf.computeHamming()

	return bf, err
}

func NewBloomFilterFromString(filter string) (BloomFilter, error) {
	var err error
	r := bufio.NewReader(strings.NewReader(filter))

	bf := &bloomFilter{}
	var bfSize uint64
	if bfSize, err = bf.deserialize(r); err != nil {
		return nil, err
	}

	var rawBf string
	if rawBf, err = r.ReadString('\n'); err != nil {
		return nil, errors.New("failed to read raw bf")
	}

	if decodedBf, err := base64.StdEncoding.DecodeString(rawBf); err != nil {
		return nil, errors.New("failed to decode raw bf")
	} else {
		bf.buffer = make([]uint8, bfSize)
		if n, err := lz4.UncompressBlock(decodedBf, bf.buffer); err != nil || uint64(n) != bfSize {
			return nil, err
		}
	}
	bf.computeHamming()

	return bf, err
}

func newBloomFilterFromExistingData(data []uint8, bfElemCount int) *bloomFilter {
	var logSize uint16
	for tmp := len(data); tmp > 0; tmp, logSize = tmp>>1, logSize+1 {
	}
	bf := &bloomFilter{
		bitMask:     uint64(bitMasks32[logSize+1]),
		hashCount:   5,
		bfElemCount: uint64(bfElemCount),
		buffer:      make([]uint8, len(data)),
	}

	copy(bf.buffer, data)
	bf.computeHamming()

	return bf
}

func (bf *bloomFilter) ElemCount() uint64 {
	return bf.bfElemCount
}

func (bf *bloomFilter) MaxElem() uint64 {
	return bf.maxElem
}

func (bf *bloomFilter) BitsPerElem() float64 {
	return float64(len(bf.buffer)<<3) / float64(bf.bfElemCount)
}

func (bf *bloomFilter) WriteToFile(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	if header, buf, err := bf.serialize(); err != nil {
		return err
	} else {
		if _, err = f.WriteString(header); err != nil {
			return err
		}

		if n, err := f.Write(buf); err != nil {
			return err
		} else if uint64(n) != bf.compSize {
			return errors.New("failed to compress bloom filter")
		}
	}

	return nil
}

func (bf *bloomFilter) Compare(other BloomFilter) int {
	ot := other.(*bloomFilter)

	if len(bf.buffer) != len(ot.buffer) {
		return -1
	}
	var res uint32
	for i := 0; i < len(bf.buffer); i++ {
		res += uint32(bits2.OnesCount8(bf.buffer[i] & ot.buffer[i]))
	}

	var maxEst uint32
	if bf.hamming < ot.hamming {
		maxEst = bf.hamming
	} else {
		maxEst = ot.hamming
	}

	if bf.bfElemCount < 32 || ot.ElemCount() < 32 {
		return 0
	}

	mn := (16 * len(bf.buffer)) / int(bf.bfElemCount+ot.ElemCount())

	var cutOff uint32
	if mn > 128 {
		cutOff = cutoffs[128] - uint32(mn-128) // setting the cutoff to cutoff -n
	} else {
		cutOff = cutoffs[mn]
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

func (bf *bloomFilter) String() string {
	if header, buf, err := bf.serialize(); err != nil {
		return err.Error()
	} else {
		return header + base64.StdEncoding.EncodeToString(buf) + "\n"
	}
}

func (bf *bloomFilter) fold(times uint32) {
	bfSize := len(bf.buffer)
	for i := uint32(0); i < times; i++ {
		for j := 0; j < bfSize/2; j++ {
			bf.buffer[j] |= bf.buffer[j+(bfSize/2)]
		}
		bfSize >>= 2
		if bfSize == 32 {
			break
		}
	}
	var logSize uint16
	for tmp := bfSize; tmp > 0; tmp, logSize = tmp>>1, logSize+1 {
	}
	bf.bitMask = uint64(bitMasks32[logSize+1])

	bf.buffer = bf.buffer[:bfSize]
}

func (bf *bloomFilter) computeHamming() {
	bf.hamming = 0
	for j := 0; j < len(bf.buffer); j++ {
		bf.hamming += uint32(bits2.OnesCount8(bf.buffer[j]))
	}
}

func (bf *bloomFilter) insertSha1(sha1 []uint32) bool {
	return bf.queryAndSet(sha1, true)
}

func (bf *bloomFilter) querySha1(sha1 []uint32) bool {
	return bf.queryAndSet(sha1, false)
}

func (bf *bloomFilter) queryAndSet(sha1 []uint32, modeSet bool) bool {
	var pos, k uint32
	var bitCount uint16
	for i := uint16(0); i < bf.hashCount; i++ {
		pos = sha1[i] & uint32(bf.bitMask)
		k = pos >> 3
		if (bf.buffer[k] & bits[pos&0x7]) != 0 { // Bit is set
			bitCount++
		} else {
			if modeSet {
				bf.buffer[k] |= bits[pos&0x7]
			} else {
				return false
			}
		}
	}
	if modeSet {
		if bitCount < bf.hashCount {
			bf.bfElemCount++
			return true
		} else {
			return false
		}
	} else {
		return bitCount == bf.hashCount
	}
}

func (bf *bloomFilter) serialize() (string, []byte, error) {
	buf := make([]uint8, 160*mB)
	if n, err := lz4.CompressBlock(bf.buffer, buf, nil); err != nil {
		return "", nil, err
	} else {
		bf.compSize = uint64(n)
	}

	header := fmt.Sprintf("sdbf-idx:%v:%v:%v:%v:%v:%s\n", len(bf.buffer), bf.bfElemCount, bf.hashCount,
		bf.bitMask, bf.compSize, bf.name)

	return header, buf[:bf.compSize], nil
}

func (bf *bloomFilter) deserialize(rd io.Reader) (uint64, error) {
	r := bufio.NewReader(rd)
	var bfSize uint64
	var err error
	if _, err := r.ReadBytes(':'); err != nil { // discard headerbit
		return 0, errors.New("failed to read headerbit")
	}
	if bfSizeStr, err := r.ReadString(':'); err != nil {
		return 0, errors.New("failed to read bfSize")
	} else {
		if bfSize, err = strconv.ParseUint(bfSizeStr[:len(bfSizeStr)-1], 10, 64); err != nil {
			return 0, errors.New("failed to parse bfSize")
		}
	}
	if bfElemCountStr, err := r.ReadString(':'); err != nil {
		return 0, errors.New("failed to read bfElemCount")
	} else {
		if bfElemCount, err := strconv.ParseUint(bfElemCountStr[:len(bfElemCountStr)-1], 10, 64); err != nil {
			return 0, errors.New("failed to parse bfElemCount")
		} else {
			bf.bfElemCount = bfElemCount
		}
	}
	if hashCountStr, err := r.ReadString(':'); err != nil {
		return 0, errors.New("failed to read hashCount")
	} else {
		if hashCount, err := strconv.ParseUint(hashCountStr[:len(hashCountStr)-1], 10, 16); err != nil {
			return 0, errors.New("failed to parse hashCount")
		} else {
			bf.hashCount = uint16(hashCount)
		}
	}
	if bitMaskStr, err := r.ReadString(':'); err != nil {
		return 0, errors.New("failed to read bitMask")
	} else {
		if bitMask, err := strconv.ParseUint(bitMaskStr[:len(bitMaskStr)-1], 10, 64); err != nil {
			return 0, errors.New("failed to parse bitMask")
		} else {
			bf.bitMask = bitMask
		}
	}
	if compSizeStr, err := r.ReadString(':'); err != nil {
		return 0, errors.New("failed to read compSize")
	} else {
		if compSize, err := strconv.ParseUint(compSizeStr[:len(compSizeStr)-1], 10, 64); err != nil {
			return 0, errors.New("failed to parse compSize")
		} else {
			bf.compSize = compSize
		}
	}
	if bf.name, err = r.ReadString('\n'); err != nil {
		return 0, errors.New("failed to read name")
	}
	bf.name = bf.name[:len(bf.name)-1] // remove ending newline

	return bfSize, nil
}
