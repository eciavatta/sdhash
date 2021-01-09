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
  get element count for comparisons
*/
func (sd *sdbf) GetElemCount(mine *sdbf, index uint64) int32 {
	var ret uint32
	if mine.elemCounts == nil {
		if index < uint64(mine.bfCount) - 1 {
			ret = mine.MaxElem
		} else {
			ret = mine.lastCount
		}
	} else {
		ret = uint32(mine.elemCounts[index])
	}

	return int32(ret)
}

func (sd *sdbf) FilterCount() uint32 {
	return sd.bfCount
}

/**
  Temporary destructive fast filter comparison.
*/
func (sd *sdbf) Fast() {
	// for each filter
	for i := uint32(0); i < sd.bfCount; i++ {
		data := sd.CloneFilter(i)
		tmp := NewBloomFilterFromExistingData(data, int(i), int(sd.GetElemCount(sd, uint64(i))), 0)
		tmp.Fold(2)
		tmp.ComputeHamming()
		sd.Hamming[i] = uint16(tmp.Hamminglg)
		copy(sd.Buffer[i*sd.bfSize:i*sd.bfSize+sd.bfSize], tmp.BF)
	}
	sd.fastMode = true
}



























