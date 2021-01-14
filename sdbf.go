package sdhash

import (
	"encoding/base64"
	"fmt"
	"github.com/tmthrgd/go-popcount"
	"strings"
)

type Sdbf struct {
	Hamming              []uint16 // hamming weight for each BF
	buffer               []uint8  // beginning of the BF cluster
	maxElem              uint32   // max number of elements per filter (n)
	bigFilters           []*BloomFilter
	hashName             string   // name (usually, source file)
	bfCount              uint32   // number of BFs
	bfSize               uint32   // bf size in bytes (==m/8)
	lastCount            uint32   // actual number of elements in last filter (n_last); ZERO means look at elemCounts value
	elemCounts           []uint16 // individual elements counts for each BF (used in dd mode)
	ddBlockSize          uint32   // size of the base block in dd mode
	origFileSize         uint64   // size of the original file
	fastMode             bool
	index                *BloomFilter
	searchIndexes        []*BloomFilter
	searchIndexesResults [][]uint32
}

func createSdbf(buffer []uint8, ddBlockSize uint32, initialIndex *BloomFilter, searchIndexes []*BloomFilter,
	name string) *Sdbf {
	sd := &Sdbf{
		hashName:      name,
		bfSize:        BfSize,
		bfCount:       1,
		bigFilters:    make([]*BloomFilter, 0),
		index:         initialIndex,
		searchIndexes: searchIndexes,
	}
	if sd.index == nil {
		sd.index = NewSimpleBloomFilter()
	}
	// trying for m/n = 8
	if bf, err := NewBloomFilter(bigFilter, 5, bigFilterElem, 0.01); err != nil {
		panic(err)
	} else {
		sd.bigFilters = append(sd.bigFilters, bf)
	}
	fileSize := uint64(len(buffer))
	sd.origFileSize = fileSize
	if ddBlockSize == 0 { // stream mode
		sd.maxElem = MaxElem
		sd.genChunkSdbf(buffer, 32*mB)
	} else { // block mode
		sd.maxElem = MaxElemDd
		ddBlockCnt := fileSize / uint64(ddBlockSize)
		if fileSize%uint64(ddBlockSize) >= minFileSize {
			ddBlockCnt++
		}
		sd.bfCount = uint32(ddBlockCnt)
		sd.ddBlockSize = ddBlockSize
		sd.buffer = make([]uint8, ddBlockCnt*uint64(BfSize))
		sd.elemCounts = make([]uint16, ddBlockCnt)
		sd.genBlockSdbfMt(buffer, uint64(ddBlockSize))
	}
	sd.computeHamming()

	return sd
}

/**
  Returns the name of the file or data this Sdbf represents.
*/
func (sd *Sdbf) Name() string {
	return sd.hashName
}

/**
  Returns the size of the hash data for this Sdbf
  \returns uint64_t length value
*/
func (sd *Sdbf) Size() uint64 {
	return uint64(sd.bfSize) * uint64(sd.bfCount)
}

/**
  Returns the size of the data that the hash was generated from.
  \returns uint64_t length value
*/
func (sd *Sdbf) InputSize() uint64 {
	return sd.origFileSize
}

func (sd *Sdbf) Compare(other *Sdbf, sample uint32) int32 {
	return int32(sd.sdbfScore(sd, other, sample))
}

/**
  Encode this Sdbf and return it as a string.
  \returns std::string containing Sdbf suitable for display or writing to file
*/
func (sd *Sdbf) String() string {
	var sb strings.Builder
	if sd.elemCounts == nil {
		sb.WriteString(fmt.Sprintf("%s:%02d:", magicStream, sdbfVersion))
		sb.WriteString(fmt.Sprintf("%d:%s:%d:sha1:", len(sd.hashName), sd.hashName, sd.origFileSize))
		sb.WriteString(fmt.Sprintf("%d:%d:%x:", sd.bfSize, defaultHashCount, defaultMask))
		sb.WriteString(fmt.Sprintf("%d:%d:%d:", sd.maxElem, sd.bfCount, sd.lastCount))
		qt, rem := sd.bfCount/6, sd.bfCount%6
		b64Block := uint64(6 * sd.bfSize)
		var pos uint64
		for i := uint32(0); i < qt; i++ {
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.buffer[pos : pos+b64Block]))
			pos += b64Block
		}
		if rem > 0 {
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.buffer[pos : pos+uint64(rem*sd.bfSize)]))
		}
	} else {
		sb.WriteString(fmt.Sprintf("%s:%02d:", magicDD, sdbfVersion))
		sb.WriteString(fmt.Sprintf("%d:%s:%d:sha1:", len(sd.hashName), sd.hashName, sd.origFileSize))
		sb.WriteString(fmt.Sprintf("%d:%d:%x:", sd.bfSize, defaultHashCount, defaultMask))
		sb.WriteString(fmt.Sprintf("%d:%d:%d", sd.maxElem, sd.bfCount, sd.ddBlockSize))
		for i := uint32(0); i < sd.bfCount; i++ {
			sb.WriteString(fmt.Sprintf(":%02x:", sd.elemCounts[i]))
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.buffer[i*sd.bfSize : i*sd.bfSize+sd.bfSize]))
		}
	}
	sb.WriteByte('\n')

	return sb.String()
}

func (sd *Sdbf) GetIndex() *BloomFilter {
	return sd.index
}

func (sd *Sdbf) CloneFilter(position uint32) []uint8 {
	if position < sd.bfCount {
		filter := make([]uint8, sd.bfSize)
		copy(filter, sd.buffer[position*sd.bfSize:position*sd.bfSize+sd.bfSize])
		return filter
	}
	return nil
}

/**
 * Pre-compute Hamming weights for each BF and adds them to the SDBF descriptor.
 */
func (sd *Sdbf) computeHamming() int {
	sd.Hamming = make([]uint16, sd.bfCount)
	for i := uint32(0); i < sd.bfCount; i++ {
		sd.Hamming[i] = uint16(popcount.CountBytes(sd.buffer[sd.bfSize*i : sd.bfSize*(i+1)]))
	}
	return 0
}

/**
  get element count for comparisons
*/
func (sd *Sdbf) GetElemCount(index uint64) int32 {
	var ret uint32
	if sd.elemCounts == nil {
		if index < uint64(sd.bfCount)-1 {
			ret = sd.maxElem
		} else {
			ret = sd.lastCount
		}
	} else {
		ret = uint32(sd.elemCounts[index])
	}

	return int32(ret)
}

func (sd *Sdbf) FilterCount() uint32 {
	return sd.bfCount
}

/**
  Temporary destructive fast filter comparison.
*/
func (sd *Sdbf) Fast() {
	// for each filter
	for i := uint32(0); i < sd.bfCount; i++ {
		data := sd.CloneFilter(i)
		tmp := NewBloomFilterFromExistingData(data, int(i), int(sd.GetElemCount(uint64(i))), 0)
		tmp.Fold(2)
		tmp.ComputeHamming()
		sd.Hamming[i] = uint16(tmp.Hamminglg)
		copy(sd.buffer[i*sd.bfSize:i*sd.bfSize+sd.bfSize], tmp.BF)
	}
	sd.fastMode = true
}
