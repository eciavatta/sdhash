package sdhash

import (
	"encoding/base64"
	"fmt"
	"github.com/tmthrgd/go-popcount"
	"strings"
	"sync"
)

type Sdbf interface {
	Name() string
	Size() uint64
	InputSize() uint64
	Compare(other Sdbf) int
	CompareSample(other Sdbf, sample uint32) int
	String() string
	GetIndex() BloomFilter
	Fast()
}

type sdbf struct {
	hamming              []uint16      // hamming weight for each buffer
	buffer               []uint8       // beginning of the buffer cluster
	maxElem              uint32        // max number of elements per filter (n)
	bigFilters           []BloomFilter // new style filters. Now seems to be not very useful
	hashName             string        // name (usually, source file)
	bfCount              uint32        // number of BFs
	bfSize               uint32        // bf size in bytes (==m/8)
	lastCount            uint32        // actual number of elements in last filter (n_last); ZERO means look at elemCounts value
	elemCounts           []uint16      // individual elements counts for each buffer (used in dd mode)
	ddBlockSize          uint32        // size of the base block in dd mode
	origFileSize         uint64        // size of the original file
	fastMode             bool
	index                BloomFilter
	searchIndexes        []BloomFilter
	searchIndexesResults [][]uint32
	indexMutex           sync.Mutex
}

func createSdbf(buffer []uint8, ddBlockSize uint32, initialIndex BloomFilter, searchIndexes []BloomFilter,
	name string) *sdbf {
	sd := &sdbf{
		hashName:      name,
		bfSize:        BfSize,
		bfCount:       1,
		bigFilters:    make([]BloomFilter, 0),
		index:         initialIndex,
		searchIndexes: searchIndexes,
	}
	if sd.index == nil {
		sd.index = NewBloomFilter()
	}
	if bf, err := newBloomFilter(bigFilter, 5, bigFilterElem); err != nil {
		panic(err)
	} else {
		sd.bigFilters = append(sd.bigFilters, bf)
	}
	fileSize := uint64(len(buffer))
	sd.origFileSize = fileSize
	if ddBlockSize == 0 { // stream mode
		sd.maxElem = MaxElem
		sd.generateChunkSdbf(buffer, 32*mB)
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
		sd.generateBlockSdbf(buffer)
	}
	sd.computeHamming()

	return sd
}

// Name of the of the file or data this Sdbf represents.
func (sd *sdbf) Name() string {
	return sd.hashName
}

// Size of the hash data for this Sdbf.
func (sd *sdbf) Size() uint64 {
	return uint64(sd.bfSize) * uint64(sd.bfCount)
}

// InputSize of the data that the hash was generated from.
func (sd *sdbf) InputSize() uint64 {
	return sd.origFileSize
}

// Compare two Sdbf and provide a similarity score ranges between 0 and 100.
// A score of 0 means that the two files are very different, a score of 100 means that the two files are equals.
func (sd *sdbf) Compare(other Sdbf) int {
	return sd.CompareSample(other, 0)
}

// CompareSample compare two Sdbf with sampling and provide a similarity score ranges between 0 and 100.
// A score of 0 means that the two files are very different, a score of 100 means that the two files are equals.
func (sd *sdbf) CompareSample(other Sdbf, sample uint32) int {
	return sd.sdbfScore(sd, other.(*sdbf), sample)
}

// String returns the encoded Sdbf as a string.
func (sd *sdbf) String() string {
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

// GetIndex returns the BloomFilter index used during the digesting process.
func (sd *sdbf) GetIndex() BloomFilter {
	return sd.index
}

// FilterCount returns the number of bloom filters count.
func (sd *sdbf) FilterCount() uint32 {
	return sd.bfCount
}

// Fast modify the bloom filter buffer for faster comparison.
// Warning: the operation overwrite the original buffer.
func (sd *sdbf) Fast() {
	for i := uint32(0); i < sd.bfCount; i++ {
		data := sd.cloneFilter(i)
		tmp := newBloomFilterFromExistingData(data, int(sd.getElemCount(uint64(i))))
		tmp.fold(2)
		tmp.computeHamming()
		sd.hamming[i] = uint16(tmp.hamming)
		copy(sd.buffer[i*sd.bfSize:(i+1)*sd.bfSize], tmp.buffer)
	}
	sd.fastMode = true
}

// getElemCount returns element count for comparisons
func (sd *sdbf) getElemCount(index uint64) int32 {
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

// computeHamming pre-compute hamming weights for each buffer and adds them to the Sdbf descriptor.
func (sd *sdbf) computeHamming() int {
	sd.hamming = make([]uint16, sd.bfCount)
	for i := uint32(0); i < sd.bfCount; i++ {
		sd.hamming[i] = uint16(popcount.CountBytes(sd.buffer[sd.bfSize*i : sd.bfSize*(i+1)]))
	}
	return 0
}

// cloneFilter returns a copy of the buffer of bfSize length at index position.
func (sd *sdbf) cloneFilter(position uint32) []uint8 {
	if position < sd.bfCount {
		filter := make([]uint8, sd.bfSize)
		copy(filter, sd.buffer[position*sd.bfSize:(position+1)*sd.bfSize])
		return filter
	}
	return nil
}
