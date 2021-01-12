package sdhash

import (
	"encoding/base64"
	"fmt"
	"github.com/tmthrgd/go-popcount"
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

/**
  \internal
  Initialize static configuration object with sensible defaults.
*/
var config = NewSdbfConf(FlagOff, MaxElemCount, MaxElemCountDD)

/**
  Create new sdbf from file.  dd_block_size turns on "block" mode.
  \param filename file to hash
  \param dd_block_size size of block to process file with. 0 is off.

  \throws exception if file cannot be opened or too small
*/
func NewSdbfWithIndex(filename string, ddBlockSize uint32, info *indexInfo) (*sdbf, error) {
	buffer, err := processFile(filename, MinFileSize)
	if err != nil {
		return nil, err
	}

	sd := createSdbf(filename)
	sd.info = info
	fileSize := uint64(len(buffer))
	sd.origFileSize = fileSize
	if ddBlockSize == 0 { // stream mode
		sd.MaxElem = config.MaxElem
		sd.genChunkSdbf(buffer, fileSize, 32 * MB)
	} else { // block mode
		sd.MaxElem = config.MaxElemDd
		ddBlockCnt := fileSize / uint64(ddBlockSize)
		if fileSize % uint64(ddBlockSize) >= MinFileSize {
			ddBlockCnt++
		}
		sd.bfCount = uint32(ddBlockCnt)
		sd.ddBlockSize = ddBlockSize
		sd.Buffer = make([]uint8, ddBlockCnt * uint64(config.BfSize))
		sd.elemCounts = make([]uint16, ddBlockCnt)
		sd.genBlockSdbfMt(buffer, fileSize, uint64(ddBlockSize))
	}
	sd.computeHamming()

	return sd, nil
}

func NewSdbf(filename string, ddBlockSize uint32) (*sdbf, error) {
	return NewSdbfWithIndex(filename, ddBlockSize, nil)
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
	// here: skip output
	return int32(sd.sdbfScore(sd, other, sample))
}

/**
  Encode this sdbf and return it as a string.
  \returns std::string containing sdbf suitable for display or writing to file
*/
func (sd *sdbf) String() string {
	var sb strings.Builder
	if sd.elemCounts == nil {
		sb.WriteString(fmt.Sprintf("%s:%02d:", MagicStream, SdbfVersion))
		sb.WriteString(fmt.Sprintf("%d:%s:%d:sha1:", len(sd.hashName), sd.hashName, sd.origFileSize))
		sb.WriteString(fmt.Sprintf("%d:%d:%x:", sd.bfSize, sd.hashCount, sd.mask))
		sb.WriteString(fmt.Sprintf("%d:%d:%d:", sd.MaxElem, sd.bfCount, sd.lastCount))
		qt, rem := sd.bfCount / 6, sd.bfCount % 6
		b64Block := uint64(6*sd.bfSize)
		var pos uint64
		for i := uint32(0); i < qt; i++ {
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.Buffer[pos:pos+b64Block]))
			pos += b64Block
		}
		if rem > 0 {
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.Buffer[pos:pos+uint64(rem*sd.bfSize)]))
		}
	} else {
		sb.WriteString(fmt.Sprintf("%s:%02d:", MagicDD, SdbfVersion))
		sb.WriteString(fmt.Sprintf("%d:%s:%d:sha1:", len(sd.hashName), sd.hashName, sd.origFileSize))
		sb.WriteString(fmt.Sprintf("%d:%d:%x:", sd.bfSize, sd.hashCount, sd.mask))
		sb.WriteString(fmt.Sprintf("%d:%d:%d", sd.MaxElem, sd.bfCount, sd.ddBlockSize))
		for i := uint32(0); i < sd.bfCount; i++ {
			sb.WriteString(fmt.Sprintf(":%02x:", sd.elemCounts[i]))
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.Buffer[i*sd.bfSize:i*sd.bfSize + sd.bfSize]))
		}
	}
	sb.WriteByte('\n')

	return sb.String()
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
	sd.Hamming = make([]uint16, sd.bfCount)
	for i := uint32(0); i < sd.bfCount; i++ {
		sd.Hamming[i] = uint16(popcount.CountBytes(sd.Buffer[sd.bfSize*i:sd.bfSize*(i+1)]))
	}
	return 0
}

/**
  get element count for comparisons
*/
func GetElemCount(mine *sdbf, index uint64) int32 {
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
		tmp := NewBloomFilterFromExistingData(data, int(i), int(GetElemCount(sd, uint64(i))), 0)
		tmp.Fold(2)
		tmp.ComputeHamming()
		sd.Hamming[i] = uint16(tmp.Hamminglg)
		copy(sd.Buffer[i*sd.bfSize:i*sd.bfSize+sd.bfSize], tmp.BF)
	}
	sd.fastMode = true
}

func createSdbf(name string) *sdbf {
	sd := &sdbf{
		hashName:   name,
		bfSize:     config.BfSize,
		hashCount:  5,
		mask:       bfClassMask[0],
		bfCount:    1,
		BigFilters: make([]*bloomFilter, 0),
	}
	// trying for m/n = 8
	if bf, err := NewBloomFilter(BigFilter, 5, BigFilterElem, 0.01); err != nil {
		panic(err)
	} else {
		sd.BigFilters = append(sd.BigFilters, bf)
	}

	return sd
}
