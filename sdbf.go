package sdhash

import (
	"encoding/base64"
	"fmt"
	"github.com/tmthrgd/go-popcount"
	"strings"
)

type Sdbf struct {
	Buffer       []uint8  // Beginning of the BF cluster
	Hamming      []uint16 // Hamming weight for each BF
	MaxElem      uint32   // Max number of elements per filter (n)
	BigFilters   []*BloomFilter

	// from the C structure
	hashName  string // name (usually, source file)
	bfCount   uint32 // Number of BFs
	bfSize    uint32 // BF size in bytes (==m/8)
	lastCount uint32 // Actual number of elements in last filter (n_last);
	// ZERO means look at elemCounts value
	elemCounts    []uint16 // Individual elements counts for each BF (used in dd mode)
	ddBlockSize   uint32   // Size of the base block in dd mode
	origFileSize  uint64   // size of the original file
	fastMode      bool
	index *BloomFilter
	indexMatches []*BloomFilter
	indexMatchesResults [][]uint32
}

/**
  Create new Sdbf from file.  dd_block_size turns on "block" mode.
  \param filename file to hash
  \param dd_block_size size of block to process file with. 0 is off.

  \throws exception if file cannot be opened or too small
*/
func NewSdbf(filename string, ddBlockSize uint32) (*Sdbf, error) {
	buffer, err := processFile(filename, minFileSize)
	if err != nil {
		return nil, err
	}

	sd := createSdbf(filename)
	fileSize := uint64(len(buffer))
	sd.origFileSize = fileSize
	if ddBlockSize == 0 { // stream mode
		sd.MaxElem = MaxElem
		sd.genChunkSdbf(buffer, fileSize, 32 *mB)
	} else { // block mode
		sd.MaxElem = MaxElemDd
		ddBlockCnt := fileSize / uint64(ddBlockSize)
		if fileSize % uint64(ddBlockSize) >= minFileSize {
			ddBlockCnt++
		}
		sd.bfCount = uint32(ddBlockCnt)
		sd.ddBlockSize = ddBlockSize
		sd.Buffer = make([]uint8, ddBlockCnt * uint64(BfSize))
		sd.elemCounts = make([]uint16, ddBlockCnt)
		sd.genBlockSdbfMt(buffer, fileSize, uint64(ddBlockSize))
	}
	sd.computeHamming()

	return sd, nil
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
		sb.WriteString(fmt.Sprintf("%s:%02d:", magicDD, sdbfVersion))
		sb.WriteString(fmt.Sprintf("%d:%s:%d:sha1:", len(sd.hashName), sd.hashName, sd.origFileSize))
		sb.WriteString(fmt.Sprintf("%d:%d:%x:", sd.bfSize, defaultHashCount, defaultMask))
		sb.WriteString(fmt.Sprintf("%d:%d:%d", sd.MaxElem, sd.bfCount, sd.ddBlockSize))
		for i := uint32(0); i < sd.bfCount; i++ {
			sb.WriteString(fmt.Sprintf(":%02x:", sd.elemCounts[i]))
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.Buffer[i*sd.bfSize:i*sd.bfSize + sd.bfSize]))
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
		copy(filter, sd.Buffer[position*sd.bfSize:position*sd.bfSize + sd.bfSize])
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
		sd.Hamming[i] = uint16(popcount.CountBytes(sd.Buffer[sd.bfSize*i:sd.bfSize*(i+1)]))
	}
	return 0
}

/**
  get element count for comparisons
*/
func (sd *Sdbf) GetElemCount(index uint64) int32 {
	var ret uint32
	if sd.elemCounts == nil {
		if index < uint64(sd.bfCount) - 1 {
			ret = sd.MaxElem
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
		copy(sd.Buffer[i*sd.bfSize:i*sd.bfSize+sd.bfSize], tmp.BF)
	}
	sd.fastMode = true
}

func createSdbf(name string) *Sdbf {
	sd := &Sdbf{
		hashName:   name,
		bfSize:     BfSize,
		bfCount:    1,
		BigFilters: make([]*BloomFilter, 0),
		index: NewSimpleBloomFilter(),
	}
	// trying for m/n = 8
	if bf, err := NewBloomFilter(bigFilter, 5, bigFilterElem, 0.01); err != nil {
		panic(err)
	} else {
		sd.BigFilters = append(sd.BigFilters, bf)
	}

	return sd
}
