package sdhash

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/tmthrgd/go-popcount"
	"io"
	"strconv"
	"strings"
	"sync"
)

// Sdbf represent the similarity digest of a file and can be compared for similarity to others Sdbf.
type Sdbf interface {

	// Name of the of the file or data this Sdbf represents.
	Name() string

	// Size of the hash data for this Sdbf.
	Size() uint64

	// InputSize of the data that the hash was generated from.
	InputSize() uint64

	// FilterCount returns the number of bloom filters count.
	FilterCount() uint32

	// Compare two Sdbf and provide a similarity score ranges between 0 and 100.
	// A score of 0 means that the two files are very different, a score of 100 means that the two files are equals.
	Compare(other Sdbf) int

	// CompareSample compare two Sdbf with sampling and provide a similarity score ranges between 0 and 100.
	// A score of 0 means that the two files are very different, a score of 100 means that the two files are equals.
	CompareSample(other Sdbf, sample uint32) int

	// String returns the encoded Sdbf as a string.
	String() string

	// GetIndex returns the BloomFilter index used during the digesting process.
	GetIndex() BloomFilter

	// GetSearchIndexesResults returns search indexes results.
	// The return value is an array of size == len(searchIndexes), and each elements has another array of length bfCount.
	GetSearchIndexesResults() [][]uint32

	// Fast modify the bloom filter buffer for faster comparison.
	// Warning: the operation overwrite the original buffer.
	Fast()
}

type sdbf struct {
	hamming              []uint16      // hamming weight for each buffer
	buffer               []uint8       // beginning of the buffer cluster
	maxElem              uint32        // max number of elements per filter (n)
	bigFilters           []BloomFilter // new style filters. Now seems to be not very useful
	hashName             string        // name (usually, source file)
	bfCount              uint32        // number of bloom filters
	bfSize               uint32        // bloom filter size in bytes (==m/8)
	lastCount            uint32        // actual number of elements in last filter (n_last); ZERO means look at elemCounts value
	elemCounts           []uint16      // individual elements counts for each buffer (used in dd mode)
	ddBlockSize          uint32        // size of the base block in dd mode
	origFileSize         uint64        // size of the original file
	fastMode             bool          // use fast mode during comparison
	index                BloomFilter   // bloom filter updated during digest process that can be exported
	searchIndexes        []BloomFilter // used to search similar bloom filter during digest process; can be nil
	searchIndexesResults [][]uint32    // results of search indexes; is nil if searchIndexes is nil
	indexMutex           sync.Mutex    // mutex used while updating index bloom filter
}

// ParseSdbfFromString decode a Sdbf from a digest string.
func ParseSdbfFromString(digest string) (Sdbf, error) {
	r := bufio.NewReader(strings.NewReader(digest))
	var err error

	sd := &sdbf{
		bigFilters: make([]BloomFilter, 0),
		index:      NewBloomFilter(),
	}

	var magic, versionStr, originFileSizeStr, bfSizeStr, maxElemStr, bfCountStr string
	var bfSize, maxElem, bfCount uint64
	if magic, err = r.ReadString(':'); err != nil {
		return nil, errors.New("failed to read magic")
	}
	if versionStr, err = r.ReadString(':'); err != nil {
		return nil, errors.New("failed to read version")
	}
	if version, err := strconv.ParseUint(versionStr[:len(versionStr)-1], 10, 64); err != nil {
		return nil, errors.New("failed to parse version")
	} else if version > sdbfVersion {
		return nil, errors.New("invalid sdbf version")
	}
	if _, err = r.ReadBytes(':'); err != nil {
		return nil, errors.New("failed to read hash length")
	}
	if sd.hashName, err = r.ReadString(':'); err != nil {
		return nil, errors.New("failed to read hash name")
	}
	if originFileSizeStr, err = r.ReadString(':'); err != nil {
		return nil, errors.New("failed to read origin file size")
	}
	if sd.origFileSize, err = strconv.ParseUint(originFileSizeStr[:len(originFileSizeStr)-1], 10, 64); err != nil {
		return nil, errors.New("failed to parse origin file size")
	}
	if _, err = r.ReadBytes(':'); err != nil {
		return nil, errors.New("failed to read hash algorithm")
	}
	if bfSizeStr, err = r.ReadString(':'); err != nil {
		return nil, errors.New("failed to read bloom filter size")
	}
	if bfSize, err = strconv.ParseUint(bfSizeStr[:len(bfSizeStr)-1], 10, 64); err != nil {
		return nil, errors.New("failed to parse bloom filter size")
	}
	if _, err = r.ReadBytes(':'); err != nil {
		return nil, errors.New("failed to read hash count")
	}
	if _, err = r.ReadBytes(':'); err != nil {
		return nil, errors.New("failed to read bit mask")
	}
	if maxElemStr, err = r.ReadString(':'); err != nil {
		return nil, errors.New("failed to read max elements count")
	}
	if maxElem, err = strconv.ParseUint(maxElemStr[:len(maxElemStr)-1], 10, 64); err != nil {
		return nil, errors.New("failed to parse max elements count")
	}
	if bfCountStr, err = r.ReadString(':'); err != nil {
		return nil, errors.New("failed to read bloom filter count")
	}
	if bfCount, err = strconv.ParseUint(bfCountStr[:len(bfCountStr)-1], 10, 64); err != nil {
		return nil, errors.New("failed to parse bloom filter count")
	}

	if magic[:len(magic)-1] == magicStream {
		var lastCountStr, encodedBuffer string
		var lastCount uint64
		if lastCountStr, err = r.ReadString(':'); err != nil {
			return nil, errors.New("failed to read last count")
		}
		if lastCount, err = strconv.ParseUint(lastCountStr[:len(lastCountStr)-1], 10, 64); err != nil {
			return nil, errors.New("failed to parse last count")
		}
		if encodedBuffer, err = r.ReadString('\n'); err != nil && err != io.EOF {
			return nil, errors.New("failed to read encoded buffer")
		} else if err == nil {
			encodedBuffer = encodedBuffer[:len(encodedBuffer)-1] // remove newline char
		}
		if sd.buffer, err = base64.StdEncoding.DecodeString(encodedBuffer); err != nil {
			return nil, errors.New("failed to decode base64 buffer")
		}
		sd.lastCount = uint32(lastCount)
	} else if magic[:len(magic)-1] == magicDD {
		var ddBlockSizeStr string
		var ddBlockSize uint64
		if ddBlockSizeStr, err = r.ReadString(':'); err != nil {
			return nil, errors.New("failed to read dd block size")
		}
		if ddBlockSize, err = strconv.ParseUint(ddBlockSizeStr[:len(ddBlockSizeStr)-1], 10, 64); err != nil {
			return nil, errors.New("failed to parse dd block size")
		}
		sd.elemCounts = make([]uint16, bfCount)
		sd.buffer = make([]uint8, bfCount*bfSize)
		for i := uint64(0); i < bfCount; i++ {
			var elemStr, encodedBuffer string
			var elem uint64
			var tmpBuffer []uint8
			if elemStr, err = r.ReadString(':'); err != nil {
				return nil, errors.New("failed to read dd elem")
			}
			if elem, err = strconv.ParseUint(elemStr[:len(elemStr)-1], 16, 64); err != nil {
				return nil, errors.New("failed to parse dd block size")
			}
			sd.elemCounts[i] = uint16(elem)

			if encodedBuffer, err = r.ReadString(':'); err != nil && err != io.EOF {
				return nil, errors.New("failed to read encoded dd buffer")
			}
			if tmpBuffer, err = base64.StdEncoding.DecodeString(encodedBuffer[:len(encodedBuffer)-1]); err != nil {
				return nil, errors.New("failed to decode dd base64 buffer")
			}
			copy(sd.buffer[i*bfSize:], tmpBuffer)
		}
		sd.ddBlockSize = uint32(ddBlockSize)
	} else {
		return nil, errors.New("invalid sdbf magic")
	}

	sd.hashName = sd.hashName[:len(sd.hashName)-1]
	sd.bfSize = uint32(bfSize)
	sd.maxElem = uint32(maxElem)
	sd.bfCount = uint32(bfCount)

	sd.computeHamming()

	return sd, nil
}

// createSdbf create and digest a sdbf file from an initial buffer.
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
		if fileSize%uint64(ddBlockSize) >= MinFileSize {
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

func (sd *sdbf) Name() string {
	return sd.hashName
}

func (sd *sdbf) Size() uint64 {
	return uint64(sd.bfSize) * uint64(sd.bfCount)
}

func (sd *sdbf) InputSize() uint64 {
	return sd.origFileSize
}

func (sd *sdbf) Compare(other Sdbf) int {
	return sd.CompareSample(other, 0)
}

func (sd *sdbf) CompareSample(other Sdbf, sample uint32) int {
	return sd.sdbfScore(sd, other.(*sdbf), sample)
}

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

func (sd *sdbf) GetIndex() BloomFilter {
	return sd.index
}

func (sd *sdbf) GetSearchIndexesResults() [][]uint32 {
	return sd.searchIndexesResults
}

func (sd *sdbf) FilterCount() uint32 {
	return sd.bfCount
}

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
