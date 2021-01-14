package main

import (
	"bufio"
	"fmt"
	"github.com/eciavatta/sdhash"
	"os"
	"strings"
	"sync"
)

type SdbfSet struct {
	Index *sdhash.BloomFilter
	BfVector []*sdhash.BloomFilter
	items []*sdhash.Sdbf
	setname string
	sep byte
	addHashMutex sync.Mutex
}

/**
  Creates empty sdbf_set
*/
func NewSdbfSet() *SdbfSet {
	return &SdbfSet{
		setname:  "default",
		BfVector: make([]*sdhash.BloomFilter, 0),
		sep:      '|',
	}
}

/**
  Creates empty sdbf_set with an index
  \param index to insert new items into
*/
func NewSdbfSetFromIndex(index *sdhash.BloomFilter) *SdbfSet {
	return &SdbfSet{
		setname:  "default",
		Index: index,
		BfVector: make([]*sdhash.BloomFilter, 0),
		sep:      '|',
	}
}

/**
  Loads all sdbfs from a file into a new set
  \param fname name of Sdbf file
*/
func NewSdbfSetFromFileName(fname string) *SdbfSet {
	ss := &SdbfSet{
		Index: nil, // right now we cannot read-in an index, but we can set one later
		BfVector: make([]*sdhash.BloomFilter, 0),
		sep:      '|',
		items: make([]*sdhash.Sdbf, 0),
	}

	if file, err := os.Open(fname); err == nil {
		if stat, err := file.Stat(); err == nil && stat.Mode().IsRegular() {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if len(line) == 0 {
					break
				}
				ss.setname = fname
				ss.items = append(ss.items, nil) // todo:
			}
		}
		_ = file.Close()
	}

	return ss
}

/**
  Accessor method for a single Sdbf* in this set
  \param pos position 0 to size()
  \returns Sdbf* or NULL if position not valid
*/
func (ss *SdbfSet) At(pos uint32) *sdhash.Sdbf {
	if pos < uint32(len(ss.items)) {
		return ss.items[pos]
	} else {
		return nil
	}
}

/**
  Adds a single hash to this set
  \param hash an existing Sdbf hash
*/
func (ss *SdbfSet) AddHash(hash *sdhash.Sdbf) {
	ss.addHashMutex.Lock()
	ss.items = append(ss.items, hash)
	ss.addHashMutex.Unlock()
}

/**
  Adds all items in another set to this set
  \param hashset sdbf_set* to be added
*/
func (ss *SdbfSet) AddHashset(hashset *SdbfSet) {
	// for all in hashset->items, add to this->items
	for _, sd := range hashset.items {
		ss.items = append(ss.items, sd)
	}
}

/**
  Computes the data size of this set, from the
  input_size() values of its' content Sdbf hashes.
  \returns uint64_t total of input sizes
*/
func (ss *SdbfSet) InputSize() uint64 {
	var size uint64
	for _, sd := range ss.items {
		size += sd.InputSize()
	}
	return size
}

/**
  Number of items in this set
  \returns uint64_t number of items in this set
*/
func (ss *SdbfSet) Size() uint64 {
	return uint64(len(ss.items))
}

/**
  Checks empty status of container
  \returns int 1 if empty, 0 if non-empty
*/
func (ss *SdbfSet) Empty() int {
	if len(ss.items) > 0 {
		return 0
	} else {
		return 1
	}
}


/**
  Generates a string which contains the output-encoded sdbfs in this set
  \returns std::string containing sdbfs.
*/
func (ss *SdbfSet) String() string {
	var sb strings.Builder
	for _, sd := range ss.items {
		sb.WriteString(sd.String())
	}
	return sb.String()
}

/**
  Retrieve name of this set
  \returns string name
*/
func (ss *SdbfSet) Name() string {
	return ss.setname
}

/**
  Change name of this set
  \param name of  string
*/
func (ss *SdbfSet) SetName(name string) {
	ss.setname = name
}

/**
  Change comparison output separator
  \param sep charactor separator for output
*/
func (ss *SdbfSet) SetSeparator(sep byte) {
	ss.sep = sep
}

/**
  Compares each Sdbf object in target to every other Sdbf object in target
  and returns the results as a list stored in a string

  \param threshold output threshold, defaults to 1
  \param thread_count processor threads to use, 0 for all available
  \returns std::string result listing
*/
func (ss *SdbfSet) CompareAll(threshold int32, fast bool) string {
	end := len(ss.items)
	var out strings.Builder

	if fast {
		for i := 0; i < end; i++ {
			ss.items[i].Fast()
		}
	}
	for i := 0; i < end; i++ {
		for j := 0; i < end; i++ {
			if i == j {
				continue
			}
			score := ss.items[i].Compare(ss.items[j], 0)
			if score >= threshold {
				out.WriteString(fmt.Sprintf("%s%c%s", ss.items[i].Name(), ss.sep, ss.items[j].Name()))
				if score != -1 {
					out.WriteString(fmt.Sprintf("%c%03d\n", ss.sep, score))
				} else {
					out.WriteString(fmt.Sprintf("%c%d\n", ss.sep, score))
				}
			}
		}
	}

	return out.String()
}

/**
  Compares each Sdbf object in other to each object in this set, and returns
  the results as a list stored in a string.

  \param other set to compare to
  \param threshold output threshold, defaults to 1
  \param sample_size size of bloom filter sample. send 0 for no sampling
  \param thread_count processor threads to use, 0 for all available
  \returns string result listing
*/
func (ss *SdbfSet) CompareTo(other *SdbfSet, threshold int32, sampleSize uint32, fast bool) string {
	tend := other.Size()
	qend := ss.Size()

	var out strings.Builder

	if fast {
		// here: could be parallelized
		for i := uint64(0); i < tend; i++ {
			other.items[i].Fast()
		}
		for i := uint64(0); i < qend; i++ {
			ss.items[i].Fast()
		}
	}
	for i := uint64(0); i < qend; i++ {
		for j := uint64(0); i < tend; i++ {
			score := ss.items[i].Compare(other.items[j], sampleSize)
			if score >= threshold {
				out.WriteString(fmt.Sprintf("%s%c%s", ss.items[i].Name(), ss.sep, other.items[j].Name()))
				if score != -1 {
					out.WriteString(fmt.Sprintf("%c%03d\n", ss.sep, score))
				} else {
					out.WriteString(fmt.Sprintf("%c%d\n", ss.sep, score))
				}
			}
		}
	}

	return out.String()
}

/**
  Returns the size of the set's own bloom_filter vector.
*/
func (ss *SdbfSet) FilterCount() uint64 {
	return uint64(len(ss.BfVector))
}

/**
  Sets up bloom filter vector.
  Should also be called by server process when done hashing to a set
*/
func (ss *SdbfSet) VectorInit() {
	for i := 0; i < len(ss.items); i++ {
		for n := uint32(0); n < ss.items[i].FilterCount(); n++ {
			data := ss.items[i].CloneFilter(n)
			tmp := sdhash.NewBloomFilterFromExistingData(data, i, int(ss.items[i].GetElemCount(uint64(n))), ss.items[i].Hamming[n])
			tmp.SetName(ss.items[i].Name())
			ss.BfVector = append(ss.BfVector, tmp)
		}
	}
}
