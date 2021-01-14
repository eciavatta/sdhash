package main

import (
	"bufio"
	"fmt"
	"github.com/eciavatta/sdhash"
	"os"
	"strings"
	"sync"
)

type sdbfSet struct {
	Index *sdhash.BloomFilter
	items []*sdhash.Sdbf
	sep byte
	addHashMutex sync.Mutex
}

/**
  Creates empty sdbf_set with an index
  \param index to insert new items into
*/
func NewSdbfSetFromIndex(index *sdhash.BloomFilter) *sdbfSet {
	return &sdbfSet{
		Index: index,
		sep:      '|',
	}
}

/**
  Loads all sdbfs from a file into a new set
  \param fname name of sdbf file
*/
func NewSdbfSetFromFileName(fname string) *sdbfSet {
	ss := &sdbfSet{
		Index: nil, // right now we cannot read-in an index, but we can set one later
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
				ss.items = append(ss.items, nil) // todo:
			}
		}
		_ = file.Close()
	}

	return ss
}

/**
  Adds a single hash to this set
  \param hash an existing sdbf hash
*/
func (ss *sdbfSet) AddHash(hash *sdhash.Sdbf) {
	ss.addHashMutex.Lock()
	ss.items = append(ss.items, hash)
	ss.addHashMutex.Unlock()
}

func (ss *sdbfSet) Details() string {
	return "" // todo:
}

/**
  Number of items in this set
  \returns uint64_t number of items in this set
*/
func (ss *sdbfSet) Size() uint64 {
	return uint64(len(ss.items))
}

/**
  Generates a string which contains the output-encoded sdbfs in this set
  \returns std::string containing sdbfs.
*/
func (ss *sdbfSet) String() string {
	var sb strings.Builder
	for _, sd := range ss.items {
		sb.WriteString(sd.String())
	}
	return sb.String()
}

/**
  Change comparison output separator
  \param sep charactor separator for output
*/
func (ss *sdbfSet) SetSeparator(sep byte) {
	ss.sep = sep
}

/**
  Compares each sdbf object in target to every other sdbf object in target
  and returns the results as a list stored in a string

  \param threshold output threshold, defaults to 1
  \param thread_count processor threads to use, 0 for all available
  \returns std::string result listing
*/
func (ss *sdbfSet) CompareAll(threshold int32, fast bool) string {
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
  Compares each sdbf object in other to each object in this set, and returns
  the results as a list stored in a string.

  \param other set to compare to
  \param threshold output threshold, defaults to 1
  \param sample_size size of bloom filter sample. send 0 for no sampling
  \param thread_count processor threads to use, 0 for all available
  \returns string result listing
*/
func (ss *sdbfSet) CompareTo(other *sdbfSet, threshold int32, sampleSize uint32, fast bool) string {
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
