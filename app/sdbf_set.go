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
	index        sdhash.BloomFilter
	items        []sdhash.Sdbf
	sep          byte
	addHashMutex sync.Mutex
}

// NewSdbfSetFromIndex creates an empty sdbf set with an initial sdhash.BloomFilter index.
func NewSdbfSetFromIndex(index sdhash.BloomFilter) *sdbfSet {
	return &sdbfSet{
		index: index,
		sep:   '|',
	}
}

// NewSdbfSetFromFileName loads all sdhash.Sdbf from a file into a new set.
func NewSdbfSetFromFileName(filename string) (*sdbfSet, error) {
	ss := &sdbfSet{
		index: nil, // right now we cannot read-in an index, but we can set one later
		sep:   '|',
		items: make([]sdhash.Sdbf, 0),
	}

	if file, err := os.Open(filename); err == nil {
		if stat, err := file.Stat(); err == nil && stat.Mode().IsRegular() {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if len(line) == 0 {
					break
				}
				var sdbf sdhash.Sdbf
				if sdbf, err = sdhash.ParseSdbfFromString(line); err != nil {
					return nil, err
				}
				ss.items = append(ss.items, sdbf)
			}
		}
		_ = file.Close()
	}

	return ss, nil
}

// AddHash add a sdhash.Sdbf to the set.
func (ss *sdbfSet) AddHash(hash sdhash.Sdbf) {
	ss.addHashMutex.Lock()
	ss.items = append(ss.items, hash)
	ss.addHashMutex.Unlock()
}

// Size returns the number of items in the set.
func (ss *sdbfSet) Size() uint64 {
	return uint64(len(ss.items))
}

// String generate a string which contains the output-encoded sdhash.Sdbf in the set.
func (ss *sdbfSet) String() string {
	var sb strings.Builder
	for _, sd := range ss.items {
		sb.WriteString(sd.String())
	}
	return sb.String()
}

// SetSeparator change the comparison output separator.
func (ss *sdbfSet) SetSeparator(sep byte) {
	ss.sep = sep
}

// CompareAll compares each sdhash.Sdbf in the set to every sdhash.Sdbf in the set.
// Returns the results as a list stored in a string.
func (ss *sdbfSet) CompareAll(threshold int, fast bool) string {
	end := len(ss.items)
	var out strings.Builder

	if fast {
		for i := 0; i < end; i++ {
			ss.items[i].Fast()
		}
	}
	for i := 0; i < end; i++ {
		for j := i; j < end; j++ {
			if i == j {
				continue
			}
			score := ss.items[i].Compare(ss.items[j])
			if score >= threshold {
				out.WriteString(fmt.Sprintf("%s%c%s", ss.items[i].Name(), ss.sep, ss.items[j].Name()))
				out.WriteString(fmt.Sprintf("%c%03d\n", ss.sep, score))
			}
		}
	}

	return out.String()
}

// Compare compares each sdhash.Sdbf in the set to every sdhash.Sdbf in the other set.
// Returns the results as a list stored in a string.
func (ss *sdbfSet) CompareTo(other *sdbfSet, threshold int, sampleSize uint32, fast bool) string {
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
		for j := uint64(0); j < tend; j++ {
			score := ss.items[i].CompareSample(other.items[j], sampleSize)
			if score >= threshold {
				out.WriteString(fmt.Sprintf("%s%c%s", ss.items[i].Name(), ss.sep, other.items[j].Name()))
				out.WriteString(fmt.Sprintf("%c%03d\n", ss.sep, score))
			}
		}
	}

	return out.String()
}
