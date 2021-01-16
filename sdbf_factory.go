package sdhash

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"
)

type SdbfFactory interface {
	WithBlockSize(blockSize uint32) SdbfFactory
	WithInitialIndex(initialIndex BloomFilter) SdbfFactory
	WithSearchIndexes(searchIndexes []BloomFilter) SdbfFactory
	WithName(name string) SdbfFactory
	Compute() Sdbf
}

type sdbfFactory struct {
	buffer        []uint8
	ddBlockSize   uint32
	initialIndex  BloomFilter
	searchIndexes []BloomFilter
	name          string
}

// CreateSdbfFromFilename returns a factory which can produce a Sdbf of a file.
func CreateSdbfFromFilename(filename string) (SdbfFactory, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filename)
	}
	if info.Size() < minFileSize {
		return nil, fmt.Errorf("%s is too small", filename)
	}
	if buffer, err := ioutil.ReadFile(filename); err == nil {
		if sdbf, err := CreateSdbfFromBytes(buffer); err != nil {
			panic(err)
		} else {
			sdbf.WithName(path.Base(filename))
			return sdbf, nil
		}
	} else {
		return nil, err
	}
}

// CreateSdbfFromBytes returns a factory which can produce a Sdbf from a bytes buffer.
func CreateSdbfFromBytes(buffer []uint8) (SdbfFactory, error) {
	if len(buffer) < minFileSize {
		return nil, fmt.Errorf("the length of buffer must be greater than %d", minFileSize)
	}
	return &sdbfFactory{
		buffer: buffer,
	}, nil
}

// CreateSdbfFromReader returns a factory which can produce a Sdbf from a io.Reader.
func CreateSdbfFromReader(r io.Reader) (SdbfFactory, error) {
	var buffer []byte
	var err error
	if buffer, err = ioutil.ReadAll(r); err != nil {
		return nil, err
	}
	return CreateSdbfFromBytes(buffer)
}

// WithBlockSize sets the block size for the block mode.
// The default value of 0 involves in a Sdbf generated in stream mode.
func (sdf *sdbfFactory) WithBlockSize(blockSize uint32) SdbfFactory {
	sdf.ddBlockSize = blockSize
	return sdf
}

// WithInitialIndex sets the initial BloomFilter index.
// Without setting an initial index the factory creates a new empty BloomFilter.
func (sdf *sdbfFactory) WithInitialIndex(initialIndex BloomFilter) SdbfFactory {
	sdf.initialIndex = initialIndex
	return sdf
}

// WithSearchIndexes sets a list of BloomFilter which are checked for similarity during digesting process.
// Without setting a value the searching operation during the digesting process is disabled.
func (sdf *sdbfFactory) WithSearchIndexes(searchIndexes []BloomFilter) SdbfFactory {
	sdf.searchIndexes = searchIndexes
	return sdf
}

// WithName sets the name of the Sdbf in the output.
func (sdf *sdbfFactory) WithName(name string) SdbfFactory {
	sdf.name = strings.ReplaceAll(name, ":", "$")
	return sdf
}

// Compute start the digesting process and provide a Sdbf with the result.
func (sdf *sdbfFactory) Compute() Sdbf {
	return createSdbf(sdf.buffer, sdf.ddBlockSize, sdf.initialIndex, sdf.searchIndexes, sdf.name)
}
