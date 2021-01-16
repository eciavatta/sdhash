package sdhash

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
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

func CreateSdbfFromFilename(filename string) (SdbfFactory, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New(fmt.Sprintf("%s is not a regular file", filename))
	}
	if info.Size() < minFileSize {
		return nil, errors.New(fmt.Sprintf("%s is too small", filename))
	}
	if buffer, err := ioutil.ReadFile(filename); err == nil {
		if sdbf, err := CreateSdbfFromBytes(buffer); err != nil {
			panic(err)
		} else {
			sdbf.WithName(filename)
			return sdbf, nil
		}
	} else {
		return nil, err
	}
}

func CreateSdbfFromBytes(buffer []uint8) (SdbfFactory, error) {
	if len(buffer) < minFileSize {
		return nil, errors.New(fmt.Sprintf("the length of buffer must be greater than %d", minFileSize))
	}
	return &sdbfFactory{
		buffer: buffer,
	}, nil
}

func CreateSdbfFromReader(r io.Reader) (SdbfFactory, error) {
	if buffer, err := ioutil.ReadAll(r); err == nil {
		return CreateSdbfFromBytes(buffer)
	} else {
		return nil, err
	}
}

func (sdf *sdbfFactory) WithBlockSize(blockSize uint32) SdbfFactory {
	sdf.ddBlockSize = blockSize
	return sdf
}

func (sdf *sdbfFactory) WithInitialIndex(initialIndex BloomFilter) SdbfFactory {
	sdf.initialIndex = initialIndex
	return sdf
}

func (sdf *sdbfFactory) WithSearchIndexes(searchIndexes []BloomFilter) SdbfFactory {
	sdf.searchIndexes = searchIndexes
	return sdf
}

func (sdf *sdbfFactory) WithName(name string) SdbfFactory {
	sdf.name = name
	return sdf
}

func (sdf *sdbfFactory) Compute() Sdbf {
	return createSdbf(sdf.buffer, sdf.ddBlockSize, sdf.initialIndex, sdf.searchIndexes, sdf.name)
}
