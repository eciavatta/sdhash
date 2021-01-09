package sdhash

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

func processFile(filename string, minFileSize int64) ([]byte, error) {
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

	return ioutil.ReadFile(filename)
}

func memsetU16(buffer []uint16, v uint16) {
	for i := range buffer {
		buffer[i] = v
	}
}

func memsetU32(buffer []uint32, v uint32) {
	for i := range buffer {
		buffer[i] = v
	}
}

func u32sha1(data []uint8) [5]uint32 {
	sha := sha1.Sum(data)

	var buf [5]uint32
	for i := range buf {
		// todo: assuming big endian
		buf[i] = binary.BigEndian.Uint32(sha[i*4:(i+1)*4])
	}

	return buf
}
