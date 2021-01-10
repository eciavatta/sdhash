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

func memsetU8(buffer []uint8, v uint8) {
	for i := range buffer {
		buffer[i] = v
	}
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
		buf[i] = binary.LittleEndian.Uint32(sha[i*4:(i+1)*4]) // checked: is little endian
	}

	return buf
}

func u32sha1a(data []uint16) [5]uint32 {
	buf := make([]uint8, len(data) * 2)
	for i := range data {
		binary.LittleEndian.PutUint16(buf[i*2:i*2+2], data[i])
	}

	return u32sha1(buf)
}
