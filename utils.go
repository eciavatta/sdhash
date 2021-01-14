package sdhash

import (
	"crypto/sha1"
	"encoding/binary"
)

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
		buf[i] = binary.LittleEndian.Uint32(sha[i*4 : (i+1)*4]) // checked: is little endian
	}

	return buf
}
