package sdhash

import (
	"fmt"
	"math"
)

type BloomVectorMessage struct {
	FilterCount int32
	Name string
	Id int32
	FileSize uint64
}

type bloomVector struct {
	Items []*bloomFilter
	FilterCount int
	FileSize uint64
	objName string
}

func NewBloomVector(bvm BloomVectorMessage) *bloomVector {
	return &bloomVector{
		Items: make([]*bloomFilter, 0),
		objName: bvm.Name,
		FilterCount: int(bvm.FilterCount),
		FileSize: bvm.FileSize,
	}
}

func (bv *bloomVector) AddFilter(srcFilter BloomFilterMessage) {
	//bf := make([]uint8, srcFilter.BfSize)
	//for j := 0; j < len(srcFilter.Filter); j++ {
	//	bf[j] = srcFilter.Filter[j]
	//
	//}

	// TODO:
}

func (bv *bloomVector) Details() string {
	return fmt.Sprintf("%s size %v filter count %v", bv.objName, bv.FileSize, bv.FilterCount)
}

func (bv *bloomVector) Compare(other *bloomVector, scale float64) int {
	thisLen, otherLen := len(bv.Items), len(other.Items)
	scoreMatrix := make([]int32, thisLen*otherLen+ 1)
	var runTotal int32
	answer := 0
	for i := 0; i < thisLen; i++ {
		for j := 0; j < otherLen; j++ {
			scoreMatrix[i *otherLen+ j] = int32(bv.Items[i].Compare(other.Items[j], scale))
		}
	}
	if thisLen <= otherLen {
		for i := 0; i < thisLen; i++ {
			var imax int32
			for j := 0; j < otherLen; j++ {
				if scoreMatrix[i*otherLen+ j] > imax {
					imax = scoreMatrix[i*otherLen+ j]
				}
			}
			runTotal += imax
		}
		answer = int(math.Round(float64(runTotal) / float64(thisLen)))
	} else {
		for j := 0; j < otherLen; j++ {
			var imax int32
			for i := 0; i < thisLen; i++ {
				if scoreMatrix[i*otherLen+ j] > imax {
					imax = scoreMatrix[i*otherLen+ j]
				}
			}
			runTotal += imax
		}
		answer = int(math.Round(float64(runTotal) / float64(otherLen)))
	}

	// todo: missing MAPNO

	return answer
}
