package sdhash

import (
	"fmt"
	"testing"
)

func TestGenericSdbf(t *testing.T) {
	test1, err := NewSdbf("/etc/passwd", 0)
	fmt.Println(err)

	fmt.Println(test1.String())
}
