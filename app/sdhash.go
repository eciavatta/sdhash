package main

import (
	"flag"
	"fmt"
	"os"
)

const Version = "sdhash 4.0, the similarity hashing tool which use bloom filters"

var deep = flag.Bool("r", false, "generate SDBFs from directories and files")
var targetList = flag.String("f", "", "generate SDBFs from list(s) of filenames")
var compare = flag.Bool("c", false,"compare SDBFs in file, or two SDBF files")
var genCompare = flag.Bool("g", false, "compare all pairs in source data")
var threshold = flag.Int("t", 16, "only show results >=threshold")
var blockSize = flag.Int("b", 4096, "hashes input files in nKB blocks")
var sampleSize = flag.Int("s", 0, "sample N filters for comparisons")
var segmentSize = flag.String("z", "", "set file segment size, 128MB default")
var output = flag.String("o", "", "send output to files")
var separator = flag.String("separator", "|", "for comparison results")
var hashName = flag.String("hash-name", "", "set name of hash on stdin")
var fast = flag.Bool("fast", false, "shrink sdbf filters for speedup")
var large = flag.Bool("large", false, "create larger (1M content) filters")
var validate = flag.Bool("validate", false, "parse SDBF file to check if it is valid")
var index = flag.Bool("index", false, "generate indexes while hashing")
var indexSearch = flag.String("index-search", "", "search directory of reference indexes")
var verbose = flag.Bool("verbose", true, "warnings, debug and progress output")
var version = flag.Bool("version", false, "produce help message")


func main() {
	flag.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, Version)
		flag.PrintDefaults()
	}
	flag.Parse()

	if *version {
		fmt.Println(Version)
		return
	}
	inputList := flag.Args()

	var set1 SdbfSet
	if *compare {
		if len(inputList) == 1 {
			set1 := NewSdbfSetFromFileName()

		}

	}

}
