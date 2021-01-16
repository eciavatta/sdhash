package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"github.com/eciavatta/sdhash"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
)

var Version string
var BuildDate string

const (
	KB = 1024
	MB = KB * KB
)

var deep = flag.Bool("r", false, "generate SDBFs from directories and files")
var targetList = flag.String("f", "", "generate SDBFs from list(s) of filenames")
var compare = flag.Bool("c", false, "compare SDBFs in file, or two SDBF files")
var genCompare = flag.Bool("g", false, "compare all pairs in source data")
var threshold = flag.Int("t", 16, "only show results >=threshold")
var blockSize = flag.Int("b", -1, "hashes input files in nKB blocks")
var sampleSize = flag.Int("s", 0, "sample N filters for comparisons")
var segmentSize = flag.Int("z", 0, "set file segment size, 128MB default")
var output = flag.String("o", "", "send output to files")
var outputDir = flag.String("output-dir", "", "send output to files")
var separator = flag.String("separator", "|", "for comparison results")
var hashName = flag.String("hash-name", "", "set name of hash on stdin")
var fast = flag.Bool("fast", false, "shrink sdbf filters for speedup")
var validate = flag.Bool("validate", false, "parse SDBF file to check if it is valid")
var index = flag.Bool("index", false, "generate indexes while hashing")
var indexSearch = flag.String("index-search", "", "search directory of reference indexes")
var verbose = flag.Bool("verbose", true, "warnings, debug and progress output")
var version = flag.Bool("version", false, "produce help message")

func main() {
	flag.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, Version+"\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	run(flag.Args())
}

func run(inputList []string) {
	if *version {
		fmt.Println(Version)
		return
	}

	sdbfSearchSet := make(map[string]*sdbfSet)
	if *indexSearch != "" {
		if err := loadIndexSearchFiles(sdbfSearchSet); err != nil {
			logFatal("failed to load index search files: %s", err)
		}
	}

	if *compare {
		if err := compareSdbf(inputList); err != nil {
			logFatal("failed to compare sdbf: %s", err)
		} else {
			return
		}
	}

	if *validate {
		for _, file := range inputList {
			if stat, err := os.Stat(file); err != nil || !stat.Mode().IsRegular() {
				logWarning("%s is not readable or not found", file)
				continue
			}
			set1 := NewSdbfSetFromFileName(file)
			fmt.Println(set1.Details())
			return
		}
	}

	var set1 *sdbfSet
	var filesToHash map[string]os.FileInfo
	if len(inputList) == 1 && inputList[0] == "-" && *targetList == "" {
		if *segmentSize == 0 {
			*segmentSize = 128 * MB
		}
		if *blockSize <= 0 {
			*blockSize = 16
		}
		// todo: set1 = sdbf_hash_stdin()
	} else if len(inputList) > 0 {
		var err error
		if filesToHash, err = listFilesToHash(inputList); err != nil {
			logFatal("failed to find files to hash: %s", err)
		}
	} else {
		flag.Usage()
		return
	}

	if err := hashFiles(filesToHash, sdbfSearchSet); err != nil {
		logFatal("failed to hash files: %s", err)
	}
	if *genCompare {
		set1.SetSeparator((*separator)[0])
		results := set1.CompareAll(*threshold, *fast)
		writeCompareResults(results)
	} else {
		// todo:
	}
}

func loadIndexSearchFiles(sdbfFiles map[string]*sdbfSet) error {
	indexFiles := make(map[string]sdhash.BloomFilter)

	if *blockSize == 0 {
		return errors.New("index searching only supported in block mode")
	} else if *blockSize < 0 {
		*blockSize = 16
		logVerbose("setting block size to 16KB for index search")
	}
	if stat, err := os.Stat(*indexSearch); err != nil {
		return err
	} else if !stat.IsDir() {
		return errors.New(fmt.Sprintf("%s must be a directory", *indexSearch))
	}

	if infos, err := ioutil.ReadDir(*indexSearch); err == nil {
		for _, info := range infos {
			if !info.Mode().IsRegular() {
				continue
			}
			if path.Ext(info.Name()) == ".sdbf" {
				sdbfFiles[info.Name()] = NewSdbfSetFromFileName(info.Name())
			}
			if path.Ext(info.Name()) == ".idx" {
				if bf, err := sdhash.NewBloomFilterFromIndexFile(info.Name()); err == nil {
					sdbfName := strings.TrimSuffix(info.Name(), filepath.Ext(info.Name()))
					if sdbfFile, ok := sdbfFiles[sdbfName]; !ok {
						logVerbose("skipping %s, no valid sdbf file found", sdbfName)
					} else {
						indexFiles[info.Name()] = bf
						sdbfFile.Index = bf
						logVerbose("loading index file %s", info.Name())
					}
				} else {
					logWarning("skipping %s, which is not a valid index file", info.Name())
				}
			}
		}
	} else {
		return err
	}

	return nil
}

func compareSdbf(inputList []string) error {
	if len(inputList) <= 2 {
		set1 := NewSdbfSetFromFileName(inputList[0]) // todo: check for exceptions
		set1.SetSeparator((*separator)[0])

		var results string
		if len(inputList) == 2 {
			set2 := NewSdbfSetFromFileName(inputList[1])
			set2.SetSeparator((*separator)[0])
			results = set1.CompareTo(set2, *threshold, uint32(*sampleSize), *fast)
		} else {
			results = set1.CompareAll(*threshold, *fast)
		}

		writeCompareResults(results)
		return nil
	} else {
		return errors.New("comparison requires 1 or 2 arguments")
	}
}

func listFilesToHash(inputList []string) (map[string]os.FileInfo, error) {
	filesToHash := make(map[string]os.FileInfo)
	logVerbose("building list of files to be hashed")

	addFile := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logWarning("failed to read %s: %s", path, err)
			return err
		} else if info.IsDir() {
			return filepath.SkipDir
		} else if info.Mode().IsRegular() {
			logVerbose("adding %s to files to hash", path)
			filesToHash[path] = info
			if info.Size() > int64(*segmentSize) {
				logWarning("file %s will be segmented in %d MB chunks prior to hashing", path, *segmentSize/MB)
			}
			return nil
		} else {
			logWarning("skipping %s because is not a regular file", path)
			return nil
		}
	}

	for _, input := range inputList {
		if stat, err := os.Stat(input); err != nil {
			return nil, errors.New("failed to open %s" + input)
		} else if stat.Mode().IsRegular() && *targetList != "" {
			if file, err := os.Open(input); err == nil {
				s := bufio.NewScanner(file)
				for s.Scan() {
					info, err := os.Stat(s.Text())
					_ = addFile(s.Text(), info, err)
				}
				_ = file.Close()
			} else {
				return nil, err
			}
		} else if stat.IsDir() && *deep {
			if err := filepath.Walk(input, addFile); err != nil {
				logWarning("recursive searching error: %s", err)
			}
		} else if stat.Mode().IsRegular() {
			_ = addFile(input, stat, nil)
		} else {
			logWarning("skipping %s because is not a regular file")
		}
	}

	return filesToHash, nil
}

func writeCompareResults(results string) {
	if *output != "" {
		if err := ioutil.WriteFile(*output+".compare", []byte(results), 0644); err != nil {
			logFatal("failed to write compare results: %s", err)
		}
	} else {
		fmt.Print(results)
	}
}

func logFatal(message string, args ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, "error: "+message+"\n", args...)
	os.Exit(1)
}

func logWarning(message string, args ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, "warning: "+message+"\n", args...)
}

func logVerbose(message string, args ...interface{}) {
	if *verbose {
		_, _ = fmt.Fprintf(os.Stderr, "verbose: "+message+"\n", args...)
	}
}
