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

const (
	KB = 1024
	MB = KB * KB
)

var deep = flag.Bool("r", false, "generate SDBFs from directories and files")
var targetList = flag.Bool("f", false, "generate SDBFs from list(s) of filenames")
var compare = flag.Bool("c", false, "compare SDBFs in file, or two SDBF files")
var genCompare = flag.Bool("g", false, "compare all pairs in source data")
var threshold = flag.Int("t", 16, "only show results >=threshold")
var blockSize = flag.Int("b", -1, "hashes input files in nKB blocks (a value <= 0 means stream mode)")
var sampleSize = flag.Int("s", 0, "sample N filters for comparisons")
var segmentSize = flag.Int("z", 128, "set file segment size, in MB")
var output = flag.String("o", "", "send output to files")
var outputDir = flag.String("output-dir", "", "send output to files")
var separator = flag.String("separator", "|", "for comparison results")
var fast = flag.Bool("fast", false, "shrink sdbf filters for speedup")
var validate = flag.Bool("validate", false, "parse SDBF file to check if it is valid")
var index = flag.Bool("index", false, "generate indexes while hashing")
var indexSearch = flag.String("index-search", "", "search directory of reference indexes")
var verbose = flag.Bool("verbose", false, "warnings, debug and progress output")
var version = flag.Bool("version", false, "produce help message")

func main() {
	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "sdhash is a tool to calculate similarity digests.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	run(flag.Args())
}

func validateArgs() {
	if *segmentSize <= 0 {
		*segmentSize = 128
	}
	*segmentSize *= MB
	if *fast {
		logFatal("not implemented")
	}
	if *index && *output != "" && *outputDir != "" {
		logFatal("indexing require -o or -output-dir flag")
	}
	if *blockSize > 16 {
		*blockSize = 16
		logVerbose("setting block size to maximum value of 16KB")
	}
	if *sampleSize < 0 {
		*sampleSize = 0
	}
	if *threshold < 0 {
		*threshold = 0
	}
	if *indexSearch != "" {
		if *blockSize == 0 {
			logFatal("index searching only supported in block mode")
		} else if *blockSize < 0 {
			*blockSize = 16
			logVerbose("setting block size to 16KB for index search")
		}

		if stat, err := os.Stat(*indexSearch); err != nil {
			logFatal("failed to open index search directory: %s", err)
		} else if !stat.IsDir() {
			logFatal("%s must be a directory", *indexSearch)
		}
	}
}

func run(inputList []string) {
	var err error
	if *version {
		fmt.Printf("sdhash version %s\n", Version)
		return
	}

	validateArgs()

	var searchIndexesNames []string
	var searchIndexes []sdhash.BloomFilter
	if *indexSearch != "" {
		var sdbfSearchSet map[string]*sdbfSet
		if sdbfSearchSet, err = loadIndexSearchFiles(); err != nil {
			logFatal("failed to load index search files: %s", err)
		}
		searchIndexesNames = make([]string, 0, len(sdbfSearchSet))
		searchIndexes = make([]sdhash.BloomFilter, 0, len(sdbfSearchSet))
		for filePath, set := range sdbfSearchSet {
			searchIndexesNames = append(searchIndexesNames, filePath)
			searchIndexes = append(searchIndexes, set.index)
		}
	}

	if *compare {
		if err := compareSdbf(inputList); err != nil {
			logFatal("failed to compare sdbf: %s", err)
		}
		return
	}

	if *validate {
		for _, file := range inputList {
			if stat, err := os.Stat(file); err != nil || !stat.Mode().IsRegular() {
				logWarning("%s is not readable or not found", file)
				continue
			}
			if set1, err := NewSdbfSetFromFileName(file); err != nil {
				logWarning("failed to parse file %s: %s", file, err)
			} else {
				fmt.Printf("file %s is a valid sdbf and contains %d hashes", file, set1.Size())
			}
		}
		return
	}

	var set1 *sdbfSet
	var tmpFile *os.File
	var filesToHash map[string]os.FileInfo
	if len(inputList) == 1 && inputList[0] == "-" && !*targetList {
		buff, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			logFatal("failed to read from stdin: %s", err)
		}
		if tmpFile, err = ioutil.TempFile("", "sdhash"); err != nil {
			logFatal("failed to create temp file: %s", err)
		}
		filesToHash = make(map[string]os.FileInfo, 1)
		filesToHash[tmpFile.Name()], _ = tmpFile.Stat()
		_, _ = tmpFile.Write(buff)
		_ = tmpFile.Close()
	} else if len(inputList) > 0 {
		if filesToHash, err = listFilesToHash(inputList); err != nil {
			logFatal("failed to find files to hash: %s", err)
		}
	} else {
		flag.Usage()
		return
	}

	if set1, err = hashFiles(filesToHash, searchIndexes); err != nil {
		logFatal("failed to hash files: %s", err)
	}
	if tmpFile != nil {
		if err = os.Remove(tmpFile.Name()); err != nil {
			logWarning("failed to remove temp file %s: %s", tmpFile.Name(), err)
		}
	}
	if *genCompare {
		set1.SetSeparator((*separator)[0])
		results := set1.CompareAll(*threshold, *fast)
		writeCompareResults(results)
	} else if *indexSearch != "" {
		var sb strings.Builder
		sep := (*separator)[0]
		for _, sdbf := range set1.items {
			for pos, matches := range sdbf.GetSearchIndexesResults() {
				for i, match := range matches {
					if match >= uint32(*threshold) && searchIndexesNames != nil {
						sb.WriteString(fmt.Sprintf("%s [%d] %c %s %c %d\n", sdbf.Name(), pos, sep,
							searchIndexesNames[i], sep, match))
					}
				}
			}
		}
		writeCompareResults(sb.String())
	}
}

func loadIndexSearchFiles() (map[string]*sdbfSet, error) {
	sdbfFiles := make(map[string]*sdbfSet)
	if infos, err := ioutil.ReadDir(*indexSearch); err == nil {
		for _, info := range infos {
			if !info.Mode().IsRegular() {
				continue
			} else if path.Ext(info.Name()) == ".sdbf" {
				filePath := path.Join(*indexSearch, info.Name())
				if sdbfFiles[filePath], err = NewSdbfSetFromFileName(filePath); err != nil {
					return nil, err
				}
			} else if path.Ext(info.Name()) == ".idx" {
				if bf, err := sdhash.NewBloomFilterFromIndexFile(info.Name()); err == nil {
					sdbfName := strings.TrimSuffix(info.Name(), filepath.Ext(info.Name()))
					if sdbfFile, ok := sdbfFiles[sdbfName]; !ok {
						logVerbose("skipping %s, no valid sdbf file found", sdbfName)
					} else {
						sdbfFile.index = bf
						logVerbose("loading index file %s", info.Name())
					}
				} else {
					logWarning("skipping %s, which is not a valid index file", info.Name())
				}
			}
		}
	} else {
		return nil, err
	}

	return sdbfFiles, nil
}

func compareSdbf(inputList []string) error {
	if len(inputList) <= 2 {
		var set1, set2 *sdbfSet
		var err error
		if set1, err = NewSdbfSetFromFileName(inputList[0]); err != nil {
			return err
		}
		set1.SetSeparator((*separator)[0])

		var results string
		if len(inputList) == 2 {
			if set2, err = NewSdbfSetFromFileName(inputList[1]); err != nil {
				return err
			}
			set2.SetSeparator((*separator)[0])
			results = set1.CompareTo(set2, *threshold, uint32(*sampleSize), *fast)
		} else {
			results = set1.CompareAll(*threshold, *fast)
		}

		writeCompareResults(results)
		return nil
	}
	return errors.New("comparison requires 1 or 2 arguments")
}

func listFilesToHash(inputList []string) (map[string]os.FileInfo, error) {
	filesToHash := make(map[string]os.FileInfo)
	logVerbose("building list of files to be hashed")

	addFile := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logWarning("failed to read %s: %s", path, err)
		} else if info.IsDir() {
			return nil
		} else if info.Mode().IsRegular() && info.Size() < sdhash.MinFileSize {
			logWarning("skipping %s because is too small", path)
		} else if info.Mode().IsRegular() {
			logVerbose("adding %s to files to hash", path)
			filesToHash[path] = info
			if info.Size() > int64(*segmentSize) {
				logWarning("file %s will be segmented in %d MB chunks prior to hashing", path, *segmentSize/MB)
			}
		} else {
			logWarning("skipping %s because is not a regular file", path)
		}
		return nil
	}

	for _, input := range inputList {
		if stat, err := os.Stat(input); err != nil {
			return nil, fmt.Errorf("failed to open %s", input)
		} else if stat.Mode().IsRegular() && *targetList {
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
