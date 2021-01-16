package main

import (
	"fmt"
	"github.com/eciavatta/sdhash"
	"io/ioutil"
	"os"
	"path"
)

func hashFiles(files map[string]os.FileInfo, sdbfSearchSet map[string]*sdbfSet) error {
	var rollIndex sdhash.BloomFilter
	if *index && *output != "" {
		rollIndex = sdhash.NewBloomFilter()
	}
	var searchIndexesNames []string
	var searchIndexes []sdhash.BloomFilter
	if sdbfSearchSet != nil {
		searchIndexesNames = make([]string, 0, len(sdbfSearchSet))
		searchIndexes = make([]sdhash.BloomFilter, 0, len(sdbfSearchSet))
		for filePath, set := range sdbfSearchSet {
			searchIndexesNames = append(searchIndexesNames, filePath)
			searchIndexes = append(searchIndexes, set.Index)
		}
	}

	set := NewSdbfSetFromIndex(rollIndex)
	for filePath, file := range files {
		// todo: dd mode chunks -- hint: io.ReadFull()
		if factory, err := sdhash.CreateSdbfFromFilename(filePath); err == nil {
			var ddBlockSize uint32
			if (*blockSize < 0 && file.Size() < 16*MB) || *blockSize == 0 {
				ddBlockSize = 0
			} else {
				ddBlockSize = uint32(*blockSize) * KB
			}
			logVerbose("digesting file %s using block-size %d", filePath, ddBlockSize)
			sdbf := factory.WithBlockSize(ddBlockSize).WithInitialIndex(rollIndex).WithSearchIndexes(searchIndexes).Compute()
			if *output != "" {
				set.AddHash(sdbf)
			} else if *outputDir != "" {
				outputFilePath := path.Join(*outputDir, file.Name()) + ".sdbf"
				if err := ioutil.WriteFile(outputFilePath, []byte(sdbf.String()), 0644); err != nil {
					return err
				}
				if *index {
					if err := sdbf.GetIndex().WriteToFile(outputFilePath + ".idx"); err != nil {
						return err
					}
				}
			} else {
				fmt.Print(sdbf.String())
			}
		} else {
			return err
		}
	}

	if *output != "" {
		outputFilePath := path.Join(*outputDir, *output) + ".sdbf"
		if err := ioutil.WriteFile(outputFilePath, []byte(set.String()), 0644); err != nil {
			return err
		}
		if *index {
			if err := set.Index.WriteToFile(outputFilePath + ".idx"); err != nil {
				return err
			}
		}
	}

	return nil
}