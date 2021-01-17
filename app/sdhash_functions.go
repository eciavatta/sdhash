package main

import (
	"fmt"
	"github.com/eciavatta/sdhash"
	"io/ioutil"
	"os"
	"path"
)

func hashFiles(files map[string]os.FileInfo, searchIndexes []sdhash.BloomFilter) (*sdbfSet, error) {
	var rollIndex sdhash.BloomFilter
	if *index && *output != "" {
		rollIndex = sdhash.NewBloomFilter()
	}

	set := NewSdbfSetFromIndex(rollIndex)
	for filePath, file := range files {
		// todo: dd mode chunks -- hint: io.ReadFull()
		if factory, err := sdhash.CreateSdbfFromFilename(filePath); err == nil {
			var ddBlockSize uint32
			if (*blockSize < 0 && file.Size() < 16*mb) || *blockSize == 0 {
				ddBlockSize = 0
			} else {
				ddBlockSize = uint32(*blockSize) * kb
			}
			logVerbose("digesting file %s using block-size %d", filePath, ddBlockSize)
			sdbf := factory.WithBlockSize(ddBlockSize).WithInitialIndex(rollIndex).WithSearchIndexes(searchIndexes).Compute()
			set.AddHash(sdbf)
			if *outputDir != "" {
				outputFilePath := path.Join(*outputDir, file.Name()) + ".sdbf"
				if err := ioutil.WriteFile(outputFilePath, []byte(sdbf.String()), 0644); err != nil {
					return nil, err
				}
				if *index {
					if err := sdbf.GetIndex().WriteToFile(outputFilePath + ".idx"); err != nil {
						return nil, err
					}
				}
			} else if *output == "" {
				fmt.Print(sdbf.String())
			}
		} else {
			return nil, err
		}
	}

	if *output != "" {
		outputFilePath := path.Join(*outputDir, *output) + ".sdbf"
		if err := ioutil.WriteFile(outputFilePath, []byte(set.String()), 0644); err != nil {
			return nil, err
		}
		if *index {
			if err := set.index.WriteToFile(outputFilePath + ".idx"); err != nil {
				return nil, err
			}
		}
	}

	return set, nil
}
