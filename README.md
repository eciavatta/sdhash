# sdhash

[![sdhash Actions Status](https://github.com/eciavatta/sdhash/workflows/Test/badge.svg)](https://github.com/eciavatta/sdhash/actions)
[![codecov](https://codecov.io/gh/eciavatta/sdhash/branch/develop/graph/badge.svg)](https://codecov.io/gh/eciavatta/sdhash)
[![Go Report Card](https://goreportcard.com/badge/github.com/eciavatta/sdhash)](https://goreportcard.com/report/github.com/eciavatta/sdhash)
[![GoDoc](https://pkg.go.dev/badge/github.com/eciavatta/sdhash?status.svg)](https://pkg.go.dev/github.com/eciavatta/sdhash?tab=doc)
[![Release](https://img.shields.io/github/release/eciavatta/sdhash.svg?style=flat-square)](https://github.com/eciavatta/sdhash/releases)
![Language](https://img.shields.io/badge/language-go-blue)
![License](https://img.shields.io/github/license/eciavatta/sdhash)

sdhash is a tool that processes binary data and produces similarity digests using bloom filters.
Two binary files with common parts produces two similar digests.
sdhash is able to compare the similarity digests to produce a score.
A score close to 0 means that two file are very different, a score equals to 100 means that two file are equal.

## Features
- calculate similarity digests of many files in a short time
- compare a large amount of digests using precalculated indexes
- the comparison can also be made during the digest process
- same results of original sdhash with similar performance, but entirely rewritten in go language

## Getting started
The sdhash package is available as binaries and as a library.

### Binaries
The binaries for all platforms are available on the [Releases](https://github.com/eciavatta/sdhash/releases) page.

### Library
1. Install sdhash package with the command below
```sh
$ go get -u github.com/eciavatta/sdhash
```

2. Import it in your code and start play around
```go
package main

import (
	"fmt"
	"github.com/eciavatta/sdhash"
)

func main() {
	factoryA, _ := sdhash.CreateSdbfFromFilename("a.bin")
	sdbfA := factoryA.Compute()
	
	factoryB, _ := sdhash.CreateSdbfFromFilename("b.bin")
	sdbfB := factoryB.Compute()
	
	fmt.Println(sdbfA.String())
	fmt.Println(sdbfB.String())
	fmt.Println(sdbfA.Compare(sdbfB))	
}
```

## Documentation
The library documentation is published at [pkg.go.dev/github.com/eciavatta/sdhash](https://pkg.go.dev/github.com/eciavatta/sdhash).
How sdhash works is described in [this paper](http://roussev.net/pubs/2010-IFIP--sdhash-design.pdf),
and [here](http://roussev.net/sdhash/tutorial/sdhash-tutorial.html) you can find a tutorial of the original version of sdhash.

## License
sdhash is originally created by Vassil Roussev and Candice Quates and is licensed under [Apache-2.0 License](SDHASH_LICENSE).
The implementation in golang was made by [Emiliano Ciavatta](https://eciavatta.dev) and is also licensed under
[Apache-2.0 License](SDHASH_LICENSE).
