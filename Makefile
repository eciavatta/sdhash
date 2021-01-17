VERSION := 4.0
NAME := sdhash
BUILDSTRING := $(shell git log --pretty=format:'%h' -n 1)
VERSIONSTRING := $(VERSION)+$(BUILDSTRING)
OUTPUT = dist/$(NAME)
LDFLAGS := "-X \"main.Version=$(VERSIONSTRING)\""
GOFILES := $(wildcard app/*.go)

default: build

.PHONY: build
build: $(OUTPUT)

.PHONY: dist/$(NAME)
$(OUTPUT):
	@mkdir -p dist/
	go build -o $(OUTPUT) -ldflags=$(LDFLAGS) -v $(GOFILES)

clean:
	rm -rf dist/

build_release: clean
	GOOS=darwin GOARCH=amd64 go build -o "dist/$(NAME)-darwin-amd64" -ldflags=$(LDFLAGS) $(GOFILES)
	GOOS=linux GOARCH=amd64 go build -o "dist/$(NAME)-linux-amd64" -ldflags=$(LDFLAGS) $(GOFILES)
	GOOS=windows GOARCH=amd64 go build -o "dist/$(NAME)-windows-amd64" -ldflags=$(LDFLAGS) $(GOFILES)
	GOOS=linux GOARCH=arm64 go build -o "dist/$(NAME)-linux-arm64" -ldflags=$(LDFLAGS) $(GOFILES)

test:
	go test -v -coverprofile=coverage.txt -covermode=atomic .

coverage: test
	go tool cover -html=coverage.txt
