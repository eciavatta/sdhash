VERSION := v4.0
NAME := sdhash
BUILDSTRING := $(shell git log --pretty=format:'%h' -n 1)
VERSIONSTRING := $(VERSION)+$(BUILDSTRING)
BUILDDATE := $(shell date -u -Iseconds)
OUTPUT = dist/$(NAME)
LDFLAGS := "-X \"main.Version=$(VERSIONSTRING)\" -X \"main.BuildDate=$(BUILDDATE)\""
GOFILES := $(wildcard app/*.go)

default: build

build: $(OUTPUT)

$(OUTPUT):
	@mkdir -p dist/
	go build -o $(OUTPUT) -ldflags=$(LDFLAGS) -v $(GOFILES)

.PHONY: clean
clean:
	rm -rf dist/

.PHONY: build_release
build_release: clean
	cd app; gox -arch="amd64" -os="windows darwin" -output="../dist/$(NAME)-{{.Arch}}-{{.OS}}" -ldflags=$(LDFLAGS)
	cd app; gox -arch="amd64 arm" -os="linux" -output="../dist/$(NAME)-{{.Arch}}-{{.OS}}" -ldflags=$(LDFLAGS)

.PHONY: test
test:
	go test -v -coverprofile=coverage.txt -covermode=atomic .

.PHONY: coverage
coverage: test
	go tool cover -html=coverage.txt
