MAJOR = $(shell go version | cut -d' ' -f3 | cut -b 3- | cut -d. -f1)
MINOR = $(shell go version | cut -d' ' -f3 | cut -b 3- | cut -d. -f2)
export GO111MODULE=on

PACKAGES = `go list ./...`

.PHONY: zkvote all clean test

zkvote:| go_version_check
	@echo "building $@..."
	@go build -o $(CURDIR)/bin/$@ ./cmd/zkvote
	@echo "done. executable created at 'bin/$@'"

all: zkvote

go_version_check:
	@if test $(MAJOR) -lt 1; then \
		echo "Go 1.13 or higher required"; \
		exit 1; \
	else \
		if test $(MAJOR) -eq 1 -a $(MINOR) -lt 13; then \
			echo "Go 1.13 or higher required"; \
			exit 1; \
		fi \
	fi

clean:
	-rm -rf \
$(CURDIR)/bin/zkvote \

test:| go_version_check
	@go test -cover $(PACKAGES)