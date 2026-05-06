BIN := avault
VERSION := v$(shell tr -d '[:space:]' < VERSION)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.date=$(BUILD_DATE)

ARTIFACTS := \
	$(BIN)-$(VERSION)-linux-amd64 \
	$(BIN)-$(VERSION)-linux-arm64 \
	$(BIN)-$(VERSION)-darwin-amd64 \
	$(BIN)-$(VERSION)-darwin-arm64 \
	$(BIN)-$(VERSION)-windows-amd64.exe

.PHONY: release clean

release: $(ARTIFACTS)

$(BIN)-$(VERSION)-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $@ .

$(BIN)-$(VERSION)-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o $@ .

$(BIN)-$(VERSION)-darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $@ .

$(BIN)-$(VERSION)-darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o $@ .

$(BIN)-$(VERSION)-windows-amd64.exe:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $@ .

clean:
	rm -f $(ARTIFACTS)
