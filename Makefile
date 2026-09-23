BINARY := scan-helper
PKG    := ./cmd/scan-helper

.PHONY: build test test-race run fmt vet tidy

build:
	go build -o $(BINARY) $(PKG)

# Plain `test` runs everywhere. The race detector needs cgo and a C
# toolchain, which plenty of boxes (including the one this was developed
# on) do not have — having `test` fail there made the default target
# useless. Run test-race where a compiler is available; CI should.
test:
	go test ./... -count=1

test-race:
	go test ./... -race -count=1

run: build
	./$(BINARY) -config ./config.yaml

fmt:
	gofmt -w .

vet:
	go vet ./...

tidy:
	go mod tidy
