BINARY := scan-helper
PKG    := ./cmd/scan-helper

.PHONY: build test run fmt vet tidy

build:
	go build -o $(BINARY) $(PKG)

test:
	go test ./... -race

run: build
	./$(BINARY) -config ./config.yaml

fmt:
	gofmt -w .

vet:
	go vet ./...

tidy:
	go mod tidy
