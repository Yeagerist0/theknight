.PHONY: build test lint vet fmt clean run

build:
	go build -o bin/theknight ./cmd/theknight

run: build
	./bin/theknight

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

lint: fmt vet

clean:
	rm -rf bin/
