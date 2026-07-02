build:
	go build -o bin/fwsim ./cmd/

static-check:
	go vet ./...
	golangci-lint run

test: static-check
	go test ./... -vet=all -race -cover -coverprofile=coverage.out

all: clean static-check test build

clean:
	rm -rf bin/*
