build:
	go build -o bin/fwsime cmd/fwsim.go

static-check:
	go vet ./...
	golangci-lint run

test: static-check
	go test ./... -vet=all -race -cover -coverprofile=coverage.out

all: clean static-check test build

clean:
	rm bin/*
