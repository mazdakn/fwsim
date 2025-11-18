static-check:
	go vet ./...
	golangci-lint run

test:
	go test ./... -vet=all -race -cover -coverprofile=coverage.out

build:
	go build -o bin/fwsime cmd/fwsim.go

all: clean static-check test build

clean:
	rm bin/*
