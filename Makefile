.PHONY: build test fmt clean

build:
	go build -o bin/dnsd .

test:
	go test ./...

fmt:
	gofmt ./...

clean:
	rm -rf bin
