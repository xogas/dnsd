.PHONY: build test run fmt vet clean

build:
	go build -o bin/dnsd .

test:
	go test ./...

run:
	go run . -listen 127.0.0.1:5353 -zone example.com=examples/example.com.zone

clean:
	rm -rf bin
