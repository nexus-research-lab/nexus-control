.PHONY: run test check

run:
	go run ./cmd/nexus-control

test:
	go test ./...

check:
	go vet ./...
	go test ./...
