
.PHONY: build test negative vet image

build:
	cd app && go build -o sealix ./cmd/sealix

test:
	cd app && go test ./... -count=1

negative:
	cd app && go test ./internal/cli -run '^TestNegativeU02ToU13$$|^TestVerifyPrecedence$$' -count=1 -v

vet:
	cd app && go vet ./...

image:
	docker build --build-arg VERSION=dev -t sealix:dev .
