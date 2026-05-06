GO = go
BATS = bats

all: luksy

luksy: cmd/luksy/*.go *.go
	$(GO) build -o luksy$(shell go env GOEXE) ./cmd/luksy

vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify
	$(GO) mod edit -toolchain none

clean:
	$(RM) luksy$(shell go env GOEXE) luksy.test

test:
	$(GO) test -timeout 45m -v -cover
	$(BATS) ./tests
